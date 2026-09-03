#include <mongoose.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto.h"
#include "json_util.h"
#include "nips/nip_event.h"
#include "nips/nip01.h"
#include "nips/nip09.h"
#include "nips/nip11.h"
#include "nips/nip13.h"
#include "nips/nip16.h"
#include "nips/nip17.h"
#include "nips/nip33.h"
#include "nips/nip40.h"
#include "nips/nip42.h"
#include "nips/nip45.h"
#include "nips/nip62.h"
#include "nips/nip67.h"
#include "server.h"

#define MAX_SUBSCRIPTIONS 20
#define MAX_FILTERS 10
#define MAX_SUB_ID_LENGTH 100
#define MAX_WS_MESSAGE_LENGTH (5 * 1024 * 1024)
#define MAX_EVENT_CONTENT_LENGTH 16384

typedef struct subscription {
    struct mg_connection *connection;
    char *id;
    filter_t *filters;
    size_t filters_count;
    struct subscription *next;
} subscription_t;

static struct mg_mgr manager;
static volatile sig_atomic_t stop_requested;
static storage_context_t *storage_ctx;
static subscription_t *subscriptions;
static struct mg_connection *query_connection;
static filter_t *query_filters;
static size_t query_filters_count;
static int min_pow_difficulty;
static time_t created_at_lower_limit;
static time_t created_at_upper_limit = 900;
static char service_url[256];

static bool mg_str_contains(struct mg_str haystack, const char *needle) {
    size_t needle_len = strlen(needle);
    if (needle_len > haystack.len) return false;
    for (size_t i = 0; i + needle_len <= haystack.len; i++) {
        if (memcmp(haystack.buf + i, needle, needle_len) == 0) return true;
    }
    return false;
}

static void send_json(struct mg_connection *connection, const char *json) {
    mg_ws_send(connection, json, strlen(json), WEBSOCKET_OP_TEXT);
}

/* ---------------------------------------------------------------------------
 * Debug logging helpers.
 *
 * Every log line is prefixed with a timestamp and the remote address of the
 * connection it relates to (when available), so the console output can be
 * correlated with a specific client. These are intentionally plain stdio
 * calls rather than pulling nob.h into the runtime binary.
 * ------------------------------------------------------------------------- */

static void log_timestamp(void) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char stamp[32];
    if (tm && strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", tm)) {
        fprintf(stdout, "[%s] ", stamp);
    }
}

static void log_peer(struct mg_connection *connection) {
    if (!connection) return;
    char peer[64];
    mg_snprintf(peer, sizeof(peer), "%M", mg_print_ip_port, &connection->rem);
    fprintf(stdout, "peer=%s ", peer);
}

static void log_message(struct mg_connection *connection, const char *fmt, ...) {
    va_list args;
    log_timestamp();
    log_peer(connection);
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fputc('\n', stdout);
    fflush(stdout);
}

static char *tag_element(struct mg_str tag, size_t index) {
    size_t length = tag.len + 3;
    char *json = (char *) malloc(length);
    char path[32];
    char *value;
    if (!json) return NULL;
    json[0] = '[';
    memcpy(json + 1, tag.buf, tag.len);
    json[tag.len + 1] = ']';
    json[tag.len + 2] = '\0';
    snprintf(path, sizeof(path), "$[%llu]", (unsigned long long) index);
    value = mg_json_get_str(mg_str(json), path);
    free(json);
    return value;
}

static bool event_has_tag(const event_t *event, const char *name, const char *value) {
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *tag_name = tag_element(tag, 0);
        char *tag_value = tag_element(tag, 1);
        bool found = tag_name && strcmp(tag_name, name) == 0 &&
                     (!value || (tag_value && strcmp(tag_value, value) == 0));
        free(tag_name);
        free(tag_value);
        if (found) return true;
    }
    return false;
}

static bool event_has_relay_tag(const event_t *event, const char *relay) {
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    size_t relay_length = strlen(relay);
    while (relay_length && relay[relay_length - 1] == '/') relay_length--;
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = tag_element(tag, 0);
        char *value = tag_element(tag, 1);
        size_t value_length = value ? strlen(value) : 0;
        while (value_length && value[value_length - 1] == '/') value_length--;
        bool found = name && value && strcmp(name, "relay") == 0 &&
                     value_length == relay_length &&
                     memcmp(value, relay, relay_length) == 0;
        free(name);
        free(value);
        if (found) return true;
    }
    return false;
}

static void send_status(struct mg_connection *connection, const char *type,
                        const char *id, bool ok, const char *message) {
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, type);
    if (id) json_builder_append_string(&builder, id);
    if (strcmp(type, "OK") == 0) json_builder_append_bool(&builder, ok);
    json_builder_append_string(&builder, message);
    send_json(connection, json_builder_finish(&builder));
}

static void filter_release(filter_t *filter) {
    if (!filter) return;
    for (size_t i = 0; i < filter->ids_count; i++) free(filter->ids[i]);
    for (size_t i = 0; i < filter->authors_count; i++) free(filter->authors[i]);
    for (size_t i = 0; i < filter->tags_count; i++) {
        for (size_t j = 0; j < filter->tags[i].count; j++) free(filter->tags[i].elements[j]);
        free(filter->tags[i].elements);
    }
    free(filter->ids); free(filter->authors); free(filter->kinds);
    free(filter->tags); free(filter->search);
    memset(filter, 0, sizeof(*filter));
}

static void remove_subscriptions(struct mg_connection *connection, const char *id) {
    subscription_t **link = &subscriptions;
    while (*link) {
        subscription_t *subscription = *link;
        if ((!connection || subscription->connection == connection) &&
            (!id || strcmp(subscription->id, id) == 0)) {
            *link = subscription->next;
            for (size_t i = 0; i < subscription->filters_count; i++) filter_release(&subscription->filters[i]);
            free(subscription->filters); free(subscription->id); free(subscription);
        } else link = &subscription->next;
    }
}

static bool matches_filter(const filter_t *filter, const event_t *event) {
    if (filter->since && event->created_at < filter->since) return false;
    if (filter->until && event->created_at > filter->until) return false;
    if (filter->ids_count) {
        bool matched = false;
        for (size_t i = 0; i < filter->ids_count; i++) if (strncmp(event->id, filter->ids[i], strlen(filter->ids[i])) == 0) matched = true;
        if (!matched) return false;
    }
    if (filter->authors_count) {
        bool matched = false;
        for (size_t i = 0; i < filter->authors_count; i++) if (strncmp(event->pubkey, filter->authors[i], strlen(filter->authors[i])) == 0) matched = true;
        if (!matched) return false;
    }
    if (filter->kinds_count) {
        bool matched = false;
        for (size_t i = 0; i < filter->kinds_count; i++) if (event->kind == filter->kinds[i]) matched = true;
        if (!matched) return false;
    }
    for (size_t i = 0; i < filter->tags_count; i++) {
        bool matched = false;
        tag_t *tag = &filter->tags[i];
        for (size_t j = 1; j < tag->count; j++) {
            if (event_has_tag(event, tag->elements[0], tag->elements[j])) matched = true;
        }
        if (!matched) return false;
    }
    if (filter->search && *filter->search &&
        !mg_str_contains(mg_str(event->content ? event->content : ""), filter->search)) return false;
    return true;
}

static void broadcast_event(const event_t *event) {
    for (subscription_t *subscription = subscriptions; subscription; subscription = subscription->next) {
        bool matched = false;
        for (size_t i = 0; i < subscription->filters_count; i++) if (matches_filter(&subscription->filters[i], event)) matched = true;
        const char *pubkey = nip42_authenticated_pubkey(subscription->connection);
        if (matched && nip17_can_deliver(event, pubkey)) {
            json_builder_t builder;
            json_builder_start(&builder);
            json_builder_append_string(&builder, "EVENT");
            json_builder_append_string(&builder, subscription->id);
            json_serialize_event(event, &builder);
            send_json(subscription->connection, json_builder_finish(&builder));
        }
    }
}

static void query_sender(const char *json) {
    json_value_t values[MAX_JSON_ARRAY_ELEMENTS] = {{0}};
    size_t count;
    event_t event;
    bool matched = false;

    if (!query_connection) return;
    count = json_array_parse(json, values, MAX_JSON_ARRAY_ELEMENTS);
    if (count == 3 && values[0].type == JSON_TYPE_STRING &&
        strcmp(values[0].value.string_val, "EVENT") == 0 &&
        values[2].type == JSON_TYPE_OBJECT &&
        json_parse_event(values[2].value.string_val, &event)) {
        for (size_t i = 0; i < query_filters_count; i++) {
            if (matches_filter(&query_filters[i], &event)) matched = true;
        }
        if (matched && nip17_can_deliver(&event, nip42_authenticated_pubkey(query_connection))) {
            send_json(query_connection, json);
        }
        event_release(&event);
    } else if (count == 3 && values[0].type == JSON_TYPE_STRING &&
               strcmp(values[0].value.string_val, "COUNT") == 0) {
        send_json(query_connection, json);
    }
    json_array_free(values, count);
}

static void query_events(struct mg_connection *connection, const char *sub,
                         filter_t *filters, size_t count, bool do_count) {
    bool has_more = false;
    query_connection = connection;
    query_filters = filters;
    query_filters_count = count;
    storage_ctx->send_records(query_sender, sub, filters, count, do_count,
                              do_count ? NULL : &has_more);
    query_connection = NULL;
    query_filters = NULL;
    query_filters_count = 0;
    if (!do_count) {
        char *eose_response = nip67_build_eose_response(sub, has_more);
        if (eose_response) {
            send_json(connection, eose_response);
            free(eose_response);
        }
    }
}

static bool collect_filters(json_value_t *values, size_t count, filter_t **out,
                            size_t *out_count) {
    filter_t *filters = NULL;
    size_t filter_capacity = 0;

    /* Two accepted layouts:
     *   nostr-tools: ["REQ"/"COUNT", id, {filter1}, {filter2}, ...]  (unwrapped)
     *   standard:    ["REQ"/"COUNT", id, [{filter1}, {filter2}]]     (wrapped array)
     */
    if (count >= 3 && values[2].type == JSON_TYPE_ARRAY) {
        json_value_t inner[MAX_JSON_ARRAY_ELEMENTS] = {{0}};
        size_t inner_count = json_array_parse(values[2].value.string_val, inner,
                                              MAX_JSON_ARRAY_ELEMENTS);
        filter_capacity = inner_count;
        filters = (filter_t *) calloc(filter_capacity, sizeof(*filters));
        if (!filters) return false;
        for (size_t i = 0; i < inner_count && *out_count < MAX_FILTERS; i++) {
            if (inner[i].type == JSON_TYPE_OBJECT &&
                json_parse_filter(inner[i].value.string_val, &filters[*out_count])) {
                (*out_count)++;
            }
        }
        json_array_free(inner, inner_count);
    } else {
        filter_capacity = count > 2 ? count - 2 : 0;
        filters = (filter_t *) calloc(filter_capacity, sizeof(*filters));
        if (!filters) return false;
        for (size_t i = 2; i < count && *out_count < MAX_FILTERS; i++) {
            if (values[i].type == JSON_TYPE_OBJECT &&
                json_parse_filter(values[i].value.string_val, &filters[*out_count])) {
                (*out_count)++;
            }
        }
    }
    if (*out_count == 0) { free(filters); return false; }
    *out = filters;
    return true;
}

static void handle_req(struct mg_connection *connection, json_value_t *values, size_t count, bool do_count) {
    const char *sub = json_array_get_string(values, count, 1);
    filter_t *filters = NULL;
    size_t filter_count = 0, subscriptions_count = 0;
    if (!sub || strlen(sub) > MAX_SUB_ID_LENGTH || count < 3 || !collect_filters(values, count, &filters, &filter_count)) {
        send_status(connection, "CLOSED", sub, false, "error: invalid filter"); return;
    }
    if (!do_count) {
        for (subscription_t *s = subscriptions; s; s = s->next) if (s->connection == connection && strcmp(s->id, sub) != 0) subscriptions_count++;
        if (subscriptions_count >= MAX_SUBSCRIPTIONS) { for (size_t i = 0; i < filter_count; i++) filter_release(&filters[i]); free(filters); send_status(connection, "CLOSED", sub, false, "error: too many subscriptions"); return; }
        remove_subscriptions(connection, sub);
        subscription_t *subscription = (subscription_t *) calloc(1, sizeof(*subscription));
        if (!subscription || !(subscription->id = string_dup(sub))) { free(subscription); for (size_t i = 0; i < filter_count; i++) filter_release(&filters[i]); free(filters); send_status(connection, "CLOSED", sub, false, "error: server unavailable"); return; }
        subscription->connection = connection; subscription->filters = filters; subscription->filters_count = filter_count;
        subscription->next = subscriptions; subscriptions = subscription;
        query_events(connection, sub, filters, filter_count, false);
    } else {
        query_events(connection, sub, filters, filter_count, true);
        for (size_t i = 0; i < filter_count; i++) filter_release(&filters[i]);
        free(filters);
    }
}

static void handle_event(struct mg_connection *connection, json_value_t *values, size_t count) {
    event_t event;
    
    /* Parse event */
    if (count != 2 || values[1].type != JSON_TYPE_OBJECT || !json_parse_event(values[1].value.string_val, &event)) {
        send_status(connection, "NOTICE", NULL, false, "error: invalid event");
        return;
    }

    log_message(connection, "event kind=%d id=%.*s pubkey=%.*s created_at=%lld",
                event.kind, (int) sizeof(event.id), event.id,
                (int) sizeof(event.pubkey), event.pubkey,
                (long long) event.created_at);
    
    /* Check for auth-required tag (must be authenticated) */
    if (event_has_tag(&event, "-", NULL)) {
        const char *auth_pubkey = nip42_authenticated_pubkey(connection);
        if (!auth_pubkey || strcmp(auth_pubkey, event.pubkey) != 0) {
            send_status(connection, "OK", event.id, false, "auth-required: authentication required");
            event_release(&event);
            return;
        }
    }
    
    /* Process event through kind dispatcher */
    nip01_process_result_t result = nip01_process_event(
        connection, &event, storage_ctx, service_url,
        MAX_EVENT_CONTENT_LENGTH,
        created_at_lower_limit,
        created_at_upper_limit,
        min_pow_difficulty
    );
    
    /* Send response to client */
    send_status(connection, "OK", event.id, result.accepted, result.response_msg);
    
    /* Broadcast event if accepted and should broadcast */
    if (result.accepted && result.should_broadcast) {
        broadcast_event(&event);
    }
    
    event_release(&event);
}

static void handle_auth(struct mg_connection *connection, json_value_t *values, size_t count) {
    event_t event;
    time_t now = time(NULL);
    if (count != 2 || values[1].type != JSON_TYPE_OBJECT || !json_parse_event(values[1].value.string_val, &event)) { send_status(connection, "NOTICE", NULL, false, "error: invalid auth"); return; }
    if (!nip42_authenticate(connection, &event, service_url, now)) send_status(connection, "OK", event.id, false, "error: failed to authenticate");
    else send_status(connection, "OK", event.id, true, "");
    event_release(&event);
}

static void handle_message(struct mg_connection *connection, struct mg_ws_message *message) {
    json_value_t values[MAX_JSON_ARRAY_ELEMENTS] = {{0}};
    char *payload; size_t count; const char *method;
    if (message->data.len > MAX_WS_MESSAGE_LENGTH) { send_status(connection, "NOTICE", NULL, false, "error: message too large"); return; }
    payload = (char *) malloc(message->data.len + 1);
    if (!payload) return;
    memcpy(payload, message->data.buf, message->data.len); payload[message->data.len] = '\0';
    log_message(connection, "recv: %s", payload);
    count = json_array_parse(payload, values, MAX_JSON_ARRAY_ELEMENTS);
    method = json_array_get_string(values, count, 0);
    if (!method || count < 2) send_status(connection, "NOTICE", NULL, false, "error: invalid request");
    else if (strcmp(method, "REQ") == 0) handle_req(connection, values, count, false);
    else if (strcmp(method, "COUNT") == 0) handle_req(connection, values, count, true);
    else if (strcmp(method, "CLOSE") == 0) { const char *sub = json_array_get_string(values, count, 1); if (sub) remove_subscriptions(connection, sub); }
    else if (strcmp(method, "EVENT") == 0) handle_event(connection, values, count);
    else if (strcmp(method, "AUTH") == 0) handle_auth(connection, values, count);
    else send_status(connection, "NOTICE", NULL, false, "error: invalid request");
    json_array_free(values, count); free(payload);
}

static void nostr_event_handler(struct mg_connection *connection, int event, void *event_data) {
    if (event == MG_EV_HTTP_MSG) {
        struct mg_http_message *request = event_data;
        struct mg_str *accept = mg_http_get_header(request, "Accept");
        if (accept && mg_str_contains(*accept, "application/nostr+json")) {
            mg_http_reply(connection, 200, "Content-Type: application/nostr+json\r\nAccess-Control-Allow-Origin: *\r\n", "%s", nip11_information_document());
        } else mg_ws_upgrade(connection, request, NULL);
    } else if (event == MG_EV_WS_OPEN) {
        char challenge[17];
        log_message(connection, "client connected (websocket open)");
        if (nip42_open(connection, challenge)) {
            json_builder_t builder;
            json_builder_start(&builder);
            json_builder_append_string(&builder, "AUTH");
            json_builder_append_string(&builder, challenge);
            send_json(connection, json_builder_finish(&builder));
        }
    } else if (event == MG_EV_WS_MSG) handle_message(connection, event_data);
    else if (event == MG_EV_CLOSE) {
        log_message(connection, "client disconnected");
        remove_subscriptions(connection, NULL);
        nip42_close(connection);
    }
}

void server_configure(storage_context_t *storage, const char *relay_url, int min_pow,
                      time_t lower_limit, time_t upper_limit) {
    storage_ctx = storage; min_pow_difficulty = min_pow < 0 ? 0 : min_pow;
    snprintf(service_url, sizeof(service_url), "%s", relay_url ? relay_url : "");
    created_at_lower_limit = lower_limit < 0 ? 0 : lower_limit;
    created_at_upper_limit = upper_limit < 0 ? 0 : upper_limit;
}

bool server_run(int port) {
    char listen_url[64];
    if (!storage_ctx || port < 1 || port > 65535) return false;
    snprintf(listen_url, sizeof(listen_url), "ws://0.0.0.0:%d", port);
    stop_requested = 0; mg_mgr_init(&manager);
    if (!mg_http_listen(&manager, listen_url, nostr_event_handler, NULL)) { mg_mgr_free(&manager); return false; }
    while (!stop_requested) mg_mgr_poll(&manager, 1000);
    mg_mgr_free(&manager); remove_subscriptions(NULL, NULL);
    return true;
}

void server_stop(void) { stop_requested = 1; }
