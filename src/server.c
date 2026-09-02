#include <mongoose.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <bcrypt.h>
#endif

#include "crypto.h"
#include "json_util.h"
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

typedef struct client_state {
    struct mg_connection *connection;
    char challenge[17];
    char pubkey[MAX_PUBKEY_SIZE + 1];
    struct client_state *next;
} client_state_t;

static struct mg_mgr manager;
static volatile sig_atomic_t stop_requested;
static storage_context_t *storage_ctx;
static subscription_t *subscriptions;
static client_state_t *clients;
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

static client_state_t *client_state(struct mg_connection *connection, bool create) {
    for (client_state_t *state = clients; state; state = state->next) {
        if (state->connection == connection) return state;
    }
    if (!create) return NULL;
    client_state_t *state = (client_state_t *) calloc(1, sizeof(*state));
    if (!state) return NULL;
    state->connection = connection;
#ifdef _WIN32
    unsigned char random[8];
    if (BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        free(state);
        return NULL;
    }
    for (size_t i = 0; i < sizeof(random); i++) {
        snprintf(state->challenge + i * 2, 3, "%02x", random[i]);
    }
#else
    free(state);
    return NULL;
#endif
    state->next = clients;
    clients = state;
    return state;
}

static void remove_client(struct mg_connection *connection) {
    client_state_t **link = &clients;
    while (*link) {
        if ((*link)->connection == connection) {
            client_state_t *state = *link;
            *link = state->next;
            free(state);
            return;
        }
        link = &(*link)->next;
    }
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
        client_state_t *state = client_state(subscription->connection, false);
        if (matched && ((event->kind != 1059 && event->kind != 21059) ||
                (state && event_has_tag(event, "p", state->pubkey)))) {
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
    client_state_t *state;

    if (!query_connection) return;
    count = json_array_parse(json, values, MAX_JSON_ARRAY_ELEMENTS);
    if (count == 3 && values[0].type == JSON_TYPE_STRING &&
        strcmp(values[0].value.string_val, "EVENT") == 0 &&
        values[2].type == JSON_TYPE_OBJECT &&
        json_parse_event(values[2].value.string_val, &event)) {
        for (size_t i = 0; i < query_filters_count; i++) {
            if (matches_filter(&query_filters[i], &event)) matched = true;
        }
        state = client_state(query_connection, false);
        if (matched && ((event.kind != 1059 && event.kind != 21059) ||
                        (state && event_has_tag(&event, "p", state->pubkey)))) {
            send_json(query_connection, json);
        }
        event_free(&event);
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
        json_builder_t builder;
        json_builder_start(&builder);
        json_builder_append_string(&builder, "EOSE");
        json_builder_append_string(&builder, sub);
        json_builder_start_array(&builder);
        json_builder_append_string(&builder, has_more ? "more" : "finish");
        json_builder_end_array(&builder);
        send_json(connection, json_builder_finish(&builder));
    }
}

static bool collect_filters(json_value_t *values, size_t count, filter_t **out,
                            size_t *out_count) {
    filter_t *filters = (filter_t *) calloc(count - 2, sizeof(*filters));
    if (!filters) return false;
    for (size_t i = 2; i < count && *out_count < MAX_FILTERS; i++) {
        if (values[i].type == JSON_TYPE_OBJECT && json_parse_filter(values[i].value.string_val, &filters[*out_count])) (*out_count)++;
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

static bool parse_address(const char *coordinate, int *kind, char *pubkey,
                          size_t pubkey_size, char **dtag) {
    char *end;
    const char *first, *second;
    long parsed_kind;
    if (!coordinate || !(first = strchr(coordinate, ':')) ||
        !(second = strchr(first + 1, ':')) || second == first + 1 ||
        (size_t) (second - first) != MAX_PUBKEY_SIZE + 1 ||
        (size_t) (second - first - 1) >= pubkey_size) return false;
    parsed_kind = strtol(coordinate, &end, 10);
    if (end != first || parsed_kind < INT_MIN || parsed_kind > INT_MAX) return false;
    memcpy(pubkey, first + 1, MAX_PUBKEY_SIZE);
    pubkey[MAX_PUBKEY_SIZE] = '\0';
    *dtag = string_dup(second + 1);
    if (!*dtag) return false;
    *kind = (int) parsed_kind;
    return true;
}

static void delete_event_targets(const event_t *event, bool *failed) {
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t tag_offset = 0;
    while ((tag_offset = mg_json_next(tags, tag_offset, &key, &tag)) != 0) {
        char *name = tag_element(tag, 0);
        if (name && strcmp(name, "e") == 0) {
            for (size_t i = 1;; i++) {
                char *id = tag_element(tag, i);
                event_t *target;
                if (!id) break;
                target = storage_ctx->get_event_by_id(id);
                if (target) {
                    int result;
                    if (target->kind == 1059) {
                        tag_t recipient = {(char *[]) {"p", (char *) event->pubkey}, 2, 2};
                        result = storage_ctx->delete_record_by_id_and_kind_and_ptag(id, 1059, &recipient);
                    } else result = storage_ctx->delete_record_by_id_and_pubkey(id, event->pubkey);
                    if (result <= 0) *failed = true;
                    event_free(target);
                }
                free(id);
            }
        } else if (name && strcmp(name, "a") == 0) {
            char *coordinate = tag_element(tag, 1);
            int kind;
            char pubkey[MAX_PUBKEY_SIZE + 1];
            char *dtag = NULL;
            if (coordinate && parse_address(coordinate, &kind, pubkey, sizeof(pubkey), &dtag) &&
                strcmp(pubkey, event->pubkey) == 0) {
                tag_t d_tag = {(char *[]) {"d", dtag}, 2, 2};
                if (storage_ctx->delete_record_by_kind_and_pubkey_and_dtag(kind, event->pubkey, &d_tag, event->created_at + 1) < 0) *failed = true;
            }
            free(dtag);
            free(coordinate);
        }
        free(name);
    }
}

static bool replace_addressable_event(const event_t *event) {
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = tag_element(tag, 0);
        if (name && strcmp(name, "d") == 0) {
            char *value = tag_element(tag, 1);
            tag_t d_tag = {(char *[]) {"d", value ? value : ""}, 2, 2};
            free(name);
            if (!value || storage_ctx->delete_record_by_kind_and_pubkey_and_dtag(event->kind, event->pubkey, &d_tag, event->created_at) < 0) { free(value); return false; }
            free(value);
            return true;
        }
        free(name);
    }
    return true;
}

static bool should_vanish(const event_t *event) {
    if (event_has_tag(event, "relay", "ALL_RELAYS")) return true;
    if (!service_url[0]) return false;
    return event_has_relay_tag(event, service_url);
}

static void handle_event(struct mg_connection *connection, json_value_t *values, size_t count) {
    event_t event;
    time_t now = time(NULL);
    if (count != 2 || values[1].type != JSON_TYPE_OBJECT || !json_parse_event(values[1].value.string_val, &event)) { send_status(connection, "NOTICE", NULL, false, "error: invalid event"); return; }
    if (event.content_len > MAX_EVENT_CONTENT_LENGTH) send_status(connection, "OK", event.id, false, "invalid: content too large");
    else if (!check_event(&event)) send_status(connection, "OK", event.id, false, "invalid: event id, signature or delegation is invalid");
    else if ((created_at_lower_limit && event.created_at < now - created_at_lower_limit) || (created_at_upper_limit && event.created_at > now + created_at_upper_limit)) send_status(connection, "OK", event.id, false, "invalid: created_at is out of the acceptable range");
    else if (min_pow_difficulty && count_leading_zero_bits(event.id) < min_pow_difficulty) send_status(connection, "OK", event.id, false, "pow: insufficient difficulty");
    else if (event_has_tag(&event, "-", NULL) && (!client_state(connection, false) || strcmp(client_state(connection, false)->pubkey, event.pubkey) != 0)) send_status(connection, "OK", event.id, false, "auth-required: authentication required");
    else if (event.kind == 5) {
        bool failed = false;
        delete_event_targets(&event, &failed);
        send_status(connection, "OK", event.id, !failed, failed ? "deletion failed" : "");
    } else if (event.kind == 62) {
        if (should_vanish(&event) && storage_ctx->delete_all_events_by_pubkey(event.pubkey, event.created_at) < 0) send_status(connection, "OK", event.id, false, "error: failed to vanish events");
        else if (!storage_ctx->insert_record(&event)) send_status(connection, "OK", event.id, false, "duplicate: event already exists");
        else { send_status(connection, "OK", event.id, true, ""); broadcast_event(&event); }
    } else if (event.kind >= 20000 && event.kind < 30000) { send_status(connection, "OK", event.id, true, ""); broadcast_event(&event); }
    else if ((event.kind == 0 || event.kind == 3 || (event.kind >= 10000 && event.kind < 20000)) && storage_ctx->delete_record_by_kind_and_pubkey(event.kind, event.pubkey, event.created_at) < 0) send_status(connection, "OK", event.id, false, "error: failed to replace event");
    else if (event.kind >= 30000 && event.kind < 40000 && !replace_addressable_event(&event)) send_status(connection, "OK", event.id, false, "error: failed to replace event");
    else if (!storage_ctx->insert_record(&event)) send_status(connection, "OK", event.id, false, "duplicate: event already exists");
    else { send_status(connection, "OK", event.id, true, ""); broadcast_event(&event); }
    event_free(&event);
}

static void handle_auth(struct mg_connection *connection, json_value_t *values, size_t count) {
    event_t event;
    client_state_t *state = client_state(connection, false);
    time_t now = time(NULL);
    if (count != 2 || values[1].type != JSON_TYPE_OBJECT || !state || !json_parse_event(values[1].value.string_val, &event)) { send_status(connection, "NOTICE", NULL, false, "error: invalid auth"); return; }
    if (event.kind != 22242 || !check_event(&event) || llabs((long long) now - (long long) event.created_at) > 600 ||
        !event_has_tag(&event, "challenge", state->challenge) || !event_has_relay_tag(&event, service_url)) send_status(connection, "OK", event.id, false, "error: failed to authenticate");
    else { strcpy(state->pubkey, event.pubkey); send_status(connection, "OK", event.id, true, ""); }
    event_free(&event);
}

static void handle_message(struct mg_connection *connection, struct mg_ws_message *message) {
    json_value_t values[MAX_JSON_ARRAY_ELEMENTS] = {{0}};
    char *payload; size_t count; const char *method;
    if (message->data.len > MAX_WS_MESSAGE_LENGTH) { send_status(connection, "NOTICE", NULL, false, "error: message too large"); return; }
    payload = (char *) malloc(message->data.len + 1);
    if (!payload) return;
    memcpy(payload, message->data.buf, message->data.len); payload[message->data.len] = '\0';
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
            mg_http_reply(connection, 200, "Content-Type: application/nostr+json\r\nAccess-Control-Allow-Origin: *\r\n", "{\"name\":\"nostrogotho\",\"supported_nips\":[1,9,11,13,16,26,33,40,62,67],\"limitation\":{\"max_message_length\":5242880,\"max_subscriptions\":20,\"max_filters\":10,\"max_limit\":500}}");
        } else mg_ws_upgrade(connection, request, NULL);
    } else if (event == MG_EV_WS_OPEN) {
        client_state_t *state = client_state(connection, true);
        if (state) {
            json_builder_t builder;
            json_builder_start(&builder);
            json_builder_append_string(&builder, "AUTH");
            json_builder_append_string(&builder, state->challenge);
            send_json(connection, json_builder_finish(&builder));
        }
    } else if (event == MG_EV_WS_MSG) handle_message(connection, event_data);
    else if (event == MG_EV_CLOSE) { remove_subscriptions(connection, NULL); remove_client(connection); }
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
    snprintf(listen_url, sizeof(listen_url), "http://0.0.0.0:%d", port);
    stop_requested = 0; mg_mgr_init(&manager);
    if (!mg_http_listen(&manager, listen_url, nostr_event_handler, NULL)) { mg_mgr_free(&manager); return false; }
    while (!stop_requested) mg_mgr_poll(&manager, 1000);
    mg_mgr_free(&manager); remove_subscriptions(NULL, NULL);
    return true;
}

void server_stop(void) { stop_requested = 1; }
