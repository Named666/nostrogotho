#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto.h"
#include "json_lite.h"
#include "json_util.h"
#include "nostrogotho.h"
#include "relay_conn_internal.h"
#include "relay_core.h"
#include "storage.h"
#include "nips/nip01.h"
#include "nips/nip_event.h"
#include "nips/nip_plugin.h"

#define MAX_SUBSCRIPTIONS 20
#define MAX_FILTERS 10
#define MAX_SUB_ID_LENGTH 100
#define MAX_WS_MESSAGE_LENGTH (5 * 1024 * 1024)
#define MAX_EVENT_CONTENT_LENGTH (16 * 1024)
#define MAX_EVENT_TAGS 100
#define MAX_LIMIT 500

/* ============================================================================
 * NIP PLUGIN ARCHITECTURE
 *
 * The core has ZERO knowledge of any specific NIP. Every NIP is a plugin in
 * src/nips/ (*.c) registering hooks via nip_plugin_t; the core walks the
 * registry and invokes the generic hooks (on_connect, on_disconnect,
 * on_message, accept_publish, can_deliver, eose_auth_hint, build_eose,
 * build_count, timer, info_document).
 * ============================================================================ */

typedef struct subscription {
    relay_conn_t *connection;
    char *id;
    filter_t *filters;
    size_t filters_count;
    struct subscription *shard_prev, *shard_next; /* shard-wide list */
    struct subscription *conn_next;               /* per-connection list */
} subscription_t;

typedef struct {
    subscription_t *subs;
    int count;
} core_conn_t;

static subscription_t *shard_subs[RELAY_MAX_SHARDS];
static storage_context_t *storage_ctx;
static int min_pow_difficulty;
static time_t created_at_lower_limit;
static time_t created_at_upper_limit;
static char service_url[256];
static bool debug_logging;
static relay_publish_fn publisher;

/* Per-thread query context for the storage streaming callback. */
static __thread relay_conn_t *query_connection;
static __thread filter_t *query_filters;
static __thread size_t query_filters_count;

void relay_core_set_debug(bool enabled) { debug_logging = enabled; }
bool relay_core_debug(void) { return debug_logging; }
storage_context_t *relay_core_storage(void) { return storage_ctx; }
void relay_core_set_publisher(relay_publish_fn fn) { publisher = fn; }

static void log_message(relay_conn_t *connection, const char *fmt, ...) {
    va_list args;
    if (!debug_logging) return;
    time_t now = time(NULL);
    struct tm tmv;
    char stamp[32];
    if (localtime_r(&now, &tmv) && strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tmv))
        fprintf(stdout, "[%s] ", stamp);
    if (connection) fprintf(stdout, "peer=%s ", relay_conn_peer(connection));
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fputc('\n', stdout);
    fflush(stdout);
}

static core_conn_t *core_of(relay_conn_t *conn) { return (core_conn_t *) conn->core; }

static void subscription_free(subscription_t *s) {
    for (size_t i = 0; i < s->filters_count; i++) filter_release(&s->filters[i]);
    free(s->filters); free(s->id); free(s);
}

static void shard_unlink(int shard, subscription_t *s) {
    if (s->shard_prev) s->shard_prev->shard_next = s->shard_next;
    else shard_subs[shard] = s->shard_next;
    if (s->shard_next) s->shard_next->shard_prev = s->shard_prev;
}

/* Remove subscriptions of `connection` (all, or only `id`). */
static void remove_subscriptions(relay_conn_t *connection, const char *id) {
    core_conn_t *cc = core_of(connection);
    if (!cc) return;
    subscription_t **link = &cc->subs;
    while (*link) {
        subscription_t *s = *link;
        if (!id || strcmp(s->id, id) == 0) {
            *link = s->conn_next;
            shard_unlink(connection->shard, s);
            subscription_free(s);
            cc->count--;
        } else link = &s->conn_next;
    }
}

static bool matches_filter(const filter_t *filter, const event_t *event) {
    if (filter->since && event->created_at < filter->since) return false;
    if (filter->until && event->created_at > filter->until) return false;
    if (filter->kinds_count) {
        bool matched = false;
        for (size_t i = 0; i < filter->kinds_count && !matched; i++) if (event->kind == filter->kinds[i]) matched = true;
        if (!matched) return false;
    }
    if (filter->ids_count) {
        bool matched = false;
        for (size_t i = 0; i < filter->ids_count && !matched; i++) if (strncmp(event->id, filter->ids[i], strlen(filter->ids[i])) == 0) matched = true;
        if (!matched) return false;
    }
    if (filter->authors_count) {
        bool matched = false;
        for (size_t i = 0; i < filter->authors_count && !matched; i++) if (strncmp(event->pubkey, filter->authors[i], strlen(filter->authors[i])) == 0) matched = true;
        if (!matched) return false;
    }
    for (size_t i = 0; i < filter->tags_count; i++) {
        bool matched = false;
        tag_t *tag = &filter->tags[i];
        for (size_t j = 1; j < tag->count && !matched; j++) {
            if (nip_event_has_tag(event, tag->elements[0], tag->elements[j])) matched = true;
        }
        if (!matched) return false;
    }
    if (filter->search && *filter->search &&
        !jl_str_contains(jl_str(event->content ? event->content : ""), filter->search)) return false;
    return true;
}

static bool plugins_accept_publish(relay_conn_t *connection, const event_t *event,
                                   char *reason, size_t reason_size) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->accept_publish && !plugin->accept_publish(connection, event, reason, reason_size, plugin->ctx)) {
            if (!reason[0]) snprintf(reason, reason_size, "invalid: event not accepted");
            return false;
        }
    }
    return true;
}

static bool plugins_can_deliver(const event_t *event, relay_conn_t *connection) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->can_deliver && !plugin->can_deliver(event, connection, plugin->ctx)) return false;
    }
    return true;
}

/* Match one event against every subscription of `shard`. Must run on the
 * shard's owner thread. The serialized event body is built once and reused
 * for every matching subscription. */
void relay_core_broadcast_shard(int shard, const event_t *event) {
    static __thread json_builder_t body, idb;  /* 64 KiB each: keep off the stack */
    const char *body_json = NULL;
    size_t body_len = 0;
    char *out = NULL;
    size_t out_cap = 0;
    for (subscription_t *s = shard_subs[shard]; s; s = s->shard_next) {
        bool matched = false;
        for (size_t i = 0; i < s->filters_count && !matched; i++) if (matches_filter(&s->filters[i], event)) matched = true;
        if (!matched || !plugins_can_deliver(event, s->connection)) continue;
        if (!body_json) {
            /* Serialize the event once: "[{...}]" -> strip the brackets. */
            json_builder_start(&body);
            json_serialize_event(event, &body);
            body_json = json_builder_finish(&body);
            body_len = strlen(body_json);
            if (body_len < 2) return;
            body_json++; body_len -= 2;
        }
        json_builder_start(&idb);
        json_builder_append_string(&idb, s->id);
        const char *idj = json_builder_finish(&idb);   /* ["<escaped id>"] */
        size_t idl = strlen(idj) - 2;
        size_t need = 9 + idl + 1 + body_len + 2;
        if (need > out_cap) {
            char *n = (char *) realloc(out, need);
            if (!n) break;
            out = n; out_cap = need;
        }
        size_t o = 0;
        memcpy(out + o, "[\"EVENT\",", 9); o += 9;
        memcpy(out + o, idj + 1, idl); o += idl;
        out[o++] = ',';
        memcpy(out + o, body_json, body_len); o += body_len;
        out[o++] = ']';
        out[o] = '\0';
        relay_conn_send(s->connection, out, o);
    }
    free(out);
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
        for (size_t i = 0; i < query_filters_count && !matched; i++) {
            if (matches_filter(&query_filters[i], &event)) matched = true;
        }
        if (matched && plugins_can_deliver(&event, query_connection)) {
            nip_plugin_send_json(query_connection, json);
        }
        event_release(&event);
    }
    json_array_free(values, count);
}

static void query_events(relay_conn_t *connection, const char *sub,
                         filter_t *filters, size_t count, bool do_count) {
    bool has_more = false;
    int total_count = 0;
    query_connection = connection;
    query_filters = filters;
    query_filters_count = count;
    storage_ctx->send_records(query_sender, sub, filters, count, do_count,
                              do_count ? NULL : &has_more, &total_count);
    query_connection = NULL;
    query_filters = NULL;
    query_filters_count = 0;

    char *response = NULL;
    if (do_count) {
        for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
            if (plugin->build_count) { response = plugin->build_count(sub, (unsigned long) total_count, plugin->ctx); break; }
        }
        if (!response) {
            json_builder_t builder;
            json_builder_start(&builder);
            json_builder_append_string(&builder, "COUNT");
            json_builder_append_string(&builder, sub);
            json_builder_start_object(&builder);
            json_builder_object_key_number(&builder, "count", (long long) total_count);
            json_builder_end_object(&builder);
            response = string_dup(json_builder_finish(&builder));
        }
    } else {
        bool auth_hint = false;
        for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
            if (plugin->eose_auth_hint && plugin->eose_auth_hint(connection, filters, count, plugin->ctx)) {
                auth_hint = true;
                break;
            }
        }
        for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
            if (plugin->build_eose) { response = plugin->build_eose(sub, has_more, auth_hint, plugin->ctx); break; }
        }
        if (!response) {
            json_builder_t builder;
            json_builder_start(&builder);
            json_builder_append_string(&builder, "EOSE");
            json_builder_append_string(&builder, sub);  /* NIP-01: ["EOSE",<sub_id>] */
            response = string_dup(json_builder_finish(&builder));
        }
    }
    if (response) {
        nip_plugin_send_json(connection, response);
        free(response);
    }
}

static bool collect_filters(json_value_t *values, size_t count, filter_t **out, size_t *out_count) {
    filter_t *filters = NULL;
    size_t filter_capacity = 0;
    /* Accepted layouts:
     *   ["REQ"/"COUNT", id, {filter1}, {filter2}, ...]   (standard)
     *   ["REQ"/"COUNT", id, [{filter1}, {filter2}]]      (wrapped array) */
    if (count >= 3 && values[2].type == JSON_TYPE_ARRAY) {
        json_value_t inner[MAX_JSON_ARRAY_ELEMENTS] = {{0}};
        size_t inner_count = json_array_parse(values[2].value.string_val, inner, MAX_JSON_ARRAY_ELEMENTS);
        filter_capacity = inner_count;
        filters = (filter_t *) calloc(filter_capacity ? filter_capacity : 1, sizeof(*filters));
        if (!filters) return false;
        for (size_t i = 0; i < inner_count && *out_count < MAX_FILTERS; i++) {
            if (inner[i].type == JSON_TYPE_OBJECT && json_parse_filter(inner[i].value.string_val, &filters[*out_count])) (*out_count)++;
        }
        json_array_free(inner, inner_count);
    } else {
        filter_capacity = count > 2 ? count - 2 : 0;
        filters = (filter_t *) calloc(filter_capacity ? filter_capacity : 1, sizeof(*filters));
        if (!filters) return false;
        for (size_t i = 2; i < count && *out_count < MAX_FILTERS; i++) {
            if (values[i].type == JSON_TYPE_OBJECT && json_parse_filter(values[i].value.string_val, &filters[*out_count])) (*out_count)++;
        }
    }
    if (*out_count == 0) { free(filters); return false; }
    *out = filters;
    return true;
}

static void release_filters(filter_t *filters, size_t n) {
    for (size_t i = 0; i < n; i++) filter_release(&filters[i]);
    free(filters);
}

static void handle_req(relay_conn_t *connection, json_value_t *values, size_t count, bool do_count) {
    const char *sub = json_array_get_string(values, count, 1);
    filter_t *filters = NULL;
    size_t filter_count = 0;
    if (!sub || strlen(sub) > MAX_SUB_ID_LENGTH || count < 3 || !collect_filters(values, count, &filters, &filter_count)) {
        nip_plugin_send_status(connection, "CLOSED", sub, false, "error: invalid filter"); return;
    }
    if (do_count) {
        query_events(connection, sub, filters, filter_count, true);
        release_filters(filters, filter_count);
        return;
    }
    core_conn_t *cc = core_of(connection);
    int others = 0;
    for (subscription_t *s = cc->subs; s; s = s->conn_next) if (strcmp(s->id, sub) != 0) others++;
    if (others >= MAX_SUBSCRIPTIONS) {
        release_filters(filters, filter_count);
        nip_plugin_send_status(connection, "CLOSED", sub, false, "error: too many subscriptions"); return;
    }
    remove_subscriptions(connection, sub);
    subscription_t *s = (subscription_t *) calloc(1, sizeof(*s));
    if (!s || !(s->id = string_dup(sub))) {
        free(s); release_filters(filters, filter_count);
        nip_plugin_send_status(connection, "CLOSED", sub, false, "error: server unavailable"); return;
    }
    s->connection = connection; s->filters = filters; s->filters_count = filter_count;
    s->conn_next = cc->subs; cc->subs = s; cc->count++;
    int shard = connection->shard;
    s->shard_next = shard_subs[shard];
    if (s->shard_next) s->shard_next->shard_prev = s;
    shard_subs[shard] = s;
    query_events(connection, sub, filters, filter_count, false);
}

nip01_process_result_t relay_core_commit_event(relay_conn_t *conn, const event_t *event) {
    return nip01_dispatch_event(conn, event, storage_ctx, service_url);
}

void relay_core_send_ok(relay_conn_t *conn, const event_t *event, const nip01_process_result_t *result) {
    nip_plugin_send_status(conn, "OK", event->id, result->accepted, result->response_msg);
}

static void handle_event(relay_conn_t *connection, json_value_t *values, size_t count) {
    event_t event;
    char reject_reason[256] = {0};

    if (count != 2 || values[1].type != JSON_TYPE_OBJECT || !json_parse_event(values[1].value.string_val, &event)) {
        nip_plugin_send_status(connection, "NOTICE", NULL, false, "error: invalid event");
        return;
    }
    log_message(connection, "event kind=%d id=%.*s pubkey=%.*s created_at=%lld",
                event.kind, (int) sizeof(event.id), event.id,
                (int) sizeof(event.pubkey), event.pubkey, (long long) event.created_at);

    /* CPU-bound, stateless: id hash, schnorr signature, size, timestamps. */
    nip01_process_result_t result = nip01_precheck_event(&event, MAX_EVENT_CONTENT_LENGTH,
        created_at_lower_limit, created_at_upper_limit, min_pow_difficulty);
    if (result.accepted && !plugins_accept_publish(connection, &event, reject_reason, sizeof(reject_reason))) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "%s", reject_reason);
    }
    if (!result.accepted) {
        relay_core_send_ok(connection, &event, &result);
        event_release(&event);
        return;
    }

    if (publisher) {
        event_t *heap = (event_t *) malloc(sizeof(*heap));
        if (!heap) { event_release(&event); return; }
        *heap = event;                 /* ownership of tags/content moves */
        relay_conn_retain(connection); /* released by the writer */
        publisher(connection, heap);
        return;
    }

    result = relay_core_commit_event(connection, &event);
    relay_core_send_ok(connection, &event, &result);
    if (result.accepted && result.should_broadcast) relay_core_broadcast_shard(0, &event);
    event_release(&event);
}

void relay_core_on_message(relay_conn_t *connection, char *payload, size_t len) {
    json_value_t values[MAX_JSON_ARRAY_ELEMENTS] = {{0}};
    size_t count; const char *method;
    if (len > MAX_WS_MESSAGE_LENGTH) { nip_plugin_send_status(connection, "NOTICE", NULL, false, "error: message too large"); return; }
    log_message(connection, "recv: %s", payload);
    count = json_array_parse(payload, values, MAX_JSON_ARRAY_ELEMENTS);
    method = json_array_get_string(values, count, 0);

    bool consumed = false;
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->on_message && plugin->on_message(connection, values, count, plugin->ctx)) { consumed = true; break; }
    }
    if (!consumed) {
        if (!method || count < 2) nip_plugin_send_status(connection, "NOTICE", NULL, false, "error: invalid request");
        else if (strcmp(method, "REQ") == 0) handle_req(connection, values, count, false);
        else if (strcmp(method, "COUNT") == 0) handle_req(connection, values, count, true);
        else if (strcmp(method, "CLOSE") == 0) { const char *sub = json_array_get_string(values, count, 1); if (sub) remove_subscriptions(connection, sub); }
        else if (strcmp(method, "EVENT") == 0) handle_event(connection, values, count);
        else nip_plugin_send_status(connection, "NOTICE", NULL, false, "error: invalid request");
    }
    json_array_free(values, count);
}

void relay_core_on_open(relay_conn_t *connection) {
    connection->core = calloc(1, sizeof(core_conn_t));
    log_message(connection, "client connected (websocket open)");
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->on_connect) plugin->on_connect(connection, plugin->ctx);
    }
}

void relay_core_on_close(relay_conn_t *connection) {
    log_message(connection, "client disconnected");
    remove_subscriptions(connection, NULL);
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->on_disconnect) plugin->on_disconnect(connection, plugin->ctx);
    }
    free(connection->core);
    connection->core = NULL;
}

const char *relay_core_info_document(void) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->info_document) return plugin->info_document(plugin->ctx);
    }
    return NULL;
}

unsigned relay_core_timer_interval(void) {
    unsigned interval = 0;
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->timer && (interval == 0 || plugin->timer_interval_ms < interval)) interval = plugin->timer_interval_ms;
    }
    return interval;
}

void relay_core_run_timers(void) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->timer) plugin->timer(storage_ctx, plugin->ctx);
    }
}

void relay_core_configure(storage_context_t *storage, const char *relay_url, int min_pow,
                          time_t lower_limit, time_t upper_limit) {
    storage_ctx = storage; min_pow_difficulty = min_pow < 0 ? 0 : min_pow;
    snprintf(service_url, sizeof(service_url), "%s", relay_url ? relay_url : "");
    created_at_lower_limit = lower_limit < 0 ? 0 : lower_limit;
    created_at_upper_limit = upper_limit < 0 ? 0 : upper_limit;

    relay_config_t config;
    memset(&config, 0, sizeof(config));
    config.service_url = service_url;
    config.storage = storage;
    config.max_message_length = MAX_WS_MESSAGE_LENGTH;
    config.max_subscriptions = MAX_SUBSCRIPTIONS;
    config.max_filters = MAX_FILTERS;
    config.max_subid_length = MAX_SUB_ID_LENGTH;
    config.max_event_tags = MAX_EVENT_TAGS;
    config.max_content_length = MAX_EVENT_CONTENT_LENGTH;
    config.min_pow_difficulty = min_pow_difficulty;
    config.max_limit = MAX_LIMIT;
    config.default_limit = MAX_LIMIT;
    config.created_at_lower_limit = created_at_lower_limit;
    config.created_at_upper_limit = created_at_upper_limit;
    config.auth_required = false;
    nip_plugins_init(&config);
}

void relay_core_shutdown(void) {
    for (int i = 0; i < RELAY_MAX_SHARDS; i++) {
        while (shard_subs[i]) {
            subscription_t *s = shard_subs[i];
            shard_subs[i] = s->shard_next;
            subscription_free(s);
        }
    }
}

/* server.h compatibility (shared by every backend). */
#include "server.h"
void server_configure(storage_context_t *storage, const char *relay_url, int min_pow,
                      time_t lower_limit, time_t upper_limit) {
    relay_core_configure(storage, relay_url, min_pow, lower_limit, upper_limit);
}
void server_set_debug(bool enabled) { relay_core_set_debug(enabled); }
