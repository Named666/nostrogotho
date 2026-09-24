#include <mongoose.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include "crypto.h"
#include "json_util.h"
#include "nostrogotho.h"
#include "storage.h"
#ifndef NHR_DYNAMIC_MODULE
#include "nips/nip_event.h"
#include "nips/nip_plugin.h"
#include "nips/nip01.h"
#endif
#include "server.h"
#include "nhr.h"

#define MAX_SUBSCRIPTIONS 20
#define MAX_FILTERS 10
#define MAX_SUB_ID_LENGTH 100
#define MAX_WS_MESSAGE_LENGTH (5 * 1024 * 1024)
#define MAX_EVENT_CONTENT_LENGTH (16 * 1024)
#define MAX_EVENT_TAGS 100    /* matches validate_event_tags() in json_util.c */
#define MAX_LIMIT 500         /* matches filter limit clamp in json_parse_filter() */

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
static int min_pow_difficulty;
static time_t created_at_lower_limit;
static time_t created_at_upper_limit;
static char service_url[256];
static bool debug_logging;
static Nhr_Runtime *host_runtime;
static char watched_module_path[1024];
static time_t watched_module_mtime;
static long watched_module_size;

static void server_send_json(struct mg_connection *connection, const char *json) {
    if (connection && json) mg_ws_send(connection, json, strlen(json), WEBSOCKET_OP_TEXT);
}

#ifndef NHR_DYNAMIC_MODULE
static void server_send_storage_json(const char *json) {
    if (!query_connection || !json) return;
    if (host_runtime && host_runtime->services.send_json) {
        host_runtime->services.send_json(host_runtime->services.userdata,
                                         query_connection, json, strlen(json));
    } else {
        server_send_json(query_connection, json);
    }
}
#endif

static void server_send_status(struct mg_connection *connection, const char *type,
                               const char *id, bool ok, const char *message) {
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, type);
    if (id) json_builder_append_string(&builder, id);
    if (strcmp(type, "OK") == 0) json_builder_append_bool(&builder, ok);
    json_builder_append_string(&builder, message ? message : "");
    server_send_json(connection, json_builder_finish(&builder));
}

static void server_plugin_send_json(struct mg_connection *connection,
                                    const char *json, size_t length) {
    if (connection && json) mg_ws_send(connection, json, length, WEBSOCKET_OP_TEXT);
}

static void server_plugin_send_json_bridge(struct mg_connection *connection,
                                           const char *json, size_t length) {
    server_plugin_send_json(connection, json, length);
}

static bool mg_str_contains(struct mg_str haystack, const char *needle) {
    size_t needle_len = strlen(needle);
    if (needle_len > haystack.len) return false;
    for (size_t i = 0; i + needle_len <= haystack.len; i++) {
        if (memcmp(haystack.buf + i, needle, needle_len) == 0) return true;
    }
    return false;
}

/* ---------------------------------------------------------------------------
 * Debug logging helpers.
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
    if (!debug_logging) return;
    log_timestamp();
    log_peer(connection);
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fputc('\n', stdout);
    fflush(stdout);
}

void server_set_debug(bool enabled) { debug_logging = enabled; }

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

#ifndef NHR_DYNAMIC_MODULE
/* The tag slice yielded by mg_json_next is itself a complete JSON array
 * (e.g. ["p","<hex>"]), so element extraction is a plain $[index] lookup
 * on it. Wrapping the slice in another bracket pair would make $[index]
 * resolve to an array, which mg_json_get_str rejects with NULL.
 *
 * tag_element() / event_has_tag() live in nip_event.c and are shared by
 * every NIP module — server.c uses them directly instead of re-implementing
 * the same JSON walk. */
#endif

static bool matches_filter(const filter_t *filter, const event_t *event) {
#ifdef NHR_DYNAMIC_MODULE
    if (host_runtime && host_runtime->active.matches_filter) {
        return host_runtime->active.matches_filter(filter, event);
    }
    (void)filter;
    (void)event;
    return false;
#else
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
#ifndef NHR_DYNAMIC_MODULE
    for (size_t i = 0; i < filter->tags_count; i++) {
        bool matched = false;
        tag_t *tag = &filter->tags[i];
        for (size_t j = 1; j < tag->count; j++) {
            if (nip_event_has_tag(event, tag->elements[0], tag->elements[j])) matched = true;
        }
        if (!matched) return false;
    }
#endif
    if (filter->search && *filter->search &&
        !mg_str_contains(mg_str(event->content ? event->content : ""), filter->search)) return false;
    return true;
#endif
}

/* Plugin veto helpers — the only interaction this file has with NIPs. */
static bool plugins_accept_publish(struct mg_connection *connection,
                                   const event_t *event, char *reason,
                                   size_t reason_size) {
#ifdef NHR_DYNAMIC_MODULE
    (void)connection;
    (void)event;
    (void)reason;
    (void)reason_size;
    return true;
#else
    (void)connection; (void)event; (void)reason; (void)reason_size;
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->accept_publish && !plugin->accept_publish(connection, event,
                                                              reason, reason_size,
                                                              plugin->ctx)) {
            if (!reason[0]) snprintf(reason, reason_size, "invalid: event not accepted");
            return false;
        }
    }
    return true;
#endif
}

static bool plugins_can_deliver(const event_t *event, struct mg_connection *connection) {
#ifdef NHR_DYNAMIC_MODULE
    return host_runtime && host_runtime->active.can_deliver
        ? host_runtime->active.can_deliver(event, connection) : true;
#else
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->can_deliver && !plugin->can_deliver(event, connection, plugin->ctx)) return false;
    }
    return true;
#endif
}

static void broadcast_event(const event_t *event) {
    for (subscription_t *subscription = subscriptions; subscription; subscription = subscription->next) {
        bool matched = false;
        for (size_t i = 0; i < subscription->filters_count; i++) if (matches_filter(&subscription->filters[i], event)) matched = true;
        if (matched && plugins_can_deliver(event, subscription->connection)) {
            json_builder_t builder;
            json_builder_start(&builder);
            json_builder_append_string(&builder, "EVENT");
            json_builder_append_string(&builder, subscription->id);
            json_serialize_event(event, &builder);
            server_send_json(subscription->connection, json_builder_finish(&builder));
        }
    }
}

static void query_events(struct mg_connection *connection, const char *sub,
                         filter_t *filters, size_t count, bool do_count) {
    bool has_more = false;
    int total_count = 0;
#ifdef NHR_DYNAMIC_MODULE
    if (host_runtime && host_runtime->active.query_events) {
        host_runtime->active.query_events(connection, sub, filters, count,
                                          do_count, do_count ? NULL : &has_more,
                                          &total_count);
    }
#else
    query_connection = connection;
    storage_ctx->send_records(server_send_storage_json, sub, filters, count, do_count,
                              do_count ? NULL : &has_more, &total_count, NULL, 0);
    query_connection = NULL;
#endif

#ifndef NHR_DYNAMIC_MODULE

    char *response = NULL;
    if (do_count) {
        /* NIP-45: the first plugin providing a COUNT builder wins; otherwise
         * emit a protocol-default bare COUNT response. */
        if (host_runtime && host_runtime->active.build_count) {
            response = host_runtime->active.build_count(sub, (unsigned long)total_count);
        } else for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
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
        /* NIP-67: ask each plugin whether this subscription needs the "auth"
         * completeness hint (and let it emit any accompanying traffic such as
         * a fresh NIP-42 AUTH challenge for gift-wrap subscriptions). */
        bool auth_hint = false;
        if (host_runtime && host_runtime->active.eose_auth_hint) {
            auth_hint = host_runtime->active.eose_auth_hint(connection, filters, count);
        } else for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
            if (plugin->eose_auth_hint && plugin->eose_auth_hint(connection, filters, count, plugin->ctx)) {
                auth_hint = true;
                break;
            }
        }
        if (host_runtime && host_runtime->active.build_eose) {
            response = host_runtime->active.build_eose(sub, has_more, auth_hint);
        } else for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
            if (plugin->build_eose) { response = plugin->build_eose(sub, has_more, auth_hint, plugin->ctx); break; }
        }
        if (!response) {
            json_builder_t builder;
            json_builder_start(&builder);
            json_builder_append_string(&builder, "EOSE");
            json_builder_append_string(&builder, sub);
            json_builder_start_array(&builder);
            json_builder_append_string(&builder, auth_hint ? "auth" : (has_more ? "more" : "finish"));
            json_builder_end_array(&builder);
            response = string_dup(json_builder_finish(&builder));
        }
    }
    if (response) {
        server_send_json(connection, response);
        free(response);
    }
#endif
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
        server_send_status(connection, "CLOSED", sub, false, "error: invalid filter"); return;
    }
    if (!do_count) {
        for (subscription_t *s = subscriptions; s; s = s->next) if (s->connection == connection && strcmp(s->id, sub) != 0) subscriptions_count++;
        if (subscriptions_count >= MAX_SUBSCRIPTIONS) { for (size_t i = 0; i < filter_count; i++) filter_release(&filters[i]); free(filters); server_send_status(connection, "CLOSED", sub, false, "error: too many subscriptions"); return; }
        remove_subscriptions(connection, sub);
        subscription_t *subscription = (subscription_t *) calloc(1, sizeof(*subscription));
        if (!subscription || !(subscription->id = string_dup(sub))) { free(subscription); for (size_t i = 0; i < filter_count; i++) filter_release(&filters[i]); free(filters); server_send_status(connection, "CLOSED", sub, false, "error: server unavailable"); return; }
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
    char reject_reason[256] = {0};

    /* Parse event */
    if (count != 2 || values[1].type != JSON_TYPE_OBJECT || !json_parse_event(values[1].value.string_val, &event)) {
        server_send_status(connection, "NOTICE", NULL, false, "error: invalid event");
        return;
    }

    log_message(connection, "event kind=%d id=%.*s pubkey=%.*s created_at=%lld",
                event.kind, (int) sizeof(event.id), event.id,
                (int) sizeof(event.pubkey), event.pubkey,
                (long long) event.created_at);

    /* Module owns event acceptance policy in hot mode. Static mode invokes
     * the compiled-in plugin registry. */
#ifdef NHR_DYNAMIC_MODULE
    bool accepted_by_module = host_runtime && host_runtime->active.accepts_event &&
                              host_runtime->active.accepts_event(&event);
    if (!accepted_by_module) {
        server_send_status(connection, "OK", event.id, false,
                           "invalid: event not accepted");
        event_release(&event);
        return;
    }
    if (!host_runtime->active.accept_publish ||
        !host_runtime->active.accept_publish(connection, &event, reject_reason,
                                             sizeof(reject_reason))) {
        server_send_status(connection, "OK", event.id, false,
                           reject_reason[0] ? reject_reason : "invalid: event not accepted");
        event_release(&event);
        return;
    }
#else
    if (!plugins_accept_publish(connection, &event, reject_reason, sizeof(reject_reason))) {
        server_send_status(connection, "OK", event.id, false, reject_reason);
        event_release(&event);
        return;
    }
#endif

    /* Process event through kind dispatcher */
    nip01_process_result_t result;
    if (host_runtime && host_runtime->active.process_event) {
        result = host_runtime->active.process_event(
            connection, &event, service_url, MAX_EVENT_CONTENT_LENGTH,
            created_at_lower_limit, created_at_upper_limit, min_pow_difficulty);
    } else {
#ifdef NHR_STATIC_MODULE
        result = nip01_process_event(
            connection, &event, storage_ctx, service_url,
            MAX_EVENT_CONTENT_LENGTH, created_at_lower_limit,
            created_at_upper_limit, min_pow_difficulty);
#else
        memset(&result, 0, sizeof(result));
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                 "error: application module unavailable");
#endif
    }

    /* Send response to client */
    server_send_status(connection, "OK", event.id, result.accepted, result.response_msg);

    /* Broadcast event if accepted and should broadcast */
    if (result.accepted && result.should_broadcast) {
        broadcast_event(&event);
    }

    event_release(&event);
}

static void handle_message(struct mg_connection *connection, struct mg_ws_message *message) {
    json_value_t values[MAX_JSON_ARRAY_ELEMENTS] = {{0}};
    char *payload; size_t count; const char *method;
    if (message->data.len > MAX_WS_MESSAGE_LENGTH) { server_send_status(connection, "NOTICE", NULL, false, "error: message too large"); return; }
    payload = (char *) malloc(message->data.len + 1);
    if (!payload) return;
    memcpy(payload, message->data.buf, message->data.len); payload[message->data.len] = '\0';
    log_message(connection, "recv: %s", payload);
    count = json_array_parse(payload, values, MAX_JSON_ARRAY_ELEMENTS);
    method = json_array_get_string(values, count, 0);

    /* Let plugins consume the message first (e.g. NIP-42 "AUTH"). */
    bool consumed = false;
    if (host_runtime && host_runtime->active.on_message) {
        consumed = host_runtime->active.on_message(connection, values, count);
    }
#ifndef NHR_DYNAMIC_MODULE
    else for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->on_message && plugin->on_message(connection, values, count, plugin->ctx)) {
            consumed = true;
            break;
        }
    }
#endif
    if (!consumed) {
        if (!method || count < 2) server_send_status(connection, "NOTICE", NULL, false, "error: invalid request");
        else if (strcmp(method, "REQ") == 0) handle_req(connection, values, count, false);
        else if (strcmp(method, "COUNT") == 0) handle_req(connection, values, count, true);
        else if (strcmp(method, "CLOSE") == 0) { const char *sub = json_array_get_string(values, count, 1); if (sub) remove_subscriptions(connection, sub); }
        else if (strcmp(method, "EVENT") == 0) handle_event(connection, values, count);
        else server_send_status(connection, "NOTICE", NULL, false, "error: invalid request");
    }
    json_array_free(values, count); free(payload);
}

static void nostr_event_handler(struct mg_connection *connection, int event, void *event_data) {
    if (event == MG_EV_HTTP_MSG) {
        struct mg_http_message *request = event_data;
        struct mg_str *accept = mg_http_get_header(request, "Accept");
        /* NIP-11: serve the information document from the first plugin that
         * provides one, if the client asked for application/nostr+json. */
        bool served_info = false;
        if (accept && mg_str_contains(*accept, "application/nostr+json")) {
            if (host_runtime && host_runtime->active.info_document) {
                const char *document = host_runtime->active.info_document();
                if (document) {
                    mg_http_reply(connection, 200,
                        "Content-Type: application/nostr+json\r\nAccess-Control-Allow-Origin: *\r\n",
                        "%s", document);
                    served_info = true;
                }
            }
#ifdef NHR_DYNAMIC_MODULE
            else {
                mg_http_reply(connection, 503,
                    "Content-Type: text/plain\r\nAccess-Control-Allow-Origin: *\r\n",
                    "Relay information module unavailable\n");
                served_info = true;
            }
#endif
#ifndef NHR_DYNAMIC_MODULE
            else for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
                if (plugin->info_document) {
                    mg_http_reply(connection, 200, "Content-Type: application/nostr+json\r\nAccess-Control-Allow-Origin: *\r\n", "%s", plugin->info_document(plugin->ctx));
                    served_info = true;
                    break;
                }
            }
#endif
        }
        if (!served_info) mg_ws_upgrade(connection, request, NULL);
    } else if (event == MG_EV_WS_OPEN) {
        log_message(connection, "client connected (websocket open)");
        if (host_runtime && host_runtime->services.connection_id) {
            host_runtime->services.connection_id(host_runtime->services.userdata,
                                                 connection);
        }
        if (host_runtime && host_runtime->active.on_connect) {
            host_runtime->active.on_connect(connection);
        }
    #ifndef NHR_DYNAMIC_MODULE
        else for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
            if (plugin->on_connect) plugin->on_connect(connection, plugin->ctx);
        }
    #endif
    } else if (event == MG_EV_WS_MSG) handle_message(connection, event_data);
    else if (event == MG_EV_CLOSE) {
        log_message(connection, "client disconnected");
        remove_subscriptions(connection, NULL);
        if (host_runtime && host_runtime->active.on_disconnect) {
            host_runtime->active.on_disconnect(connection);
        }
    #ifndef NHR_DYNAMIC_MODULE
        else for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
            if (plugin->on_disconnect) plugin->on_disconnect(connection, plugin->ctx);
        }
    #endif
        if (host_runtime) nhr_runtime_connection_closed(host_runtime, connection);
    }
}

static void nhr_check_candidate_timer(void *arg) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)arg;
    struct stat st;
    if (!runtime) return;
    if (!runtime->library.handle) {
        fprintf(stderr, "NHR: no active module after reload/rollback failure; stopping relay\n");
        server_stop();
        return;
    }
    if (!watched_module_path[0] || stat(watched_module_path, &st) != 0) return;
    if (st.st_mtime == watched_module_mtime && st.st_size == watched_module_size) return;
    /* Build scripts publish atomically; a file size/time change marks a new
     * candidate. Keep the last good image when validation fails. */
    Nhr_Library candidate;
    if (!nhr_runtime_build_candidate(runtime, watched_module_path, &candidate)) {
        watched_module_mtime = st.st_mtime;
        watched_module_size = (long)st.st_size;
        fprintf(stderr, "NHR: candidate rejected; continuing current module\n");
        return;
    }
    if (nhr_runtime_activate_candidate(runtime, &candidate)) {
        watched_module_mtime = st.st_mtime;
        watched_module_size = (long)st.st_size;
        log_message(NULL, "NHR: loaded new module generation");
    } else {
        /* Avoid retrying an invalid candidate every polling tick. A later
         * publication changes mtime or size and triggers another attempt. */
        watched_module_mtime = st.st_mtime;
        watched_module_size = (long)st.st_size;
        fprintf(stderr, "NHR: candidate rejected; continuing current module\n");
    }
}

/* Periodic maintenance tick for plugins that need one (e.g. NIP-40 GC). The
 * smallest requested interval drives the timer; every tick runs all plugins. */
static void plugin_timer_fn(void *arg) {
    (void) arg;
    if (host_runtime && host_runtime->active.timer) {
        host_runtime->active.timer();
        return;
    }
#ifndef NHR_DYNAMIC_MODULE
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->timer) plugin->timer(storage_ctx, plugin->ctx);
    }
#endif
}

static bool server_configure_plugins(storage_context_t *storage,
                                     const char *relay_url, int min_pow,
                                     time_t lower_limit, time_t upper_limit,
                                     relay_config_t *out_config) {
    relay_config_t config;
    if (!out_config) return false;
    storage_ctx = storage; min_pow_difficulty = min_pow < 0 ? 0 : min_pow;
    snprintf(service_url, sizeof(service_url), "%s", relay_url ? relay_url : "");
    created_at_lower_limit = lower_limit < 0 ? 0 : lower_limit;
    created_at_upper_limit = upper_limit < 0 ? 0 : upper_limit;

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
    *out_config = config;
    return true;
}

bool server_make_relay_config(storage_context_t *storage, const char *relay_url,
                              int min_pow, time_t lower_limit,
                              time_t upper_limit, relay_config_t *config) {
    return server_configure_plugins(storage, relay_url, min_pow, lower_limit,
                                    upper_limit, config);
}

void server_configure(storage_context_t *storage, const char *relay_url, int min_pow,
                      time_t lower_limit, time_t upper_limit) {
    relay_config_t config;
    if (!server_configure_plugins(storage, relay_url, min_pow, lower_limit,
                                  upper_limit, &config)) return;
#ifndef NHR_DYNAMIC_MODULE
    nip_plugin_set_send_json(server_plugin_send_json_bridge);
    nip_plugins_init(&config);
#else
    (void)config;
#endif
}

bool server_run_hot(int port, Nhr_Runtime *runtime,
                    const char *published_module_path) {
    struct stat st;
    if (!runtime || !published_module_path || strlen(published_module_path) >=
        sizeof(watched_module_path)) return false;
    snprintf(watched_module_path, sizeof(watched_module_path), "%s",
             published_module_path);
    if (stat(watched_module_path, &st) == 0) {
        watched_module_mtime = st.st_mtime;
        watched_module_size = (long)st.st_size;
    } else {
        watched_module_mtime = 0;
        watched_module_size = 0;
    }
    host_runtime = runtime;
    storage_ctx = runtime->storage;
    char listen_url[64];
    if (port < 1 || port > 65535) return false;
    snprintf(listen_url, sizeof(listen_url), "ws://0.0.0.0:%d", port);
    stop_requested = 0;
    mg_mgr_init(&manager);
    if (!mg_http_listen(&manager, listen_url, nostr_event_handler, NULL)) {
        mg_mgr_free(&manager);
        host_runtime = NULL;
        return false;
    }
    mg_timer_add(&manager, 300, MG_TIMER_REPEAT, nhr_check_candidate_timer,
                 runtime);
    /* Keep the timer host-owned and installed across generations. A later
     * module may introduce or remove maintenance hooks during reload. */
    mg_timer_add(&manager, 60 * 1000, MG_TIMER_REPEAT, plugin_timer_fn,
                 runtime);
    while (!stop_requested) mg_mgr_poll(&manager, 250);
    mg_mgr_free(&manager);
    remove_subscriptions(NULL, NULL);
    host_runtime = NULL;
    watched_module_path[0] = '\0';
    return true;
}

bool server_run(int port) {
    char listen_url[64];
    if (!storage_ctx || port < 1 || port > 65535) return false;
    snprintf(listen_url, sizeof(listen_url), "ws://0.0.0.0:%d", port);
    stop_requested = 0; mg_mgr_init(&manager);
    if (!mg_http_listen(&manager, listen_url, nostr_event_handler, NULL)) { mg_mgr_free(&manager); return false; }

    /* Schedule the plugin maintenance timer if any plugin requested one. */
    unsigned interval = 0;
#ifndef NHR_DYNAMIC_MODULE
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->timer && (interval == 0 || plugin->timer_interval_ms < interval)) {
            interval = plugin->timer_interval_ms;
        }
    }
#endif
    if (interval > 0) {
        mg_timer_add(&manager, interval, MG_TIMER_REPEAT | MG_TIMER_RUN_NOW,
                     plugin_timer_fn, NULL);
    }

    while (!stop_requested) mg_mgr_poll(&manager, 1000);
    mg_mgr_free(&manager); remove_subscriptions(NULL, NULL);
    return true;
}

void server_stop(void) { stop_requested = 1; }