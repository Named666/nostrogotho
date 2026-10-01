#include "relay/relay.h"
#include "transport/server.h"
#include "nips/nip_capability.h"
#include "crypto.h"
#include "json_util.h"
#include "nostrogotho.h"
#include "subscriptions/subscription_manager.h"
#include "relay/connection_session.h"
#include "protocol/protocol.h"
#include "protocol/event_tags.h"
#include "nhr.h"
#include "log.h"
#include <mongoose.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * RELAY.C - Relay Runtime Implementation
 * This module implements the core relay runtime, managing the lifecycle of connections,
 * subscriptions, NIP capabilities, and hot reload functionality. It serves as the central
 * coordinator for all relay operations, ensuring that events are properly routed and
 * that the system remains consistent and responsive.
 * 
 * ============================================================================ */

/* struct relay is defined in relay.h (single owner; transport/server.c needs
 * relay->manager). Do not duplicate it here. */

/* Forward declarations. Publication policy has a single path:
 * nip_composition_check_publication (the plugins_accept_publish wrapper was
 * deleted as legacy duplication). Stored queries have a single path:
 * subscription_manager_query -> query_with_new_api. */
static void remove_subscriptions(relay_t *relay, struct mg_connection *connection, const char *id);
static void broadcast_event(relay_t *relay, const event_t *event);
static void send_event_json(connection_id_t connection_id, const char *sub, const event_t *event);
static bool query_events(relay_t *relay, connection_id_t connection_id, const char *sub,
                          filter_t *filters, size_t count, bool do_count, char *reject_reason, size_t reason_size);
static void handle_req(relay_t *relay, struct mg_connection *connection,
                       protocol_message_t *proto_msg, bool do_count);

/* Index NIP-01 queryable tags (e/p/a) so stored tag-filter queries (#e/#p/#a)
 * can match. The default insert path previously passed no indexed tags, so
 * event_tag_index stayed empty and every stored tag query came back blank
 * (live delivery was unaffected — it uses matches_filter, not the index).
 * Mirrors nip01_extract_indexed_tags, but owns its copies: values are
 * strdup'd here and released after insert, never borrowed-then-freed. */
#define RELAY_INDEXED_TAG_CAP 64

static size_t relay_collect_index_tags(const event_t *event,
                                       storage_tag_match_t *out,
                                       size_t cap) {
    static const char *names[] = { "e", "p", "a" };
    size_t count = 0;
    size_t n;
    if (!event || !out || cap == 0) return 0;
    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        size_t tag_count = 0;
        char ***all = event_tag_get_all(event, names[n], &tag_count);
        size_t t, i;
        if (!all) continue;
        for (t = 0; t < tag_count && count < cap; t++) {
            if (!all[t]) continue;
            for (i = 0; all[t][i] && count < cap; i++) {
                char *value = strdup(all[t][i]);
                if (!value) break;
                out[count].tag_name = (char *)names[n];
                out[count].tag_value = value;
                out[count].filter_index = 0;
                count++;
            }
        }
        event_tag_free_all(all, tag_count);
    }
    return count;
}

static void relay_free_index_tags(storage_tag_match_t *tags, size_t count) {
    size_t i;
    if (!tags) return;
    for (i = 0; i < count; i++) free(tags[i].tag_value);
}
static void handle_event(relay_t *relay, struct mg_connection *connection, const event_t *event);
static void handle_message(relay_t *relay, struct mg_connection *connection, struct mg_ws_message *message);



static bool module_file_fingerprint(const char *path, struct stat *metadata, uint64_t *hash);
static void nhr_check_candidate_timer(void *arg);
static void plugin_timer_fn(void *arg);

/* mg_str_contains() is shared from json_util.h. */

/* All resource limits come from relay_config_t (the single authoritative
 * configuration); no independent constants live here. */

relay_t *relay_create(const relay_config_t *config, storage_context_t *storage) {
    if (!config || !storage) return NULL;
    
    relay_t *relay = calloc(1, sizeof(*relay));
    if (!relay) return NULL;
    
    relay->config = *config;
    relay->storage = storage;
    /* Clamp: main() validates, but relay_create is also called by tests and
     * embedders — never index the log level table out of range. */
    relay->verbosity = config->verbosity;
    if (relay->verbosity < LOG_VERBOSITY_QUIET)
        relay->verbosity = LOG_VERBOSITY_QUIET;
    if (relay->verbosity > LOG_VERBOSITY_DEBUG)
        relay->verbosity = LOG_VERBOSITY_DEBUG;
    log_set_verbosity((log_verbosity_t)relay->verbosity);
    relay->stop_requested = 0;
    relay->subscriptions = subscription_manager_create(
        (size_t)config->max_subscriptions_per_connection,
        (size_t)config->max_filters_per_subscription,
        (size_t)config->max_subscription_id_length);
    relay->nip_registry = nip_registry_create();
    /* Connection IDs start at 1: ID 0 is reserved as "no session" so every
     * `session ? id : 0` lookup stays unambiguous. */
    relay->next_connection_id = 1;
    relay->host_runtime = NULL;
    relay->watched_module_path[0] = '\0';

    /* Register every capability provider linked into this image (monolithic
     * build). Hot reload clears this set and re-registers the module's
     * generation in relay_init_hot_reload(). */
    nip_registry_register_providers(relay->nip_registry);

    /* Run NIP lifecycle init hooks so publication policy config (NIP-13 PoW
     * difficulty, NIP-11 limits, ...) is applied before any traffic. */
    for (nip_capability_t *cap = relay->nip_registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_LIFECYCLE && cap->caps.lifecycle.init) {
            cap->caps.lifecycle.init(&relay->config, cap->ctx);
        }
    }

    mg_mgr_init(&relay->manager);

    return relay;
}

bool relay_run(relay_t *relay) {
    if (!relay || !relay->storage) return false;
    
    char listen_url[64];
    if (relay->config.port < 1 || relay->config.port > 65535) return false;
    snprintf(listen_url, sizeof(listen_url), "ws://0.0.0.0:%d", relay->config.port);
    
    if (!mg_http_listen(&relay->manager, listen_url, relay_event_handler, relay)) {
        mg_mgr_free(&relay->manager);
        return false;
    }

    relay_schedule_maintenance(relay);

    while (!relay->stop_requested) {
        mg_mgr_poll(&relay->manager, 1000);
    }

    mg_mgr_free(&relay->manager);
    remove_subscriptions(relay, NULL, NULL);
    return true;
}

void relay_schedule_maintenance(relay_t *relay) {
    if (!relay || !relay->nip_registry) return;

    /* The smallest requested interval drives the timer; every tick runs ALL
     * registered maintenance handlers (see composition rules). */
    unsigned interval = 0;
    for (nip_capability_t *cap = relay->nip_registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_MAINTENANCE && cap->caps.maintenance.timer &&
            (interval == 0 || cap->caps.maintenance.interval_ms < interval)) {
            interval = cap->caps.maintenance.interval_ms;
        }
    }
    if (interval > 0) {
        mg_timer_add(&relay->manager, interval, MG_TIMER_REPEAT | MG_TIMER_RUN_NOW,
                     plugin_timer_fn, relay);
    }
}

void relay_stop(relay_t *relay) {
    if (relay) relay->stop_requested = 1;
}

void relay_destroy(relay_t *relay) {
    if (!relay) return;
    relay_stop(relay);

    /* Clean up NHR runtime if initialized */
    if (relay->host_runtime) {
        nhr_runtime_shutdown(relay->host_runtime);
        free(relay->host_runtime);
        relay->host_runtime = NULL;
    }

    /* Run NIP lifecycle shutdown hooks before dropping the registry. */
    if (relay->nip_registry) {
        for (nip_capability_t *cap = relay->nip_registry->capabilities; cap; cap = cap->next) {
            if (cap->type == NIP_CAP_LIFECYCLE && cap->caps.lifecycle.shutdown) {
                cap->caps.lifecycle.shutdown(cap->ctx);
            }
        }
    }

    mg_mgr_free(&relay->manager);
    subscription_manager_destroy(relay->subscriptions);
    nip_registry_destroy(relay->nip_registry);
    connection_session_cleanup_all();
    free(relay);
}

storage_context_t *relay_get_storage(relay_t *relay) {
    return relay ? relay->storage : NULL;
}

const relay_config_t *relay_get_config(relay_t *relay) {
    return relay ? &relay->config : NULL;
}

nip_registry_t *relay_get_nip_registry(relay_t *relay) {
    return relay ? relay->nip_registry : NULL;
}

/* Initialize NHR (hot reload) runtime with the given module path */
bool relay_init_hot_reload(relay_t *relay, const char *module_path) {
    if (!relay || !module_path) return false;
    
    relay->host_runtime = calloc(1, sizeof(Nhr_Runtime));
    if (!relay->host_runtime) return false;
    
    if (!nhr_runtime_init(relay->host_runtime, relay->storage, &relay->config, module_path)) {
        free(relay->host_runtime);
        relay->host_runtime = NULL;
        return false;
    }

    /* Hot mode: the module is the sole NIP provider. Replace the statically
     * registered set with the module's generation so add/remove/change of a
     * NIP file is reflected without restart. Registry nodes are host-owned
     * deep copies; the module keeps its own registry for its lifetime. */
    relay_hot_swap_capabilities(relay);

    snprintf(relay->watched_module_path, sizeof(relay->watched_module_path), "%s", module_path);
    
    /* Initialize fingerprint for change detection */
    struct stat st;
    uint64_t hash;
    if (module_file_fingerprint(module_path, &st, &hash)) {
        relay->watched_module_mtime = st.st_mtime;
        relay->watched_module_size = (long)st.st_size;
        relay->watched_module_hash = hash;
    }
    
    /* NOTE: the reload-watch timer is NOT armed here. The Mongoose manager
     * is not initialized until the transport loop starts (server_run_hot);
     * arming earlier would be wiped by mg_mgr_init. Transport calls
     * relay_arm_hot_watch() once the loop is up. Fingerprint state above is
     * plain data and is safe to record here. */
    return true;
}

/* Arm the module reload watcher. Called by the transport loop after
 * mg_mgr_init + listen (see transport/server.c). No-op without hot reload. */
void relay_arm_hot_watch(relay_t *relay) {
    if (!relay || !relay->host_runtime) return;
    mg_timer_add(&relay->manager, 1000, MG_TIMER_REPEAT,
                 nhr_check_candidate_timer, relay);
}

/* Get the NHR runtime (for advanced use) */
Nhr_Runtime *relay_get_nhr_runtime(relay_t *relay) {
    return relay ? relay->host_runtime : NULL;
}

bool relay_process_ws_message(relay_t *relay, struct mg_connection *connection,
                              const char *data, size_t length) {
    if (!relay || !connection || !data) return false;
    
    struct mg_ws_message msg;
    msg.data.buf = (char *)data;
    msg.data.len = length;
    handle_message(relay, connection, &msg);
    return true;
}

void relay_on_connect(relay_t *relay, struct mg_connection *connection) {
    if (!relay || !connection) return;
    log_conn_info(0, "CONNECT", "client connected (websocket open)");
    log_conn_debug(0, "CONNECT", "connection=%p", (void*)connection);
    
    /* Sessions are owned by the connection_session module; the relay hands
     * out IDs from a range that never collides with "no session" (0). */
    connection_id_t conn_id = connection_session_create(relay->next_connection_id++, connection);
    log_conn_debug(conn_id, "CONNECT", "conn_id=%llu next_connection_id=%llu", 
                     (unsigned long long)conn_id, (unsigned long long)relay->next_connection_id);
    if (!conn_id) {
        log_conn_warn(0, "CONNECT", "failed to create session");
        return;
    }
    
    /* Notify NIP capabilities */
    for (nip_capability_t *cap = relay->nip_registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_CONNECTION && cap->caps.connection.on_connect) {
            log_conn_debug(conn_id, "CONNECT", "calling on_connect for cap");
            cap->caps.connection.on_connect(conn_id, cap->ctx);
        }
    }
}

void relay_on_disconnect(relay_t *relay, struct mg_connection *connection) {
    if (!relay || !connection) return;
    log_conn_info(0, "DISCONNECT", "client disconnected");
    log_conn_debug(0, "DISCONNECT", "connection=%p", (void*)connection);
    
    /* Find connection ID */
    connection_session_t *session = connection_session_get_by_mg_connection(connection);
    connection_id_t conn_id = session ? connection_session_get_id(session) : 0;
    
    remove_subscriptions(relay, connection, NULL);
    
    /* Notify NIP capabilities */
    if (conn_id) {
        for (nip_capability_t *cap = relay->nip_registry->capabilities; cap; cap = cap->next) {
            if (cap->type == NIP_CAP_CONNECTION && cap->caps.connection.on_disconnect) {
                log_conn_debug(conn_id, "DISCONNECT", "calling on_disconnect for cap");
                cap->caps.connection.on_disconnect(conn_id, cap->ctx);
            }
        }
    }
    
    /* Destroy connection session */
    if (session) {
        log_conn_debug(conn_id, "DISCONNECT", "destroying session");
        connection_session_destroy(session);
    }
}

bool relay_handle_http(relay_t *relay, struct mg_connection *connection,
                       struct mg_http_message *request) {
    if (!relay || !connection || !request) return false;
    
    struct mg_str *accept = mg_http_get_header(request, "Accept");
    bool served_info = false;
    
    if (accept && mg_str_contains(*accept, "application/nostr+json")) {
        /* Deterministic metadata composition: first non-NULL wins. HTTP
         * handling owns the response; the NIP only provides the payload. */
        const char *doc = nip_composition_get_info_document(relay->nip_registry);
        if (doc) {
            mg_http_reply(connection, 200,
                "Content-Type: application/nostr+json\r\nAccess-Control-Allow-Origin: *\r\n",
                "%s", doc);
            served_info = true;
        }
    }
    
    if (!served_info) {
        mg_ws_upgrade(connection, request, NULL);
    }
    return true;
}

/* ============================================================================
 * Internal Implementation
 * ============================================================================ */

void relay_event_handler(struct mg_connection *connection, int event, void *event_data) {
    relay_t *relay = (relay_t *)connection->fn_data;
    if (!relay) return;
    
    if (event == MG_EV_HTTP_MSG) {
        relay_handle_http(relay, connection, event_data);
    } else if (event == MG_EV_WS_OPEN) {
        connection->fn_data = relay; /* Ensure fn_data is set for later events */
        relay_on_connect(relay, connection);
    } else if (event == MG_EV_WS_MSG) {
        handle_message(relay, connection, event_data);
    } else if (event == MG_EV_CLOSE) {
        relay_on_disconnect(relay, connection);
    }
}

static void remove_subscriptions(relay_t *relay, struct mg_connection *connection, const char *id) {
    if (!relay) return;
    
    /* Find connection ID */
    connection_session_t *session = connection ? connection_session_get_by_mg_connection(connection) : NULL;
    connection_id_t conn_id = session ? connection_session_get_id(session) : 0;
    
    if (connection && id) {
        subscription_manager_close_subscription(relay->subscriptions, conn_id, id);
    } else if (connection) {
        subscription_manager_remove_connection(relay->subscriptions, conn_id);
    }
}

/* Publication policy: single path via NIP composition (legacy
 * plugins_accept_publish wrapper deleted). */



/* Wrapper for delivery check that captures the registry */
static bool relay_can_deliver(const event_t *event, connection_id_t connection_id, void *ctx) {
    nip_registry_t *registry = (nip_registry_t *)ctx;
    return nip_composition_check_delivery(registry, event, connection_id);
}

static void broadcast_event(relay_t *relay, const event_t *event) {
    if (!relay) return;
    log_event_info(0, event->id, event->kind, "BROADCAST", "kind=%d id=%.16s", event->kind, event->id);
    subscription_manager_match_and_deliver(relay->subscriptions, event,
        relay_can_deliver,
        relay->nip_registry,
        send_event_json);
}

static void send_event_json(connection_id_t connection_id, const char *sub, const event_t *event) {
    char *event_json = protocol_serialize_event(sub, event);
    if (event_json) {
        relay_send_json(connection_id, event_json);
        protocol_free_string(event_json);
    }
}

/* Wrapper functions for protocol response builders that capture the registry
 * via the context parameter (passed by subscription_manager_query). */
static char *relay_build_eose(const char *sub, bool has_more, bool auth_hint, void *ctx) {
    return nip_composition_build_eose((nip_registry_t *)ctx, sub, has_more, auth_hint);
}

static char *relay_build_count(const char *sub, unsigned long count, void *ctx) {
    return nip_composition_build_count((nip_registry_t *)ctx, sub, count);
}

static bool relay_needs_auth_hint(const filter_t *filters, size_t count,
                                  connection_id_t conn_id, void *ctx) {
    return nip_composition_needs_auth_hint((nip_registry_t *)ctx, filters, count, conn_id);
}

static void relay_send_auth_challenge(connection_id_t conn_id, void *ctx) {
    nip_composition_send_auth_challenge((nip_registry_t *)ctx, conn_id);
}

static bool relay_authorize_query(connection_id_t connection_id, filter_t *filters,
                                   size_t filters_count, char *reason, size_t reason_size,
                                   void *ctx) {
    nip_registry_t *registry = (nip_registry_t *)ctx;
    return nip_composition_authorize_query(registry, connection_id, filters, filters_count, reason, reason_size);
}

static void send_query_json(connection_id_t connection_id, const char *json) {
    relay_send_json(connection_id, json);
}

static bool query_events(relay_t *relay, connection_id_t connection_id, const char *sub,
                          filter_t *filters, size_t count, bool do_count,
                          char *reject_reason, size_t reason_size) {
    if (!relay) return true;
    log_proto_debug(0, "QUERY_EVENTS", "sub=%s filter_count=%zu do_count=%d", sub, count, do_count);
    for (size_t i = 0; i < count; i++) {
        log_proto_debug(0, "QUERY_EVENTS", "filter[%zu]: ids=%zu authors=%zu kinds=%zu since=%lld until=%lld limit=%d",
                    i, filters[i].ids_count, filters[i].authors_count, filters[i].kinds_count,
                    (long long)filters[i].since, (long long)filters[i].until, filters[i].limit);
    }

    bool allowed = subscription_manager_query(relay->subscriptions, relay->storage, connection_id, sub, filters, count, do_count,
        send_query_json,
        relay_can_deliver,
        relay->nip_registry,
        relay_build_eose,
        relay_build_count,
        relay_needs_auth_hint,
        relay_send_auth_challenge,
        relay_authorize_query,
        relay->nip_registry,
        relay->nip_registry,
        reject_reason, reason_size);
    
    if (!allowed) {
        /* subscription_manager_query fills reject_reason with the specific
         * NIP-42 prefix (auth-required: / restricted:) via composition.
         * Fall back to generic only if no NIP provided a reason. */
        if ((!reject_reason || !reject_reason[0]) && reject_reason && reason_size > 0) {
            snprintf(reject_reason, reason_size, "auth-required: authentication required");
        }
        log_proto_debug(connection_id, "QUERY_EVENTS", "query rejected: %s",
                        reject_reason ? reject_reason : "(no reason)");
    }
    return allowed;
}

static void handle_req(relay_t *relay, struct mg_connection *connection,
                        protocol_message_t *proto_msg, bool do_count) {
    /* Find connection ID */
    connection_session_t *session = connection_session_get_by_mg_connection(connection);
    connection_id_t conn_id = session ? connection_session_get_id(session) : 0;
    
    const char *sub = do_count ? proto_msg->payload.count.subscription_id : proto_msg->payload.req.subscription_id;
    filter_t *filters = do_count ? proto_msg->payload.count.filters : proto_msg->payload.req.filters;
    size_t filter_count = do_count ? proto_msg->payload.count.filters_count : proto_msg->payload.req.filters_count;
    
    log_sub_debug(conn_id, sub, "HANDLE_REQ", "ENTRY filter_count=%zu do_count=%d filters_ptr=%p", 
                filter_count, do_count, (void*)filters);
    
    if (!sub || strlen(sub) > relay->config.max_subscription_id_length || filter_count == 0) {
        log_sub_warn(conn_id, sub, "HANDLE_REQ", "invalid filter len=%zu filter_count=%zu", sub ? strlen(sub) : 0, filter_count);
        char *closed = protocol_serialize_closed(sub, false, "error: invalid filter");
        if (closed) {
            transport_send_json(connection, closed);
            protocol_free_string(closed);
        }
        /* DO NOT free filters here - protocol_message_free will handle it */
        log_sub_debug(conn_id, sub, "HANDLE_REQ", "EXIT early (invalid filter), filters still owned by proto_msg");
        return;
    }
    
    if (!do_count) {
        /* REQ: authorize BEFORE mutating subscription state (capability
         * composition is the authorization gate). Creating first would
         * leak a live subscription for live broadcasts via
         * match_and_deliver even after CLOSED. */
        char pre_reason[256] = {0};
        if (!relay_authorize_query(conn_id, filters, filter_count,
                                   pre_reason, sizeof(pre_reason),
                                   relay->nip_registry)) {
            /* NIP-42 flow: client must have a stored challenge to act on
             * auth-required CLOSED. Refresh it before CLOSED. */
            if (strncmp(pre_reason, "auth-required:", 14) == 0) {
                nip_composition_send_auth_challenge(relay->nip_registry, conn_id);
            }
            char *closed = protocol_serialize_closed(
                sub, false,
                pre_reason[0] ? pre_reason : "auth-required: authentication required");
            if (closed) {
                transport_send_json(connection, closed);
                protocol_free_string(closed);
            }
            return;
        }
        size_t subscriptions_count = subscription_manager_count_for_connection(relay->subscriptions, conn_id);
        if (subscriptions_count >= relay->config.max_subscriptions_per_connection) {
            log_sub_warn(conn_id, sub, "HANDLE_REQ", "too many subscriptions (%zu >= %d)", subscriptions_count, relay->config.max_subscriptions_per_connection);
            char *closed = protocol_serialize_closed(sub, false, "error: too many subscriptions");
            if (closed) {
                transport_send_json(connection, closed);
                protocol_free_string(closed);
            }
            /* DO NOT free filters - protocol_message_free will handle it */
            log_sub_debug(conn_id, sub, "HANDLE_REQ", "EXIT early (too many subscriptions), filters still owned by proto_msg");
            return;
        }
        log_sub_debug(conn_id, sub, "HANDLE_REQ", "calling subscription_manager_create_subscription, transferring filters ownership");
        if (!subscription_manager_create_subscription(relay->subscriptions, conn_id, sub, filters, filter_count)) {
            log_sub_warn(conn_id, sub, "HANDLE_REQ", "failed to create subscription");
            char *closed = protocol_serialize_closed(sub, false, "error: server unavailable");
            if (closed) {
                transport_send_json(connection, closed);
                protocol_free_string(closed);
            }
            /* DO NOT free filters - protocol_message_free will handle it (ownership NOT transferred) */
            log_sub_debug(conn_id, sub, "HANDLE_REQ", "EXIT early (create failed), filters still owned by proto_msg");
            return;
        }
        /* Subscription created successfully - subscription manager now owns the filters.
         * NULL out the filters in proto_msg so protocol_message_free doesn't double-free them. */
        log_sub_debug(conn_id, sub, "HANDLE_REQ", "subscription created, NULLing proto_msg filters to transfer ownership");
        proto_msg->payload.req.filters = NULL;
        proto_msg->payload.req.filters_count = 0;
        char reject_reason[256] = {0};
        if (!query_events(relay, conn_id, sub, filters, filter_count, false, reject_reason, sizeof(reject_reason))) {
            /* Query failed after subscription creation (e.g. auth revoked
             * between pre-check and query). Close the just-created
             * subscription so live broadcasts cannot leak to it. */
            subscription_manager_close_subscription(relay->subscriptions, conn_id, sub);
            if (strncmp(reject_reason, "auth-required:", 14) == 0) {
                nip_composition_send_auth_challenge(relay->nip_registry, conn_id);
            }
            char *closed = protocol_serialize_closed(sub, false, reject_reason[0] ? reject_reason : "auth-required: authentication required");
            if (closed) {
                transport_send_json(connection, closed);
                protocol_free_string(closed);
            }
        }
    } else {
        /* COUNT: query only, no subscription created. Filters remain owned by proto_msg.
         * protocol_message_free will free them. */
        log_sub_debug(conn_id, sub, "HANDLE_REQ", "COUNT query, filters borrowed (proto_msg retains ownership)");
        char reject_reason[256] = {0};
        if (!query_events(relay, conn_id, sub, filters, filter_count, true, reject_reason, sizeof(reject_reason))) {
            if (strncmp(reject_reason, "auth-required:", 14) == 0) {
                nip_composition_send_auth_challenge(relay->nip_registry, conn_id);
            }
            char *closed = protocol_serialize_closed(sub, false, reject_reason[0] ? reject_reason : "auth-required: authentication required");
            if (closed) {
                transport_send_json(connection, closed);
                protocol_free_string(closed);
            }
        }
    }
    log_sub_debug(conn_id, sub, "HANDLE_REQ", "EXIT");
}

/* Validation stage of the EVENT pipeline: structure,
 * event ID, Schnorr signature, delegation, relay timestamps.
 * Runs AFTER NIP publication policies (matching the legacy order where
 * accept_publish hooks ran before nip01_process_event validation) and BEFORE
 * kind dispatch. Reasons preserve the legacy wire messages.
 * 
 * NOTE: Proof of Work (NIP-13) is checked by NIP-13's publication policy,
 * NOT here, to avoid duplicate computation.
 * 
 * BORROWS event - does NOT take ownership. Caller (proto_msg) retains ownership.
 */
static bool validate_event_for_publish(relay_t *relay, const event_t *event,  /* BORROWED */
                                       char *reason, size_t reason_size) {
    log_event_debug(0, event->id, event->kind, "VALIDATE_EVENT", "ENTRY event_ptr=%p (BORROWED)", (void*)event);
    log_event_debug(0, event->id, event->kind, "VALIDATE_EVENT", "kind=%d id=%.16s pubkey=%.16s created_at=%lld",
                event->kind, event->id, event->pubkey, (long long)event->created_at);
    
    /* Check structure */
    if (!event) {
        snprintf(reason, reason_size, "event is null");
        log_event_error(0, event ? event->id : "null", event ? event->kind : 0, "VALIDATE_EVENT", "FAIL - event is null");
        log_debug("EVENT", "VALIDATE_EVENT", "EXIT (null event)");
        return false;
    }
    
    if (!event->id[0] || !event->pubkey[0] || !event->sig[0]) {
        snprintf(reason, reason_size, "missing required fields");
        log_event_error(0, event->id, event->kind, "VALIDATE_EVENT", "FAIL - missing required fields");
        log_debug("EVENT", "VALIDATE_EVENT", "EXIT (missing fields)");
        return false;
    }
    
    if (event->kind < 0) {
        snprintf(reason, reason_size, "invalid kind");
        log_event_error(0, event->id, event->kind, "VALIDATE_EVENT", "FAIL - invalid kind");
        log_debug("EVENT", "VALIDATE_EVENT", "EXIT (invalid kind)");
        return false;
    }
    
    if (event->created_at == 0) {
        snprintf(reason, reason_size, "invalid created_at");
        log_event_error(0, event->id, event->kind, "VALIDATE_EVENT", "FAIL - invalid created_at");
        log_debug("EVENT", "VALIDATE_EVENT", "EXIT (invalid created_at)");
        return false;
    }
    
    size_t max_content = relay->config.max_event_content_length;
    if (max_content > 0 && event->content_len > max_content) {
        snprintf(reason, reason_size, "content too large");
        log_event_error(0, event->id, event->kind, "VALIDATE_EVENT", "FAIL - content too large (%zu > %zu)", event->content_len, max_content);
        log_debug("EVENT", "VALIDATE_EVENT", "EXIT (content too large)");
        return false;
    }
    
    /* Check event serialization size */
    size_t serialized_size = json_serialized_event_size(event);
    if (serialized_size + 160 > 65536) {
        snprintf(reason, reason_size, "event serialization too large");
        log_event_error(0, event->id, event->kind, "VALIDATE_EVENT", "FAIL - event serialization too large (%zu)", serialized_size);
        log_debug("EVENT", "VALIDATE_EVENT", "EXIT (serialization too large)");
        return false;
    }
    
    /* Verify event ID */
    if (!check_event_id(event)) {
        snprintf(reason, reason_size, "invalid: event id, signature or delegation is invalid");
        log_event_error(0, event->id, event->kind, "VALIDATE_EVENT", "FAIL - check_event_id failed");
        log_debug("EVENT", "VALIDATE_EVENT", "EXIT (check_event_id failed)");
        return false;
    }
    
    /* Verify signature - need to recompute digest */
    size_t buffer_size = event_hash_input_size(event);
    if (buffer_size == 0) {
        snprintf(reason, reason_size, "invalid: event id, signature or delegation is invalid");
        log_event_error(0, event->id, event->kind, "VALIDATE_EVENT", "FAIL - event_hash_input_size returned 0");
        log_debug("EVENT", "VALIDATE_EVENT", "EXIT (hash input size 0)");
        return false;
    }
    
    char *buffer = (char *)malloc(buffer_size);
    if (!buffer) {
        snprintf(reason, reason_size, "invalid: event id, signature or delegation is invalid");
        log_event_error(0, event->id, event->kind, "VALIDATE_EVENT", "FAIL - malloc failed for buffer");
        log_debug("EVENT", "VALIDATE_EVENT", "EXIT (malloc failed)");
        return false;
    }
    
    size_t len = event_build_hash_input(event, buffer, buffer_size);
    if (len == 0) {
        free(buffer);
        snprintf(reason, reason_size, "invalid: event id, signature or delegation is invalid");
        log_event_error(0, event->id, event->kind, "VALIDATE_EVENT", "FAIL - event_build_hash_input returned 0");
        log_debug("EVENT", "VALIDATE_EVENT", "EXIT (build hash input failed)");
        return false;
    }
    
    uint8_t digest[32];
    sha256((const uint8_t *)buffer, len, digest);
    free(buffer);
    
    if (!signature_verify(event->sig, event->pubkey, digest)) {
        snprintf(reason, reason_size, "invalid: event id, signature or delegation is invalid");
        log_event_error(0, event->id, event->kind, "VALIDATE_EVENT", "FAIL - signature_verify failed");
        log_debug("EVENT", "VALIDATE_EVENT", "EXIT (signature verify failed)");
        return false;
    }
    
    /* Check timestamp bounds */
    time_t now = time(NULL);
    if (relay->config.created_at_lower_limit > 0 && 
        event->created_at < now - relay->config.created_at_lower_limit) {
        snprintf(reason, reason_size, "invalid: created_at is out of the acceptable range");
        log_event_error(0, event->id, event->kind, "VALIDATE_EVENT", "FAIL - created_at too old (%lld < %lld)", (long long)event->created_at, (long long)(now - relay->config.created_at_lower_limit));
        log_debug("EVENT", "VALIDATE_EVENT", "EXIT (created_at too old)");
        return false;
    }
    
    if (relay->config.created_at_upper_limit > 0 && 
        event->created_at > now + relay->config.created_at_upper_limit) {
        snprintf(reason, reason_size, "invalid: created_at is out of the acceptable range");
        log_event_error(0, event->id, event->kind, "VALIDATE_EVENT", "FAIL - created_at too far in future (%lld > %lld)", (long long)event->created_at, (long long)(now + relay->config.created_at_upper_limit));
        log_debug("EVENT", "VALIDATE_EVENT", "EXIT (created_at too far in future)");
        return false;
    }
    
    log_event_info(0, event->id, event->kind, "VALIDATE_EVENT", "PASS");
    log_debug("EVENT", "VALIDATE_EVENT", "EXIT (PASS), event still owned by caller");
    return true;
}

static void handle_event(relay_t *relay, struct mg_connection *connection, const event_t *event) {
    /* BORROWED: event is owned by proto_msg, will be freed by protocol_message_free().
     * Do NOT call event_release - proto_msg owns the event and will free it via protocol_message_free. */
    const event_t *event_borrowed = event;
    char reject_reason[256] = {0};
    
    log_event_debug(0, event_borrowed->id, event_borrowed->kind, "HANDLE_EVENT", "ENTRY kind=%d id=%.16s pubkey=%.16s created_at=%lld event_ptr=%p", 
                event_borrowed->kind, event_borrowed->id, event_borrowed->pubkey,
                (long long)event_borrowed->created_at, (void*)event_borrowed);
    
    /* Find connection ID */
    connection_session_t *session = connection_session_get_by_mg_connection(connection);
    connection_id_t conn_id = session ? connection_session_get_id(session) : 0;
    
    log_conn_debug(conn_id, "HANDLE_EVENT", "conn_id=%u", (unsigned)conn_id);
    
    /* 1. Validate event FIRST (structure, ID, signature, delegation, timestamps, PoW)
     * Reject invalid events immediately without wasting compute on policy checks. */
    log_conn_debug(conn_id, "HANDLE_EVENT", "step 1 - validate_event_for_publish");
    if (!validate_event_for_publish(relay, event_borrowed, reject_reason, sizeof(reject_reason))) {
        log_conn_warn(conn_id, "HANDLE_EVENT", "validation FAILED - %s", reject_reason);
        char *ok = protocol_serialize_ok(event_borrowed->id, false, reject_reason);
        if (ok) {
            transport_send_json(connection, ok);
            protocol_free_string(ok);
        }
        /* DO NOT call event_release - proto_msg owns the event and will free it */
        log_conn_debug(conn_id, "HANDLE_EVENT", "EXIT early (validation failed), event still owned by proto_msg");
        return;
    }
    log_conn_debug(conn_id, "HANDLE_EVENT", "step 1 - PASS");
    
    /* 2. Then check NIP publication policies (NIP-13 PoW, NIP-26 delegation, NIP-42 auth, etc.) */
    log_conn_debug(conn_id, "HANDLE_EVENT", "step 2 - nip_composition_check_publication");
    log_event_debug(conn_id, event_borrowed->id, event_borrowed->kind, "CHECK_PUBLICATION",
                    "conn_id=%u event_kind=%d event_id=%.16s",
                    (unsigned)conn_id, event_borrowed->kind, event_borrowed->id);
    if (!nip_composition_check_publication(relay->nip_registry, conn_id, event_borrowed, reject_reason, sizeof(reject_reason))) {
        log_conn_warn(conn_id, "HANDLE_EVENT", "policy FAILED - %s", reject_reason);
        char *ok = protocol_serialize_ok(event_borrowed->id, false, reject_reason);
        if (ok) {
            transport_send_json(connection, ok);
            protocol_free_string(ok);
        }
        /* DO NOT call event_release - proto_msg owns the event and will free it */
        log_conn_debug(conn_id, "HANDLE_EVENT", "EXIT early (policy failed), event still owned by proto_msg");
        return;
    }
    log_conn_debug(conn_id, "HANDLE_EVENT", "step 2 - PASS");
    
    /* 3. Process via kind handler (NIP-01 replaceable/addressable, etc.) */
    log_conn_debug(conn_id, "HANDLE_EVENT", "step 3 - nip_composition_process_kind");
    nip_kind_composition_result_t kind_result = nip_composition_process_kind(
        relay->nip_registry, conn_id, event_borrowed, relay->storage, relay->config.service_url);
    
    nip01_process_result_t result;
    if (kind_result.any_handler_matched) {
        result = kind_result.result;
        log_event_debug(conn_id, event_borrowed->id, event_borrowed->kind, "HANDLE_EVENT", "kind handler matched, accepted=%d broadcast=%d msg=%s",
                    result.accepted, result.should_broadcast, result.response_msg);
    } else {
        log_conn_debug(conn_id, "HANDLE_EVENT", "no kind handler, using default NIP-01");
        /* Default NIP-01 behavior for kinds without handlers */
        if (event_borrowed->kind >= 20000 && event_borrowed->kind < 30000) {
            result.accepted = true;
            result.should_broadcast = true;
            result.response_msg[0] = '\0';
        } else {
            storage_tag_match_t indexed_tags[RELAY_INDEXED_TAG_CAP];
            size_t indexed_tags_count = relay_collect_index_tags(
                event_borrowed, indexed_tags, RELAY_INDEXED_TAG_CAP);
            storage_insert_result_t insert_result = relay->storage->insert_record(
                event_borrowed, indexed_tags, indexed_tags_count);
            relay_free_index_tags(indexed_tags, indexed_tags_count);
            log_conn_debug(conn_id, "HANDLE_EVENT", "storage insert result=%d", insert_result.result);
            if (insert_result.result == STORAGE_OK) {
                result.accepted = true;
                result.should_broadcast = true;
                result.response_msg[0] = '\0';
            } else if (insert_result.result == STORAGE_DUPLICATE) {
                result.accepted = true;
                result.should_broadcast = true;
                snprintf(result.response_msg, sizeof(result.response_msg), "duplicate: event already exists");
            } else {
                result.accepted = false;
                result.should_broadcast = false;
                snprintf(result.response_msg, sizeof(result.response_msg), "error: %s", insert_result.error_message);
            }
        }
        log_event_debug(conn_id, event_borrowed->id, event_borrowed->kind, "HANDLE_EVENT", "default result accepted=%d broadcast=%d msg=%s",
                    result.accepted, result.should_broadcast, result.response_msg);
    }
    
    log_conn_info(conn_id, "HANDLE_EVENT", "sending OK response accepted=%d msg=%s", result.accepted, result.response_msg);
    char *ok = protocol_serialize_ok(event_borrowed->id, result.accepted, result.response_msg);
    if (ok) {
        transport_send_json(connection, ok);
        protocol_free_string(ok);
    }
    
    if (result.accepted && result.should_broadcast) {
        log_conn_debug(conn_id, "HANDLE_EVENT", "broadcasting event");
        broadcast_event(relay, event_borrowed);
    }
    
    log_conn_debug(conn_id, "HANDLE_EVENT", "END");
    log_debug("EVENT", "HANDLE_EVENT", "EXIT, event still owned by proto_msg (will be freed by protocol_message_free)");
    /* DO NOT call event_release - proto_msg owns the event and will free it via protocol_message_free */
}

static void handle_message(relay_t *relay, struct mg_connection *connection, struct mg_ws_message *message) {
    char reject_reason[256] = {0};
    protocol_message_t proto_msg;
    bool proto_valid;
    bool consumed = false;

    log_proto_debug(0, "HANDLE_MESSAGE", "ENTRY len=%zu data=%.100s", message->data.len, message->data.buf);

    /* Parse using the protocol parser with config limits */
    proto_valid = protocol_parse_client_message(message->data.buf, message->data.len,
                                                 &relay->config, &proto_msg, reject_reason, sizeof(reject_reason));

    log_proto_debug(0, "HANDLE_MESSAGE", "parse result=%d command=%d proto_msg_ptr=%p", proto_valid, proto_msg.command, (void*)&proto_msg);

    /* Find connection ID */
    connection_session_t *session = connection_session_get_by_mg_connection(connection);
    connection_id_t conn_id = session ? connection_session_get_id(session) : 0;

    if (!proto_valid) {
        log_proto_warn(conn_id, "HANDLE_MESSAGE", "INVALID proto - %s", reject_reason);
        if (reject_reason[0]) {
            char *notice = protocol_serialize_notice(reject_reason);
            if (notice) {
                transport_send_json(connection, notice);
                protocol_free_string(notice);
            }
        }
        log_debug("PROTOCOL", "HANDLE_MESSAGE", "EXIT early (invalid proto), no proto_msg to free");
        return;
    }

    /* Log ownership state after successful parse */
    log_debug("PROTOCOL", "HANDLE_MESSAGE", "proto_msg owns - event: %s, filters: %s, sub_id: %s",
                proto_msg.command == PROTOCOL_CMD_EVENT ? "yes" : "no",
                (proto_msg.command == PROTOCOL_CMD_REQ || proto_msg.command == PROTOCOL_CMD_COUNT) ? "yes" : "no",
                (proto_msg.command == PROTOCOL_CMD_REQ || proto_msg.command == PROTOCOL_CMD_COUNT || proto_msg.command == PROTOCOL_CMD_CLOSE) ? "yes" : "no");

    /* Offer to message intercept capabilities (e.g. NIP-42 AUTH) */
    for (nip_capability_t *cap = relay->nip_registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_MESSAGE_INTERCEPT && cap->caps.message_intercept.on_message) {
            log_proto_debug(conn_id, "HANDLE_MESSAGE", "trying message interceptor");
            if (cap->caps.message_intercept.on_message(conn_id, &proto_msg, cap->ctx)) {
                consumed = true;
                log_proto_info(conn_id, "HANDLE_MESSAGE", "message consumed by interceptor");
                break;
            }
        }
    }

    if (!consumed) {
        log_debug("PROTOCOL", "HANDLE_MESSAGE", "dispatching command=%d", proto_msg.command);
        switch (proto_msg.command) {
            case PROTOCOL_CMD_REQ:
                log_proto_info(conn_id, "HANDLE_MESSAGE", "dispatching REQ sub=%s", proto_msg.payload.req.subscription_id);
                handle_req(relay, connection, &proto_msg, false);
                break;
            case PROTOCOL_CMD_COUNT:
                log_proto_info(conn_id, "HANDLE_MESSAGE", "dispatching COUNT sub=%s", proto_msg.payload.count.subscription_id);
                handle_req(relay, connection, &proto_msg, true);
                break;
            case PROTOCOL_CMD_CLOSE:
                log_proto_info(conn_id, "HANDLE_MESSAGE", "dispatching CLOSE sub=%s", proto_msg.payload.close.subscription_id);
                if (proto_msg.payload.close.subscription_id) {
                    remove_subscriptions(relay, connection, proto_msg.payload.close.subscription_id);
                }
                break;
            case PROTOCOL_CMD_EVENT:
                log_proto_info(conn_id, "HANDLE_MESSAGE", "dispatching EVENT");
                handle_event(relay, connection, &proto_msg.payload.event.event);
                break;
            case PROTOCOL_CMD_AUTH:
                /* AUTH was already offered to interceptors above (NIP-42 owns
                 * the challenge flow and answers OK itself). Reaching here
                 * means no capability consumed it: malformed AUTH or no AUTH
                 * provider in this module generation. */
                log_proto_warn(conn_id, "HANDLE_MESSAGE", "AUTH not consumed by interceptor, sending error");
                {
                    char *notice = protocol_serialize_notice("error: invalid auth");
                    if (notice) {
                        transport_send_json(connection, notice);
                        protocol_free_string(notice);
                    }
                }
                break;
            default:
                log_proto_warn(conn_id, "HANDLE_MESSAGE", "UNKNOWN command=%d", proto_msg.command);
                {
                    char *notice = protocol_serialize_notice("error: invalid request");
                    if (notice) {
                        transport_send_json(connection, notice);
                        protocol_free_string(notice);
                    }
                }
                break;
        }
    } else {
        log_debug("PROTOCOL", "HANDLE_MESSAGE", "message consumed by interceptor, proto_msg still owned here");
    }

    log_debug("PROTOCOL", "HANDLE_MESSAGE", "calling protocol_message_free, proto_msg_ptr=%p", (void*)&proto_msg);
    protocol_message_free(&proto_msg);
    log_debug("RELAY", "HANDLE_MESSAGE", "EXIT");
}

static bool module_file_fingerprint(const char *path, struct stat *metadata, uint64_t *hash) {
    FILE *file;
    unsigned char buffer[8192];
    size_t count;
    uint64_t value = UINT64_C(1469598103934665603);
    if (!path || !metadata || !hash || stat(path, metadata) != 0) return false;
    file = fopen(path, "rb");
    if (!file) return false;
    while ((count = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        for (size_t index = 0; index < count; ++index) {
            value ^= buffer[index];
            value *= UINT64_C(1099511628211);
        }
    }
    if (ferror(file)) {
        fclose(file);
        return false;
    }
    fclose(file);
    *hash = value;
    return true;
}

static void nhr_check_candidate_timer(void *arg) {
    relay_t *relay = (relay_t *)arg;
    if (!relay || !relay->host_runtime) return;
    
    struct stat st;
    uint64_t module_hash;
    if (!relay->watched_module_path[0] ||
        !module_file_fingerprint(relay->watched_module_path, &st, &module_hash)) return;
    
    if (st.st_mtime == relay->watched_module_mtime && st.st_size == relay->watched_module_size &&
        module_hash == relay->watched_module_hash) {
        relay->watched_module_pending = false;
        return;
    }
    
    if (!relay->watched_module_pending || st.st_mtime != relay->pending_module_mtime ||
        st.st_size != relay->pending_module_size || module_hash != relay->pending_module_hash) {
        relay->watched_module_pending = true;
        relay->pending_module_mtime = st.st_mtime;
        relay->pending_module_size = (long)st.st_size;
        relay->pending_module_hash = module_hash;
    }
    
    Nhr_Library candidate;
    if (!nhr_runtime_build_candidate(relay->host_runtime, relay->watched_module_path, &candidate)) {
        log_nhr_warn("RELOAD", "candidate rejected; continuing current module");
        return;
    }
    
    /* Activation swaps module code synchronously on this event-loop thread;
     * no dispatch runs concurrently. Re-point the host capability table at
     * the new generation (or the rollback generation on failure) so
     * changed/added/removed NIPs take effect without restart. Nodes are
     * host-owned deep copies; old function pointers never survive the swap. */
    bool activated = nhr_runtime_activate_candidate(relay->host_runtime, &candidate);
    relay_hot_swap_capabilities(relay);
    if (activated) {
        relay->watched_module_mtime = st.st_mtime;
        relay->watched_module_size = (long)st.st_size;
        relay->watched_module_hash = module_hash;
        relay->watched_module_pending = false;
        log_nhr_info("RELOAD", "loaded new module generation");
    } else {
        log_nhr_warn("RELOAD", "candidate rejected; retrying published artifact");
    }
}

static void plugin_timer_fn(void *arg) {
    relay_t *relay = (relay_t *)arg;
    if (!relay) return;

    /* Shared delivery path: ALL maintenance handlers run (see composition
     * rules). Interval is fixed at startup; per-generation intervals are
     * honored on next reload via fresh timer registration. */
    nip_composition_run_maintenance(relay->nip_registry, relay->storage);
}

/* NOTE: transport_send_json() is owned by transport/server.c (sole frame
 * sender). Relay and NIP code resolve opaque connection IDs to connections
 * and delegate here — no Mongoose calls outside transport. */

void relay_send_json(connection_id_t connection_id, const char *json) {
    connection_session_t *session = connection_session_get(connection_id);
    struct mg_connection *connection = session ?
        connection_session_get_mg_connection(session) : NULL;
    if (connection && json) {
        transport_send_json(connection, json);
    }
}

void relay_hot_swap_capabilities(relay_t *relay) {
    if (!relay || !relay->nip_registry || !relay->host_runtime) return;
    if (!relay->host_runtime->library.handle ||
        !relay->host_runtime->active.register_capabilities) return;
    nip_registry_clear(relay->nip_registry);
    relay->host_runtime->active.register_capabilities(relay->nip_registry);
}