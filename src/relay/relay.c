#include "relay/relay.h"
#include "transport/server.h"
#include "nips/nip_capability.h"
#include "crypto.h"
#include "json_util.h"
#include "nostrogotho.h"
#include "subscriptions/subscription_manager.h"
#include "relay/connection_session.h"
#include "protocol/protocol.h"
#include "nhr.h"
#include <mongoose.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * RELAY.C - Relay Runtime Implementation
 * 
 * Aggregates all runtime state previously scattered as globals in server.c
 * ============================================================================ */

/* struct relay is defined in relay.h (single owner; transport/server.c needs
 * relay->manager). Do not duplicate it here. */

/* Forward declarations */
static void remove_subscriptions(relay_t *relay, struct mg_connection *connection, const char *id);
static bool plugins_accept_publish(relay_t *relay, connection_id_t connection_id,
                                    const event_t *event, char *reason, size_t reason_size);
static void broadcast_event(relay_t *relay, const event_t *event);
static void send_event_json(struct mg_connection *connection, const char *sub, const event_t *event);
static void query_events(relay_t *relay, struct mg_connection *connection, const char *sub,
                          filter_t *filters, size_t count, bool do_count);
static void handle_req(relay_t *relay, struct mg_connection *connection,
                       const char *sub, filter_t *filters, size_t filter_count, bool do_count);
static void handle_event(relay_t *relay, struct mg_connection *connection, const event_t *event);
static void handle_message(relay_t *relay, struct mg_connection *connection, struct mg_ws_message *message);
static void log_timestamp(void);
static void log_peer(struct mg_connection *connection);
static void log_message(relay_t *relay, struct mg_connection *connection, const char *fmt, ...);
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
    relay->debug_logging = config->debug_logging;
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
    log_message(relay, connection, "client connected (websocket open)");
    
    /* Sessions are owned by the connection_session module; the relay hands
     * out IDs from a range that never collides with "no session" (0). */
    connection_id_t conn_id = connection_session_create(relay->next_connection_id++, connection);
    if (!conn_id) return;
    
    /* Notify NIP capabilities */
    for (nip_capability_t *cap = relay->nip_registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_CONNECTION && cap->caps.connection.on_connect) {
            cap->caps.connection.on_connect(conn_id, cap->ctx);
        }
    }
}

void relay_on_disconnect(relay_t *relay, struct mg_connection *connection) {
    if (!relay || !connection) return;
    log_message(relay, connection, "client disconnected");
    
    /* Find connection ID */
    connection_session_t *session = connection_session_get_by_mg_connection(connection);
    connection_id_t conn_id = session ? connection_session_get_id(session) : 0;
    
    remove_subscriptions(relay, connection, NULL);
    
    /* Notify NIP capabilities */
    if (conn_id) {
        for (nip_capability_t *cap = relay->nip_registry->capabilities; cap; cap = cap->next) {
            if (cap->type == NIP_CAP_CONNECTION && cap->caps.connection.on_disconnect) {
                cap->caps.connection.on_disconnect(conn_id, cap->ctx);
            }
        }
    }
    
    /* Destroy connection session */
    if (session) {
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

static bool plugins_accept_publish(relay_t *relay, connection_id_t connection_id,
                                   const event_t *event, char *reason, size_t reason_size) {
    (void)relay;
    return nip_composition_check_publication(relay->nip_registry, connection_id, event, reason, reason_size);
}



/* Wrapper for delivery check that captures the registry */
static bool relay_can_deliver(const event_t *event, connection_id_t connection_id, void *ctx) {
    nip_registry_t *registry = (nip_registry_t *)ctx;
    return nip_composition_check_delivery(registry, event, connection_id);
}

static void broadcast_event(relay_t *relay, const event_t *event) {
    if (!relay) return;
    subscription_manager_match_and_deliver(relay->subscriptions, event,
        relay_can_deliver,
        relay->nip_registry,
        send_event_json);
}

static void send_event_json(struct mg_connection *connection, const char *sub, const event_t *event) {
    char *event_json = protocol_serialize_event(sub, event);
    if (event_json) {
        connection_session_t *session = connection_session_get_by_mg_connection(connection);
        connection_id_t conn_id = session ? connection_session_get_id(session) : 0;
        if (conn_id) relay_send_json(conn_id, event_json);
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

static void send_query_json(struct mg_connection *connection, const char *json) {
    transport_send_json(connection, json);
}

static void query_events(relay_t *relay, struct mg_connection *connection, const char *sub,
                          filter_t *filters, size_t count, bool do_count) {
    if (!relay) return;

    subscription_manager_query(relay->subscriptions, relay->storage, connection, sub, filters, count, do_count,
        send_query_json,
        relay_can_deliver,
        relay->nip_registry,
        relay_build_eose,
        relay_build_count,
        relay_needs_auth_hint,
        relay_send_auth_challenge,
        relay->nip_registry);
}

static void handle_req(relay_t *relay, struct mg_connection *connection,
                       const char *sub, filter_t *filters, size_t filter_count, bool do_count) {
    /* Find connection ID */
    connection_session_t *session = connection_session_get_by_mg_connection(connection);
    connection_id_t conn_id = session ? connection_session_get_id(session) : 0;
    
    if (!sub || strlen(sub) > relay->config.max_subscription_id_length || filter_count == 0) {
        char *closed = protocol_serialize_closed(sub, false, "error: invalid filter");
        if (closed) {
            transport_send_json(connection, closed);
            protocol_free_string(closed);
        }
        if (!do_count) {
            for (size_t i = 0; i < filter_count; i++) filter_release(&filters[i]);
            free(filters);
        }
        return;
    }
    
    if (!do_count) {
        size_t subscriptions_count = subscription_manager_count_for_connection(relay->subscriptions, conn_id);
        if (subscriptions_count >= relay->config.max_subscriptions_per_connection) {
            for (size_t i = 0; i < filter_count; i++) filter_release(&filters[i]);
            free(filters);
            char *closed = protocol_serialize_closed(sub, false, "error: too many subscriptions");
            if (closed) {
                transport_send_json(connection, closed);
                protocol_free_string(closed);
            }
            return;
        }
        if (!subscription_manager_create_subscription(relay->subscriptions, conn_id, sub, filters, filter_count)) {
            for (size_t i = 0; i < filter_count; i++) filter_release(&filters[i]);
            free(filters);
            char *closed = protocol_serialize_closed(sub, false, "error: server unavailable");
            if (closed) {
                transport_send_json(connection, closed);
                protocol_free_string(closed);
            }
            return;
        }
        query_events(relay, connection, sub, filters, filter_count, false);
    } else {
        query_events(relay, connection, sub, filters, filter_count, true);
        for (size_t i = 0; i < filter_count; i++) filter_release(&filters[i]);
        free(filters);
    }
}

/* Validation stage of the EVENT pipeline: structure,
 * event ID, Schnorr signature, delegation, relay timestamps.
 * Runs AFTER NIP publication policies (matching the legacy order where
 * accept_publish hooks ran before nip01_process_event validation) and BEFORE
 * kind dispatch. Reasons preserve the legacy wire messages.
 * 
 * NOTE: Proof of Work (NIP-13) is checked by NIP-13's publication policy,
 * NOT here, to avoid duplicate computation.
 */
static bool validate_event_for_publish(relay_t *relay, const event_t *event,
                                       char *reason, size_t reason_size) {
    /* Check structure */
    if (!event) {
        snprintf(reason, reason_size, "event is null");
        return false;
    }
    
    if (!event->id[0] || !event->pubkey[0] || !event->sig[0]) {
        snprintf(reason, reason_size, "missing required fields");
        return false;
    }
    
    if (event->kind < 0) {
        snprintf(reason, reason_size, "invalid kind");
        return false;
    }
    
    if (event->created_at == 0) {
        snprintf(reason, reason_size, "invalid created_at");
        return false;
    }
    
    size_t max_content = relay->config.max_event_content_length;
    if (max_content > 0 && event->content_len > max_content) {
        snprintf(reason, reason_size, "content too large");
        return false;
    }
    
    /* Check event serialization size */
    size_t serialized_size = json_serialized_event_size(event);
    if (serialized_size + 160 > 65536) {
        snprintf(reason, reason_size, "event serialization too large");
        return false;
    }
    
    /* Verify event ID */
    if (!check_event_id(event)) {
        snprintf(reason, reason_size, "invalid: event id, signature or delegation is invalid");
        return false;
    }
    
    /* Verify signature - need to recompute digest */
    size_t buffer_size = event_hash_input_size(event);
    if (buffer_size == 0) {
        snprintf(reason, reason_size, "invalid: event id, signature or delegation is invalid");
        return false;
    }
    
    char *buffer = (char *)malloc(buffer_size);
    if (!buffer) {
        snprintf(reason, reason_size, "invalid: event id, signature or delegation is invalid");
        return false;
    }
    
    size_t len = event_build_hash_input(event, buffer, buffer_size);
    if (len == 0) {
        free(buffer);
        snprintf(reason, reason_size, "invalid: event id, signature or delegation is invalid");
        return false;
    }
    
    uint8_t digest[32];
    sha256((const uint8_t *)buffer, len, digest);
    free(buffer);
    
    if (!signature_verify(event->sig, event->pubkey, digest)) {
        snprintf(reason, reason_size, "invalid: event id, signature or delegation is invalid");
        return false;
    }
    
    /* Check timestamp bounds */
    time_t now = time(NULL);
    if (relay->config.created_at_lower_limit > 0 && 
        event->created_at < now - relay->config.created_at_lower_limit) {
        snprintf(reason, reason_size, "invalid: created_at is out of the acceptable range");
        return false;
    }
    
    if (relay->config.created_at_upper_limit > 0 && 
        event->created_at > now + relay->config.created_at_upper_limit) {
        snprintf(reason, reason_size, "invalid: created_at is out of the acceptable range");
        return false;
    }
    
    return true;
}

static void handle_event(relay_t *relay, struct mg_connection *connection, const event_t *event) {
    event_t event_copy = *event;
    char reject_reason[256] = {0};
    
    log_message(relay, connection, "event kind=%d id=%.*s pubkey=%.*s created_at=%lld",
                event_copy.kind, (int)sizeof(event_copy.id), event_copy.id,
                (int)sizeof(event_copy.pubkey), event_copy.pubkey,
                (long long)event_copy.created_at);
    
    /* Find connection ID */
    connection_session_t *session = connection_session_get_by_mg_connection(connection);
    connection_id_t conn_id = session ? connection_session_get_id(session) : 0;
    
    /* 1. Validate event FIRST (structure, ID, signature, delegation, timestamps, PoW)
     * Reject invalid events immediately without wasting compute on policy checks. */
    if (!validate_event_for_publish(relay, &event_copy, reject_reason, sizeof(reject_reason))) {
        char *ok = protocol_serialize_ok(event_copy.id, false, reject_reason);
        if (ok) {
            transport_send_json(connection, ok);
            protocol_free_string(ok);
        }
        event_release(&event_copy);
        return;
    }
    
    /* 2. Then check NIP publication policies (NIP-13 PoW, NIP-26 delegation, NIP-42 auth, etc.) */
    if (!plugins_accept_publish(relay, conn_id, &event_copy, reject_reason, sizeof(reject_reason))) {
        char *ok = protocol_serialize_ok(event_copy.id, false, reject_reason);
        if (ok) {
            transport_send_json(connection, ok);
            protocol_free_string(ok);
        }
        event_release(&event_copy);
        return;
    }
    
    /* 3. Process via kind handler (NIP-01 replaceable/addressable, etc.) */
    nip_kind_composition_result_t kind_result = nip_composition_process_kind(
        relay->nip_registry, conn_id, &event_copy, relay->storage, relay->config.service_url);
    
    nip01_process_result_t result;
    if (kind_result.any_handler_matched) {
        result = kind_result.result;
    } else {
        /* Default NIP-01 behavior for kinds without handlers */
        if (event_copy.kind >= 20000 && event_copy.kind < 30000) {
            result.accepted = true;
            result.should_broadcast = true;
            result.response_msg[0] = '\0';
        } else {
            storage_insert_result_t insert_result = relay->storage->insert_record(&event_copy, NULL, 0);
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
    }
    
    char *ok = protocol_serialize_ok(event_copy.id, result.accepted, result.response_msg);
    if (ok) {
        transport_send_json(connection, ok);
        protocol_free_string(ok);
    }
    
    if (result.accepted && result.should_broadcast) {
        broadcast_event(relay, &event_copy);
    }
    
    event_release(&event_copy);
}

static void handle_message(relay_t *relay, struct mg_connection *connection, struct mg_ws_message *message) {
    char reject_reason[256] = {0};
    protocol_message_t proto_msg;
    bool proto_valid;
    bool consumed = false;

    /* Parse using the protocol parser with config limits */
    proto_valid = protocol_parse_client_message(message->data.buf, message->data.len,
                                                 &relay->config, &proto_msg, reject_reason, sizeof(reject_reason));

    /* Find connection ID */
    connection_session_t *session = connection_session_get_by_mg_connection(connection);
    connection_id_t conn_id = session ? connection_session_get_id(session) : 0;

    if (!proto_valid) {
        if (reject_reason[0]) {
            char *notice = protocol_serialize_notice(reject_reason);
            if (notice) {
                transport_send_json(connection, notice);
                protocol_free_string(notice);
            }
        }
        return;
    }

    /* Offer to message intercept capabilities (e.g. NIP-42 AUTH) */
    for (nip_capability_t *cap = relay->nip_registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_MESSAGE_INTERCEPT && cap->caps.message_intercept.on_message) {
            if (cap->caps.message_intercept.on_message(conn_id, &proto_msg, cap->ctx)) {
                consumed = true;
                break;
            }
        }
    }

    if (!consumed) {
        switch (proto_msg.command) {
            case PROTOCOL_CMD_REQ:
                handle_req(relay, connection, proto_msg.payload.req.subscription_id,
                           proto_msg.payload.req.filters, proto_msg.payload.req.filters_count, false);
                break;
            case PROTOCOL_CMD_COUNT:
                handle_req(relay, connection, proto_msg.payload.count.subscription_id,
                           proto_msg.payload.count.filters, proto_msg.payload.count.filters_count, true);
                break;
            case PROTOCOL_CMD_CLOSE:
                if (proto_msg.payload.close.subscription_id) {
                    remove_subscriptions(relay, connection, proto_msg.payload.close.subscription_id);
                }
                break;
            case PROTOCOL_CMD_EVENT:
                handle_event(relay, connection, &proto_msg.payload.event.event);
                break;
            case PROTOCOL_CMD_AUTH:
                /* AUTH was already offered to interceptors above (NIP-42 owns
                 * the challenge flow and answers OK itself). Reaching here
                 * means no capability consumed it: malformed AUTH or no AUTH
                 * provider in this module generation. */
                {
                    char *notice = protocol_serialize_notice("error: invalid auth");
                    if (notice) {
                        transport_send_json(connection, notice);
                        protocol_free_string(notice);
                    }
                }
                break;
            default:
                {
                    char *notice = protocol_serialize_notice("error: invalid request");
                    if (notice) {
                        transport_send_json(connection, notice);
                        protocol_free_string(notice);
                    }
                }
                break;
        }
    }

    protocol_message_free(&proto_msg);
}

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

static void log_message(relay_t *relay, struct mg_connection *connection, const char *fmt, ...) {
    if (!relay || !relay->debug_logging) return;
    log_timestamp();
    log_peer(connection);
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fputc('\n', stdout);
    fflush(stdout);
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
        fprintf(stderr, "NHR: candidate rejected; continuing current module\n");
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
        log_message(relay, NULL, "NHR: loaded new module generation");
    } else {
        fprintf(stderr, "NHR: candidate rejected; retrying published artifact\n");
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