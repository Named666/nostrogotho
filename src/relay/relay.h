#ifndef RELAY_H_
#define RELAY_H_

#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <mongoose.h>
#include "storage.h"
#include "nips/nip_capability.h"
#include "relay/config.h"
#include "nhr.h"
#include "subscriptions/subscription_manager.h"

/* ============================================================================
 * RELAY.H - Relay Runtime Context
 * 
 * The relay_t aggregates all runtime state and provides lifecycle management.
 * This replaces the global state scattered across server.c.
 * ============================================================================ */

struct relay {
    relay_config_t config;
    storage_context_t *storage;
    struct mg_mgr manager;
    volatile sig_atomic_t stop_requested;
    subscription_manager_t *subscriptions;
    nip_registry_t *nip_registry;
    int verbosity; /* log_verbosity_t snapshot from config at create */
    Nhr_Runtime *host_runtime;
    uintptr_t next_connection_id;
    char watched_module_path[1024];
    time_t watched_module_mtime;
    long watched_module_size;
    uint64_t watched_module_hash;
    bool watched_module_pending;
    time_t pending_module_mtime;
    long pending_module_size;
    uint64_t pending_module_hash;
};

typedef struct relay relay_t;

/* Create and initialize a new relay instance */
relay_t *relay_create(const relay_config_t *config, storage_context_t *storage);

/* NOTE: the event loop lives in transport/server.c (server_run /
 * server_run_hot). relay_t owns dispatch + state, never the loop. */

/* Stop the relay event loop */
void relay_stop(relay_t *relay);

/* Destroy and free relay instance */
void relay_destroy(relay_t *relay);

/* Schedule the maintenance timer from registered NIP maintenance
 * capabilities. Idempotent per event loop; the smallest requested interval
 * drives the timer and every tick runs ALL maintenance handlers. */
void relay_schedule_maintenance(relay_t *relay);

/* Handle new WebSocket connection */
void relay_on_connect(relay_t *relay, struct mg_connection *connection);

/* Handle WebSocket disconnection */
void relay_on_disconnect(relay_t *relay, struct mg_connection *connection);

/* Handle HTTP request (for NIP-11) */
bool relay_handle_http(relay_t *relay, struct mg_connection *connection, 
                       struct mg_http_message *request);

/* Initialize NHR (hot reload) runtime with the given module path */
bool relay_init_hot_reload(relay_t *relay, const char *module_path);

/* Arm the hot-reload watch timer. Must be called after the Mongoose manager
 * is initialized (arming earlier is wiped by mg_mgr_init). Transport calls
 * this from server_run_hot; no-op when hot reload is disabled. */
void relay_arm_hot_watch(relay_t *relay);

/* Send a JSON message to a connection by opaque ID. Relay-owned transport
 * bridge for NIP capabilities: NIP code never sees Mongoose. No-op when the
 * connection is unknown. Safe to call during capability dispatch. */
void relay_send_json(connection_id_t connection_id, const char *json);

/* Atomically re-point the host capability table at the active module
 * generation (clear + register). No-op without an active hot-reload module.
 * Called at startup (relay_init_hot_reload) and after every activation or
 * rollback so changed/added/removed NIPs take effect without restart.
 * Runs synchronously on the event-loop thread; no dispatch runs mid-swap. */
void relay_hot_swap_capabilities(relay_t *relay);

/* Mongoose event handler for transport layer */
void relay_event_handler(struct mg_connection *connection, int event, void *event_data);

#endif /* RELAY_H_ */