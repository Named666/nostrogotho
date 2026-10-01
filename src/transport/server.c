#include <mongoose.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "relay/relay.h"
#include "transport/server.h"

/* ============================================================================
 * TRANSPORT/SERVER.C - Pure Mongoose transport adapter.
 *
 * Owns the event loop, listener socket, and raw frame sending. All protocol
 * decisions (parse/dispatch/policy/query) live in relay_t; module reload
 * watching lives in relay.c. 
 * ============================================================================ */

void transport_send_json(struct mg_connection *connection, const char *json) {
    if (connection && json) {
        mg_ws_send(connection, json, strlen(json), WEBSOCKET_OP_TEXT);
    }
}

bool server_run_hot(int port, relay_t *relay, const char *published_module_path) {
    if (!relay || !published_module_path || strlen(published_module_path) >=
        sizeof(relay->watched_module_path)) return false;

    /* Module reload watching is owned by relay_init_hot_reload; this function
     * only records the published path and runs the transport loop. */
    snprintf(relay->watched_module_path, sizeof(relay->watched_module_path), "%s",
             published_module_path);

    char listen_url[64];
    if (port < 1 || port > 65535) return false;
    snprintf(listen_url, sizeof(listen_url), "ws://0.0.0.0:%d", port);

    relay->stop_requested = 0;
    mg_mgr_init(&relay->manager);

    if (!mg_http_listen(&relay->manager, listen_url, relay_event_handler, relay)) {
        mg_mgr_free(&relay->manager);
        return false;
    }

    /* Relay-owned NIP maintenance shares this loop (same as monolithic). */
    relay_schedule_maintenance(relay);
    /* Arm the reload watcher now that the manager exists (arming earlier
     * would be wiped by mg_mgr_init above). No-op without hot reload. */
    relay_arm_hot_watch(relay);

    while (!relay->stop_requested) {
        mg_mgr_poll(&relay->manager, 250);
    }

    mg_mgr_free(&relay->manager);
    return true;
}

bool server_run(int port, relay_t *relay) {
    char listen_url[64];
    if (!relay || port < 1 || port > 65535) return false;
    snprintf(listen_url, sizeof(listen_url), "ws://0.0.0.0:%d", port);

    relay->stop_requested = 0;
    mg_mgr_init(&relay->manager);

    if (!mg_http_listen(&relay->manager, listen_url, relay_event_handler, relay)) {
        mg_mgr_free(&relay->manager);
        return false;
    }

    relay_schedule_maintenance(relay);

    while (!relay->stop_requested) {
        mg_mgr_poll(&relay->manager, 1000);
    }

    mg_mgr_free(&relay->manager);
    return true;
}

void server_stop(relay_t *relay) {
    if (relay) relay->stop_requested = 1;
}