/* ============================================================================
 * Mongoose backend (GPLv2/commercial; kept for comparison/compatibility).
 * Single thread, single shard: the relay core runs inline in the mongoose
 * event handler, writes happen synchronously on this thread.
 * ============================================================================ */
#include <mongoose.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "relay_conn_internal.h"
#include "relay_core.h"
#include "server.h"

static struct mg_mgr manager;
static volatile sig_atomic_t stop_requested;
static uint64_t next_id = 1;

static void mgb_send(relay_conn_t *conn, const char *json, size_t len) {
    struct mg_connection *c = (struct mg_connection *) conn->backend;
    if (c) mg_ws_send(c, json, len, WEBSOCKET_OP_TEXT);
}
static void mgb_close(relay_conn_t *conn) {
    struct mg_connection *c = (struct mg_connection *) conn->backend;
    if (c) c->is_draining = 1;
}
static void mgb_destroy(relay_conn_t *conn) { free(conn); }
static const relay_backend_ops_t mg_ops = { mgb_send, mgb_close, mgb_destroy };

static bool str_contains(struct mg_str h, const char *needle) {
    size_t n = strlen(needle);
    for (size_t i = 0; n <= h.len && i + n <= h.len; i++) if (memcmp(h.buf + i, needle, n) == 0) return true;
    return false;
}

static void handler(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = ev_data;
        struct mg_str *accept = mg_http_get_header(hm, "Accept");
        const char *doc = (accept && str_contains(*accept, "application/nostr+json")) ? relay_core_info_document() : NULL;
        if (doc) mg_http_reply(c, 200, "Content-Type: application/nostr+json\r\nAccess-Control-Allow-Origin: *\r\n", "%s", doc);
        else mg_ws_upgrade(c, hm, NULL);
    } else if (ev == MG_EV_WS_OPEN) {
        relay_conn_t *conn = calloc(1, sizeof(*conn));
        if (!conn) { c->is_closing = 1; return; }
        conn->id = next_id++;
        conn->ops = &mg_ops;
        conn->backend = c;
        conn->shard = 0;
        atomic_init(&conn->refs, 1);
        mg_snprintf(conn->peer, sizeof(conn->peer), "%M", mg_print_ip_port, &c->rem);
        c->fn_data = conn;
        relay_core_on_open(conn);
    } else if (ev == MG_EV_WS_MSG) {
        relay_conn_t *conn = c->fn_data;
        struct mg_ws_message *wm = ev_data;
        if (!conn) return;
        char *payload = malloc(wm->data.len + 1);
        if (!payload) return;
        memcpy(payload, wm->data.buf, wm->data.len);
        payload[wm->data.len] = '\0';
        relay_core_on_message(conn, payload, wm->data.len);
        free(payload);
    } else if (ev == MG_EV_CLOSE) {
        relay_conn_t *conn = c->fn_data;
        if (conn) {
            relay_core_on_close(conn);
            atomic_store(&conn->closed, true);
            conn->backend = NULL;
            c->fn_data = NULL;
            relay_conn_unref(conn);
        }
    }
}

static void timer_fn(void *arg) { (void) arg; relay_core_run_timers(); }

bool server_run(int port) {
    char url[64];
    if (!relay_core_storage() || port < 1 || port > 65535) return false;
    snprintf(url, sizeof(url), "ws://0.0.0.0:%d", port);
    stop_requested = 0;
    mg_mgr_init(&manager);
    if (!mg_http_listen(&manager, url, handler, NULL)) { mg_mgr_free(&manager); return false; }
    unsigned interval = relay_core_timer_interval();
    if (interval) mg_timer_add(&manager, interval, MG_TIMER_REPEAT | MG_TIMER_RUN_NOW, timer_fn, NULL);
    fprintf(stderr, "nostrogotho (mongoose backend) listening on :%d\n", port);
    while (!stop_requested) mg_mgr_poll(&manager, 1000);
    mg_mgr_free(&manager);
    relay_core_shutdown();
    return true;
}

void server_stop(void) { stop_requested = 1; }
