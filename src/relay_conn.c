#include "relay_conn_internal.h"

#include <stdlib.h>

static atomic_int next_slot;

void relay_conn_send(relay_conn_t *conn, const char *json, size_t len) {
    if (conn && json && !atomic_load(&conn->closed)) conn->ops->send(conn, json, len);
}

void relay_conn_close(relay_conn_t *conn) {
    if (conn && !atomic_load(&conn->closed)) conn->ops->close(conn);
}

uint64_t relay_conn_id(const relay_conn_t *conn) { return conn ? conn->id : 0; }
const char *relay_conn_peer(const relay_conn_t *conn) { return conn ? conn->peer : ""; }

int relay_conn_slot_alloc(void) {
    int s = atomic_fetch_add(&next_slot, 1);
    if (s >= RELAY_CONN_MAX_SLOTS) abort();
    return s;
}

void *relay_conn_get_slot(const relay_conn_t *conn, int slot) {
    return conn && slot >= 0 && slot < RELAY_CONN_MAX_SLOTS ? conn->slots[slot] : NULL;
}

void relay_conn_set_slot(relay_conn_t *conn, int slot, void *value) {
    if (conn && slot >= 0 && slot < RELAY_CONN_MAX_SLOTS) conn->slots[slot] = value;
}

void relay_conn_retain(relay_conn_t *conn) { atomic_fetch_add(&conn->refs, 1); }

void relay_conn_unref(relay_conn_t *conn) {
    if (conn && atomic_fetch_sub(&conn->refs, 1) == 1) conn->ops->destroy(conn);
}
