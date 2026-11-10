#include "relay_conn_internal.h"

#include <stdlib.h>
#include <string.h>

static ng_atomic_int next_slot;

void relay_conn_send(relay_conn_t *conn, const char *json, size_t len) {
    if (conn && json && !ng_atomic_load(&conn->closed)) conn->ops->send(conn, json, len);
}

void relay_conn_close(relay_conn_t *conn) {
    if (conn && !ng_atomic_load(&conn->closed)) conn->ops->close(conn);
}

uint64_t relay_conn_id(const relay_conn_t *conn) { return conn ? conn->id : 0; }
const char *relay_conn_peer(const relay_conn_t *conn) { return conn ? conn->peer : ""; }

int relay_conn_slot_alloc(void) {
    int s = ng_atomic_fetch_add(&next_slot, 1);
    if (s >= RELAY_CONN_MAX_SLOTS) abort();
    return s;
}

void *relay_conn_get_slot(const relay_conn_t *conn, int slot) {
    return conn && slot >= 0 && slot < RELAY_CONN_MAX_SLOTS ? conn->slots[slot] : NULL;
}

void relay_conn_set_slot(relay_conn_t *conn, int slot, void *value) {
    if (conn && slot >= 0 && slot < RELAY_CONN_MAX_SLOTS) conn->slots[slot] = value;
}

void relay_conn_retain(relay_conn_t *conn) { ng_atomic_fetch_add(&conn->refs, 1); }

void relay_conn_unref(relay_conn_t *conn) {
    if (conn && ng_atomic_fetch_sub(&conn->refs, 1) == 1) conn->ops->destroy(conn);
}

relay_body_t *relay_body_new(const char *json, size_t len) {
    relay_body_t *b = (relay_body_t *) malloc(sizeof(*b) + len + 1);
    if (!b) return NULL;
    ng_atomic_init(&b->refs, 1);
    b->len = len;
    memcpy(b->json, json, len); b->json[len] = '\0';
    return b;
}
void relay_body_retain(relay_body_t *b, int n) { ng_atomic_fetch_add_explicit(&b->refs, n, NG_MO_RELAXED); }
void relay_body_release_n(relay_body_t *b, int n) {
    if (b && ng_atomic_fetch_sub_explicit(&b->refs, n, NG_MO_ACQ_REL) == n) free(b);
}
void relay_body_release(relay_body_t *b) {
    if (b && ng_atomic_fetch_sub(&b->refs, 1) == 1) free(b);
}

void relay_conn_send_event(relay_conn_t *conn, const char *sub_json, size_t sub_len, relay_body_t *body) {
    if (!conn || ng_atomic_load(&conn->closed)) return;
    if (conn->ops->send_event) { conn->ops->send_event(conn, sub_json, sub_len, body); return; }
    size_t n = 9 + sub_len + 1 + body->len + 1;
    char *m = (char *) malloc(n + 1);
    if (!m) return;
    memcpy(m, "[\"EVENT\",", 9); memcpy(m + 9, sub_json, sub_len); m[9 + sub_len] = ',';
    memcpy(m + 10 + sub_len, body->json, body->len); m[n - 1] = ']'; m[n] = '\0';
    conn->ops->send(conn, m, n);
    free(m);
}
