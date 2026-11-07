#ifndef RELAY_CONN_INTERNAL_H_
#define RELAY_CONN_INTERNAL_H_

#include <stdatomic.h>
#include "relay_conn.h"

/* Backend operations. One backend is linked per binary. */
typedef struct {
    void (*send)(relay_conn_t *conn, const char *json, size_t len);
    void (*close)(relay_conn_t *conn);
    void (*destroy)(relay_conn_t *conn);   /* last reference dropped */
} relay_backend_ops_t;

struct relay_conn {
    uint64_t id;
    const relay_backend_ops_t *ops;
    void *backend;            /* backend-specific (mg_connection*, us socket) */
    int shard;                /* worker / loop index owning protocol state */
    atomic_int refs;          /* backend ref + in-flight jobs */
    atomic_bool closed;
    void *slots[RELAY_CONN_MAX_SLOTS];
    char peer[64];
    void *core;               /* relay core per-connection state */
};

void relay_conn_retain(relay_conn_t *conn);
/* Drop a reference; calls ops->destroy on the last one. */
void relay_conn_unref(relay_conn_t *conn);

#endif
