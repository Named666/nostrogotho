#ifndef RELAY_CONN_H_
#define RELAY_CONN_H_

/* ============================================================================
 * relay_conn - transport-neutral connection handle.
 *
 * The relay core and every NIP plugin talk to clients only through this
 * opaque handle; the concrete backend (Mongoose or uSockets) lives behind it.
 *
 * Threading contract (uSockets backend):
 *   - A connection is pinned to one worker ("shard"). All protocol callbacks
 *     for that connection (on_connect/on_message/on_disconnect, delivery
 *     checks for its subscriptions) run on that worker, in order.
 *   - relay_conn_send()/relay_conn_close() are safe from any thread; frames
 *     are queued to the owning I/O loop.
 *   - The handle stays valid (refcounted) until the backend has delivered
 *     on_disconnect AND every in-flight job referencing it has finished.
 * ============================================================================ */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct relay_conn relay_conn_t;

#define RELAY_CONN_MAX_SLOTS 8

void relay_conn_send(relay_conn_t *conn, const char *json, size_t len);
void relay_conn_close(relay_conn_t *conn);
uint64_t relay_conn_id(const relay_conn_t *conn);
const char *relay_conn_peer(const relay_conn_t *conn);

/* Per-connection plugin storage (O(1), no global lists/locks). Allocate a
 * slot once at startup (plugin constructor/init), then get/set per conn. */
int relay_conn_slot_alloc(void);
void *relay_conn_get_slot(const relay_conn_t *conn, int slot);
void relay_conn_set_slot(relay_conn_t *conn, int slot, void *value);

#endif /* RELAY_CONN_H_ */
