#ifndef RELAY_CORE_H_
#define RELAY_CORE_H_

/* ============================================================================
 * relay_core - transport-agnostic Nostr protocol engine.
 *
 * Backends (backend_mongoose.c, backend_usockets.c) feed it connection
 * lifecycle + text messages through relay_conn_t handles. Protocol state is
 * sharded: each connection belongs to one shard (conn->shard) and all calls
 * for that connection, plus broadcast matching for its subscriptions, must
 * happen on the thread that owns the shard. The Mongoose backend uses a
 * single shard on its single thread.
 *
 * EVENT publishing has two halves so the writer can be a single thread:
 *   worker:  parse + precheck (sig verify) + plugin accept_publish
 *   writer:  relay_core_commit_event() (kind dispatch, storage writes)
 *   then:    OK to the publisher, and relay_core_broadcast_shard() on every
 *            shard's owner thread.
 * ============================================================================ */

#include <stdbool.h>
#include <time.h>
#include "nostrogotho.h"
#include "relay_conn.h"
#include "storage.h"
#include "nips/nip01.h"

#define RELAY_MAX_SHARDS 64

void relay_core_configure(storage_context_t *storage, const char *relay_url,
                          int min_pow, time_t lower_limit, time_t upper_limit);
void relay_core_set_debug(bool enabled);
bool relay_core_debug(void);

void relay_core_on_open(relay_conn_t *conn);
/* payload must be NUL-terminated at payload[len]; caller keeps ownership. */
void relay_core_on_message(relay_conn_t *conn, char *payload, size_t len);
void relay_core_on_close(relay_conn_t *conn);

/* NIP-11 document (from the first plugin providing one) or NULL. */
const char *relay_core_info_document(void);

/* Smallest plugin timer interval in ms (0 = none) and the tick itself.
 * The tick may write storage: run it on the writer thread. */
unsigned relay_core_timer_interval(void);
void relay_core_run_timers(void);

storage_context_t *relay_core_storage(void);

/* Asynchronous publish hook. When set, a prechecked EVENT is handed to it
 * (heap event_t, ownership transferred; conn already retained by the core
 * via relay_conn_retain — the hook's consumer must release it). When NULL
 * the core commits inline and broadcasts to shard 0. */
typedef void (*relay_publish_fn)(relay_conn_t *conn, event_t *event);
void relay_core_set_publisher(relay_publish_fn fn);

nip01_process_result_t relay_core_commit_event(relay_conn_t *conn, const event_t *event);
void relay_core_send_ok(relay_conn_t *conn, const event_t *event,
                        const nip01_process_result_t *result);
void relay_core_broadcast_shard(int shard, const event_t *event);

/* Free all subscriptions of every shard (shutdown). */
void relay_core_shutdown(void);

#endif
