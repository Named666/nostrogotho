#ifndef RELAY_CORE_H_
#define RELAY_CORE_H_

/* ============================================================================
 * relay_core - transport-agnostic Nostr protocol engine.
 *
 * The backend (backend_ngws.c) feeds it connection lifecycle + text messages
 * through relay_conn_t handles. Protocol state is sharded: each connection
 * belongs to one shard (conn->shard) and all calls for that connection, plus
 * broadcast matching for its subscriptions, must happen on the thread that
 * owns the shard.
 *
 * EVENT publishing has two halves so the writer can be a single thread:
 *   worker:  parse + precheck (sig verify) + plugin accept_publish
 *   writer:  relay_core_commit_event() (kind dispatch, storage writes)
 *   then:    OK to the publisher, and relay_core_broadcast_shard() on every
 *            shard's owner thread.
 *
 * Threading: configure / set_* / plugin registration happen single-threaded
 * before the backend starts; relay_core_shutdown after every thread
 * stopped. on_open/on_message/on_close/broadcast_shard: the shard's owner
 * thread only. commit_event / dedupe_settle / run_timers: the writer only.
 * relay_core_send_ok, relay_bcast_* and relay_tags_*: any thread.
 * Errors: protocol errors are answered to the client (NOTICE / CLOSED /
 * OK false) and never returned; allocation failures are answered as
 * "error: ..." the same way; nothing is dropped silently.
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
struct relay_bcast;
/* The worker pre-serializes the broadcast body and parses tags before
 * queueing (keeps that CPU off the single writer); ownership moves. */
typedef void (*relay_publish_fn)(relay_conn_t *conn, struct relay_bcast *bcast);
void relay_core_set_publisher(relay_publish_fn fn);

/* Admission control (load shedding), consulted before expensive work:
 * REQ/COUNT before the query, EVENT before signature verification. On
 * false the core answers CLOSED / OK false with *why ("error: ..."). */
typedef enum { RELAY_ADMIT_REQ, RELAY_ADMIT_EVENT } relay_admit_kind_t;
typedef bool (*relay_admit_fn)(relay_conn_t *conn, relay_admit_kind_t kind, const char **why);
void relay_core_set_admission(relay_admit_fn fn);
/* Max bytes of stored events one REQ may queue (0 = unlimited); results
 * past it are dropped, EOSE still follows. */
void relay_core_set_query_bytes_max(size_t n);

nip01_process_result_t relay_core_commit_event(relay_conn_t *conn, const event_t *event);
/* Writer: after a batch commits (or rolls back with r->accepted cleared),
 * move the event id from in-flight to known or release it. */
void relay_core_dedupe_settle(const event_t *event, const nip01_process_result_t *r);
void relay_core_send_ok(relay_conn_t *conn, const event_t *event,
                        const nip01_process_result_t *result);
/* Single-letter-or-longer tag (name, first value) pairs of an event, decoded
 * once and shared read-only by every shard during a broadcast. */
typedef struct { const char *name; size_t nlen; const char *val; size_t vlen; } relay_tagpair_t;
typedef struct { relay_tagpair_t *p; size_t n; char *store; } relay_tags_t;
/* false on allocation failure (out is then empty and needs no free). */
bool relay_tags_parse(const event_t *ev, relay_tags_t *out);
void relay_tags_free(relay_tags_t *t);

/* A committed event prepared for fan-out: serialized once (body), tags
 * decoded once. Immutable after creation; safe to read from all shards. */
typedef struct relay_bcast {
    event_t ev;
    relay_body_t *body;
    relay_tags_t tags;
} relay_bcast_t;
/* Consumes ev's heap fields in every case; NULL on allocation failure. */
relay_bcast_t *relay_bcast_new(event_t *ev);
void relay_bcast_free(relay_bcast_t *b);
void relay_core_broadcast_shard(int shard, const relay_bcast_t *b);

/* Relay-generated events (writer thread, inside the batch transaction).
 * relay_core_emit signs ev with the relay key, stores it (replacing an
 * older version of a replaceable / addressable one) and queues it for
 * fan-out once the batch commits. Consumes ev's heap fields in every case.
 * The writer calls relay_core_take_emits after a successful COMMIT and
 * relay_core_drop_emits after a failed one. */
bool relay_core_emit(event_t *ev);
size_t relay_core_take_emits(relay_bcast_t **out, size_t cap);
void relay_core_drop_emits(void);

/* Free all subscriptions of every shard (shutdown). */
void relay_core_shutdown(void);

#endif
