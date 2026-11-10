/* ngb_workers - the protocol worker threads of the ngws backend.
 *
 * Each connection is pinned to one worker (its shard, base.shard), which
 * owns the connection's protocol state and subscriptions: every
 * relay_core_on_open / on_message / on_close for it and every broadcast
 * match on that shard runs on that worker, in arrival order.
 *
 * Producers:
 *   I/O loops  ngb_queue_open / ngb_queue_message / ngb_queue_close batch
 *              jobs per worker during a loop iteration and hand them over
 *              with one lock + one signal at its end (loop thread only;
 *              per-loop state lives in a static table indexed by loop).
 *   writer     ngb_workers_broadcast posts one committed batch's events to
 *              every worker (one shared, refcounted set).
 * Each job holds one connection reference, released after the worker's
 * outbox is posted (ngb_unref_later).
 *
 * Budgets: ngb_worker_queued_bytes() is the inbound bytes queued or in
 * progress on a worker (relaxed), used by the loops' admission.
 * Errors: allocation failure on queueing returns false; the caller answers
 * the client itself (never a silent drop).
 */
#ifndef NGB_WORKERS_H_
#define NGB_WORKERS_H_

#include <stdbool.h>
#include <stddef.h>
#include "ngb_conn.h"

/* Start n (1..RELAY_MAX_SHARDS) workers. batch_verify enables batch
 * Schnorr pre-verification of EVENT bursts. Returns the number started. */
int ngb_workers_start(int n, bool batch_verify);
/* Wake every worker, let it finish queued jobs, join it. */
void ngb_workers_stop(void);
int ngb_workers_count(void);

/* --- I/O loop thread only ------------------------------------------------ */
/* Queue on_open for c (takes a connection reference on success). */
bool ngb_queue_open(ng_conn_t *c);
/* Queue a copy of msg[0..len) (NUL-terminated for the core). Takes a
 * reference and increments c->pending on success. */
bool ngb_queue_message(ng_conn_t *c, const char *msg, size_t len);
/* Queue on_close; inherits the socket's reference (released by the worker).
 * On allocation failure the reference is dropped here. */
void ngb_queue_close(ng_conn_t *c);

/* Inbound bytes queued + in progress on worker w (any thread, relaxed). */
size_t ngb_worker_queued_bytes(int w);
/* Bytes one queued message of len costs against that budget. */
size_t ngb_message_cost(size_t len);

/* --- writer thread ------------------------------------------------------ */
/* Hand n committed broadcasts to every worker; takes ownership of them and
 * of the array contents (the array itself stays the caller's). */
void ngb_workers_broadcast(relay_bcast_t *const *b, int n);

/* Signatures proven by batch verification so far (any thread). */
unsigned long long ngb_workers_preverified(void);

#endif /* NGB_WORKERS_H_ */
