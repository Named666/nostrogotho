/* ngb_writer - the ONE SQLite writer thread and the WAL checkpointer.
 *
 * Workers hand prechecked EVENTs (signature verified, id claimed in the
 * dedupe in-flight set) to ngb_writer_publish, which never blocks: when the
 * queue holds writer_queue_max events it answers OK false itself. The
 * writer drains the queue in batches (up to NG_BATCH_MAX, default 4096, hard
 * cap 8192) inside one transaction per batch:
 *   1. duplicate guard layer 1: a second copy of an id inside the batch is
 *      answered "duplicate" and never reaches SQLite or fan-out;
 *   2. relay_core_commit_event per event (kind dispatch, storage writes;
 *      the UNIQUE index is the last guard);
 *   3. COMMIT (ROLLBACK and "error: storage commit failed" on failure);
 *   4. dedupe settle, OK to every publisher, and the newly stored events go
 *      to every worker for matching (ngb_workers_broadcast).
 * Plugin timers (relay_core_run_timers) also run on this thread.
 *
 * The checkpointer runs PASSIVE WAL checkpoints on its own connection every
 * NG_CKPT_MS (250 ms), so COMMIT never does checkpoint I/O.
 *
 * Ownership: ngb_writer_publish takes the bcast and the connection
 * reference the core took for it; both are released by the writer (or on
 * refusal, immediately).
 */
#ifndef NGB_WRITER_H_
#define NGB_WRITER_H_

#include <stdbool.h>
#include "relay_conn.h"

struct relay_bcast;

/* Start the writer and checkpoint threads. false if the writer could not
 * be created. queue_max: EVENTs waiting before publish refuses. */
bool ngb_writer_start(int queue_max);
/* Drain the queue, stop and join both threads (after the I/O loops stopped,
 * before the workers stop: the writer still hands broadcasts to them). */
void ngb_writer_stop(void);

/* relay_publish_fn: worker thread. */
void ngb_writer_publish(relay_conn_t *conn, struct relay_bcast *bcast);

/* EVENTs queued for the writer (any thread, relaxed). */
int ngb_writer_depth(void);
/* Publishes refused because the queue was full. */
unsigned long long ngb_writer_shed(void);

#endif /* NGB_WRITER_H_ */
