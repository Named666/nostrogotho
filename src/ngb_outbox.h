/* ngb_outbox - cross-thread output path of the ngws backend.
 *
 * Workers and the writer never touch sockets. relay_conn_send /
 * relay_conn_send_event / relay_conn_close on any thread append a record
 * to that thread's outbox for the connection's I/O loop (thread-local, one
 * buffer per loop, no locks). After each job batch the thread posts every
 * non-empty outbox to its loop as one ngws task, which writes the frames
 * (corked: one send() per socket per loop iteration).
 *
 * Event deliveries carry a reference to the shared relay_body_t instead of
 * a copy; consecutive records of one body take that reference with one
 * atomic add (ngb_outbox_commit_refs), and the loop drops them in runs
 * after the iteration's output is flushed.
 *
 * Connection lifetime rule (why records hold no connection reference): a
 * thread drops its connection references only after posting its outbox
 * (ngb_unref_later + ngb_outbox_flush_and_unref), loop task queues are FIFO,
 * and the final free is itself a task on the connection's loop. So the free
 * runs after every record that can still point at the connection.
 *
 * Thread-safety: every function except ngb_outbox_set_server and
 * ngb_outbox_pending_bytes acts on the calling thread's outbox only.
 * Errors: allocation failure drops the frame being queued (the connection
 * then misses that message; budgets in ngb_admit keep this rare).
 */
#ifndef NGB_OUTBOX_H_
#define NGB_OUTBOX_H_

#include <stddef.h>
#include "ngb_conn.h"

/* relay_conn_t backend operations (send, close, destroy, send_event). */
extern const relay_backend_ops_t ngb_conn_ops;

/* The server whose loops receive posted outboxes. Set once, before any
 * connection exists. */
void ngb_outbox_set_server(ngws_server_t *srv);

/* Bytes posted to loops and not yet written by them (any thread, relaxed). */
size_t ngb_outbox_pending_bytes(void);

/* Take the pending bulk body references now (call before the caller may
 * drop its own reference on a body it just delivered). */
void ngb_outbox_commit_refs(void);

/* Drop rc's reference after this thread's outbox is posted. */
void ngb_unref_later(relay_conn_t *rc);

/* Post every outbox of this thread, then drop the deferred references. */
void ngb_outbox_flush_and_unref(void);

/* Thread exit: flush and release this thread's outbox buffers. */
void ngb_outbox_thread_done(void);

#endif /* NGB_OUTBOX_H_ */
