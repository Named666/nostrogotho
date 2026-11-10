/* ngb_conn.h - the ngws backend's connection object, shared by the backend
 * modules (backend_ngws.c, ngb_outbox.c, ngb_workers.c, ngb_writer.c).
 * Not a public API: the relay core sees only relay_conn_t.
 *
 * Lifetime: allocated by the I/O loop in on_open with one reference held by
 * the socket; every queued job and writer entry holds another. The last
 * relay_conn_unref() calls ngb_destroy (ngb_outbox.c), which frees the
 * object on its own loop after every outbox record that may point at it
 * has run (see ngb_outbox.h).
 *
 * Field ownership:
 *   base     relay_conn_t; base.closed is the cross-thread "socket gone" flag.
 *   loop     immutable after on_open.
 *   ws       owning loop thread only; NULL once the socket closed.
 *   free_task  used once, by ngb_destroy.
 *   pending  messages queued to the worker and not yet handled (atomic).
 *   out_buffered  socket output backlog as last seen by its loop (atomic,
 *            relaxed: an admission hint, not a synchronization point).
 */
#ifndef NGB_CONN_H_
#define NGB_CONN_H_

#include <stdbool.h>
#include "ngws/ngws.h"
#include "platform/ng_atomic.h"
#include "relay_conn_internal.h"
#include "relay_core.h"

/* Reason sent with every load-shedding refusal. JSON-safe. */
#define NGB_OVERLOAD_MSG "error: relay overloaded, try again later"

typedef struct {
    relay_conn_t base;              /* must be first */
    ngws_loop_t *loop;
    ngws_socket_t *ws;
    ngws_task_t free_task;
    ng_atomic_int pending;
    ng_atomic_size out_buffered;
} ng_conn_t;

/* relay_conn_t* -> ng_conn_t* (base is the first member). */
static inline ng_conn_t *ngb_conn(relay_conn_t *rc) { return (ng_conn_t *) (void *) rc; }

/* Admission check shared by the core hook and batch pre-verification
 * (backend_ngws.c). Thread-safe, never blocks, no side effects.
 * false: *why is set to an "error: ..." reason. */
bool ngb_admit(relay_conn_t *rc, relay_admit_kind_t kind, const char **why);

#endif /* NGB_CONN_H_ */
