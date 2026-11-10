/* ngb_outbox - see ngb_outbox.h. */
#include "ngb_outbox.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform/ng_alloc.h"
#include "platform/ng_platform.h"
#include "ng_config.h"
#include "ws_proto.h"

#define OUTBOX_FLUSH (256u * 1024)      /* post a loop's outbox once it holds this much */
#ifndef SMALL_EVENT_COPY
#define SMALL_EVENT_COPY 2048           /* event bodies up to this size are copied per subscriber */
#endif

/* Records: header + payload padded to 8 bytes, back to back in one task. */
enum { R_FRAME = 1, R_CLOSE, R_EVENT };
typedef struct {
    uint32_t kind, len;         /* len: bytes of data after this header */
    ng_conn_t *conn;
    relay_body_t *body;         /* R_EVENT */
} rec_t;

typedef struct {
    ngws_task_t task;
    size_t len;
    char data[];
} outtask_t;

typedef struct { outtask_t *t; size_t cap; relay_body_t *rbody; int rn; } outbox_t;

static ngws_server_t *srv;                          /* set once before connections exist */
static ng_atomic_size out_task_bytes;               /* posted, not yet run by a loop */
static NG_THREAD_LOCAL outbox_t tl_outbox[NG_MAX_IO_LOOPS];
static NG_THREAD_LOCAL uint64_t tl_outbox_dirty;    /* loops with a non-empty outbox */
static NG_THREAD_LOCAL relay_conn_t **tl_unref;
static NG_THREAD_LOCAL size_t tl_unref_n, tl_unref_cap;

NG_STATIC_ASSERT(NG_MAX_IO_LOOPS <= 64, dirty_mask_fits);

/* Test hook (see header): reservations left before one injected failure. */
static bool fault_armed;
static ng_atomic_size fault_left;

void ngb_outbox_set_server(ngws_server_t *s) {
    srv = s;
    const char *f = getenv("NG_FAULT_OUTBOX_OOM");
    if (f && *f) {
        ng_atomic_store(&fault_left, (size_t) strtoull(f, NULL, 10) + 1);
        fault_armed = true;
    }
}

static bool fault_fire(void) {      /* only when armed; wraps harmlessly after firing */
    return ng_atomic_fetch_sub_explicit(&fault_left, 1, NG_MO_RELAXED) == 1;
}
size_t ngb_outbox_pending_bytes(void) { return ng_atomic_load_explicit(&out_task_bytes, NG_MO_RELAXED); }

static size_t rec_size(uint32_t len) { return sizeof(rec_t) + (((size_t) len + 7) & ~(size_t) 7); }

/* --------------------------------------------------------- loop side ----- */
/* After the iteration's output is flushed: drop body references in runs
 * (one atomic per run of consecutive records sharing a body). */
static void outtask_free(void *p) {
    outtask_t *t = (outtask_t *) p;
    relay_body_t *run = NULL; int n = 0;
    for (size_t o = 0; o < t->len; ) {
        rec_t *r = (rec_t *) (void *) (t->data + o);
        if (r->kind == R_EVENT) {
            if (r->body != run) { if (run) relay_body_release_n(run, n); run = r->body; n = 0; }
            n++;
        }
        o += rec_size(r->len);
    }
    if (run) relay_body_release_n(run, n);
    free(t);
}

static void run_outtask(ngws_task_t *tk, ngws_loop_t *loop) {
    outtask_t *t = (outtask_t *) (void *) tk;
    size_t o = 0;
    while (o < t->len) {
        rec_t *r = (rec_t *) (void *) (t->data + o);
        char *d = (char *) (r + 1);
        ng_conn_t *c = r->conn;
        ngws_socket_t *ws = c->ws;
        if (ws && !ng_atomic_load_explicit(&c->base.closed, NG_MO_RELAXED)) {
            if (r->kind == R_FRAME) ngws_send_shared(ws, d, r->len);
            else if (r->kind == R_CLOSE) ngws_close(ws, 1000, NULL);
            else if (r->kind == R_EVENT) {
                /* d = frame header + ["EVENT",<sub>, ; then shared body, then ] */
                if (r->body->len <= SMALL_EVENT_COPY) {   /* one contiguous copy beats 3 iovecs */
                    ngws_send_raw3(ws, d, r->len, r->body->json, r->body->len, "]", 1);
                } else {
                    ngws_send_shared(ws, d, r->len);
                    ngws_send_shared(ws, r->body->json, r->body->len);
                    ngws_send_shared(ws, "]", 1);
                }
            }
            if (c->ws) {                    /* mirror for admission; write only on change (shared line) */
                size_t b = ngws_buffered(ws);
                if (ng_atomic_load_explicit(&c->out_buffered, NG_MO_RELAXED) != b)
                    ng_atomic_store_explicit(&c->out_buffered, b, NG_MO_RELAXED);
            }
        }
        o += rec_size(r->len);
    }
    ng_atomic_fetch_sub_explicit(&out_task_bytes, t->len, NG_MO_RELAXED);
    ngws_loop_defer(loop, outtask_free, t);   /* frames/bodies are referenced until flushed */
}

/* ---------------------------------------------------- producer side ----- */
static void outbox_commit_ref(outbox_t *ob) {
    if (ob->rbody) { relay_body_retain(ob->rbody, ob->rn); ob->rbody = NULL; ob->rn = 0; }
}

void ngb_outbox_commit_refs(void) {
    uint64_t m = tl_outbox_dirty;
    while (m) { int i = ng_ctz64(m); m &= m - 1; outbox_commit_ref(&tl_outbox[i]); }
}

static void outbox_flush_loop(int i) {
    outbox_t *ob = &tl_outbox[i];
    outbox_commit_ref(ob);
    if (!ob->t || !ob->t->len) return;
    outtask_t *t = ob->t;
    ob->t = NULL; ob->cap = 0;
    t->task.run = run_outtask;
    ng_atomic_fetch_add_explicit(&out_task_bytes, t->len, NG_MO_RELAXED);
    ngws_loop_post(ngws_server_loop(srv, i), &t->task);
}

static void outbox_flush(void) {
    uint64_t m = tl_outbox_dirty;
    tl_outbox_dirty = 0;
    while (m) { int i = ng_ctz64(m); m &= m - 1; outbox_flush_loop(i); }
}

/* Runs on c's loop: close the connection whose output could not be queued,
 * then drop the reference taken by conn_fail. */
static void conn_fail_task(ngws_task_t *t, ngws_loop_t *loop) {
    (void) loop;
    ng_conn_t *c = (ng_conn_t *) (void *) ((char *) t - offsetof(ng_conn_t, fail_task));
    if (c->ws) ngws_close(c->ws, 1011, "server out of memory");   /* terminates if it cannot queue */
    relay_conn_unref(&c->base);
}

/* A record for c could not be queued: mark c failed (its later records are
 * refused) and close it from its loop. Allocation-free; first caller wins. */
static void conn_fail(ng_conn_t *c) {
    if (ng_atomic_exchange(&c->failed, 1)) return;
    fprintf(stderr, "outbox: out of memory queueing output for connection %llu; closing it\n",
            (unsigned long long) c->base.id);
    relay_conn_retain(&c->base);
    c->fail_task.run = conn_fail_task;
    ngws_loop_post(c->loop, &c->fail_task);
}

/* Append a record of len payload bytes for c; returns the payload area, or
 * NULL when the record cannot be queued (c failed earlier, allocation
 * failure, size overflow) -- c is then closed by conn_fail. */
static char *outbox_reserve(ng_conn_t *c, uint32_t kind, size_t len, relay_body_t *body) {
    int li = ngws_loop_index(c->loop);
    outbox_t *ob = &tl_outbox[li];
    if (NG_UNLIKELY(ng_atomic_load_explicit(&c->failed, NG_MO_RELAXED))) return NULL;
    if (NG_UNLIKELY(fault_armed) && fault_fire()) goto fail;
    if (NG_UNLIKELY(len > (size_t) UINT32_MAX - 8)) goto fail;   /* rec_t.len is 32-bit */
    size_t need = rec_size((uint32_t) len);
    if (ob->t && ob->t->len + need > ob->cap) {
        if (ob->t->len >= OUTBOX_FLUSH) outbox_flush_loop(li);
        else {
            size_t want, nc, bytes;
            if (!ng_size_add(ob->t->len, need, &want)) goto fail;
            nc = ng_grow_cap(ob->cap, want, 16384);
            if (!ng_size_add(sizeof(outtask_t), nc, &bytes)) goto fail;
            outtask_t *nt = (outtask_t *) realloc(ob->t, bytes);
            if (!nt) goto fail;
            ob->t = nt; ob->cap = nc;
        }
    }
    if (!ob->t) {
        size_t cap = need > 16384 ? need : 16384;
        ob->t = (outtask_t *) ng_malloc_add(sizeof(outtask_t), cap);
        if (!ob->t) goto fail;
        ob->t->len = 0; ob->cap = cap;
    }
    rec_t *r = (rec_t *) (void *) (ob->t->data + ob->t->len);
    r->kind = kind; r->len = (uint32_t) len; r->conn = c; r->body = body;
    ob->t->len += need;
    tl_outbox_dirty |= 1ull << li;
    if (body) {
        if (ob->rbody != body) { outbox_commit_ref(ob); ob->rbody = body; }
        ob->rn++;
    }
    return (char *) (r + 1);
fail:
    conn_fail(c);
    return NULL;
}

/* ------------------------------------------------- relay_conn backend --- */
static void ngb_send(relay_conn_t *rc, const char *json, size_t len) {
    ng_conn_t *c = ngb_conn(rc);
    size_t fl = len + ngws_frame_overhead(len);
    char *d = outbox_reserve(c, R_FRAME, fl, NULL);
    if (d) ngws_frame_build(d, NGWS_OP_TEXT, json, len);
}

static void ngb_send_event(relay_conn_t *rc, const char *sub, size_t sl, relay_body_t *body) {
    ng_conn_t *c = ngb_conn(rc);
    size_t payload = 9 + sl + 1 + body->len + 1;     /* sl <= ~600 (escaped sub id), body < 5 MiB */
    size_t hl = ngws_frame_overhead(payload);
    char *d = outbox_reserve(c, R_EVENT, hl + 9 + sl + 1, body);   /* takes the body ref */
    if (!d) return;
    ws_frame_header((unsigned char *) d, NGWS_OP_TEXT, payload);
    memcpy(d + hl, "[\"EVENT\",", 9);
    memcpy(d + hl + 9, sub, sl);
    d[hl + 9 + sl] = ',';
}

static void ngb_close(relay_conn_t *rc) {
    (void) outbox_reserve(ngb_conn(rc), R_CLOSE, 0, NULL);
}

/* Last reference dropped: free on the connection's own loop (see header). */
static void conn_free_task(ngws_task_t *t, ngws_loop_t *loop) {
    (void) loop;
    free((char *) t - offsetof(ng_conn_t, free_task));
}
static void ngb_destroy(relay_conn_t *rc) {
    ng_conn_t *c = ngb_conn(rc);
    c->free_task.run = conn_free_task;
    ngws_loop_post(c->loop, &c->free_task);
}

const relay_backend_ops_t ngb_conn_ops = { ngb_send, ngb_close, ngb_destroy, ngb_send_event };

/* -------------------------------------------------------- deferred unref - */
void ngb_unref_later(relay_conn_t *rc) {
    if (tl_unref_n == tl_unref_cap) {
        size_t nc = tl_unref_cap ? tl_unref_cap * 2 : 1024;
        relay_conn_t **nv = (relay_conn_t **) ng_realloc_array(tl_unref, nc, sizeof(*nv));
        if (!nv) { outbox_flush(); relay_conn_unref(rc); return; }   /* flush first: still ordered */
        tl_unref = nv; tl_unref_cap = nc;
    }
    tl_unref[tl_unref_n++] = rc;
}

void ngb_outbox_flush_and_unref(void) {
    outbox_flush();
    for (size_t i = 0; i < tl_unref_n; i++) relay_conn_unref(tl_unref[i]);
    tl_unref_n = 0;
}

void ngb_outbox_thread_done(void) {
    ngb_outbox_flush_and_unref();
    free(tl_unref); tl_unref = NULL; tl_unref_cap = 0;
}
