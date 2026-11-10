/* ============================================================================
 * Relay transport: ngws (uSockets + in-tree RFC 6455, pure C, no TLS: put
 * nginx/haproxy in front for wss://).
 *
 * Thread layout
 *   I/O loops  (io_threads / NG_IO_THREADS, default: usable CPUs): ngws loops on
 *              one port via SO_REUSEPORT. TCP, HTTP upgrade, NIP-11, framing,
 *              corked writev output. No protocol logic.
 *   Workers    (workers / NG_WORKERS, default: usable CPUs): each connection is pinned to one
 *              worker (id % W) which owns its protocol state and its
 *              subscriptions (one relay_core shard + subscription index),
 *              parses JSON, verifies signatures, runs REQ queries on its own
 *              read-only SQLite connection and matches broadcasts.
 *   Writer     exactly ONE thread owning the only read-write SQLite
 *              connection. Prechecked EVENTs are committed in batches
 *              (BEGIN IMMEDIATE..COMMIT, ROLLBACK on failure), then OK is sent
 *              and each accepted event is serialized ONCE (relay_bcast_t) and
 *              handed to every worker for matching. Plugin timers run here.
 *
 * Cross-thread traffic is batched in both directions:
 *   loop -> worker: messages are queued per worker during a loop iteration and
 *                   pushed with one lock + one signal at the end of it.
 *   worker/writer -> loop: sends go to a thread-local outbox per loop, posted
 *                   as one ngws task after each job batch. Event deliveries
 *                   carry a reference to the shared body and are written with
 *                   writev (frame prefix | shared body | "]"), zero copy
 *                   (bodies <= 2 KiB are copied into one contiguous frame).
 *                   Records hold no per-delivery connection reference and
 *                   body references are taken/dropped once per run of
 *                   records (see ngb_destroy, outbox_commit_ref); a socket's
 *                   frames from one loop iteration go out in one send().
 * ============================================================================ */
#include "platform/ng_platform.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include "platform/ng_atomic.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <stdint.h>
#include "crypto.h"
#include "ngws/ngws.h"
#include "nips/nip_plugin.h"
#include "dedupe.h"
#include "json_lite.h"
#include "relay_conn_internal.h"
#include "relay_core.h"
#include "server.h"
#include "ws_proto.h"

#define MAX_WS_MESSAGE   (5u * 1024 * 1024)
#define MAX_IO_LOOPS     64
#define WRITER_BATCH     8192   /* hard cap; NG_BATCH_MAX tunes below it */
#define OUTBOX_FLUSH     (256u * 1024)
/* Default I/O loop count for n usable CPUs (io_threads = auto): one per CPU.
 * Fan-out is kernel-send bound on the loops (loopback: ~90% system time), so
 * they must scale with cores; idle loops cost nothing. On 4 CPUs, 4 loops vs
 * the previous nproc/4 halved fan-out p50 latency (SCALING.md). */
#ifndef IO_THREADS_AUTO
#define IO_THREADS_AUTO(n) ((int) (n))
#endif

/* ---------------------------------------------------------------- types -- */
typedef struct {
    relay_conn_t base;          /* must be first */
    ngws_loop_t *loop;
    ngws_socket_t *ws;          /* loop thread only; NULL once closed */
    ngws_task_t free_task;      /* final free runs on the owning loop (see ngb_destroy) */
    ng_atomic_int pending;         /* messages queued to the worker, not yet handled */
    ng_atomic_size out_buffered; /* socket output backlog as last seen by its loop */
} ng_conn_t;

/* ------------------------------------------------------- runtime options --
 * Set from nostrogotho.conf (server_config_set) before server_run(). The
 * NG_IO_THREADS / NG_WORKERS environment variables still override the thread
 * counts (benchmark scripts). Byte values accept K/M/G (binary) suffixes. */
static struct {
    int io_threads, workers;            /* 0 = auto */
    size_t conn_out_max;                /* per-connection output backlog, then close */
    size_t total_out_max;               /* process-wide output budget */
    size_t worker_queue_max;            /* queued inbound bytes per worker */
    int writer_queue_max;               /* EVENTs waiting for the writer */
    int conn_pending_max;               /* queued messages per connection */
    int listen_backlog;                 /* 0 = net.core.somaxconn */
} opt = { 0, 0, 4u << 20, 1u << 30, 16u << 20, 65536, 1024, 0 };

enum { J_OPEN, J_MSG, J_CLOSE, J_BSET };
typedef struct job {
    struct job *next;
    int type;
    ng_conn_t *conn;
    relay_bcast_t *bc;
    struct bset *bset;
    size_t len;
    char payload[];             /* J_MSG: NUL-terminated message */
} job_t;

/* One committed batch's broadcasts, shared by every worker (one job per
 * worker per batch); the last worker to finish frees it. */
typedef struct bset { ng_atomic_int refs; int n; relay_bcast_t *b[]; } bset_t;

typedef struct {
    int idx;
    pthread_t th;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    job_t *head, *tail;
    NG_ALIGNED(64) ng_atomic_size qbytes;  /* queued + in-progress inbound bytes (budget) */
} worker_t;

typedef struct wjob {
    struct wjob *next;
    ng_conn_t *conn;
    relay_bcast_t *bc;
} wjob_t;

/* per-loop pending jobs for each worker, flushed at end of iteration */
typedef struct {
    job_t *head[64], *tail[64];
    uint64_t pending_mask;
    bool flush_scheduled;
} loop_ctx_t;

/* outbox records (thread-local, one buffer per loop) */
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

/* Per-thread outbox for one loop. Body references for R_EVENT records are
 * taken in bulk: consecutive records of one body (a broadcast walks all of a
 * shard's subscribers for one event) cost one atomic add, not one each. */
typedef struct { outtask_t *t; size_t cap; relay_body_t *rbody; int rn; } outbox_t;

#ifndef SMALL_EVENT_COPY
#define SMALL_EVENT_COPY 2048   /* event bodies up to this size are copied per subscriber */
#endif

/* ---------------------------------------------------------------- state -- */
static ngws_server_t *srv;
static int n_loops;
static worker_t workers[RELAY_MAX_SHARDS];
static int n_workers;
static bool batch_verify = true;        /* NG_BATCH_VERIFY=0 disables (A/B benchmarks) */
static ng_atomic_ullong next_conn_id = { 1 };
static ng_atomic_bool stopping;
static char *info_doc;
static size_t info_doc_len;
static ng_atomic_llong stat_open_conns;
static ng_atomic_size out_task_bytes;    /* posted outbox bytes not yet run by a loop */
static ng_atomic_ullong stat_shed_loop, stat_shed_core, stat_shed_writer, stat_preverified;
static ng_atomic_int writer_depth;          /* EVENTs queued for the writer */

static pthread_t writer_th;
static pthread_mutex_t writer_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t writer_cv = PTHREAD_COND_INITIALIZER;
static wjob_t *writer_head, *writer_tail;

static NG_THREAD_LOCAL outbox_t tl_outbox[MAX_IO_LOOPS];
static NG_THREAD_LOCAL uint64_t tl_outbox_dirty;

/* --------------------------------------------------------- loop side ----- */
static void run_outtask(ngws_task_t *t, ngws_loop_t *loop);

/* After the iteration's output is flushed: drop body references in runs
 * (one atomic per run of consecutive records sharing a body). */
static void outtask_free(void *p) {
    outtask_t *t = (outtask_t *) p;
    relay_body_t *run = NULL; int n = 0;
    for (size_t o = 0; o < t->len; ) {
        rec_t *r = (rec_t *) (t->data + o);
        if (r->kind == R_EVENT) {
            if (r->body != run) { if (run) relay_body_release_n(run, n); run = r->body; n = 0; }
            n++;
        }
        o += sizeof(rec_t) + ((r->len + 7) & ~(size_t) 7);
    }
    if (run) relay_body_release_n(run, n);
    free(t);
}

static void run_outtask(ngws_task_t *tk, ngws_loop_t *loop) {
    outtask_t *t = (outtask_t *) tk;
    size_t o = 0;
    while (o < t->len) {
        rec_t *r = (rec_t *) (t->data + o);
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
        /* No per-record connection reference: a connection is only freed by
         * a task on this loop, posted after every thread that could still
         * hold a record for it has flushed its outbox (see ngb_destroy). */
        o += sizeof(rec_t) + ((r->len + 7) & ~(size_t) 7);
    }
    ng_atomic_fetch_sub_explicit(&out_task_bytes, t->len, NG_MO_RELAXED);
    ngws_loop_defer(loop, outtask_free, t);   /* frames/bodies are referenced until flushed */
}

/* ---------------------------------------------------------- outbox ------- */
static void outbox_commit_ref(outbox_t *ob) {
    if (ob->rbody) { relay_body_retain(ob->rbody, ob->rn); ob->rbody = NULL; ob->rn = 0; }
}
/* Take pending bulk body references now (before the caller may drop its own). */
static void outbox_commit_refs(void) {
    uint64_t m = tl_outbox_dirty;
    while (m) { int i = __builtin_ctzll(m); m &= m - 1; outbox_commit_ref(&tl_outbox[i]); }
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
    while (m) { int i = __builtin_ctzll(m); m &= m - 1; outbox_flush_loop(i); }
}

static char *outbox_reserve(ng_conn_t *c, uint32_t kind, size_t len, relay_body_t *body) {
    int li = ngws_loop_index(c->loop);
    outbox_t *ob = &tl_outbox[li];
    size_t need = sizeof(rec_t) + ((len + 7) & ~(size_t) 7);
    if (ob->t && ob->t->len + need > ob->cap) {
        if (ob->t->len >= OUTBOX_FLUSH) outbox_flush_loop(li);
        else {
            size_t nc = ob->cap * 2; while (nc < ob->t->len + need) nc *= 2;
            outtask_t *nt = (outtask_t *) realloc(ob->t, sizeof(outtask_t) + nc);
            if (!nt) return NULL;
            ob->t = nt; ob->cap = nc;
        }
    }
    if (!ob->t) {
        size_t cap = need > 16384 ? need : 16384;
        ob->t = (outtask_t *) malloc(sizeof(outtask_t) + cap);
        if (!ob->t) return NULL;
        ob->t->len = 0; ob->cap = cap;
    }
    rec_t *r = (rec_t *) (ob->t->data + ob->t->len);
    r->kind = kind; r->len = (uint32_t) len; r->conn = c; r->body = body;
    ob->t->len += need;
    tl_outbox_dirty |= 1ull << li;
    if (body) {
        if (ob->rbody != body) { outbox_commit_ref(ob); ob->rbody = body; }
        ob->rn++;
    }
    return (char *) (r + 1);
}

static void ngb_send(relay_conn_t *rc, const char *json, size_t len) {
    ng_conn_t *c = (ng_conn_t *) rc;
    size_t fl = len + ngws_frame_overhead(len);
    char *d = outbox_reserve(c, R_FRAME, fl, NULL);
    if (d) ngws_frame_build(d, NGWS_OP_TEXT, json, len);
}

static void ngb_send_event(relay_conn_t *rc, const char *sub, size_t sl, relay_body_t *body) {
    ng_conn_t *c = (ng_conn_t *) rc;
    size_t payload = 9 + sl + 1 + body->len + 1;
    size_t hl = ngws_frame_overhead(payload);
    char *d = outbox_reserve(c, R_EVENT, hl + 9 + sl + 1, body);   /* takes the body ref */
    if (!d) return;
    ws_frame_header((unsigned char *) d, NGWS_OP_TEXT, payload);
    memcpy(d + hl, "[\"EVENT\",", 9);
    memcpy(d + hl + 9, sub, sl);
    d[hl + 9 + sl] = ',';
}

static void ngb_close(relay_conn_t *rc) {
    (void) outbox_reserve((ng_conn_t *) rc, R_CLOSE, 0, NULL);
}

/* Last reference dropped. Every thread drops its connection references only
 * after posting its outbox (see unref_later), and loop task queues are FIFO,
 * so freeing from a task on the connection's own loop runs after every
 * record that still points at it. */
static void conn_free_task(ngws_task_t *t, ngws_loop_t *loop) {
    (void) loop;
    free((char *) t - offsetof(ng_conn_t, free_task));
}
static void ngb_destroy(relay_conn_t *rc) {
    ng_conn_t *c = (ng_conn_t *) rc;
    c->free_task.run = conn_free_task;
    ngws_loop_post(c->loop, &c->free_task);
}

/* Deferred unref: workers/writer release connection references only after
 * flushing their outbox (required by ngb_destroy's ordering argument). */
static NG_THREAD_LOCAL relay_conn_t **tl_unref; static NG_THREAD_LOCAL size_t tl_unref_n, tl_unref_cap;
static void unref_later(relay_conn_t *rc) {
    if (tl_unref_n == tl_unref_cap) {
        size_t nc = tl_unref_cap ? tl_unref_cap * 2 : 1024;
        relay_conn_t **nv = (relay_conn_t **) realloc(tl_unref, nc * sizeof(*nv));
        if (!nv) { outbox_flush(); relay_conn_unref(rc); return; }   /* flush first: still ordered */
        tl_unref = nv; tl_unref_cap = nc;
    }
    tl_unref[tl_unref_n++] = rc;
}
/* Flush the outbox, then drop the deferred references. */
static void outbox_flush_and_unref(void) {
    outbox_flush();
    for (size_t i = 0; i < tl_unref_n; i++) relay_conn_unref(tl_unref[i]);
    tl_unref_n = 0;
}
/* Thread exit: flush, then release the deferred-unref buffer itself. */
static void outbox_thread_done(void) {
    outbox_flush_and_unref();
    free(tl_unref); tl_unref = NULL; tl_unref_cap = 0;
}
static const relay_backend_ops_t ng_ops = { ngb_send, ngb_close, ngb_destroy, ngb_send_event };

/* -------------------------------------------------------- worker queue --- */
static void worker_push_list(int w, job_t *h, job_t *t) {
    worker_t *wk = &workers[w];
    pthread_mutex_lock(&wk->mu);
    bool was_empty = wk->head == NULL;
    if (wk->tail) wk->tail->next = h; else wk->head = h;
    wk->tail = t;
    pthread_mutex_unlock(&wk->mu);
    if (was_empty) pthread_cond_signal(&wk->cv);
}
static void worker_push(int w, job_t *j) { j->next = NULL; worker_push_list(w, j, j); }

static void loop_flush_jobs(void *arg) {
    loop_ctx_t *lc = (loop_ctx_t *) arg;
    uint64_t m = lc->pending_mask;
    lc->pending_mask = 0; lc->flush_scheduled = false;
    while (m) {
        int w = __builtin_ctzll(m); m &= m - 1;
        worker_push_list(w, lc->head[w], lc->tail[w]);
        lc->head[w] = lc->tail[w] = NULL;
    }
}

static size_t job_cost(const job_t *j) { return sizeof(job_t) + (j->type == J_MSG ? j->len + 1 : 0); }

/* queue from a loop thread; delivered at the end of the iteration */
static void loop_queue_job(ngws_loop_t *loop, int w, job_t *j) {
    loop_ctx_t *lc = (loop_ctx_t *) ngws_loop_get_user(loop);
    ng_atomic_fetch_add_explicit(&workers[w].qbytes, job_cost(j), NG_MO_RELAXED);
    j->next = NULL;
    if (lc->tail[w]) lc->tail[w]->next = j; else lc->head[w] = j;
    lc->tail[w] = j;
    lc->pending_mask |= 1ull << w;
    if (!lc->flush_scheduled) { lc->flush_scheduled = true; ngws_loop_defer(loop, loop_flush_jobs, lc); }
}

/* ----------------------------------------------------- ngws callbacks ---- */
static void on_loop_start(ngws_loop_t *loop) { ngws_loop_set_user(loop, calloc(1, sizeof(loop_ctx_t))); }
static void on_loop_stop(ngws_loop_t *loop) { free(ngws_loop_get_user(loop)); ngws_loop_set_user(loop, NULL); }

static void on_http(ngws_socket_t *s, const ngws_http_req_t *req) {
    static const char cors[] = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: *\r\n"
                               "Access-Control-Allow-Methods: GET, OPTIONS\r\n";
    if (req->method_len == 7 && memcmp(req->method, "OPTIONS", 7) == 0) { ngws_http_respond(s, "204 No Content", cors, NULL, "", 0); return; }
    if (!(req->method_len == 3 && memcmp(req->method, "GET", 3) == 0)) { ngws_http_respond(s, "405 Method Not Allowed", cors, NULL, "", 0); return; }
    const char *h = req->headers, *e = h + req->headers_len;
    bool nostr_json = false;
    while (h < e) {
        const char *eol = memchr(h, '\n', (size_t) (e - h)); if (!eol) eol = e;
        if ((size_t) (eol - h) > 7 && strncasecmp(h, "Accept:", 7) == 0) {
            for (const char *p = h; p + 22 <= eol; p++) if (strncasecmp(p, "application/nostr+json", 22) == 0) { nostr_json = true; break; }
        }
        h = eol + 1;
    }
    if (nostr_json && info_doc) ngws_http_respond(s, "200 OK", cors, "application/nostr+json", info_doc, info_doc_len);
    else {
        static const char msg[] = "nostrogotho relay: connect with a Nostr client (WebSocket)\n";
        ngws_http_respond(s, "200 OK", cors, "text/plain", msg, sizeof(msg) - 1);
    }
}

static job_t *job_new(int type, ng_conn_t *c, size_t extra) {
    job_t *j = (job_t *) malloc(sizeof(*j) + extra);
    if (j) { memset(j, 0, sizeof(*j)); j->type = type; j->conn = c; }
    return j;
}

static void on_open(ngws_socket_t *ws, const ngws_http_req_t *req) {
    (void) req;
    ng_conn_t *c = (ng_conn_t *) calloc(1, sizeof(*c));
    if (!c) { ngws_terminate(ws); return; }
    c->base.id = ng_atomic_fetch_add(&next_conn_id, 1);
    c->base.ops = &ng_ops;
    c->base.backend = c;
    c->base.shard = (int) (c->base.id % (uint64_t) n_workers);
    ng_atomic_init(&c->base.refs, 1);            /* held by the socket */
    c->loop = ngws_socket_loop(ws);
    c->ws = ws;
    ngws_remote_address(ws, c->base.peer, sizeof(c->base.peer));
    *(ng_conn_t **) ngws_user(ws) = c;
    ng_atomic_fetch_add(&stat_open_conns, 1);
    job_t *j = job_new(J_OPEN, c, 0);
    if (j) { relay_conn_retain(&c->base); loop_queue_job(c->loop, c->base.shard, j); }
}

/* ------------------------------------------------------ load shedding ---
 * Inline rejection on the I/O thread when a message cannot be queued (worker
 * budget or per-connection pending limit). Never blocks, never parses more
 * than the first two array elements: EVENT -> ["OK",<id>,false,msg],
 * REQ/COUNT -> ["CLOSED",<sub>,msg], anything else -> NOTICE. */
static const char overload_msg[] = "error: relay overloaded, try again later";

static void shed_inline(ngws_socket_t *ws, const char *data, size_t len) {
    ng_atomic_fetch_add_explicit(&stat_shed_loop, 1, NG_MO_RELAXED);
    while (len && (*data == ' ' || *data == '\t' || *data == '\r' || *data == '\n')) { data++; len--; }
    jstr_t arr = jl_str_n(data, len), k, v0, v1;
    char out[320];
    int n = 0;
    size_t o = jl_next(arr, 0, &k, &v0);
    if (o && jl_next(arr, o, &k, &v1)) {
        if (jl_tok_eq(v0, "EVENT") && v1.buf[0] == '{') {
            jstr_t kk, vv; size_t q = 0;
            while ((q = jl_next(v1, q, &kk, &vv)) != 0) {
                if (kk.len == 4 && memcmp(kk.buf, "\"id\"", 4) == 0) {
                    bool hex = vv.len == 66 && vv.buf[0] == '"' && vv.buf[65] == '"';
                    for (size_t i = 1; hex && i < 65; i++) hex = (vv.buf[i] >= '0' && vv.buf[i] <= '9') || (vv.buf[i] >= 'a' && vv.buf[i] <= 'f');
                    if (hex) n = snprintf(out, sizeof(out), "[\"OK\",%.*s,false,\"%s\"]", 66, vv.buf, overload_msg);
                    break;
                }
            }
        } else if ((jl_tok_eq(v0, "REQ") || jl_tok_eq(v0, "COUNT")) && v1.buf[0] == '"' && v1.len <= 2 + 200) {
            bool clean = true;   /* echo the raw sub-id token only if it is plain */
            for (size_t i = 1; clean && i + 1 < v1.len; i++) clean = (unsigned char) v1.buf[i] >= 0x20 && v1.buf[i] != '"' && v1.buf[i] != '\\';
            if (clean) n = snprintf(out, sizeof(out), "[\"CLOSED\",%.*s,\"%s\"]", (int) v1.len, v1.buf, overload_msg);
        }
    }
    if (n <= 0 || (size_t) n >= sizeof(out)) n = snprintf(out, sizeof(out), "[\"NOTICE\",\"%s\"]", overload_msg);
    ngws_send(ws, out, (size_t) n, NGWS_OP_TEXT);
}

/* Worker-side admission (relay_core hook), checked before any expensive
 * work: signature verification for EVENT, the query for REQ/COUNT. */
static bool admit_quiet(relay_conn_t *rc, relay_admit_kind_t kind, const char **why) {
    ng_conn_t *c = (ng_conn_t *) rc;
    size_t total = ng_atomic_load_explicit(&out_task_bytes, NG_MO_RELAXED) + (srv ? ngws_server_backlog_bytes(srv) : 0);
    bool ok = total < opt.total_out_max / 10 * 9;   /* 90%: shedding (75%, ngws) did not keep up */
    if (ok && ng_atomic_load_explicit(&c->out_buffered, NG_MO_RELAXED) > opt.conn_out_max / 2) {
        ok = false; *why = "error: output backlog too large, read faster";   /* slow reader */
    } else if (!ok) *why = overload_msg;
    if (ok && kind == RELAY_ADMIT_EVENT && ng_atomic_load_explicit(&writer_depth, NG_MO_RELAXED) >= opt.writer_queue_max) {
        ok = false; *why = overload_msg;
    }
    return ok;
}
static bool core_admit(relay_conn_t *rc, relay_admit_kind_t kind, const char **why) {
    bool ok = admit_quiet(rc, kind, why);
    if (!ok) ng_atomic_fetch_add_explicit(&stat_shed_core, 1, NG_MO_RELAXED);
    return ok;
}

static void on_drain(ngws_socket_t *ws) {
    ng_conn_t *c = *(ng_conn_t **) ngws_user(ws);
    if (c) ng_atomic_store_explicit(&c->out_buffered, ngws_buffered(ws), NG_MO_RELAXED);
}

static void on_message(ngws_socket_t *ws, char *data, size_t len, int op) {
    (void) op;
    ng_conn_t *c = *(ng_conn_t **) ngws_user(ws);
    if (!c) return;
    worker_t *wk = &workers[c->base.shard];
    if (ng_atomic_load_explicit(&c->pending, NG_MO_RELAXED) >= opt.conn_pending_max ||
        ng_atomic_load_explicit(&wk->qbytes, NG_MO_RELAXED) + sizeof(job_t) + len + 1 > opt.worker_queue_max) {
        shed_inline(ws, data, len);
        return;
    }
    ng_atomic_fetch_add_explicit(&c->pending, 1, NG_MO_RELAXED);
    job_t *j = job_new(J_MSG, c, len + 1);
    if (!j) { ng_atomic_fetch_sub(&c->pending, 1); return; }
    memcpy(j->payload, data, len); j->payload[len] = '\0'; j->len = len;
    relay_conn_retain(&c->base);
    loop_queue_job(c->loop, c->base.shard, j);
}

static void on_close(ngws_socket_t *ws, int code) {
    (void) code;
    ng_conn_t *c = *(ng_conn_t **) ngws_user(ws);
    if (!c) return;
    *(ng_conn_t **) ngws_user(ws) = NULL;
    c->ws = NULL;
    ng_atomic_store(&c->base.closed, true);
    ng_atomic_fetch_sub(&stat_open_conns, 1);
    job_t *j = job_new(J_CLOSE, c, 0);       /* inherits the socket's ref */
    if (j) loop_queue_job(c->loop, c->base.shard, j);
    else relay_conn_unref(&c->base);
}

/* -------------------------------------------------------------- workers -- */
/* Batch signature pre-verification for one job list (worker thread).
 * Pipelined publishers and many connections per shard deliver several EVENTs
 * per wakeup; their (sig, pubkey, claimed id) triples are verified together
 * (crypto_batch_verify, shared multi-scalar multiplication). The normal
 * per-message path then runs unchanged: it recomputes the id from the
 * serialization and calls signature_verify, which skips curve work only for
 * byte-identical triples proven here. Messages the admission check would
 * reject are skipped, so overload does not buy extra crypto. */
#define PREVERIFY_MAX 1024
static bool hex_field(jstr_t v, size_t nbytes, uint8_t *out) {
    size_t got;
    return v.len == 2 * nbytes + 2 && v.buf[0] == '"' && hex_to_bytes(v.buf + 1, 2 * nbytes, out, nbytes, &got) && got == nbytes;
}
typedef struct { uint8_t sig[64], pk[32], id[32]; } pv_item_t;
static NG_THREAD_LOCAL pv_item_t *pv;
static NG_THREAD_LOCAL const uint8_t **ps, **pm, **pp;
static void preverify_free(void) { free(pv); free(ps); free(pm); free(pp); pv = NULL; ps = pm = pp = NULL; }
static void preverify_events(job_t *j) {
    size_t n = 0;
    for (; j && n < PREVERIFY_MAX; j = j->next) {
        if (j->type != J_MSG || j->len < 16 || ng_atomic_load_explicit(&j->conn->base.closed, NG_MO_RELAXED)) continue;
        const char *d = j->payload; size_t len = j->len;
        while (len && (*d == ' ' || *d == '\t' || *d == '\r' || *d == '\n')) { d++; len--; }
        if (len < 10 || memcmp(d, "[\"EVENT\"", 8) != 0) continue;
        jstr_t arr = jl_str_n(d, len), k, v0, ev;
        size_t o = jl_next(arr, 0, &k, &v0);
        if (!o || !jl_next(arr, o, &k, &ev) || ev.buf[0] != '{') continue;
        if (!pv) {
            pv = malloc(PREVERIFY_MAX * sizeof(*pv));
            ps = malloc(PREVERIFY_MAX * sizeof(*ps)); pm = malloc(PREVERIFY_MAX * sizeof(*pm)); pp = malloc(PREVERIFY_MAX * sizeof(*pp));
            if (!pv || !ps || !pm || !pp) { preverify_free(); return; }   /* all or nothing; plain verify still runs */
        }
        int have = 0; jstr_t kk, vv; size_t q = 0;
        while (have != 7 && (q = jl_next(ev, q, &kk, &vv)) != 0) {
            if (kk.len == 4 && memcmp(kk.buf, "\"id\"", 4) == 0) have |= hex_field(vv, 32, pv[n].id) ? 1 : 0;
            else if (kk.len == 8 && memcmp(kk.buf, "\"pubkey\"", 8) == 0) have |= hex_field(vv, 32, pv[n].pk) ? 2 : 0;
            else if (kk.len == 5 && memcmp(kk.buf, "\"sig\"", 5) == 0) have |= hex_field(vv, 64, pv[n].sig) ? 4 : 0;
        }
        if (have != 7) continue;
        const char *why;
        if (!admit_quiet(&j->conn->base, RELAY_ADMIT_EVENT, &why)) continue;
        ps[n] = pv[n].sig; pm[n] = pv[n].id; pp[n] = pv[n].pk; n++;
    }
    if (n >= 2) ng_atomic_fetch_add_explicit(&stat_preverified, crypto_batch_verify(ps, pm, pp, n), NG_MO_RELAXED);
}

static void bset_unref(bset_t *s) {
    if (ng_atomic_fetch_sub(&s->refs, 1) == 1) {
        for (int i = 0; i < s->n; i++) relay_bcast_free(s->b[i]);
        free(s);
    }
}

static void *worker_thread(void *arg) {
    worker_t *wk = (worker_t *) arg;
#ifdef __linux__
    char name[16]; snprintf(name, sizeof(name), "ng-worker-%d", wk->idx);
    pthread_setname_np(pthread_self(), name);
#endif
    storage_context_t *st = relay_core_storage();
    if (st->thread_open && !st->thread_open(true)) fprintf(stderr, "worker %d: no reader db\n", wk->idx);
    for (;;) {
        pthread_mutex_lock(&wk->mu);
        while (!wk->head && !ng_atomic_load(&stopping)) pthread_cond_wait(&wk->cv, &wk->mu);
        job_t *j = wk->head;
        wk->head = wk->tail = NULL;
        pthread_mutex_unlock(&wk->mu);
        if (!j && ng_atomic_load(&stopping)) break;
        if (batch_verify) preverify_events(j);
        while (j) {
            job_t *next = j->next;
            relay_conn_t *rc = j->conn ? &j->conn->base : NULL;
            switch (j->type) {
            case J_OPEN: relay_core_on_open(rc); unref_later(rc); break;
            case J_MSG:
                if (rc->core && !ng_atomic_load(&rc->closed)) relay_core_on_message(rc, j->payload, j->len);
                ng_atomic_fetch_sub_explicit(&j->conn->pending, 1, NG_MO_RELAXED);
                unref_later(rc); break;
            case J_CLOSE: if (rc->core) relay_core_on_close(rc); unref_later(rc); break;
            case J_BSET:
                for (int i = 0; i < j->bset->n; i++) {
                    relay_core_broadcast_shard(wk->idx, j->bset->b[i]);
                    outbox_commit_refs();          /* bulk body refs, before the set can be freed */
                }
                bset_unref(j->bset); break;
            }
            if (j->type != J_BSET) ng_atomic_fetch_sub_explicit(&wk->qbytes, job_cost(j), NG_MO_RELAXED);
            free(j);
            j = next;
        }
        outbox_flush_and_unref();
        crypto_preverified_clear();
    }
    outbox_thread_done();
    crypto_thread_cleanup();
    preverify_free();
    if (st->thread_close) st->thread_close();
    return NULL;
}

/* --------------------------------------------------------------- writer -- */
/* Never blocks the caller: a full writer queue answers OK false. */
static void publish_to_writer(relay_conn_t *rc, relay_bcast_t *bc) {
    bool full = ng_atomic_fetch_add(&writer_depth, 1) >= opt.writer_queue_max;
    wjob_t *w = full ? NULL : (wjob_t *) malloc(sizeof(*w));
    if (!w) {
        ng_atomic_fetch_sub(&writer_depth, 1);
        if (full) ng_atomic_fetch_add_explicit(&stat_shed_writer, 1, NG_MO_RELAXED);
        nip_plugin_send_status(rc, "OK", bc->ev.id, false, full ? overload_msg : "error: out of memory");
        dedupe_release(bc->ev.id); relay_bcast_free(bc); unref_later(rc); return;   /* worker thread */
    }
    w->next = NULL; w->conn = (ng_conn_t *) rc; w->bc = bc;
    pthread_mutex_lock(&writer_mu);
    bool was_empty = writer_head == NULL;
    if (writer_tail) writer_tail->next = w; else writer_head = w;
    writer_tail = w;
    pthread_mutex_unlock(&writer_mu);
    if (was_empty) pthread_cond_signal(&writer_cv);
}

static int env_int(const char *name, int dflt) {
    const char *v = getenv(name);
    int x = v ? atoi(v) : 0;
    return x > 0 ? x : dflt;
}

/* Per-batch id set (writer thread only). */
static struct { const char *id; unsigned gen; } bseen[16384];
static unsigned bseen_gen;
static unsigned long long stat_batches, stat_events;
static void batch_seen_reset(int n) { (void) n; if (++bseen_gen == 0) { memset(bseen, 0, sizeof(bseen)); bseen_gen = 1; } }
static bool batch_seen_add(const char *id) {
    uint64_t h; memcpy(&h, id, 8); h *= 0x9E3779B97F4A7C15ull;
    for (size_t i = (size_t) (h >> 50);; i = (i + 1) & 16383) {
        if (bseen[i].gen != bseen_gen) { bseen[i].gen = bseen_gen; bseen[i].id = id; return true; }
        if (strcmp(bseen[i].id, id) == 0) return false;
    }
}

static unsigned long long stat_us[3];
static long long now_us(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long) ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static long long now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void *writer_thread(void *arg) {
    (void) arg;
#ifdef __linux__
    pthread_setname_np(pthread_self(), "ng-writer");
#endif
    storage_context_t *st = relay_core_storage();
    if (st->thread_open && !st->thread_open(false)) { fprintf(stderr, "writer: db open failed\n"); return NULL; }
    unsigned interval = relay_core_timer_interval();
    long long next_timer = interval ? now_ms() : 0;
    static wjob_t *batch[WRITER_BATCH];
    static nip01_process_result_t results[WRITER_BATCH];
    int batch_max = env_int("NG_BATCH_MAX", 4096);
    if (batch_max > WRITER_BATCH) batch_max = WRITER_BATCH;
    int batch_min = env_int("NG_BATCH_MIN", 1024);
    int linger_min = env_int("NG_LINGER_MIN", 64);
    /* Off by default: measured no gain (COMMIT cost here scales with pages
     * dirtied, i.e. with events, not with commits) and it can only add
     * latency for closed-loop publishers. */
    long long linger_us = getenv("NG_LINGER_US") ? atoi(getenv("NG_LINGER_US")) : 0;
    int prev_n = 0;
    for (;;) {
        pthread_mutex_lock(&writer_mu);
        while (!writer_head && !ng_atomic_load(&stopping)) {
            if (!interval) { pthread_cond_wait(&writer_cv, &writer_mu); continue; }
            long long wait = next_timer - now_ms();
            if (wait <= 0) break;
            struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += wait / 1000; ts.tv_nsec += (wait % 1000) * 1000000;
            if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
            pthread_cond_timedwait(&writer_cv, &writer_mu, &ts);
            if (now_ms() >= next_timer) break;
        }
        int n = 0;
        while (writer_head && n < batch_max) { batch[n++] = writer_head; writer_head = writer_head->next; }
        /* Adaptive linger: only when the previous batch shows sustained load
         * (>= linger_min events), wait up to linger_us for the batch to reach
         * batch_min, amortizing COMMIT over more events. Idle/light traffic
         * never waits, so OK latency stays at one commit. */
        if (n > 0 && n < batch_min && prev_n >= linger_min && linger_us > 0 && !ng_atomic_load(&stopping)) {
            long long deadline = now_us() + linger_us;
            while (n < batch_min) {
                if (!writer_head) {
                    long long left = deadline - now_us();
                    if (left <= 0) break;
                    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
                    ts.tv_nsec += (long) (left % 1000000) * 1000; ts.tv_sec += left / 1000000;
                    if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
                    pthread_cond_timedwait(&writer_cv, &writer_mu, &ts);
                    if (!writer_head) continue;
                }
                while (writer_head && n < batch_max) { batch[n++] = writer_head; writer_head = writer_head->next; }
                if (n >= batch_max) break;
            }
        }
        prev_n = n;
        ng_atomic_fetch_sub(&writer_depth, n);
        if (!writer_head) writer_tail = NULL;
        bool stop = ng_atomic_load(&stopping) && n == 0;
        pthread_mutex_unlock(&writer_mu);
        if (stop) break;

        if (interval && now_ms() >= next_timer) {
            relay_core_run_timers();
            next_timer = now_ms() + interval;
        }
        if (n == 0) continue;

        /* Layer 1 duplicate guard: two copies of one id inside this batch
         * (possible only if the in-flight set was full/disabled) - the first
         * is dispatched, later ones are answered as duplicates and never hit
         * SQLite or the broadcast path. */
        long long t0 = now_us();
        batch_seen_reset(n);
        bool tx = st->begin_batch && st->begin_batch();
        for (int i = 0; i < n; i++) {
            if (!batch_seen_add(batch[i]->bc->ev.id)) {
                results[i] = nip_plugin_duplicate("duplicate: already have this event");
                continue;
            }
            results[i] = relay_core_commit_event(&batch[i]->conn->base, &batch[i]->bc->ev);
        }
        long long t1 = now_us();
        if (tx && st->commit_batch && !st->commit_batch()) {
            if (st->rollback_batch) st->rollback_batch();
            for (int i = 0; i < n; i++) if (results[i].accepted) {
                results[i].accepted = false; results[i].should_broadcast = false; results[i].duplicate = false;
                snprintf(results[i].response_msg, sizeof(results[i].response_msg), "error: storage commit failed");
            }
        }
        long long t2 = now_us();
        for (int i = 0; i < n; i++) relay_core_dedupe_settle(&batch[i]->bc->ev, &results[i]);
        stat_batches++; stat_events += (unsigned long long) n;
        bset_t *set = (bset_t *) malloc(sizeof(*set) + (size_t) n * sizeof(relay_bcast_t *));
        if (set) set->n = 0;
        for (int i = 0; i < n; i++) {
            relay_conn_t *rc = &batch[i]->conn->base;
            relay_core_send_ok(rc, &batch[i]->bc->ev, &results[i]);
            /* Only events newly written (or ephemeral) are ever broadcast. */
            if (set && results[i].accepted && results[i].should_broadcast && !results[i].duplicate)
                set->b[set->n++] = batch[i]->bc;
            else relay_bcast_free(batch[i]->bc);
            unref_later(rc);
            free(batch[i]);
        }
        if (set && set->n) {
            ng_atomic_init(&set->refs, n_workers);
            for (int w = 0; w < n_workers; w++) {
                job_t *j = job_new(J_BSET, NULL, 0);
                if (!j) { bset_unref(set); continue; }
                j->bset = set;
                worker_push(w, j);
            }
        } else free(set);
        outbox_flush_and_unref();
        stat_us[0] += t1 - t0; stat_us[1] += t2 - t1; stat_us[2] += now_us() - t2;
    }
    outbox_thread_done();
    if (getenv("NG_WRITER_STATS")) fprintf(stderr, "writer: dispatch %.2fs commit %.2fs post %.2fs\n", stat_us[0]/1e6, stat_us[1]/1e6, stat_us[2]/1e6);
    if (getenv("NG_WRITER_STATS")) fprintf(stderr, "writer: %llu events in %llu batches (avg %.1f)\n",
        stat_events, stat_batches, stat_batches ? (double) stat_events / (double) stat_batches : 0.0);
    if (st->thread_close) st->thread_close();
    return NULL;
}

/* ---------------------------------------------------------- checkpointer -- */
/* WAL checkpoints moved off the writer: the writer's connection runs with
 * wal_autocheckpoint=0 so COMMIT never does checkpoint I/O; this thread runs
 * PASSIVE checkpoints on its own connection (they never take the write lock,
 * so they cannot stall the writer) every NG_CKPT_MS (default 250 ms). */
static pthread_t ckpt_th;
static void *checkpoint_thread(void *arg) {
    (void) arg;
#ifdef __linux__
    pthread_setname_np(pthread_self(), "ng-checkpoint");
#endif
    storage_context_t *st = relay_core_storage();
    if (!st->checkpoint || (st->thread_open && !st->thread_open(false))) return NULL;
    int ms = 250;
    { const char *v = getenv("NG_CKPT_MS"); if (v && atoi(v) > 0) ms = atoi(v); }
    while (!ng_atomic_load(&stopping)) {
        struct timespec ts = { ms / 1000, (long) (ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
        st->checkpoint();
    }
    st->checkpoint();
    if (st->thread_close) st->thread_close();
    return NULL;
}

/* ----------------------------------------------------------------- run --- */
static bool parse_size(const char *v, size_t lo, size_t hi, size_t *out) {
    char *end; errno = 0;
    unsigned long long x = strtoull(v, &end, 10);
    if (end == v || errno || *v == '-') return false;
    unsigned long long m = 1;
    if (*end == 'K' || *end == 'k') { m = 1ull << 10; end++; }
    else if (*end == 'M' || *end == 'm') { m = 1ull << 20; end++; }
    else if (*end == 'G' || *end == 'g') { m = 1ull << 30; end++; }
    if (*end || x > (unsigned long long) hi / m || x * m < lo) return false;
    *out = (size_t) (x * m);
    return true;
}

bool server_config_set(const char *key, const char *value) {
    size_t v;
    if (strcmp(key, "io_threads") == 0 || strcmp(key, "workers") == 0) {
        if (!(strcmp(value, "auto") == 0 ? (v = 0, true) : parse_size(value, 1, strcmp(key, "workers") == 0 ? RELAY_MAX_SHARDS : MAX_IO_LOOPS, &v))) return false;
        if (key[0] == 'i') opt.io_threads = (int) v; else opt.workers = (int) v;
        return true;
    }
    if (strcmp(key, "conn_outbound_max") == 0) return parse_size(value, 64u << 10, (size_t) 1 << 32, &opt.conn_out_max);
    if (strcmp(key, "total_outbound_max") == 0) return parse_size(value, 256u << 10, (size_t) 1 << 40, &opt.total_out_max);
    if (strcmp(key, "worker_queue_max") == 0) return parse_size(value, 64u << 10, (size_t) 1 << 36, &opt.worker_queue_max);
    if (strcmp(key, "writer_queue_max") == 0) { if (!parse_size(value, 1, 1u << 24, &v)) return false; opt.writer_queue_max = (int) v; return true; }
    if (strcmp(key, "listen_backlog") == 0) {
        if (strcmp(value, "auto") == 0) { opt.listen_backlog = 0; return true; }
        if (!parse_size(value, 1, 1u << 20, &v)) return false;
        opt.listen_backlog = (int) v; return true;
    }
    if (strcmp(key, "conn_pending_max") == 0) { if (!parse_size(value, 1, 1u << 20, &v)) return false; opt.conn_pending_max = (int) v; return true; }
    return false;
}


bool server_run(int port) {
    if (!relay_core_storage() || port < 1 || port > 65535) return false;
    /* CPUs this process may run on (taskset/cgroup cpusets), not all online. */
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
#ifdef __linux__
    { cpu_set_t cs; if (sched_getaffinity(0, sizeof(cs), &cs) == 0 && CPU_COUNT(&cs) > 0) ncpu = CPU_COUNT(&cs); }
#endif
    if (ncpu < 1) ncpu = 1;
    n_loops = env_int("NG_IO_THREADS", opt.io_threads ? opt.io_threads : IO_THREADS_AUTO(ncpu));
    n_workers = env_int("NG_WORKERS", opt.workers ? opt.workers : (int) ncpu);
    if (n_loops > MAX_IO_LOOPS) n_loops = MAX_IO_LOOPS;
    if (n_workers > RELAY_MAX_SHARDS) n_workers = RELAY_MAX_SHARDS;

    const char *doc = relay_core_info_document();
    if (doc) { info_doc = strdup(doc); info_doc_len = strlen(info_doc); }
    signal(SIGPIPE, SIG_IGN);
    relay_core_set_publisher(publish_to_writer);
    relay_core_set_admission(core_admit);
    relay_core_set_query_bytes_max(opt.conn_out_max / 2);
    { const char *bv = getenv("NG_BATCH_VERIFY"); batch_verify = !(bv && strcmp(bv, "0") == 0); }

    for (int i = 0; i < n_workers; i++) {
        workers[i].idx = i;
        pthread_mutex_init(&workers[i].mu, NULL);
        pthread_cond_init(&workers[i].cv, NULL);
        pthread_create(&workers[i].th, NULL, worker_thread, &workers[i]);
    }
    pthread_create(&writer_th, NULL, writer_thread, NULL);
    pthread_create(&ckpt_th, NULL, checkpoint_thread, NULL);

    ngws_config_t cfg; memset(&cfg, 0, sizeof(cfg));
    cfg.port = port;
    cfg.loops = n_loops;
    cfg.max_payload = MAX_WS_MESSAGE;
    cfg.max_backpressure = opt.conn_out_max;
    cfg.max_total_backlog = opt.total_out_max;
    cfg.listen_backlog = opt.listen_backlog;
    cfg.idle_timeout = (unsigned) env_int("NG_IDLE_TIMEOUT", 120);
    cfg.handshake_timeout = 16;
    cfg.user_size = sizeof(ng_conn_t *);
    cfg.on_open = on_open; cfg.on_message = on_message; cfg.on_close = on_close; cfg.on_drain = on_drain;
    cfg.on_http = on_http; cfg.on_loop_start = on_loop_start; cfg.on_loop_stop = on_loop_stop;
    srv = ngws_server_create(&cfg);
    fprintf(stderr, "nostrogotho (ngws) listening on :%d  io_loops=%d workers=%d writer=1 backlog=%d\n",
            port, n_loops, n_workers, ngws_listen_backlog(&cfg));
    bool ok = srv && ngws_server_run(srv);

    ng_atomic_store(&stopping, true);
    pthread_mutex_lock(&writer_mu); pthread_cond_broadcast(&writer_cv); pthread_mutex_unlock(&writer_mu);
    pthread_join(writer_th, NULL);
    pthread_join(ckpt_th, NULL);
    for (int i = 0; i < n_workers; i++) {
        pthread_mutex_lock(&workers[i].mu);
        pthread_cond_broadcast(&workers[i].cv);
        pthread_mutex_unlock(&workers[i].mu);
        pthread_join(workers[i].th, NULL);
    }
    if (srv) {
        ngws_stats_t ns; ngws_server_stats(srv, &ns);
        fprintf(stderr, "overload: shed_inline=%llu shed_admission=%llu shed_writer_full=%llu "
                "closed_conn_limit=%llu closed_total_limit=%llu batch_verified=%llu\n",
                (unsigned long long) ng_atomic_load(&stat_shed_loop), (unsigned long long) ng_atomic_load(&stat_shed_core),
                (unsigned long long) ng_atomic_load(&stat_shed_writer), ns.closed_conn_limit, ns.closed_total_limit, (unsigned long long) ng_atomic_load(&stat_preverified));
    }
    relay_core_shutdown();
    return ok;
}

void server_stop(void) {
    ng_atomic_store(&stopping, true);
    if (srv) ngws_server_stop(srv);
}
