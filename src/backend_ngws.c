/* ============================================================================
 * Relay transport: ngws (uSockets + in-tree RFC 6455, pure C, no TLS: put
 * nginx/haproxy in front for wss://).
 *
 * Thread layout
 *   I/O loops  (NG_IO_THREADS, default max(1, nproc/4)): ngws event loops on
 *              one port via SO_REUSEPORT. TCP, HTTP upgrade, NIP-11, framing,
 *              corked writev output. No protocol logic.
 *   Workers    (NG_WORKERS, default nproc): each connection is pinned to one
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
 *                   writev (frame prefix | shared body | "]"), zero copy.
 * ============================================================================ */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <stdint.h>
#include "ngws/ngws.h"
#include "nips/nip_plugin.h"
#include "dedupe.h"
#include "relay_conn_internal.h"
#include "relay_core.h"
#include "server.h"
#include "ws_proto.h"

#define MAX_WS_MESSAGE   (5u * 1024 * 1024)
#define MAX_OUT_BUFFER   (32u * 1024 * 1024)   /* slow-consumer cutoff */
#define MAX_IO_LOOPS     64
#define WRITER_BATCH     8192   /* hard cap; NG_BATCH_MAX tunes below it */
#define OUTBOX_FLUSH     (256u * 1024)

/* ---------------------------------------------------------------- types -- */
typedef struct {
    relay_conn_t base;          /* must be first */
    ngws_loop_t *loop;
    ngws_socket_t *ws;          /* loop thread only; NULL once closed */
} ng_conn_t;

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
typedef struct bset { atomic_int refs; int n; relay_bcast_t *b[]; } bset_t;

typedef struct {
    int idx;
    pthread_t th;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    job_t *head, *tail;
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

typedef struct { outtask_t *t; size_t cap; } outbox_t;

/* ---------------------------------------------------------------- state -- */
static ngws_server_t *srv;
static int n_loops;
static worker_t workers[RELAY_MAX_SHARDS];
static int n_workers;
static atomic_ullong next_conn_id = 1;
static atomic_bool stopping;
static char *info_doc;
static size_t info_doc_len;
static atomic_llong stat_open_conns;

static pthread_t writer_th;
static pthread_mutex_t writer_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t writer_cv = PTHREAD_COND_INITIALIZER;
static wjob_t *writer_head, *writer_tail;

static __thread outbox_t tl_outbox[MAX_IO_LOOPS];
static __thread uint64_t tl_outbox_dirty;

/* --------------------------------------------------------- loop side ----- */
static void run_outtask(ngws_task_t *t, ngws_loop_t *loop);

static void outtask_free(void *p) { free(p); }
static void body_release_cb(void *p) { relay_body_release((relay_body_t *) p); }

static void run_outtask(ngws_task_t *tk, ngws_loop_t *loop) {
    outtask_t *t = (outtask_t *) tk;
    size_t o = 0;
    while (o < t->len) {
        rec_t *r = (rec_t *) (t->data + o);
        char *d = (char *) (r + 1);
        ng_conn_t *c = r->conn;
        ngws_socket_t *ws = c->ws;
        if (ws && !atomic_load_explicit(&c->base.closed, memory_order_relaxed)) {
            if (r->kind == R_FRAME) ngws_send_shared(ws, d, r->len);
            else if (r->kind == R_CLOSE) ngws_close(ws, 1000, NULL);
            else if (r->kind == R_EVENT) {
                /* d = frame header + ["EVENT",<sub>, ; then shared body, then ] */
                ngws_send_shared(ws, d, r->len);
                ngws_send_shared(ws, r->body->json, r->body->len);
                ngws_send_shared(ws, "]", 1);
            }
        }
        if (r->kind == R_EVENT) ngws_loop_defer(loop, body_release_cb, r->body);
        relay_conn_unref(&c->base);
        o += sizeof(rec_t) + ((r->len + 7) & ~(size_t) 7);
    }
    ngws_loop_defer(loop, outtask_free, t);   /* frames are referenced until flushed */
}

/* ---------------------------------------------------------- outbox ------- */
static void outbox_flush_loop(int i) {
    outbox_t *ob = &tl_outbox[i];
    if (!ob->t || !ob->t->len) return;
    outtask_t *t = ob->t;
    ob->t = NULL; ob->cap = 0;
    t->task.run = run_outtask;
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
    relay_conn_retain(&c->base);
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
    char *d = outbox_reserve(c, R_EVENT, hl + 9 + sl + 1, body);
    if (!d) return;
    relay_body_retain(body, 1);
    ws_frame_header((unsigned char *) d, NGWS_OP_TEXT, payload);
    memcpy(d + hl, "[\"EVENT\",", 9);
    memcpy(d + hl + 9, sub, sl);
    d[hl + 9 + sl] = ',';
}

static void ngb_close(relay_conn_t *rc) {
    (void) outbox_reserve((ng_conn_t *) rc, R_CLOSE, 0, NULL);
}

static void ngb_destroy(relay_conn_t *rc) { free(rc); }
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

/* queue from a loop thread; delivered at the end of the iteration */
static void loop_queue_job(ngws_loop_t *loop, int w, job_t *j) {
    loop_ctx_t *lc = (loop_ctx_t *) ngws_loop_get_user(loop);
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
    c->base.id = atomic_fetch_add(&next_conn_id, 1);
    c->base.ops = &ng_ops;
    c->base.backend = c;
    c->base.shard = (int) (c->base.id % (uint64_t) n_workers);
    atomic_init(&c->base.refs, 1);            /* held by the socket */
    c->loop = ngws_socket_loop(ws);
    c->ws = ws;
    ngws_remote_address(ws, c->base.peer, sizeof(c->base.peer));
    *(ng_conn_t **) ngws_user(ws) = c;
    atomic_fetch_add(&stat_open_conns, 1);
    job_t *j = job_new(J_OPEN, c, 0);
    if (j) { relay_conn_retain(&c->base); loop_queue_job(c->loop, c->base.shard, j); }
}

static void on_message(ngws_socket_t *ws, char *data, size_t len, int op) {
    (void) op;
    ng_conn_t *c = *(ng_conn_t **) ngws_user(ws);
    if (!c) return;
    job_t *j = job_new(J_MSG, c, len + 1);
    if (!j) return;
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
    atomic_store(&c->base.closed, true);
    atomic_fetch_sub(&stat_open_conns, 1);
    job_t *j = job_new(J_CLOSE, c, 0);       /* inherits the socket's ref */
    if (j) loop_queue_job(c->loop, c->base.shard, j);
    else relay_conn_unref(&c->base);
}

/* -------------------------------------------------------------- workers -- */
static void bset_unref(bset_t *s) {
    if (atomic_fetch_sub(&s->refs, 1) == 1) {
        for (int i = 0; i < s->n; i++) relay_bcast_free(s->b[i]);
        free(s);
    }
}

static void *worker_thread(void *arg) {
    worker_t *wk = (worker_t *) arg;
    storage_context_t *st = relay_core_storage();
    if (st->thread_open && !st->thread_open(true)) fprintf(stderr, "worker %d: no reader db\n", wk->idx);
    for (;;) {
        pthread_mutex_lock(&wk->mu);
        while (!wk->head && !atomic_load(&stopping)) pthread_cond_wait(&wk->cv, &wk->mu);
        job_t *j = wk->head;
        wk->head = wk->tail = NULL;
        pthread_mutex_unlock(&wk->mu);
        if (!j && atomic_load(&stopping)) break;
        while (j) {
            job_t *next = j->next;
            relay_conn_t *rc = j->conn ? &j->conn->base : NULL;
            switch (j->type) {
            case J_OPEN: relay_core_on_open(rc); relay_conn_unref(rc); break;
            case J_MSG:
                if (rc->core && !atomic_load(&rc->closed)) relay_core_on_message(rc, j->payload, j->len);
                relay_conn_unref(rc); break;
            case J_CLOSE: if (rc->core) relay_core_on_close(rc); relay_conn_unref(rc); break;
            case J_BSET:
                for (int i = 0; i < j->bset->n; i++) relay_core_broadcast_shard(wk->idx, j->bset->b[i]);
                bset_unref(j->bset); break;
            }
            free(j);
            j = next;
            if (tl_outbox_dirty && !j) outbox_flush();
        }
        outbox_flush();
    }
    outbox_flush();
    if (st->thread_close) st->thread_close();
    return NULL;
}

/* --------------------------------------------------------------- writer -- */
static void publish_to_writer(relay_conn_t *rc, relay_bcast_t *bc) {
    wjob_t *w = (wjob_t *) malloc(sizeof(*w));
    if (!w) { dedupe_release(bc->ev.id); relay_bcast_free(bc); relay_conn_unref(rc); return; }
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
        while (!writer_head && !atomic_load(&stopping)) {
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
        if (n > 0 && n < batch_min && prev_n >= linger_min && linger_us > 0 && !atomic_load(&stopping)) {
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
        if (!writer_head) writer_tail = NULL;
        bool stop = atomic_load(&stopping) && n == 0;
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
            relay_conn_unref(rc);
            free(batch[i]);
        }
        if (set && set->n) {
            atomic_init(&set->refs, n_workers);
            for (int w = 0; w < n_workers; w++) {
                job_t *j = job_new(J_BSET, NULL, 0);
                if (!j) { bset_unref(set); continue; }
                j->bset = set;
                worker_push(w, j);
            }
        } else free(set);
        outbox_flush();
        stat_us[0] += t1 - t0; stat_us[1] += t2 - t1; stat_us[2] += now_us() - t2;
    }
    outbox_flush();
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
    storage_context_t *st = relay_core_storage();
    if (!st->checkpoint || (st->thread_open && !st->thread_open(false))) return NULL;
    int ms = 250;
    { const char *v = getenv("NG_CKPT_MS"); if (v && atoi(v) > 0) ms = atoi(v); }
    while (!atomic_load(&stopping)) {
        struct timespec ts = { ms / 1000, (long) (ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
        st->checkpoint();
    }
    st->checkpoint();
    if (st->thread_close) st->thread_close();
    return NULL;
}

/* ----------------------------------------------------------------- run --- */

bool server_run(int port) {
    if (!relay_core_storage() || port < 1 || port > 65535) return false;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1) ncpu = 1;
    n_loops = env_int("NG_IO_THREADS", ncpu >= 4 ? (int) (ncpu / 4) : 1);
    n_workers = env_int("NG_WORKERS", (int) ncpu);
    if (n_loops > MAX_IO_LOOPS) n_loops = MAX_IO_LOOPS;
    if (n_workers > RELAY_MAX_SHARDS) n_workers = RELAY_MAX_SHARDS;

    const char *doc = relay_core_info_document();
    if (doc) { info_doc = strdup(doc); info_doc_len = strlen(info_doc); }
    signal(SIGPIPE, SIG_IGN);
    relay_core_set_publisher(publish_to_writer);

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
    cfg.max_backpressure = MAX_OUT_BUFFER;
    cfg.idle_timeout = (unsigned) env_int("NG_IDLE_TIMEOUT", 120);
    cfg.handshake_timeout = 16;
    cfg.user_size = sizeof(ng_conn_t *);
    cfg.on_open = on_open; cfg.on_message = on_message; cfg.on_close = on_close;
    cfg.on_http = on_http; cfg.on_loop_start = on_loop_start; cfg.on_loop_stop = on_loop_stop;
    srv = ngws_server_create(&cfg);
    fprintf(stderr, "nostrogotho (ngws) listening on :%d  io_loops=%d workers=%d writer=1\n",
            port, n_loops, n_workers);
    bool ok = srv && ngws_server_run(srv);

    atomic_store(&stopping, true);
    pthread_mutex_lock(&writer_mu); pthread_cond_broadcast(&writer_cv); pthread_mutex_unlock(&writer_mu);
    pthread_join(writer_th, NULL);
    pthread_join(ckpt_th, NULL);
    for (int i = 0; i < n_workers; i++) {
        pthread_mutex_lock(&workers[i].mu);
        pthread_cond_broadcast(&workers[i].cv);
        pthread_mutex_unlock(&workers[i].mu);
        pthread_join(workers[i].th, NULL);
    }
    relay_core_shutdown();
    return ok;
}

void server_stop(void) {
    atomic_store(&stopping, true);
    if (srv) ngws_server_stop(srv);
}
