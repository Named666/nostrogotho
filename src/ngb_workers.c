/* ngb_workers - see ngb_workers.h. */
#include "ngb_workers.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "ng_config.h"
#include "ngb_outbox.h"
#include "platform/ng_alloc.h"
#include "platform/ng_platform.h"
#include "relay_core.h"
#include "relay_wire.h"

enum { J_OPEN, J_MSG, J_CLOSE, J_BSET };

/* One committed batch's broadcasts, shared by every worker (one job per
 * worker per batch); the last worker to finish frees it. */
typedef struct bset { ng_atomic_int refs; int n; relay_bcast_t *b[]; } bset_t;

typedef struct job {
    struct job *next;
    int type;
    ng_conn_t *conn;
    bset_t *bset;
    size_t len;
    char payload[];             /* J_MSG: NUL-terminated message */
} job_t;

typedef struct {
    int idx;
    pthread_t th;
    pthread_mutex_t mu;         /* guards head/tail */
    pthread_cond_t cv;
    job_t *head, *tail;
    NG_ALIGNED(NG_CACHELINE) ng_atomic_size qbytes;   /* queued + in-progress inbound bytes */
} worker_t;

/* Per-loop pending jobs for each worker, flushed at the end of the loop
 * iteration. Entry i is touched only by loop i's thread. */
typedef struct {
    job_t *head[RELAY_MAX_SHARDS], *tail[RELAY_MAX_SHARDS];
    uint64_t pending_mask;
    bool flush_scheduled;
} NG_ALIGNED(NG_CACHELINE) loop_ctx_t;

NG_STATIC_ASSERT(RELAY_MAX_SHARDS <= 64, pending_mask_fits);

static worker_t workers[RELAY_MAX_SHARDS];
static int n_workers;
static bool batch_verify = true;
static ng_atomic_bool stopping;
static ng_atomic_ullong stat_preverified;
static loop_ctx_t loop_ctx[NG_MAX_IO_LOOPS];

int ngb_workers_count(void) { return n_workers; }
unsigned long long ngb_workers_preverified(void) { return ng_atomic_load(&stat_preverified); }
size_t ngb_worker_queued_bytes(int w) { return ng_atomic_load_explicit(&workers[w].qbytes, NG_MO_RELAXED); }
size_t ngb_message_cost(size_t len) { return sizeof(job_t) + len + 1; }

/* ------------------------------------------------------------ queues --- */
static void worker_push_list(int w, job_t *h, job_t *t) {
    worker_t *wk = &workers[w];
    pthread_mutex_lock(&wk->mu);
    bool was_empty = wk->head == NULL;
    if (wk->tail) wk->tail->next = h; else wk->head = h;
    wk->tail = t;
    pthread_mutex_unlock(&wk->mu);
    if (was_empty) pthread_cond_signal(&wk->cv);
}

static void loop_flush_jobs(void *arg) {
    loop_ctx_t *lc = (loop_ctx_t *) arg;
    uint64_t m = lc->pending_mask;
    lc->pending_mask = 0; lc->flush_scheduled = false;
    while (m) {
        int w = ng_ctz64(m); m &= m - 1;
        worker_push_list(w, lc->head[w], lc->tail[w]);
        lc->head[w] = lc->tail[w] = NULL;
    }
}

static size_t job_cost(const job_t *j) { return sizeof(job_t) + (j->type == J_MSG ? j->len + 1 : 0); }

static job_t *job_new(int type, ng_conn_t *c, size_t extra) {
    job_t *j = (job_t *) ng_malloc_add(sizeof(*j), extra);
    if (j) { memset(j, 0, sizeof(*j)); j->type = type; j->conn = c; }
    return j;
}

/* Loop thread: queue j for worker w; delivered at the end of the iteration. */
static void loop_queue_job(ngws_loop_t *loop, int w, job_t *j) {
    loop_ctx_t *lc = &loop_ctx[ngws_loop_index(loop)];
    ng_atomic_fetch_add_explicit(&workers[w].qbytes, job_cost(j), NG_MO_RELAXED);
    j->next = NULL;
    if (lc->tail[w]) lc->tail[w]->next = j; else lc->head[w] = j;
    lc->tail[w] = j;
    lc->pending_mask |= 1ull << w;
    if (!lc->flush_scheduled) { lc->flush_scheduled = true; ngws_loop_defer(loop, loop_flush_jobs, lc); }
}

bool ngb_queue_open(ng_conn_t *c) {
    job_t *j = job_new(J_OPEN, c, 0);
    if (!j) return false;
    relay_conn_retain(&c->base);
    loop_queue_job(c->loop, c->base.shard, j);
    return true;
}

bool ngb_queue_message(ng_conn_t *c, const char *msg, size_t len) {
    job_t *j = job_new(J_MSG, c, len + 1);          /* len <= max_payload (ngws) */
    if (!j) return false;
    ng_atomic_fetch_add_explicit(&c->pending, 1, NG_MO_RELAXED);
    memcpy(j->payload, msg, len); j->payload[len] = '\0'; j->len = len;
    relay_conn_retain(&c->base);
    loop_queue_job(c->loop, c->base.shard, j);
    return true;
}

void ngb_queue_close(ng_conn_t *c) {
    job_t *j = job_new(J_CLOSE, c, 0);              /* inherits the socket's ref */
    if (j) loop_queue_job(c->loop, c->base.shard, j);
    else relay_conn_unref(&c->base);
}

static void bset_unref(bset_t *s) {
    if (ng_atomic_fetch_sub(&s->refs, 1) == 1) {
        for (int i = 0; i < s->n; i++) relay_bcast_free(s->b[i]);
        free(s);
    }
}

void ngb_workers_broadcast(relay_bcast_t *const *b, int n) {
    if (n <= 0) return;
    bset_t *set = (bset_t *) ng_malloc_flex(sizeof(bset_t), (size_t) n, sizeof(relay_bcast_t *));
    if (!set) { for (int i = 0; i < n; i++) relay_bcast_free(b[i]); return; }   /* stored; not fanned out */
    set->n = n;
    memcpy(set->b, b, (size_t) n * sizeof(*b));
    ng_atomic_init(&set->refs, n_workers);
    for (int w = 0; w < n_workers; w++) {
        job_t *j = job_new(J_BSET, NULL, 0);
        if (!j) { bset_unref(set); continue; }
        j->bset = set;
        j->next = NULL;
        worker_push_list(w, j, j);
    }
}

/* ----------------------------------------------- batch pre-verification --
 * Pipelined publishers and many connections per shard deliver several
 * EVENTs per wakeup; their (sig, pubkey, claimed id) triples are verified
 * together (crypto_batch_verify, shared multi-scalar multiplication). The
 * normal per-message path then runs unchanged: it recomputes the id from the
 * serialization and calls signature_verify, which skips curve work only for
 * byte-identical triples proven here. Messages the admission check would
 * reject are skipped, so overload does not buy extra crypto. */
#define PREVERIFY_MAX 1024
typedef struct { uint8_t sig[64], pk[32], id[32]; } pv_item_t;
static NG_THREAD_LOCAL pv_item_t *pv;
static NG_THREAD_LOCAL const uint8_t **ps, **pm, **pp;

static void preverify_free(void) { free(pv); free(ps); free(pm); free(pp); pv = NULL; ps = pm = pp = NULL; }

static void preverify_events(job_t *j) {
    size_t n = 0;
    for (; j && n < PREVERIFY_MAX; j = j->next) {
        if (j->type != J_MSG || j->len < 16 || ng_atomic_load_explicit(&j->conn->base.closed, NG_MO_RELAXED)) continue;
        pv_item_t it;
        if (!relay_wire_event_sig(j->payload, j->len, it.id, it.pk, it.sig)) continue;
        if (!pv) {                          /* first EVENT on this thread */
            pv = (pv_item_t *) ng_malloc_array(PREVERIFY_MAX, sizeof(*pv));
            ps = (const uint8_t **) ng_malloc_array(PREVERIFY_MAX, sizeof(*ps));
            pm = (const uint8_t **) ng_malloc_array(PREVERIFY_MAX, sizeof(*pm));
            pp = (const uint8_t **) ng_malloc_array(PREVERIFY_MAX, sizeof(*pp));
            if (!pv || !ps || !pm || !pp) { preverify_free(); return; }   /* all or nothing; plain verify still runs */
        }
        const char *why;
        if (!ngb_admit(&j->conn->base, RELAY_ADMIT_EVENT, &why)) continue;
        pv[n] = it;
        ps[n] = pv[n].sig; pm[n] = pv[n].id; pp[n] = pv[n].pk; n++;
    }
    if (n >= 2) ng_atomic_fetch_add_explicit(&stat_preverified, (unsigned long long) crypto_batch_verify(ps, pm, pp, n), NG_MO_RELAXED);
}

/* ------------------------------------------------------------ thread --- */
static void run_job(worker_t *wk, job_t *j) {
    relay_conn_t *rc = j->conn ? &j->conn->base : NULL;
    switch (j->type) {
    case J_OPEN: relay_core_on_open(rc); ngb_unref_later(rc); break;
    case J_MSG:
        if (rc->core && !ng_atomic_load(&rc->closed)) relay_core_on_message(rc, j->payload, j->len);
        ng_atomic_fetch_sub_explicit(&j->conn->pending, 1, NG_MO_RELAXED);
        ngb_unref_later(rc); break;
    case J_CLOSE: if (rc->core) relay_core_on_close(rc); ngb_unref_later(rc); break;
    case J_BSET:
        for (int i = 0; i < j->bset->n; i++) {
            relay_core_broadcast_shard(wk->idx, j->bset->b[i]);
            ngb_outbox_commit_refs();          /* bulk body refs, before the set can be freed */
        }
        bset_unref(j->bset); break;
    }
    if (j->type != J_BSET) ng_atomic_fetch_sub_explicit(&wk->qbytes, job_cost(j), NG_MO_RELAXED);
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
            run_job(wk, j);
            free(j);
            j = next;
        }
        ngb_outbox_flush_and_unref();
        crypto_preverified_clear();
    }
    ngb_outbox_thread_done();
    crypto_thread_cleanup();
    preverify_free();
    if (st->thread_close) st->thread_close();
    return NULL;
}

int ngb_workers_start(int n, bool bv) {
    if (n < 1) n = 1;
    if (n > RELAY_MAX_SHARDS) n = RELAY_MAX_SHARDS;
    batch_verify = bv;
    n_workers = 0;
    for (int i = 0; i < n; i++) {
        workers[i].idx = i;
        pthread_mutex_init(&workers[i].mu, NULL);
        pthread_cond_init(&workers[i].cv, NULL);
        if (pthread_create(&workers[i].th, NULL, worker_thread, &workers[i]) != 0) break;
        n_workers++;
    }
    return n_workers;
}

void ngb_workers_stop(void) {
    ng_atomic_store(&stopping, true);
    for (int i = 0; i < n_workers; i++) {
        pthread_mutex_lock(&workers[i].mu);
        pthread_cond_broadcast(&workers[i].cv);
        pthread_mutex_unlock(&workers[i].mu);
        pthread_join(workers[i].th, NULL);
    }
}
