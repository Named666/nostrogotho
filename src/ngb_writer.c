/* ngb_writer - see ngb_writer.h. */
#include "ngb_writer.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dedupe.h"
#include "ngb_conn.h"
#include "ngb_outbox.h"
#include "ngb_workers.h"
#include "nips/nip_plugin.h"
#include "platform/ng_platform.h"
#include "relay_core.h"

#define WRITER_BATCH 8192               /* hard cap; NG_BATCH_MAX tunes below it */

typedef struct wjob {
    struct wjob *next;
    relay_conn_t *conn;
    relay_bcast_t *bc;
} wjob_t;

/* Queue: producers are the workers, the consumer is the writer. */
static pthread_mutex_t writer_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t writer_cv = PTHREAD_COND_INITIALIZER;
static wjob_t *writer_head, *writer_tail;            /* guarded by writer_mu */
static ng_atomic_int writer_depth;                   /* EVENTs queued */
static int queue_max = 65536;                        /* set before start */
static ng_atomic_bool stopping;
static ng_atomic_ullong stat_shed;
static pthread_t writer_th, ckpt_th;
static bool writer_started, ckpt_started;

int ngb_writer_depth(void) { return ng_atomic_load_explicit(&writer_depth, NG_MO_RELAXED); }
unsigned long long ngb_writer_shed(void) { return ng_atomic_load(&stat_shed); }

static int env_int(const char *name, int dflt) {
    const char *v = getenv(name);
    int x = v ? atoi(v) : 0;
    return x > 0 ? x : dflt;
}

static long long now_us(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long) ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}
static long long now_ms(void) { return now_us() / 1000; }

/* Absolute CLOCK_REALTIME deadline us microseconds from now (condvar wait). */
static struct timespec deadline_in_us(long long us) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += (time_t) (us / 1000000); ts.tv_nsec += (long) (us % 1000000) * 1000;
    if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
    return ts;
}

/* ----------------------------------------------------------- publish --- */
void ngb_writer_publish(relay_conn_t *rc, relay_bcast_t *bc) {
    bool full = ng_atomic_fetch_add(&writer_depth, 1) >= queue_max;
    wjob_t *w = full ? NULL : (wjob_t *) malloc(sizeof(*w));
    if (!w) {
        ng_atomic_fetch_sub(&writer_depth, 1);
        if (full) ng_atomic_fetch_add_explicit(&stat_shed, 1, NG_MO_RELAXED);
        nip_plugin_send_status(rc, "OK", bc->ev.id, false, full ? NGB_OVERLOAD_MSG : "error: out of memory");
        dedupe_release(bc->ev.id); relay_bcast_free(bc); ngb_unref_later(rc); return;   /* worker thread */
    }
    w->next = NULL; w->conn = rc; w->bc = bc;
    pthread_mutex_lock(&writer_mu);
    bool was_empty = writer_head == NULL;
    if (writer_tail) writer_tail->next = w; else writer_head = w;
    writer_tail = w;
    pthread_mutex_unlock(&writer_mu);
    if (was_empty) pthread_cond_signal(&writer_cv);
}

/* ---------------------------------------------- per-batch id set ------
 * Writer thread only. Open addressing over pointers into the batch's own
 * events, invalidated in O(1) per batch by bumping the generation. */
#define BSEEN_SLOTS 16384               /* > 2 * WRITER_BATCH */
static struct { const char *id; unsigned gen; } bseen[BSEEN_SLOTS];
static unsigned bseen_gen;
static void batch_seen_reset(void) { if (++bseen_gen == 0) { memset(bseen, 0, sizeof(bseen)); bseen_gen = 1; } }
static bool batch_seen_add(const char *id) {   /* false: already in this batch */
    uint64_t h; memcpy(&h, id, 8); h *= 0x9E3779B97F4A7C15ull;
    for (size_t i = (size_t) (h >> 50);; i = (i + 1) & (BSEEN_SLOTS - 1)) {
        if (bseen[i].gen != bseen_gen) { bseen[i].gen = bseen_gen; bseen[i].id = id; return true; }
        if (strcmp(bseen[i].id, id) == 0) return false;
    }
}
NG_STATIC_ASSERT(BSEEN_SLOTS >= 2 * WRITER_BATCH && (BSEEN_SLOTS & (BSEEN_SLOTS - 1)) == 0, bseen_sized);

/* ------------------------------------------------------------ writer --- */
typedef struct {
    int batch_max, batch_min, linger_min;
    long long linger_us;
    unsigned timer_ms;
    long long next_timer;
} knobs_t;

static unsigned long long stat_batches, stat_events;
static unsigned long long stat_us[3];   /* dispatch, commit, post (writer thread) */

/* Wait for work (or the next plugin timer) and dequeue up to batch_max
 * events into batch. Adaptive linger: only when the previous batch shows
 * sustained load (>= linger_min events), wait up to linger_us for the batch
 * to reach batch_min, amortizing COMMIT over more events; idle/light
 * traffic never waits. Off by default (NG_LINGER_US): measured no gain,
 * since COMMIT cost here scales with pages dirtied, not with commits.
 * Returns the count; *stop is set when stopping and the queue is empty. */
static int writer_take(wjob_t **batch, const knobs_t *k, int prev_n, bool *stop) {
    pthread_mutex_lock(&writer_mu);
    while (!writer_head && !ng_atomic_load(&stopping)) {
        if (!k->timer_ms) { pthread_cond_wait(&writer_cv, &writer_mu); continue; }
        long long wait = k->next_timer - now_ms();
        if (wait <= 0) break;
        struct timespec ts = deadline_in_us(wait * 1000);
        pthread_cond_timedwait(&writer_cv, &writer_mu, &ts);
        if (now_ms() >= k->next_timer) break;
    }
    int n = 0;
    while (writer_head && n < k->batch_max) { batch[n++] = writer_head; writer_head = writer_head->next; }
    if (n > 0 && n < k->batch_min && prev_n >= k->linger_min && k->linger_us > 0 && !ng_atomic_load(&stopping)) {
        long long deadline = now_us() + k->linger_us;
        while (n < k->batch_min) {
            if (!writer_head) {
                long long left = deadline - now_us();
                if (left <= 0) break;
                struct timespec ts = deadline_in_us(left);
                pthread_cond_timedwait(&writer_cv, &writer_mu, &ts);
                if (!writer_head) continue;
            }
            while (writer_head && n < k->batch_max) { batch[n++] = writer_head; writer_head = writer_head->next; }
            if (n >= k->batch_max) break;
        }
    }
    ng_atomic_fetch_sub(&writer_depth, n);
    if (!writer_head) writer_tail = NULL;
    *stop = ng_atomic_load(&stopping) && n == 0;
    pthread_mutex_unlock(&writer_mu);
    return n;
}

/* Guard layer 1 + storage writes + COMMIT for one batch. On a failed
 * COMMIT every accepted result is turned into "error: storage commit
 * failed" (the transaction rolled back). */
static void writer_commit(storage_context_t *st, wjob_t **batch, nip01_process_result_t *results, int n) {
    long long t0 = now_us();
    batch_seen_reset();
    bool tx = st->begin_batch && st->begin_batch();
    for (int i = 0; i < n; i++) {
        if (!batch_seen_add(batch[i]->bc->ev.id)) {
            results[i] = nip_plugin_duplicate("duplicate: already have this event");
            continue;
        }
        results[i] = relay_core_commit_event(batch[i]->conn, &batch[i]->bc->ev);
    }
    long long t1 = now_us();
    stat_us[0] += (unsigned long long) (t1 - t0);
    if (tx && st->commit_batch && !st->commit_batch()) {
        if (st->rollback_batch) st->rollback_batch();
        relay_core_drop_emits();          /* relay-generated events rolled back too */
        for (int i = 0; i < n; i++) if (results[i].accepted) {
            results[i].accepted = false; results[i].should_broadcast = false; results[i].duplicate = false;
            snprintf(results[i].response_msg, sizeof(results[i].response_msg), "error: storage commit failed");
        }
    }
    stat_us[1] += (unsigned long long) (now_us() - t1);
}

/* Settle dedupe, answer OK, and fan out only events newly written (or
 * ephemeral). Releases every batch entry. */
static void writer_finish(wjob_t **batch, nip01_process_result_t *results, int n, relay_bcast_t **fan) {
    for (int i = 0; i < n; i++) relay_core_dedupe_settle(&batch[i]->bc->ev, &results[i]);
    int k = 0;
    for (int i = 0; i < n; i++) {
        relay_conn_t *rc = batch[i]->conn;
        relay_core_send_ok(rc, &batch[i]->bc->ev, &results[i]);
        if (results[i].accepted && results[i].should_broadcast && !results[i].duplicate) fan[k++] = batch[i]->bc;
        else relay_bcast_free(batch[i]->bc);
        ngb_unref_later(rc);
        free(batch[i]);
    }
    ngb_workers_broadcast(fan, k);
    /* Relay-generated events (NIP-29 / NIP-43) committed with this batch. */
    static relay_bcast_t *emitted[256];
    size_t m = relay_core_take_emits(emitted, sizeof(emitted) / sizeof(emitted[0]));
    if (m) ngb_workers_broadcast(emitted, (int) m);
    ngb_outbox_flush_and_unref();
}

static void *writer_thread(void *arg) {
    (void) arg;
#ifdef __linux__
    pthread_setname_np(pthread_self(), "ng-writer");
#endif
    storage_context_t *st = relay_core_storage();
    if (st->thread_open && !st->thread_open(false)) { fprintf(stderr, "writer: db open failed\n"); return NULL; }
    static wjob_t *batch[WRITER_BATCH];
    static nip01_process_result_t results[WRITER_BATCH];
    static relay_bcast_t *fan[WRITER_BATCH];
    knobs_t k;
    k.batch_max = env_int("NG_BATCH_MAX", 4096);
    if (k.batch_max > WRITER_BATCH) k.batch_max = WRITER_BATCH;
    k.batch_min = env_int("NG_BATCH_MIN", 1024);
    k.linger_min = env_int("NG_LINGER_MIN", 64);
    k.linger_us = getenv("NG_LINGER_US") ? atoi(getenv("NG_LINGER_US")) : 0;
    k.timer_ms = relay_core_timer_interval();
    k.next_timer = k.timer_ms ? now_ms() : 0;
    int prev_n = 0;
    for (;;) {
        bool stop;
        int n = writer_take(batch, &k, prev_n, &stop);
        prev_n = n;
        if (stop) break;
        if (k.timer_ms && now_ms() >= k.next_timer) {
            relay_core_run_timers();
            k.next_timer = now_ms() + k.timer_ms;
        }
        if (n == 0) continue;
        writer_commit(st, batch, results, n);
        long long t2 = now_us();
        stat_batches++; stat_events += (unsigned long long) n;
        writer_finish(batch, results, n, fan);
        stat_us[2] += (unsigned long long) (now_us() - t2);
    }
    ngb_outbox_thread_done();
    if (getenv("NG_WRITER_STATS")) {
        fprintf(stderr, "writer: dispatch %.2fs commit %.2fs post %.2fs\n",
                (double) stat_us[0] / 1e6, (double) stat_us[1] / 1e6, (double) stat_us[2] / 1e6);
        fprintf(stderr, "writer: %llu events in %llu batches (avg %.1f)\n",
                stat_events, stat_batches, stat_batches ? (double) stat_events / (double) stat_batches : 0.0);
    }
    if (st->thread_close) st->thread_close();
    return NULL;
}

/* -------------------------------------------------------- checkpointer -- */
static void *checkpoint_thread(void *arg) {
    (void) arg;
#ifdef __linux__
    pthread_setname_np(pthread_self(), "ng-checkpoint");
#endif
    storage_context_t *st = relay_core_storage();
    if (!st->checkpoint || (st->thread_open && !st->thread_open(false))) return NULL;
    int ms = env_int("NG_CKPT_MS", 250);
    while (!ng_atomic_load(&stopping)) {
        struct timespec ts = { ms / 1000, (long) (ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
        st->checkpoint();
    }
    st->checkpoint();
    if (st->thread_close) st->thread_close();
    return NULL;
}

bool ngb_writer_start(int qmax) {
    queue_max = qmax > 0 ? qmax : 1;
    writer_started = pthread_create(&writer_th, NULL, writer_thread, NULL) == 0;
    ckpt_started = pthread_create(&ckpt_th, NULL, checkpoint_thread, NULL) == 0;
    return writer_started;
}

void ngb_writer_stop(void) {
    ng_atomic_store(&stopping, true);
    pthread_mutex_lock(&writer_mu); pthread_cond_broadcast(&writer_cv); pthread_mutex_unlock(&writer_mu);
    if (writer_started) pthread_join(writer_th, NULL);
    if (ckpt_started) pthread_join(ckpt_th, NULL);
    writer_started = ckpt_started = false;
}
