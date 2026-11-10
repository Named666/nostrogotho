/* ============================================================================
 * Relay transport: ngws (uSockets + in-tree RFC 6455, pure C, no TLS: put
 * nginx/haproxy in front for wss://). This file is the orchestration layer:
 * thread setup/teardown, the ngws callbacks of the I/O loops, admission and
 * inline load shedding. The other backend modules:
 *
 *   ngb_conn.h     connection object shared by the modules
 *   ngb_workers.*  protocol workers (sharded relay_core state), job queues,
 *                  batch signature pre-verification
 *   ngb_writer.*   the ONE SQLite writer (batched commits, duplicate guard
 *                  layer 1, fan-out hand-off) and the WAL checkpointer
 *   ngb_outbox.*   worker/writer -> loop output path and connection lifetime
 *   relay_wire.*   pure raw-message helpers (overload replies, sig triples)
 *
 * Thread layout
 *   I/O loops  (io_threads / NG_IO_THREADS, default: usable CPUs): ngws loops on
 *              one port via SO_REUSEPORT. TCP, HTTP upgrade, NIP-11, framing,
 *              corked writev output. No protocol logic.
 *   Workers    (workers / NG_WORKERS, default: usable CPUs): each connection is
 *              pinned to one worker (id % W) which owns its protocol state and
 *              its subscriptions, parses JSON, verifies signatures, runs REQ
 *              queries on its own read-only SQLite connection and matches
 *              broadcasts.
 *   Writer     exactly ONE thread owning the only read-write SQLite
 *              connection (ngb_writer.h).
 *
 * Cross-thread traffic is batched in both directions:
 *   loop -> worker: messages are queued per worker during a loop iteration and
 *                   pushed with one lock + one signal at the end of it.
 *   worker/writer -> loop: thread-local outbox per loop (ngb_outbox.h).
 *
 * Shutdown order: loops stop (ngws_server_run returns) -> writer and
 * checkpointer drain and stop -> workers drain and stop -> core shutdown.
 * ============================================================================ */
#include "platform/ng_platform.h"
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "ng_config.h"
#include "ngb_conn.h"
#include "ngb_outbox.h"
#include "ngb_workers.h"
#include "ngb_writer.h"
#include "ngws/ngws.h"
#include "platform/ng_atomic.h"
#include "relay_core.h"
#include "relay_wire.h"
#include "server.h"

/* Default I/O loop count for n usable CPUs (io_threads = auto): one per CPU.
 * Fan-out is kernel-send bound on the loops (loopback: ~90% system time), so
 * they must scale with cores; idle loops cost nothing. On 4 CPUs, 4 loops vs
 * the previous nproc/4 halved fan-out p50 latency (SCALING.md). */
#ifndef IO_THREADS_AUTO
#define IO_THREADS_AUTO(n) ((int) (n))
#endif

/* Worker and loop sets are tracked in 64-bit masks. */
NG_STATIC_ASSERT(NG_MAX_WORKERS == RELAY_MAX_SHARDS, workers_are_shards);
NG_STATIC_ASSERT(RELAY_MAX_SHARDS <= 64 && NG_MAX_IO_LOOPS <= 64, masks_fit_64_bits);

/* ------------------------------------------------------- runtime options --
 * Copied from the parsed config (server_set_config) before server_run();
 * read-only afterwards, so every thread may read it without
 * synchronization. NG_IO_THREADS / NG_WORKERS (environment) still override
 * the thread counts for benchmark scripts. */
static ng_config_t opt;
static bool opt_set;                    /* else ng_config_defaults() */

/* ---------------------------------------------------------------- state -- */
static ngws_server_t *srv;              /* set once in server_run */
static int n_shards = 1;                /* workers running; immutable while loops run */
static ng_atomic_ullong next_conn_id = { 1 };
static char *info_doc;                  /* NIP-11 document, immutable while loops run */
static size_t info_doc_len;
static ng_atomic_llong stat_open_conns;
static ng_atomic_ullong stat_shed_loop, stat_shed_core;

static int env_int(const char *name, int dflt) {
    const char *v = getenv(name);
    int x = v ? atoi(v) : 0;
    return x > 0 ? x : dflt;
}

/* ------------------------------------------------------------ admission --
 * Worker-side admission (relay_core hook), checked before any expensive
 * work: signature verification for EVENT, the query for REQ/COUNT. Also used
 * quietly (no stat) by batch pre-verification. */
bool ngb_admit(relay_conn_t *rc, relay_admit_kind_t kind, const char **why) {
    ng_conn_t *c = ngb_conn(rc);
    size_t total = ngb_outbox_pending_bytes() + (srv ? ngws_server_backlog_bytes(srv) : 0);
    bool ok = total < opt.total_outbound_max / 10 * 9;   /* 90%: shedding (75%, ngws) did not keep up */
    if (ok && ng_atomic_load_explicit(&c->out_buffered, NG_MO_RELAXED) > opt.conn_outbound_max / 2) {
        ok = false; *why = "error: output backlog too large, read faster";   /* slow reader */
    } else if (!ok) *why = NGB_OVERLOAD_MSG;
    if (ok && kind == RELAY_ADMIT_EVENT && ngb_writer_depth() >= opt.writer_queue_max) {
        ok = false; *why = NGB_OVERLOAD_MSG;
    }
    return ok;
}

static bool core_admit(relay_conn_t *rc, relay_admit_kind_t kind, const char **why) {
    bool ok = ngb_admit(rc, kind, why);
    if (!ok) ng_atomic_fetch_add_explicit(&stat_shed_core, 1, NG_MO_RELAXED);
    return ok;
}

/* Inline rejection on the I/O thread when a message cannot be queued
 * (worker budget, per-connection pending limit, or allocation failure).
 * Never blocks; see relay_wire_overload_reply. */
static void shed_inline(ngws_socket_t *ws, const char *data, size_t len) {
    char out[RELAY_WIRE_REPLY_MAX];
    ng_atomic_fetch_add_explicit(&stat_shed_loop, 1, NG_MO_RELAXED);
    size_t n = relay_wire_overload_reply(data, len, NGB_OVERLOAD_MSG, out, sizeof(out));
    if (n) ngws_send(ws, out, n, NGWS_OP_TEXT);
}

/* ----------------------------------------------------- ngws callbacks ----
 * All run on the socket's I/O loop thread. */
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

static void on_open(ngws_socket_t *ws, const ngws_http_req_t *req) {
    (void) req;
    ng_conn_t *c = (ng_conn_t *) calloc(1, sizeof(*c));
    if (!c) { ngws_terminate(ws); return; }
    c->base.id = ng_atomic_fetch_add(&next_conn_id, 1);
    c->base.ops = &ngb_conn_ops;
    c->base.backend = c;
    c->base.shard = (int) (c->base.id % (uint64_t) n_shards);
    ng_atomic_init(&c->base.refs, 1);            /* held by the socket */
    c->loop = ngws_socket_loop(ws);
    c->ws = ws;
    ngws_remote_address(ws, c->base.peer, sizeof(c->base.peer));
    *(ng_conn_t **) ngws_user(ws) = c;
    ng_atomic_fetch_add(&stat_open_conns, 1);
    if (!ngb_queue_open(c)) {                    /* no protocol state: refuse */
        static const char notice[] = "[\"NOTICE\",\"error: server unavailable\"]";
        ngws_send(ws, notice, sizeof(notice) - 1, NGWS_OP_TEXT);
        ngws_close(ws, 1011, "server unavailable");
    }
}

static void on_drain(ngws_socket_t *ws) {
    ng_conn_t *c = *(ng_conn_t **) ngws_user(ws);
    if (c) ng_atomic_store_explicit(&c->out_buffered, ngws_buffered(ws), NG_MO_RELAXED);
}

static void on_message(ngws_socket_t *ws, char *data, size_t len, int op) {
    (void) op;
    ng_conn_t *c = *(ng_conn_t **) ngws_user(ws);
    if (!c) return;
    if (ng_atomic_load_explicit(&c->pending, NG_MO_RELAXED) >= opt.conn_pending_max ||
        ngb_worker_queued_bytes(c->base.shard) + ngb_message_cost(len) > opt.worker_queue_max ||
        !ngb_queue_message(c, data, len))        /* OOM: answer, never drop silently */
        shed_inline(ws, data, len);
}

static void on_close(ngws_socket_t *ws, int code) {
    (void) code;
    ng_conn_t *c = *(ng_conn_t **) ngws_user(ws);
    if (!c) return;
    *(ng_conn_t **) ngws_user(ws) = NULL;
    c->ws = NULL;
    ng_atomic_store(&c->base.closed, true);
    ng_atomic_fetch_sub(&stat_open_conns, 1);
    ngb_queue_close(c);                          /* hands over the socket's ref */
}

/* ----------------------------------------------------------------- run --- */
void server_set_config(const ng_config_t *cfg) { opt = *cfg; opt_set = true; }

static long usable_cpus(void) {
    /* CPUs this process may run on (taskset/cgroup cpusets), not all online. */
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
#ifdef __linux__
    { cpu_set_t cs; if (sched_getaffinity(0, sizeof(cs), &cs) == 0 && CPU_COUNT(&cs) > 0) ncpu = CPU_COUNT(&cs); }
#endif
    return ncpu < 1 ? 1 : ncpu;
}

bool server_run(int port) {
    if (!relay_core_storage() || port < 1 || port > 65535) return false;
    if (!opt_set) { ng_config_defaults(&opt); opt_set = true; }
    long ncpu = usable_cpus();
    int n_loops = env_int("NG_IO_THREADS", opt.io_threads ? opt.io_threads : IO_THREADS_AUTO(ncpu));
    int n_workers = env_int("NG_WORKERS", opt.workers ? opt.workers : (int) ncpu);
    if (n_loops > NG_MAX_IO_LOOPS) n_loops = NG_MAX_IO_LOOPS;
    if (n_workers > RELAY_MAX_SHARDS) n_workers = RELAY_MAX_SHARDS;

    const char *doc = relay_core_info_document();
    if (doc) { info_doc = strdup(doc); info_doc_len = info_doc ? strlen(info_doc) : 0; }
    signal(SIGPIPE, SIG_IGN);
    relay_core_set_publisher(ngb_writer_publish);
    relay_core_set_admission(core_admit);
    relay_core_set_query_bytes_max(opt.conn_outbound_max / 2);
    const char *bv = getenv("NG_BATCH_VERIFY");      /* NG_BATCH_VERIFY=0 disables (A/B benchmarks) */

    n_shards = ngb_workers_start(n_workers, !(bv && strcmp(bv, "0") == 0));
    bool ok = n_shards > 0 && ngb_writer_start(opt.writer_queue_max);
    if (!ok) fprintf(stderr, "server: could not start worker/writer threads\n");

    if (ok) {
        ngws_config_t cfg; memset(&cfg, 0, sizeof(cfg));
        cfg.port = port;
        cfg.loops = n_loops;
        cfg.max_payload = ng_limits.max_message_length;
        cfg.max_backpressure = opt.conn_outbound_max;
        cfg.max_total_backlog = opt.total_outbound_max;
        cfg.listen_backlog = opt.listen_backlog;
        cfg.idle_timeout = (unsigned) env_int("NG_IDLE_TIMEOUT", 120);
        cfg.handshake_timeout = 16;
        cfg.user_size = sizeof(ng_conn_t *);
        cfg.on_open = on_open; cfg.on_message = on_message; cfg.on_close = on_close; cfg.on_drain = on_drain;
        cfg.on_http = on_http;
        srv = ngws_server_create(&cfg);
        if (srv) ngb_outbox_set_server(srv);
        fprintf(stderr, "nostrogotho (ngws) listening on :%d  io_loops=%d workers=%d writer=1 backlog=%d\n",
                port, n_loops, n_shards, ngws_listen_backlog(&cfg));
        ok = srv && ngws_server_run(srv);
    }

    ngb_writer_stop();          /* still hands broadcasts to the workers */
    ngb_workers_stop();
    if (srv) {
        ngws_stats_t ns; ngws_server_stats(srv, &ns);
        fprintf(stderr, "overload: shed_inline=%llu shed_admission=%llu shed_writer_full=%llu "
                "closed_conn_limit=%llu closed_total_limit=%llu batch_verified=%llu\n",
                (unsigned long long) ng_atomic_load(&stat_shed_loop), (unsigned long long) ng_atomic_load(&stat_shed_core),
                ngb_writer_shed(), ns.closed_conn_limit, ns.closed_total_limit, ngb_workers_preverified());
    }
    relay_core_shutdown();
    return ok;
}

void server_stop(void) {
    if (srv) ngws_server_stop(srv);
}
