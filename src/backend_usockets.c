/* ============================================================================
 * uSockets backend (Apache-2.0 transport + in-tree RFC 6455; no TLS: put
 * nginx/haproxy in front for wss://).
 *
 * Thread layout
 *   I/O loops  (NG_IO_THREADS, default nproc/4, min 1): one uSockets epoll
 *              loop each, all listening on the same port via SO_REUSEPORT.
 *              They only do TCP, HTTP upgrade, NIP-11, WS framing.
 *   Workers    (NG_WORKERS, default nproc): each connection is pinned to
 *              one worker (id % W). The worker owns that connection's
 *              protocol state and subscriptions (one relay_core shard),
 *              runs JSON parsing, signature verification, REQ queries on
 *              its own read-only SQLite connection, and broadcast matching
 *              for its shard.
 *   Writer     exactly ONE thread with the only read-write SQLite
 *              connection. Prechecked EVENTs are queued to it; it commits
 *              them in batches (BEGIN IMMEDIATE..COMMIT), then sends OK and
 *              fans the event out to every worker for matching. Plugin
 *              timers (e.g. NIP-40 GC) also run here.
 * Cross-thread sends go through a per-loop mutex queue + us_wakeup_loop().
 * ============================================================================ */
#include <arpa/inet.h>
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

#include "libusockets.h"
#include "relay_conn_internal.h"
#include "relay_core.h"
#include "server.h"
#include "ws_proto.h"

#define MAX_WS_MESSAGE   (5u * 1024 * 1024)
#define MAX_HTTP_HEADER  8192
#define MAX_OUT_BUFFER   (32u * 1024 * 1024)   /* slow-consumer cutoff */
#define MAX_IO_LOOPS     64
#define WRITER_BATCH     1024

/* ---------------------------------------------------------------- types -- */
typedef struct io_loop io_loop_t;

typedef struct {
    relay_conn_t base;          /* must be first */
    io_loop_t *io;
    struct us_socket_t *s;      /* touched only on io's thread */
} us_conn_t;

typedef struct outmsg {
    struct outmsg *next;
    us_conn_t *conn;
    int close;                  /* 1 = close request, 0 = data */
    size_t len;
    char data[];
} outmsg_t;

struct io_loop {
    int idx;
    struct us_loop_t *loop;
    struct us_socket_context_t *ctx;
    struct us_listen_socket_t *ls;
    pthread_t th;
    pthread_mutex_t mu;
    outmsg_t *head, *tail;
    atomic_bool wake_pending;
};

enum { ST_HTTP = 0, ST_WS = 1, ST_CLOSING = 2 };

typedef struct {
    us_conn_t *conn;
    io_loop_t *io;
    int state;
    int msg_op;
    bool shutdown_after_flush;
    bool in_data;               /* inside on_data: defer buffer frees */
    unsigned char *rbuf; size_t rlen, rcap;
    unsigned char *msg; size_t mlen, mcap;
    char *obuf; size_t olen, ooff, ocap;
} sock_t;

typedef struct bcast {
    event_t ev;
    atomic_int refs;
} bcast_t;

enum { J_OPEN, J_MSG, J_CLOSE, J_BCAST };
typedef struct job {
    struct job *next;
    int type;
    us_conn_t *conn;
    bcast_t *bc;
    size_t len;
    char *payload;
} job_t;

typedef struct {
    int idx;
    pthread_t th;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    job_t *head, *tail;
} worker_t;

typedef struct wjob {
    struct wjob *next;
    us_conn_t *conn;
    event_t *ev;
} wjob_t;

/* ---------------------------------------------------------------- state -- */
static io_loop_t loops[MAX_IO_LOOPS];
static int n_loops;
static worker_t workers[RELAY_MAX_SHARDS];
static int n_workers;
static atomic_ullong next_conn_id = 1;
static atomic_bool stopping;
static int listen_port;
static char *info_doc;          /* cached NIP-11 document */
static size_t info_doc_len;

static pthread_t writer_th;
static pthread_mutex_t writer_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t writer_cv = PTHREAD_COND_INITIALIZER;
static wjob_t *writer_head, *writer_tail;

/* stats */
static atomic_llong stat_open_conns;

/* --------------------------------------------------------- worker queue -- */
static void worker_push(int w, job_t *j) {
    worker_t *wk = &workers[w];
    j->next = NULL;
    pthread_mutex_lock(&wk->mu);
    bool was_empty = wk->head == NULL;
    if (wk->tail) wk->tail->next = j; else wk->head = j;
    wk->tail = j;
    pthread_mutex_unlock(&wk->mu);
    if (was_empty) pthread_cond_signal(&wk->cv);
}

static job_t *job_new(int type, us_conn_t *c) {
    job_t *j = (job_t *) calloc(1, sizeof(*j));
    if (j) { j->type = type; j->conn = c; }
    return j;
}

/* ------------------------------------------------------- outbound path -- */
static void io_enqueue(io_loop_t *io, outmsg_t *m) {
    m->next = NULL;
    pthread_mutex_lock(&io->mu);
    if (io->tail) io->tail->next = m; else io->head = m;
    io->tail = m;
    pthread_mutex_unlock(&io->mu);
    if (!atomic_exchange(&io->wake_pending, true)) us_wakeup_loop(io->loop);
}

static void usb_send(relay_conn_t *rc, const char *json, size_t len) {
    us_conn_t *c = (us_conn_t *) rc;
    unsigned char hdr[10];
    size_t hl = ws_frame_header(hdr, WS_OP_TEXT, len);
    outmsg_t *m = (outmsg_t *) malloc(sizeof(*m) + hl + len);
    if (!m) return;
    m->conn = c; m->close = 0; m->len = hl + len;
    memcpy(m->data, hdr, hl);
    memcpy(m->data + hl, json, len);
    relay_conn_retain(rc);
    io_enqueue(c->io, m);
}

static void usb_close(relay_conn_t *rc) {
    us_conn_t *c = (us_conn_t *) rc;
    outmsg_t *m = (outmsg_t *) malloc(sizeof(*m));
    if (!m) return;
    m->conn = c; m->close = 1; m->len = 0;
    relay_conn_retain(rc);
    io_enqueue(c->io, m);
}

static void usb_destroy(relay_conn_t *rc) { free(rc); }
static const relay_backend_ops_t us_ops = { usb_send, usb_close, usb_destroy };

/* Socket-level buffered write with backpressure (loop thread only). */
static void sock_write(struct us_socket_t *s, sock_t *st, const char *data, size_t len) {
    if (st->olen == st->ooff) {
        st->olen = st->ooff = 0;
        int w = us_socket_write(0, s, data, (int) len, 0);
        if (w < 0) w = 0;
        if ((size_t) w == len) return;
        data += w; len -= (size_t) w;
    }
    if (st->olen - st->ooff + len > MAX_OUT_BUFFER) {
        us_socket_close(0, s, 0, NULL);          /* slow consumer */
        return;
    }
    if (st->ooff > 0 && st->olen + len > st->ocap) {
        memmove(st->obuf, st->obuf + st->ooff, st->olen - st->ooff);
        st->olen -= st->ooff; st->ooff = 0;
    }
    if (st->olen + len > st->ocap) {
        size_t nc = st->ocap ? st->ocap : 4096;
        while (nc < st->olen + len) nc *= 2;
        char *nb = (char *) realloc(st->obuf, nc);
        if (!nb) { us_socket_close(0, s, 0, NULL); return; }
        st->obuf = nb; st->ocap = nc;
    }
    memcpy(st->obuf + st->olen, data, len);
    st->olen += len;
}

static struct us_socket_t *on_writable(struct us_socket_t *s) {
    sock_t *st = (sock_t *) us_socket_ext(0, s);
    while (st->olen > st->ooff) {
        int w = us_socket_write(0, s, st->obuf + st->ooff, (int) (st->olen - st->ooff), 0);
        if (w <= 0) return s;
        st->ooff += (size_t) w;
    }
    free(st->obuf); st->obuf = NULL; st->olen = st->ooff = st->ocap = 0;
    if (st->shutdown_after_flush) us_socket_shutdown(0, s);
    return s;
}

static void send_frame(struct us_socket_t *s, sock_t *st, int op, const void *p, size_t n) {
    unsigned char hdr[10];
    size_t hl = ws_frame_header(hdr, op, n);
    if (st->olen == st->ooff && n < 4096) {
        char tmp[4106];
        memcpy(tmp, hdr, hl); memcpy(tmp + hl, p, n);
        sock_write(s, st, tmp, hl + n);
    } else {
        sock_write(s, st, (const char *) hdr, hl);
        sock_write(s, st, (const char *) p, n);
    }
}

static void ws_fail(struct us_socket_t *s, sock_t *st, unsigned code) {
    if (us_socket_is_closed(0, s)) return;
    unsigned char b[2] = { (unsigned char) (code >> 8), (unsigned char) code };
    if (st->state == ST_WS) send_frame(s, st, WS_OP_CLOSE, b, 2);
    st->state = ST_CLOSING;
    if (st->olen > st->ooff) st->shutdown_after_flush = true;
    else us_socket_shutdown(0, s);
}

static void wakeup_cb(struct us_loop_t *loop) {
    io_loop_t *io = *(io_loop_t **) us_loop_ext(loop);
    atomic_store(&io->wake_pending, false);
    pthread_mutex_lock(&io->mu);
    outmsg_t *m = io->head;
    io->head = io->tail = NULL;
    pthread_mutex_unlock(&io->mu);
    while (m) {
        outmsg_t *next = m->next;
        us_conn_t *c = m->conn;
        if (!atomic_load(&c->base.closed) && c->s) {
            sock_t *st = (sock_t *) us_socket_ext(0, c->s);
            if (m->close) ws_fail(c->s, st, 1000);
            else if (st->state == ST_WS) sock_write(c->s, st, m->data, m->len);
        }
        relay_conn_unref(&c->base);
        free(m);
        m = next;
    }
    if (atomic_load(&stopping)) {
        if (io->ls) { us_listen_socket_close(0, io->ls); io->ls = NULL; }
        us_socket_context_close(0, io->ctx);
    }
}

/* --------------------------------------------------------- inbound path -- */
static bool header_value(const char *hdrs, size_t n, const char *name, const char **v, size_t *vl) {
    size_t nl = strlen(name);
    const char *p = hdrs, *end = hdrs + n;
    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t) (end - p));
        if (!eol) eol = end;
        if ((size_t) (eol - p) > nl && strncasecmp(p, name, nl) == 0 && p[nl] == ':') {
            const char *a = p + nl + 1, *b = eol;
            while (a < b && (*a == ' ' || *a == '\t')) a++;
            while (b > a && (b[-1] == '\r' || b[-1] == ' ' || b[-1] == '\t')) b--;
            *v = a; *vl = (size_t) (b - a);
            return true;
        }
        p = eol + 1;
    }
    return false;
}

static bool contains_ci(const char *v, size_t vl, const char *needle) {
    size_t n = strlen(needle);
    for (size_t i = 0; i + n <= vl; i++) if (strncasecmp(v + i, needle, n) == 0) return true;
    return false;
}

static void http_reply_close(struct us_socket_t *s, sock_t *st, const char *status,
                             const char *ctype, const char *body, size_t blen) {
    char head[512];
    int hl = snprintf(head, sizeof(head),
        "HTTP/1.1 %s\r\nContent-Type: %s\r\nAccess-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: *\r\nAccess-Control-Allow-Methods: GET, OPTIONS\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n", status, ctype, blen);
    sock_write(s, st, head, (size_t) hl);
    if (blen) sock_write(s, st, body, blen);
    st->state = ST_CLOSING;
    if (us_socket_is_closed(0, s)) return;
    if (st->olen > st->ooff) st->shutdown_after_flush = true;
    else us_socket_shutdown(0, s);
}

/* Returns bytes consumed from rbuf (0 = need more), or -1 on fatal. */
static long handle_http(struct us_socket_t *s, sock_t *st, unsigned char *ub, size_t n) {
    const char *b = (const char *) ub;
    const char *endh = NULL;
    for (size_t i = 3; i < n; i++) if (b[i] == '\n' && b[i-1] == '\r' && b[i-2] == '\n' && b[i-3] == '\r') { endh = b + i + 1; break; }
    if (!endh) {
        if (n > MAX_HTTP_HEADER) { http_reply_close(s, st, "431 Request Header Fields Too Large", "text/plain", "", 0); return -1; }
        return 0;
    }
    size_t hn = (size_t) (endh - b);
    const char *v; size_t vl;
    bool is_get = hn > 4 && memcmp(b, "GET ", 4) == 0;
    bool is_options = hn > 8 && memcmp(b, "OPTIONS ", 8) == 0;
    if (is_options) { http_reply_close(s, st, "204 No Content", "text/plain", "", 0); return -1; }
    if (!is_get) { http_reply_close(s, st, "405 Method Not Allowed", "text/plain", "", 0); return -1; }
    bool upgrade = header_value(b, hn, "Upgrade", &v, &vl) && contains_ci(v, vl, "websocket");
    if (!upgrade) {
        if (header_value(b, hn, "Accept", &v, &vl) && contains_ci(v, vl, "application/nostr+json") && info_doc)
            http_reply_close(s, st, "200 OK", "application/nostr+json", info_doc, info_doc_len);
        else {
            static const char msg[] = "nostrogotho relay: connect with a Nostr client (WebSocket)\n";
            http_reply_close(s, st, "200 OK", "text/plain", msg, sizeof(msg) - 1);
        }
        return -1;
    }
    if (!header_value(b, hn, "Sec-WebSocket-Key", &v, &vl) || vl == 0 || vl > 64) {
        http_reply_close(s, st, "400 Bad Request", "text/plain", "", 0); return -1;
    }
    char accept[29];
    ws_accept_key(v, vl, accept);
    char resp[256];
    int rl = snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n", accept);
    sock_write(s, st, resp, (size_t) rl);
    st->state = ST_WS;
    us_socket_timeout(0, s, 0);   /* no idle timeout once upgraded */

    us_conn_t *c = (us_conn_t *) calloc(1, sizeof(*c));
    if (!c) return -1;
    c->base.id = atomic_fetch_add(&next_conn_id, 1);
    c->base.ops = &us_ops;
    c->base.backend = c;
    c->base.shard = (int) (c->base.id % (uint64_t) n_workers);
    atomic_init(&c->base.refs, 1);            /* held by the socket */
    c->io = st->io;
    c->s = s;
    char ip[16]; int iplen = sizeof(ip);
    us_socket_remote_address(0, s, ip, &iplen);
    if (iplen == 4) inet_ntop(AF_INET, ip, c->base.peer, sizeof(c->base.peer));
    else if (iplen == 16) inet_ntop(AF_INET6, ip, c->base.peer, sizeof(c->base.peer));
    snprintf(c->base.peer + strlen(c->base.peer), sizeof(c->base.peer) - strlen(c->base.peer), ":%d", us_socket_remote_port(0, s));
    st->conn = c;
    atomic_fetch_add(&stat_open_conns, 1);
    job_t *j = job_new(J_OPEN, c);
    if (j) { relay_conn_retain(&c->base); worker_push(c->base.shard, j); }
    return (long) hn;
}

static void dispatch_message(sock_t *st, const unsigned char *p, size_t n) {
    us_conn_t *c = st->conn;
    job_t *j = job_new(J_MSG, c);
    if (!j) return;
    j->payload = (char *) malloc(n + 1);
    if (!j->payload) { free(j); return; }
    memcpy(j->payload, p, n); j->payload[n] = '\0'; j->len = n;
    relay_conn_retain(&c->base);
    worker_push(c->base.shard, j);
}

/* Returns bytes consumed (0 = need more), -1 = connection failed. */
static long handle_ws(struct us_socket_t *s, sock_t *st, unsigned char *b, size_t blen) {
    ws_frame_t f;
    int r = ws_parse_header(b, blen, &f);
    if (r < 0) { ws_fail(s, st, 1002); return -1; }
    if (r == 0) return 0;
    if (!f.masked) { ws_fail(s, st, 1002); return -1; }
    if (f.len > MAX_WS_MESSAGE || st->mlen + f.len > MAX_WS_MESSAGE) { ws_fail(s, st, 1009); return -1; }
    if (blen < f.header_len + f.len) return 0;
    unsigned char *p = b + f.header_len;
    size_t n = (size_t) f.len;
    ws_unmask(p, n, f.mask);
    switch (f.opcode) {
    case WS_OP_PING: send_frame(s, st, WS_OP_PONG, p, n); break;
    case WS_OP_PONG: break;
    case WS_OP_CLOSE: {
        unsigned char code[2] = { 0x03, 0xE8 };
        if (n >= 2) { code[0] = p[0]; code[1] = p[1]; }
        send_frame(s, st, WS_OP_CLOSE, code, 2);
        st->state = ST_CLOSING;
        if (st->olen > st->ooff) st->shutdown_after_flush = true; else us_socket_shutdown(0, s);
        return -1;
    }
    case WS_OP_TEXT: case WS_OP_BIN:
        if (st->mlen || st->msg_op) { ws_fail(s, st, 1002); return -1; }
        if (f.fin) dispatch_message(st, p, n);
        else {
            st->msg_op = f.opcode;
            st->mcap = n > 1024 ? n * 2 : 2048;
            st->msg = (unsigned char *) malloc(st->mcap);
            if (!st->msg) { ws_fail(s, st, 1011); return -1; }
            memcpy(st->msg, p, n); st->mlen = n;
        }
        break;
    case WS_OP_CONT:
        if (!st->msg_op) { ws_fail(s, st, 1002); return -1; }
        if (st->mlen + n > st->mcap) {
            size_t nc = st->mcap; while (nc < st->mlen + n) nc *= 2;
            unsigned char *nb = (unsigned char *) realloc(st->msg, nc);
            if (!nb) { ws_fail(s, st, 1011); return -1; }
            st->msg = nb; st->mcap = nc;
        }
        memcpy(st->msg + st->mlen, p, n); st->mlen += n;
        if (f.fin) {
            dispatch_message(st, st->msg, st->mlen);
            free(st->msg); st->msg = NULL; st->mlen = st->mcap = 0; st->msg_op = 0;
        }
        break;
    }
    return (long) (f.header_len + n);
}

static struct us_socket_t *on_data(struct us_socket_t *s, char *data, int length) {
    sock_t *st = (sock_t *) us_socket_ext(0, s);
    if (st->state == ST_CLOSING || length <= 0) return s;
    if (st->rlen + (size_t) length > st->rcap) {
        size_t nc = st->rcap ? st->rcap : 4096;
        while (nc < st->rlen + (size_t) length) nc *= 2;
        unsigned char *nb = (unsigned char *) realloc(st->rbuf, nc);
        if (!nb) return us_socket_close(0, s, 0, NULL);
        st->rbuf = nb; st->rcap = nc;
    }
    memcpy(st->rbuf + st->rlen, data, (size_t) length);
    st->rlen += (size_t) length;
    size_t off = 0;
    st->in_data = true;
    while (off < st->rlen && st->state != ST_CLOSING && !us_socket_is_closed(0, s)) {
        long used = st->state == ST_HTTP ? handle_http(s, st, st->rbuf + off, st->rlen - off)
                                         : handle_ws(s, st, st->rbuf + off, st->rlen - off);
        if (used <= 0) break;
        off += (size_t) used;
    }
    st->in_data = false;
    if (us_socket_is_closed(0, s)) {          /* on_close ran: we own the frees */
        free(st->rbuf); st->rbuf = NULL; st->rlen = st->rcap = 0;
        return s;
    }
    if (off >= st->rlen || st->state == ST_CLOSING) {
        free(st->rbuf); st->rbuf = NULL; st->rlen = st->rcap = 0;   /* idle conns hold no buffer */
    } else if (off) {
        memmove(st->rbuf, st->rbuf + off, st->rlen - off);
        st->rlen -= off;
    }
    return s;
}

static struct us_socket_t *on_open(struct us_socket_t *s, int is_client, char *ip, int ip_length) {
    (void) is_client; (void) ip; (void) ip_length;
    sock_t *st = (sock_t *) us_socket_ext(0, s);
    memset(st, 0, sizeof(*st));
    struct us_loop_t *loop = us_socket_context_loop(0, us_socket_context(0, s));
    st->io = *(io_loop_t **) us_loop_ext(loop);
    us_socket_timeout(0, s, 15);             /* handshake deadline */
    return s;
}

static struct us_socket_t *on_close(struct us_socket_t *s, int code, void *reason) {
    (void) code; (void) reason;
    sock_t *st = (sock_t *) us_socket_ext(0, s);
    if (!st->in_data) { free(st->rbuf); st->rbuf = NULL; st->rlen = st->rcap = 0; }
    free(st->msg); free(st->obuf);
    st->msg = NULL; st->obuf = NULL; st->olen = st->ooff = st->ocap = 0;
    us_conn_t *c = st->conn;
    if (c) {
        st->conn = NULL;
        c->s = NULL;
        atomic_store(&c->base.closed, true);
        atomic_fetch_sub(&stat_open_conns, 1);
        job_t *j = job_new(J_CLOSE, c);     /* inherits the socket's ref */
        if (j) worker_push(c->base.shard, j);
        else relay_conn_unref(&c->base);
    }
    return s;
}

static struct us_socket_t *on_end(struct us_socket_t *s) { return us_socket_close(0, s, 0, NULL); }
static struct us_socket_t *on_timeout(struct us_socket_t *s) {
    sock_t *st = (sock_t *) us_socket_ext(0, s);
    if (st->state != ST_WS) return us_socket_close(0, s, 0, NULL);
    return s;
}

static void loop_noop(struct us_loop_t *loop) { (void) loop; }
static struct us_socket_t *on_long_timeout(struct us_socket_t *s) { return s; }

static void *io_thread(void *arg) {
    io_loop_t *io = (io_loop_t *) arg;
    us_loop_run(io->loop);
    return NULL;
}

/* -------------------------------------------------------------- workers -- */
static void bcast_unref(bcast_t *b) {
    if (atomic_fetch_sub(&b->refs, 1) == 1) { event_release(&b->ev); free(b); }
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
                free(j->payload); relay_conn_unref(rc); break;
            case J_CLOSE: if (rc->core) relay_core_on_close(rc); relay_conn_unref(rc); break;
            case J_BCAST: relay_core_broadcast_shard(wk->idx, &j->bc->ev); bcast_unref(j->bc); break;
            }
            free(j);
            j = next;
        }
    }
    if (st->thread_close) st->thread_close();
    return NULL;
}

/* --------------------------------------------------------------- writer -- */
static void publish_to_writer(relay_conn_t *rc, event_t *ev) {
    wjob_t *w = (wjob_t *) malloc(sizeof(*w));
    if (!w) { event_release(ev); free(ev); relay_conn_unref(rc); return; }
    w->next = NULL; w->conn = (us_conn_t *) rc; w->ev = ev;
    pthread_mutex_lock(&writer_mu);
    bool was_empty = writer_head == NULL;
    if (writer_tail) writer_tail->next = w; else writer_head = w;
    writer_tail = w;
    pthread_mutex_unlock(&writer_mu);
    if (was_empty) pthread_cond_signal(&writer_cv);
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
        while (writer_head && n < WRITER_BATCH) {
            batch[n++] = writer_head;
            writer_head = writer_head->next;
        }
        if (!writer_head) writer_tail = NULL;
        bool stop = atomic_load(&stopping) && n == 0;
        pthread_mutex_unlock(&writer_mu);
        if (stop) break;

        if (interval && now_ms() >= next_timer) {
            relay_core_run_timers();
            next_timer = now_ms() + interval;
        }
        if (n == 0) continue;

        bool tx = st->begin_batch && st->begin_batch();
        for (int i = 0; i < n; i++) results[i] = relay_core_commit_event(&batch[i]->conn->base, batch[i]->ev);
        if (tx && st->commit_batch && !st->commit_batch()) {
            for (int i = 0; i < n; i++) if (results[i].accepted) {
                results[i].accepted = false; results[i].should_broadcast = false;
                snprintf(results[i].response_msg, sizeof(results[i].response_msg), "error: storage commit failed");
            }
        }
        for (int i = 0; i < n; i++) {
            relay_conn_t *rc = &batch[i]->conn->base;
            relay_core_send_ok(rc, batch[i]->ev, &results[i]);
            if (results[i].accepted && results[i].should_broadcast) {
                bcast_t *b = (bcast_t *) malloc(sizeof(*b));
                if (b) {
                    b->ev = *batch[i]->ev;             /* take ownership */
                    atomic_init(&b->refs, n_workers);
                    for (int w = 0; w < n_workers; w++) {
                        job_t *j = job_new(J_BCAST, NULL);
                        if (!j) { bcast_unref(b); continue; }
                        j->bc = b;
                        worker_push(w, j);
                    }
                    free(batch[i]->ev);
                } else { event_release(batch[i]->ev); free(batch[i]->ev); }
            } else { event_release(batch[i]->ev); free(batch[i]->ev); }
            relay_conn_unref(rc);
            free(batch[i]);
        }
    }
    if (st->thread_close) st->thread_close();
    return NULL;
}

/* ----------------------------------------------------------------- run --- */
static int env_int(const char *name, int dflt) {
    const char *v = getenv(name);
    int x = v ? atoi(v) : 0;
    return x > 0 ? x : dflt;
}

bool server_run(int port) {
    if (!relay_core_storage() || port < 1 || port > 65535) return false;
    listen_port = port;
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

    for (int i = 0; i < n_loops; i++) {
        io_loop_t *io = &loops[i];
        io->idx = i;
        pthread_mutex_init(&io->mu, NULL);
        io->loop = us_create_loop(NULL, wakeup_cb, loop_noop, loop_noop, sizeof(io_loop_t *));
        *(io_loop_t **) us_loop_ext(io->loop) = io;
        struct us_socket_context_options_t opts = {0};
        io->ctx = us_create_socket_context(0, io->loop, 0, opts);
        us_socket_context_on_open(0, io->ctx, on_open);
        us_socket_context_on_data(0, io->ctx, on_data);
        us_socket_context_on_writable(0, io->ctx, on_writable);
        us_socket_context_on_close(0, io->ctx, on_close);
        us_socket_context_on_end(0, io->ctx, on_end);
        us_socket_context_on_timeout(0, io->ctx, on_timeout);
        us_socket_context_on_long_timeout(0, io->ctx, on_long_timeout);
        io->ls = us_socket_context_listen(0, io->ctx, NULL, port, 0, sizeof(sock_t));
        if (!io->ls) { fprintf(stderr, "listen on :%d failed\n", port); return false; }
    }
    fprintf(stderr, "nostrogotho (uSockets backend) listening on :%d  io_loops=%d workers=%d writer=1\n",
            port, n_loops, n_workers);
    for (int i = 0; i < n_loops; i++) pthread_create(&loops[i].th, NULL, io_thread, &loops[i]);
    for (int i = 0; i < n_loops; i++) pthread_join(loops[i].th, NULL);

    atomic_store(&stopping, true);
    pthread_cond_broadcast(&writer_cv);
    pthread_join(writer_th, NULL);
    for (int i = 0; i < n_workers; i++) {
        pthread_mutex_lock(&workers[i].mu);
        pthread_cond_broadcast(&workers[i].cv);
        pthread_mutex_unlock(&workers[i].mu);
        pthread_join(workers[i].th, NULL);
    }
    relay_core_shutdown();
    return true;
}

void server_stop(void) {
    atomic_store(&stopping, true);
    for (int i = 0; i < n_loops; i++) if (loops[i].loop) us_wakeup_loop(loops[i].loop);
}
