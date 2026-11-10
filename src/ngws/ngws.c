/* ngws - see ngws.h. MIT, in-tree. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ngws.h"

#include <arpa/inet.h>
#ifdef __GLIBC__
#include <malloc.h>
#endif
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "libusockets.h"
#include "../ws_proto.h"


#define MAX_HTTP_HEADER   8192
#define ARENA_CHUNK       (256 * 1024)
#define SEND_WATERMARK    (64 * 1024)
#define DIRECT_MIN        (64 * 1024)  /* frames this big skip the arena copy (send_direct) */
#define MSG_CHUNK         65536      /* pooled message-assembly buffer */
#define POOL_MAX          256        /* pooled buffers kept per loop */
#define MAX_LOOPS         64

enum { ST_HTTP = 0, ST_WS, ST_CLOSING, ST_CLOSED };

typedef struct sockx {
    struct sockx *dprev, *dnext;      /* loop dirty list (needs flush) */
    struct sockx *aprev, *anext;      /* loop list of open WebSockets */
    struct sockx *bprev, *bnext;      /* loop list of sockets owning a backlog buffer */
    struct us_socket_t *s;
    ngws_loop_t *loop;
    uint8_t state, msg_op, ping_sent, dirty, shutdown_after_flush, in_data, in_frame, frame_op, drain;
    unsigned char *rbuf; size_t rlen, rcap;    /* HTTP header / native partial frame */
    unsigned char *msg;  size_t mlen, mcap;    /* fragmented message / split control frame */
    char *obuf; size_t olen, ooff, ocap;       /* backlog the kernel did not take */
    uint32_t qhead, qtail;                     /* this iteration's iovec queue (node idx+1) */
    uint64_t skip;                             /* closing: payload bytes still to discard */
    size_t qbytes;
} sockx_t;

#define USER_OFF ((sizeof(sockx_t) + 15) & ~(size_t) 15)

typedef struct pool_item { struct pool_item *next; } pool_item_t;
typedef struct arena_chunk { struct arena_chunk *next; size_t cap, used; unsigned char data[]; } arena_chunk_t;
typedef struct { const void *p; size_t len; uint32_t next; } ionode_t;
typedef struct { void (*fn)(void *); void *arg; } defer_t;

struct ngws_loop {
    int idx;
    ngws_server_t *srv;
    struct us_loop_t *loop;
    struct us_socket_context_t *ctx;
    struct us_listen_socket_t *ls;
    bool ctx_closed;                    /* loop_stop_listening ran */
    pthread_t th;
    pthread_mutex_t mu;
    ngws_task_t *head, *tail;
    atomic_bool wake_pending;
    sockx_t *dirty;                     /* head of dirty list */
    sockx_t *all;                       /* open WebSockets */
    sockx_t *blog;                      /* sockets with a backlog buffer (obuf) */
    size_t n_open;
    arena_chunk_t *arena, *arena_cur;
    ionode_t *nodes; uint32_t n_nodes, cap_nodes;
    defer_t *defer; uint32_t n_defer, cap_defer;
    pool_item_t *msg_pool; int n_msg_pool;
    void *user;
};

struct ngws_server {
    ngws_config_t cfg;
    int n_loops;
    ngws_loop_t loops[MAX_LOOPS];
    atomic_bool stopping;
    atomic_size_t backlog_total;        /* sum of obuf capacities, all loops */
    atomic_ullong closed_conn_limit, closed_total_limit;
    bool uncork;                        /* flush a socket at the end of its on_data */
};

static inline sockx_t *X(struct us_socket_t *s) { return (sockx_t *) us_socket_ext(0, s); }
static inline ngws_server_t *SRV(sockx_t *x) { return x->loop->srv; }

/* ------------------------------------------------------------- pools ---- */

/* ------------------------------------------------------------- frames --- */
size_t ngws_frame_overhead(size_t len) { return len < 126 ? 2 : len <= 0xFFFF ? 4 : 10; }


size_t ngws_frame_build(void *out, int op, const void *data, size_t len) {
    size_t h = ws_frame_header((unsigned char *) out, op, len);
    memcpy((char *) out + h, data, len);
    return h + len;
}

/* ------------------------------------------------------------- output --- */
/* Output model
 *   During a loop iteration every send becomes an iovec node on the socket's
 *   queue. Node bytes live in the loop arena (copied once, contiguous, reused
 *   every iteration so it stays in cache) or, for ngws_send_shared(), point at
 *   caller memory shared by many sockets (zero copy broadcast). At the end of
 *   the iteration each dirty socket is flushed with one writev(). Whatever the
 *   kernel does not take is copied into the socket's private backlog buffer
 *   (obuf); while a backlog exists, new sends append to it to keep order. */
static void dirty_add(sockx_t *x) {
    if (x->dirty) return;
    ngws_loop_t *l = x->loop;
    x->dirty = 1; x->dprev = NULL; x->dnext = l->dirty;
    if (l->dirty) l->dirty->dprev = x;
    l->dirty = x;
}
static void dirty_del(sockx_t *x) {
    if (!x->dirty) return;
    if (x->dprev) x->dprev->dnext = x->dnext; else x->loop->dirty = x->dnext;
    if (x->dnext) x->dnext->dprev = x->dprev;
    x->dirty = 0; x->dprev = x->dnext = NULL;
}

static void *arena_alloc(ngws_loop_t *l, size_t n);
void *ngws_loop_alloc(ngws_loop_t *l, size_t n) {
    arena_chunk_t *c = l->arena_cur;
    if (c) c->used = (c->used + 15) & ~(size_t) 15;    /* caller-visible blocks are 16-aligned */
    if (c && c->used > c->cap) c->used = c->cap;
    return arena_alloc(l, (n + 15) & ~(size_t) 15);
}

void *ngws_loop_alloc_frame(ngws_loop_t *l, size_t n) { return arena_alloc(l, n); }

/* Unaligned bump allocation (frame bytes need no alignment), so that a
 * socket's consecutive frames in one iteration land back to back and can
 * be coalesced into a single iovec. */
static void *arena_alloc(ngws_loop_t *l, size_t n) {
    arena_chunk_t *c = l->arena_cur;
    if (c && c->used + n <= c->cap) { void *p = c->data + c->used; c->used += n; return p; }
    /* next chunk: reuse a retained one or allocate */
    arena_chunk_t *nc = c ? c->next : l->arena;
    if (nc && nc->cap >= n) { nc->used = n; l->arena_cur = nc; return nc->data; }
    size_t cap = n > ARENA_CHUNK ? n : ARENA_CHUNK;
    arena_chunk_t *a = (arena_chunk_t *) malloc(sizeof(*a) + cap);
    if (!a) return NULL;
    a->cap = cap; a->used = n;
    if (c) { a->next = c->next; c->next = a; } else { a->next = l->arena; l->arena = a; }
    l->arena_cur = a;
    return a->data;
}

static void arena_reset(ngws_loop_t *l) {
    /* keep the first two standard chunks, free the rest (large/oversized) */
    int kept = 0;
    arena_chunk_t **pp = &l->arena;
    while (*pp) {
        arena_chunk_t *c = *pp;
        if (kept < 2 && c->cap == ARENA_CHUNK) { c->used = 0; kept++; pp = &c->next; }
        else { *pp = c->next; free(c); }
    }
    l->arena_cur = l->arena;
    l->n_nodes = 0;
}

static bool node_add(sockx_t *x, const void *p, size_t n) {
    ngws_loop_t *l = x->loop;
    if (l->n_nodes == l->cap_nodes) {
        uint32_t nc = l->cap_nodes ? l->cap_nodes * 2 : 4096;
        ionode_t *nn = (ionode_t *) realloc(l->nodes, nc * sizeof(ionode_t));
        if (!nn) return false;
        l->nodes = nn; l->cap_nodes = nc;
    }
    uint32_t i = l->n_nodes++;
    l->nodes[i].p = p; l->nodes[i].len = n; l->nodes[i].next = 0;
    if (x->qtail) l->nodes[x->qtail - 1].next = i + 1; else x->qhead = i + 1;
    x->qtail = i + 1;
    x->qbytes += n;
    dirty_add(x);
    return true;
}

/* Grow the private backlog so that `need` bytes fit after compaction.
 * Enforces the per-socket limit (max_backpressure) and the process-wide
 * budget (max_total_backlog): once the budget is exhausted a socket that
 * wants a backlog above the drain watermark is a slow reader and is refused
 * (the caller terminates it). Capacity is accounted, not bytes in use, so
 * the budget tracks real memory. */
static bool obuf_room(sockx_t *x, size_t n) {
    ngws_server_t *srv = SRV(x);
    size_t pending = x->olen - x->ooff;
    if (pending + n > srv->cfg.max_backpressure) { atomic_fetch_add_explicit(&srv->closed_conn_limit, 1, memory_order_relaxed); return false; }
    if (x->olen + n <= x->ocap) return true;
    if (x->ooff) { memmove(x->obuf, x->obuf + x->ooff, pending); x->olen = pending; x->ooff = 0; }
    if (x->olen + n <= x->ocap) return true;
    size_t nc = x->ocap ? x->ocap * 2 : 4096; while (nc < x->olen + n) nc *= 2;
    size_t grow = nc - x->ocap;
    if (srv->cfg.max_total_backlog && pending + n > SEND_WATERMARK &&
        atomic_load_explicit(&srv->backlog_total, memory_order_relaxed) + grow > srv->cfg.max_total_backlog) {
        atomic_fetch_add_explicit(&srv->closed_total_limit, 1, memory_order_relaxed);
        return false;
    }
    char *nb = (char *) realloc(x->obuf, nc);
    if (!nb) return false;
    atomic_fetch_add_explicit(&srv->backlog_total, grow, memory_order_relaxed);
    if (!x->ocap) {                                   /* join the loop's backlog list */
        ngws_loop_t *l = x->loop;
        x->bprev = NULL; x->bnext = l->blog;
        if (l->blog) l->blog->bprev = x;
        l->blog = x;
    }
    x->obuf = nb; x->ocap = nc;
    return true;
}

/* Append to the private backlog buffer. */
static bool backlog_append(sockx_t *x, const void *p, size_t n) {
    if (!obuf_room(x, n)) return false;
    memcpy(x->obuf + x->olen, p, n); x->olen += n;
    return true;
}

static void out_release(sockx_t *x) {
    if (x->ocap) {
        atomic_fetch_sub_explicit(&SRV(x)->backlog_total, x->ocap, memory_order_relaxed);
        if (x->bprev) x->bprev->bnext = x->bnext; else x->loop->blog = x->bnext;
        if (x->bnext) x->bnext->bprev = x->bprev;
        x->bprev = x->bnext = NULL;
    }
    free(x->obuf);
    x->obuf = NULL; x->olen = x->ooff = x->ocap = 0;
}

/* Reserve n writable bytes for this socket's output. NULL = limit/oom (socket terminated). */
static char *out_reserve(sockx_t *x, size_t n) {
    if (x->olen > x->ooff) {                       /* backlog: keep order */
        if (!obuf_room(x, n)) goto fail;
        char *p = x->obuf + x->olen; x->olen += n;
        return p;
    }
    if (x->qbytes + n > SRV(x)->cfg.max_backpressure) { atomic_fetch_add_explicit(&SRV(x)->closed_conn_limit, 1, memory_order_relaxed); goto fail; }
    ngws_loop_t *l = x->loop;
    arena_chunk_t *c = l->arena_cur;
    if (x->qtail && c && c->used + n <= c->cap) {
        ionode_t *t = &l->nodes[x->qtail - 1];
        if ((const unsigned char *) t->p + t->len == c->data + c->used) {   /* extend our tail iovec */
            char *p = (char *) c->data + c->used;
            c->used += n; t->len += n; x->qbytes += n;
            return p;
        }
    }
    char *p = (char *) arena_alloc(l, n);
    if (!p || !node_add(x, p, n)) goto fail;
    return p;
fail:
    ngws_terminate((ngws_socket_t *) x->s);
    return NULL;
}

/* Write pending output. Returns true if everything was flushed. */
static bool flush(sockx_t *x) {
    struct us_socket_t *s = x->s;
    ngws_loop_t *l = x->loop;
    while (x->ooff < x->olen) {                     /* backlog first */
        size_t n = x->olen - x->ooff;
        int w = us_socket_write(0, s, x->obuf + x->ooff, n > 0x40000000 ? 0x40000000 : (int) n, 0);
        if (w <= 0) break;
        x->ooff += (size_t) w;
        if ((size_t) w < n) break;
    }
    if (x->ooff < x->olen) {
        /* still backlogged: move queued nodes behind it */
        for (uint32_t i = x->qhead; i; i = l->nodes[i - 1].next)
            if (!backlog_append(x, l->nodes[i - 1].p, l->nodes[i - 1].len)) { x->qhead = x->qtail = 0; x->qbytes = 0; ngws_terminate((ngws_socket_t *) s); return false; }
        x->qhead = x->qtail = 0; x->qbytes = 0;
        return false;
    }
    if (x->obuf) {
        out_release(x);
        if (x->state == ST_WS && SRV(x)->cfg.on_drain) SRV(x)->cfg.on_drain((ngws_socket_t *) s);
    }
    if (x->qhead) {
        int fd = (int) (intptr_t) us_socket_get_native_handle(0, s);
        uint32_t i = x->qhead;
        while (i) {
            struct iovec iov[64]; int k = 0; size_t want = 0;
            uint32_t j = i;
            for (; j && k < 64; j = l->nodes[j - 1].next, k++) {
                iov[k].iov_base = (void *) l->nodes[j - 1].p; iov[k].iov_len = l->nodes[j - 1].len; want += iov[k].iov_len;
            }
            /* one iovec (the common case: a socket's frames coalesce): send() skips the iovec import */
            ssize_t w = us_socket_is_closed(0, s) || us_socket_is_shut_down(0, s) ? -1 :
                        k == 1 ? send(fd, iov[0].iov_base, iov[0].iov_len, MSG_NOSIGNAL) : writev(fd, iov, k);
            if (w == (ssize_t) want) { i = j; continue; }
            /* partial: copy the unsent rest of this batch and all later nodes to the backlog */
            size_t done = w > 0 ? (size_t) w : 0;
            bool ok = true;
            for (int m = 0; m < k && ok; m++) {
                if (done >= iov[m].iov_len) { done -= iov[m].iov_len; continue; }
                ok = backlog_append(x, (char *) iov[m].iov_base + done, iov[m].iov_len - done);
                done = 0;
            }
            for (; j && ok; j = l->nodes[j - 1].next) ok = backlog_append(x, l->nodes[j - 1].p, l->nodes[j - 1].len);
            x->qhead = x->qtail = 0; x->qbytes = 0;
            if (!ok) { ngws_terminate((ngws_socket_t *) s); return false; }
            if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { ngws_terminate((ngws_socket_t *) s); return false; }
            /* let uSockets arm the writable poll */
            if (x->olen > x->ooff) {
                int w2 = us_socket_write(0, s, x->obuf + x->ooff, (int) (x->olen - x->ooff), 0);
                if (w2 > 0) x->ooff += (size_t) w2;
                if (x->ooff == x->olen) { out_release(x); break; }
            }
            return false;
        }
        x->qhead = x->qtail = 0; x->qbytes = 0;
    }
    if (x->shutdown_after_flush && !us_socket_is_closed(0, s)) us_socket_shutdown(0, s);
    return true;
}

static int send_status(sockx_t *x) {
    return (x->olen - x->ooff) + x->qbytes > SEND_WATERMARK ? NGWS_SEND_BACKPRESSURE : NGWS_SEND_OK;
}

/* Large frame with nothing queued ahead of it: write it straight from the
 * caller's buffer (header + payload in one writev) instead of copying it
 * into the arena first; only what the kernel does not take is copied, to
 * the backlog. Saves one full copy per large message. Smaller frames keep
 * the arena path so a socket's frames coalesce into one writev. */
static int send_direct(sockx_t *x, int op, const void *data, size_t len) {
    struct us_socket_t *s = x->s;
    unsigned char hdr[10];
    size_t h = ws_frame_header(hdr, op, len), total = h + len;
    if (total > SRV(x)->cfg.max_backpressure) { atomic_fetch_add_explicit(&SRV(x)->closed_conn_limit, 1, memory_order_relaxed); ngws_terminate((ngws_socket_t *) s); return NGWS_SEND_DROPPED; }
    struct iovec iov[2] = { { hdr, h }, { (void *) data, len } };
    ssize_t w = writev((int) (intptr_t) us_socket_get_native_handle(0, s), iov, 2);
    if (w == (ssize_t) total) return NGWS_SEND_OK;
    if (w < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { ngws_terminate((ngws_socket_t *) s); return NGWS_SEND_DROPPED; }
        w = 0;
    }
    size_t done = (size_t) w;
    bool ok = done < h ? backlog_append(x, hdr + done, h - done) && backlog_append(x, data, len)
                       : backlog_append(x, (const char *) data + (done - h), len - (done - h));
    if (!ok) { ngws_terminate((ngws_socket_t *) s); return NGWS_SEND_DROPPED; }
    /* let uSockets arm the writable poll (on_writable drains the backlog) */
    int w2 = us_socket_write(0, s, x->obuf + x->ooff, (int) (x->olen - x->ooff), 0);
    if (w2 > 0) x->ooff += (size_t) w2;
    if (x->ooff == x->olen) { out_release(x); return NGWS_SEND_OK; }
    return send_status(x);
}

static int queue_frame(sockx_t *x, int op, const void *data, size_t len) {
    if (len >= DIRECT_MIN && !x->qhead && x->olen == x->ooff && !us_socket_is_closed(0, x->s) &&
        !us_socket_is_shut_down(0, x->s))
        return send_direct(x, op, data, len);
    char *p = out_reserve(x, len + ngws_frame_overhead(len));
    if (!p) return NGWS_SEND_DROPPED;
    size_t h = ws_frame_header((unsigned char *) p, op, len);
    memcpy(p + h, data, len);
    return send_status(x);
}

int ngws_send(ngws_socket_t *ws, const void *data, size_t len, int opcode) {
    struct us_socket_t *s = (struct us_socket_t *) ws;
    sockx_t *x = X(s);
    if (x->state != ST_WS) return NGWS_SEND_DROPPED;
    return queue_frame(x, opcode, data, len);
}

int ngws_send_raw(ngws_socket_t *ws, const void *frame, size_t len) {
    struct us_socket_t *s = (struct us_socket_t *) ws;
    sockx_t *x = X(s);
    if (x->state != ST_WS) return NGWS_SEND_DROPPED;
    char *p = out_reserve(x, len);
    if (!p) return NGWS_SEND_DROPPED;
    memcpy(p, frame, len);
    return send_status(x);
}

int ngws_send_raw3(ngws_socket_t *ws, const void *a, size_t an, const void *b, size_t bn, const void *c, size_t cn) {
    struct us_socket_t *s = (struct us_socket_t *) ws;
    sockx_t *x = X(s);
    if (x->state != ST_WS) return NGWS_SEND_DROPPED;
    char *p = out_reserve(x, an + bn + cn);
    if (!p) return NGWS_SEND_DROPPED;
    memcpy(p, a, an); memcpy(p + an, b, bn); memcpy(p + an + bn, c, cn);
    return send_status(x);
}

int ngws_send_shared(ngws_socket_t *ws, const void *frame, size_t len) {
    struct us_socket_t *s = (struct us_socket_t *) ws;
    sockx_t *x = X(s);
    if (x->state != ST_WS) return NGWS_SEND_DROPPED;
    if (x->olen > x->ooff) {
        if (!backlog_append(x, frame, len)) { ngws_terminate(ws); return NGWS_SEND_DROPPED; }
        dirty_add(x);
    } else {
        if (x->qbytes + len > SRV(x)->cfg.max_backpressure) { atomic_fetch_add_explicit(&SRV(x)->closed_conn_limit, 1, memory_order_relaxed); ngws_terminate(ws); return NGWS_SEND_DROPPED; }
        ionode_t *t = x->qtail ? &x->loop->nodes[x->qtail - 1] : NULL;
        if (t && (const char *) t->p + t->len == (const char *) frame) { t->len += len; x->qbytes += len; }  /* contiguous: one iovec */
        else if (!node_add(x, frame, len)) { ngws_terminate(ws); return NGWS_SEND_DROPPED; }
    }
    return send_status(x);
}

void ngws_loop_defer(ngws_loop_t *l, void (*fn)(void *), void *arg) {
    if (l->n_defer == l->cap_defer) {
        uint32_t nc = l->cap_defer ? l->cap_defer * 2 : 256;
        defer_t *nd = (defer_t *) realloc(l->defer, nc * sizeof(defer_t));
        if (!nd) { fn(arg); return; }      /* cannot defer: caller must not rely on it then */
        l->defer = nd; l->cap_defer = nc;
    }
    l->defer[l->n_defer].fn = fn; l->defer[l->n_defer].arg = arg; l->n_defer++;
}

static void close_after_flush(sockx_t *x) {
    x->state = ST_CLOSING;
    x->shutdown_after_flush = 1;
    if (x->olen == x->ooff && !x->qbytes) { if (!us_socket_is_closed(0, x->s)) us_socket_shutdown(0, x->s); }
    else dirty_add(x);
    us_socket_timeout(0, x->s, 8);      /* don't wait forever for the peer's FIN */
}

/* Server-initiated WebSocket close: send the close frame, then wait (up to
 * 8 s) for the peer to finish its close handshake and FIN instead of sending
 * our FIN at once; a client still writing a large message would otherwise
 * see its write fail. Input is discarded meanwhile. */
static void close_wait_peer(sockx_t *x) {
    x->state = ST_CLOSING;
    x->drain = 1;
    x->rlen = 0;
    if (x->olen > x->ooff || x->qbytes) dirty_add(x);
    us_socket_timeout(0, x->s, 8);
}

static void ws_fail(sockx_t *x, int code) {
    if (x->state == ST_WS) {
        unsigned char b[2] = { (unsigned char) (code >> 8), (unsigned char) code };
        queue_frame(x, NGWS_OP_CLOSE, b, 2);
        if (!us_socket_is_closed(0, x->s)) close_wait_peer(x);
        return;
    }
    if (!us_socket_is_closed(0, x->s)) close_after_flush(x);
}

void ngws_close(ngws_socket_t *ws, int code, const char *reason) {
    struct us_socket_t *s = (struct us_socket_t *) ws;
    sockx_t *x = X(s);
    if (x->state != ST_WS || us_socket_is_closed(0, s)) return;
    unsigned char b[125];
    size_t rl = reason ? strlen(reason) : 0; if (rl > 123) rl = 123;
    b[0] = (unsigned char) (code >> 8); b[1] = (unsigned char) code;
    if (rl) memcpy(b + 2, reason, rl);
    queue_frame(x, NGWS_OP_CLOSE, b, 2 + rl);
    if (!us_socket_is_closed(0, s)) close_wait_peer(x);
}

void ngws_terminate(ngws_socket_t *ws) {
    struct us_socket_t *s = (struct us_socket_t *) ws;
    if (!us_socket_is_closed(0, s)) us_socket_close(0, s, 0, NULL);
}

bool ngws_is_closed(ngws_socket_t *ws) {
    struct us_socket_t *s = (struct us_socket_t *) ws;
    return us_socket_is_closed(0, s) || X(s)->state != ST_WS;
}
size_t ngws_buffered(ngws_socket_t *ws) { sockx_t *x = X((struct us_socket_t *) ws); return x->olen - x->ooff + x->qbytes; }
void *ngws_user(ngws_socket_t *ws) { return (char *) X((struct us_socket_t *) ws) + USER_OFF; }
ngws_loop_t *ngws_socket_loop(ngws_socket_t *ws) { return X((struct us_socket_t *) ws)->loop; }
ngws_server_t *ngws_socket_server(ngws_socket_t *ws) { return X((struct us_socket_t *) ws)->loop->srv; }

int ngws_remote_address(ngws_socket_t *ws, char *buf, size_t cap) {
    struct us_socket_t *s = (struct us_socket_t *) ws;
    char ip[16]; int iplen = sizeof(ip);
    char txt[64] = "";
    us_socket_remote_address(0, s, ip, &iplen);
    if (iplen == 4) inet_ntop(AF_INET, ip, txt, sizeof(txt));
    else if (iplen == 16) inet_ntop(AF_INET6, ip, txt, sizeof(txt));
    return snprintf(buf, cap, "%s:%d", txt, us_socket_remote_port(0, s));
}

void ngws_http_respond(ngws_socket_t *ws, const char *status, const char *extra,
                       const char *ctype, const void *body, size_t len) {
    struct us_socket_t *s = (struct us_socket_t *) ws;
    sockx_t *x = X(s);
    if (x->state != ST_HTTP || us_socket_is_closed(0, s)) return;
    char head[1024];
    int hl = snprintf(head, sizeof(head),
        "HTTP/1.1 %s\r\n%sContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        status, extra ? extra : "", ctype ? ctype : "text/plain", len);
    if (hl < 0 || (size_t) hl >= sizeof(head)) hl = 0;
    char *p = out_reserve(x, (size_t) hl + len);
    if (!p) return;
    memcpy(p, head, (size_t) hl);
    if (len) memcpy(p + hl, body, len);
    close_after_flush(x);
}

/* ------------------------------------------------------------- input ---- */
static bool header_value(const char *h, size_t n, const char *name, const char **v, size_t *vl) {
    size_t nl = strlen(name);
    const char *p = h, *end = h + n;
    while (p < end) {
        const char *eol = (const char *) memchr(p, '\n', (size_t) (end - p));
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

static void ws_list_add(sockx_t *x) {
    ngws_loop_t *l = x->loop;
    x->aprev = NULL; x->anext = l->all;
    if (l->all) l->all->aprev = x;
    l->all = x; l->n_open++;
}
static void ws_list_del(sockx_t *x) {
    ngws_loop_t *l = x->loop;
    if (x->aprev) x->aprev->anext = x->anext; else if (l->all == x) l->all = x->anext; else return;
    if (x->anext) x->anext->aprev = x->aprev;
    x->aprev = x->anext = NULL; l->n_open--;
}

/* Returns header bytes consumed, 0 if incomplete, -1 if the request was answered/failed. */
static long handle_http(sockx_t *x, const char *b, size_t n) {
    ngws_server_t *srv = SRV(x);
    const char *endh = NULL;
    for (size_t i = 3; i < n; i++)
        if (b[i] == '\n' && b[i-1] == '\r' && b[i-2] == '\n' && b[i-3] == '\r') { endh = b + i + 1; break; }
    if (!endh) {
        if (n > MAX_HTTP_HEADER) { ngws_http_respond((ngws_socket_t *) x->s, "431 Request Header Fields Too Large", NULL, NULL, "", 0); return -1; }
        return 0;
    }
    size_t hn = (size_t) (endh - b);
    ngws_http_req_t req = {0};
    const char *sp = (const char *) memchr(b, ' ', hn);
    if (!sp) { ngws_http_respond((ngws_socket_t *) x->s, "400 Bad Request", NULL, NULL, "", 0); return -1; }
    req.method = b; req.method_len = (size_t) (sp - b);
    req.path = sp + 1;
    const char *sp2 = (const char *) memchr(req.path, ' ', (size_t) (endh - req.path));
    req.path_len = sp2 ? (size_t) (sp2 - req.path) : 0;
    const char *eol = (const char *) memchr(b, '\n', hn);
    req.headers = eol ? eol + 1 : endh; req.headers_len = (size_t) (endh - req.headers);

    const char *v; size_t vl;
    bool upgrade = req.method_len == 3 && memcmp(b, "GET", 3) == 0 &&
                   header_value(req.headers, req.headers_len, "Upgrade", &v, &vl) && contains_ci(v, vl, "websocket");
    if (!upgrade) {
        if (srv->cfg.on_http) srv->cfg.on_http((ngws_socket_t *) x->s, &req);
        if (x->state == ST_HTTP && !us_socket_is_closed(0, x->s))
            ngws_http_respond((ngws_socket_t *) x->s, "426 Upgrade Required", "Upgrade: websocket\r\n", NULL, "", 0);
        return -1;
    }
    if (!header_value(req.headers, req.headers_len, "Sec-WebSocket-Key", &v, &vl) || vl == 0 || vl > 64) {
        ngws_http_respond((ngws_socket_t *) x->s, "400 Bad Request", NULL, NULL, "", 0); return -1;
    }
    char accept[29];
    ws_accept_key(v, vl, accept);
    static const char r1[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
    char *p = out_reserve(x, sizeof(r1) - 1 + 28 + 4);
    if (!p) return -1;
    memcpy(p, r1, sizeof(r1) - 1); p += sizeof(r1) - 1;
    memcpy(p, accept, 28); p += 28;
    memcpy(p, "\r\n\r\n", 4);
    x->state = ST_WS;
    us_socket_timeout(0, x->s, srv->cfg.idle_timeout);
    ws_list_add(x);
    if (srv->cfg.on_open) srv->cfg.on_open((ngws_socket_t *) x->s, &req);
    if (us_socket_is_closed(0, x->s)) return -1;
    return (long) hn;
}

static void deliver(sockx_t *x, char *data, size_t len, int op) {
    ngws_server_t *srv = SRV(x);
    if (op == NGWS_OP_TEXT || op == NGWS_OP_BINARY) {
        if (op == NGWS_OP_TEXT && !srv->cfg.skip_utf8_check &&
            !ws_utf8_valid((const unsigned char *) data, len)) { ws_fail(x, 1007); return; }
        if (srv->cfg.on_message) srv->cfg.on_message((ngws_socket_t *) x->s, data, len, op);
    } else if (op == NGWS_OP_PING) {
        queue_frame(x, NGWS_OP_PONG, data, len);
    } else if (op == NGWS_OP_CLOSE) {
        unsigned char code[2] = { 0x03, 0xE8 };
        if (len == 1) { ws_fail(x, 1002); return; }
        if (len >= 2) {
            unsigned c = (unsigned) (unsigned char) data[0] << 8 | (unsigned char) data[1];
            bool ok = (c >= 1000 && c <= 1003) || (c >= 1007 && c <= 1011) || (c >= 3000 && c <= 4999);
            if (!ok) { ws_fail(x, 1002); return; }
            if (!ws_utf8_valid((const unsigned char *) data + 2, len - 2)) { ws_fail(x, 1007); return; }
            code[0] = (unsigned char) data[0]; code[1] = (unsigned char) data[1];
        }
        queue_frame(x, NGWS_OP_CLOSE, code, 2);
        close_after_flush(x);
    }
}

static void msg_free(ngws_loop_t *l, unsigned char *m, size_t cap) {
    if (!m) return;
    if (cap == MSG_CHUNK && l->n_msg_pool < POOL_MAX) {
        pool_item_t *p = (pool_item_t *) m; p->next = l->msg_pool; l->msg_pool = p; l->n_msg_pool++;
    } else free(m);
}
static bool msg_append(sockx_t *x, const void *p, size_t n) {
    if (!x->msg && n < MSG_CHUNK && x->loop->msg_pool) {
        pool_item_t *it = x->loop->msg_pool; x->loop->msg_pool = it->next; x->loop->n_msg_pool--;
        x->msg = (unsigned char *) it; x->mcap = MSG_CHUNK; x->mlen = 0;
    }
    if (x->mlen + n > x->mcap) {
        size_t nc = x->mcap ? x->mcap : (n < MSG_CHUNK ? MSG_CHUNK : 1024);
        while (nc < x->mlen + n) nc *= 2;
        unsigned char *nb = (unsigned char *) realloc(x->msg, nc);
        if (!nb) return false;
        x->msg = nb; x->mcap = nc;
    }
    memcpy(x->msg + x->mlen, p, n); x->mlen += n;
    return true;
}
static void msg_reset(sockx_t *x) { msg_free(x->loop, x->msg, x->mcap); x->msg = NULL; x->mlen = x->mcap = 0; x->msg_op = 0; }

/* Validate a new frame header. Returns 0 or a close code. */
static int frame_check(sockx_t *x, int fin, int rsv, int op, int mask, uint64_t plen) {
    size_t maxp = SRV(x)->cfg.max_payload;
    if (rsv) return 1002;
    if (!mask) return 1002;
    if ((op > 2 && op < 8) || op > 10) return 1002;
    if (op >= 8) return (!fin || plen > 125) ? 1002 : 0;
    if (op == NGWS_OP_CONT) { if (!x->msg_op) return 1002; }
    else if (x->msg_op) return 1002;
    if (plen > maxp || x->mlen + plen > maxp) return 1009;
    return 0;
}

/* In-tree codec: parse frames in place from the receive buffer (zero copy). */
static long ws_frame(sockx_t *x, unsigned char *b, size_t blen) {
    ws_frame_t f;
    int r = ws_parse_header(b, blen, &f);
    if (r < 0) { ws_fail(x, 1002); return -1; }
    if (r == 0) return 0;
    int code = frame_check(x, f.fin, 0, f.opcode, f.masked, f.len);
    if (code) {
        ws_fail(x, code);
        uint64_t total = f.header_len + f.len;
        x->skip = total > blen ? total - blen : 0;   /* rest of the rejected frame */
        return -1;
    }
    if (blen - f.header_len < f.len) return 0;
    unsigned char *p = b + f.header_len;
    size_t n = (size_t) f.len;
    ws_unmask(p, n, f.mask);
    int op = f.opcode;
    if (op >= 8 || (f.fin && op != NGWS_OP_CONT)) deliver(x, (char *) p, n, op);
    else {
        if (op != NGWS_OP_CONT) x->msg_op = (uint8_t) op;
        if (!msg_append(x, p, n)) { ws_fail(x, 1011); return -1; }
        if (f.fin) {
            if (msg_append(x, "", 1)) x->mlen--;
            int mop = x->msg_op; unsigned char *m = x->msg; size_t ml = x->mlen, mc = x->mcap;
            x->msg = NULL; x->mlen = x->mcap = 0; x->msg_op = 0;
            deliver(x, (char *) m, ml, mop);
            msg_free(x->loop, m, mc);
        }
    }
    return (long) (f.header_len + n);
}
/* Bytes needed to hold the whole frame starting at b (header + payload),
 * or 4096 when the header itself is still incomplete. Sizing the partial-
 * frame buffer once avoids realloc/copy cascades for large messages. */
static size_t frame_need(sockx_t *x, const unsigned char *b, size_t n) {
    ws_frame_t f;
    if (ws_parse_header(b, n, &f) <= 0) return 4096;
    if (f.len > SRV(x)->cfg.max_payload) return 4096;   /* rejected anyway; never trust it */
    uint64_t t = f.header_len + f.len;
    return t < 4096 ? 4096 : (size_t) t;
}

static void ws_feed(sockx_t *x, unsigned char *data, size_t len) {
    unsigned char *b = data; size_t n = len;
    bool owned = false;
    if (x->rlen) {                        /* append to partial frame */
        if (x->rlen + len > x->rcap) {
            size_t nc = x->rcap ? x->rcap : 4096; while (nc < x->rlen + len) nc *= 2;
            size_t fn = frame_need(x, x->rbuf, x->rlen);
            if (fn >= x->rlen + len && fn > x->rcap) nc = fn;
            unsigned char *nb = (unsigned char *) realloc(x->rbuf, nc);
            if (!nb) { ngws_terminate((ngws_socket_t *) x->s); return; }
            x->rbuf = nb; x->rcap = nc;
        }
        memcpy(x->rbuf + x->rlen, data, len); x->rlen += len;
        b = x->rbuf; n = x->rlen; owned = true;
    }
    size_t off = 0;
    while (off < n && x->state == ST_WS && !us_socket_is_closed(0, x->s)) {
        long used = ws_frame(x, b + off, n - off);
        if (used <= 0) break;
        off += (size_t) used;
    }
    if (us_socket_is_closed(0, x->s) || x->state != ST_WS) { if (owned) x->rlen = 0; return; }
    size_t rest = n - off;
    if (!rest) { x->rlen = 0; if (x->rbuf && x->rcap > 65536) { free(x->rbuf); x->rbuf = NULL; x->rcap = 0; } return; }
    if (owned) { memmove(x->rbuf, x->rbuf + off, rest); x->rlen = rest; }
    else {
        size_t need = frame_need(x, b + off, rest);
        if (need < rest) need = rest;
        if (need > x->rcap) {
            unsigned char *nb = (unsigned char *) realloc(x->rbuf, need);
            if (!nb) { ngws_terminate((ngws_socket_t *) x->s); return; }
            x->rbuf = nb; x->rcap = need;
        }
        memcpy(x->rbuf, b + off, rest); x->rlen = rest;
    }
}

static void free_inputs(sockx_t *x) {
    free(x->rbuf); x->rbuf = NULL; x->rlen = x->rcap = 0;
    msg_reset(x);
}

/* After a server-initiated close: discard frames until the peer's close frame
 * arrives, then close TCP (RFC 6455 7.1.1: the server closes first). */
static void drain_input(sockx_t *x, unsigned char *d, size_t n) {
    while (n) {
        if (x->skip) { size_t k = x->skip < n ? (size_t) x->skip : n; x->skip -= k; d += k; n -= k; continue; }
        unsigned char hb[14]; size_t have = x->rlen < 14 ? x->rlen : 14;
        if (have) memcpy(hb, x->rbuf, have);
        size_t take = 14 - have < n ? 14 - have : n;
        memcpy(hb + have, d, take);
        ws_frame_t f;
        int r = ws_parse_header(hb, have + take, &f);
        if (r < 0) { us_socket_close(0, x->s, 0, NULL); return; }
        if (r == 0) {                          /* keep partial header */
            if (!x->rbuf) { x->rbuf = (unsigned char *) malloc(16); x->rcap = 16; if (!x->rbuf) return; }
            memcpy(x->rbuf, hb, have + take); x->rlen = have + take;
            return;
        }
        if (f.opcode == NGWS_OP_CLOSE) { x->rlen = 0; us_socket_close(0, x->s, 0, NULL); return; }
        size_t used_new = f.header_len - have;   /* header bytes taken from d */
        x->rlen = 0;
        d += used_new; n -= used_new;
        x->skip = f.len;
    }
}

static struct us_socket_t *on_data(struct us_socket_t *s, char *data, int length) {
    sockx_t *x = X(s);
    if (length <= 0 || x->state == ST_CLOSED) return s;
    if (x->state == ST_CLOSING) {
        if (x->drain) drain_input(x, (unsigned char *) data, (size_t) length);
        return s;
    }
    x->in_data = 1;
    if (x->state == ST_HTTP) {
        const char *b = data; size_t n = (size_t) length;
        {
            if (x->rlen + n > x->rcap) {
                size_t nc = x->rcap ? x->rcap : 1024; while (nc < x->rlen + n) nc *= 2;
                unsigned char *nb = (unsigned char *) realloc(x->rbuf, nc);
                if (!nb) { x->in_data = 0; return us_socket_close(0, s, 0, NULL); }
                x->rbuf = nb; x->rcap = nc;
            }
            memcpy(x->rbuf + x->rlen, b, n); x->rlen += n;
        }
        long used = handle_http(x, (const char *) x->rbuf, x->rlen);
        if (used > 0 && !us_socket_is_closed(0, s) && x->state == ST_WS) {
            size_t rest = x->rlen - (size_t) used;
            unsigned char *hb = x->rbuf;
            x->rbuf = NULL; x->rlen = x->rcap = 0;
            if (rest) ws_feed(x, hb + used, rest);
            free(hb);
        }
    } else {
        x->ping_sent = 0;
        if (SRV(x)->cfg.idle_timeout) us_socket_timeout(0, s, SRV(x)->cfg.idle_timeout);
        ws_feed(x, (unsigned char *) data, (size_t) length);
    }
    x->in_data = 0;
    if (us_socket_is_closed(0, s)) { free_inputs(x); return s; }
    /* Uncork: replies produced while handling this read go out now instead
     * of at the end of the loop iteration (lower latency; same writev
     * count, since a socket's frames from one read are already coalesced).
     * Sends from other sockets' callbacks/tasks still batch until loop_post. */
    if (x->dirty && SRV(x)->uncork) { dirty_del(x); flush(x); }
    return s;
}

static struct us_socket_t *on_writable(struct us_socket_t *s) {
    sockx_t *x = X(s);
    bool had = x->olen > x->ooff || x->qbytes;
    if (flush(x)) {
        dirty_del(x);
        if (had && x->state == ST_WS && SRV(x)->cfg.on_drain) SRV(x)->cfg.on_drain((ngws_socket_t *) s);
    }
    return s;
}

static struct us_socket_t *on_open(struct us_socket_t *s, int is_client, char *ip, int ip_length) {
    (void) is_client; (void) ip; (void) ip_length;
    sockx_t *x = X(s);
    ngws_loop_t *l = *(ngws_loop_t **) us_loop_ext(us_socket_context_loop(0, us_socket_context(0, s)));
    memset(x, 0, USER_OFF + l->srv->cfg.user_size);
    x->s = s; x->loop = l;
    us_socket_timeout(0, s, l->srv->cfg.handshake_timeout);
    return s;
}

static struct us_socket_t *on_close(struct us_socket_t *s, int code, void *reason) {
    (void) code; (void) reason;
    sockx_t *x = X(s);
    int was = x->state;
    x->state = ST_CLOSED;
    dirty_del(x);
    out_release(x);
    if (!x->in_data) free_inputs(x);
    if (was == ST_WS || x->aprev || x->loop->all == x) {
        ws_list_del(x);
        if (SRV(x)->cfg.on_close) SRV(x)->cfg.on_close((ngws_socket_t *) s, 1006);
    } else if (was == ST_CLOSING && x->anext == NULL && x->aprev == NULL) {
        /* closing sockets that were WebSockets are still in the list until here */
    }
    return s;
}

static struct us_socket_t *on_end(struct us_socket_t *s) { return us_socket_close(0, s, 0, NULL); }

static struct us_socket_t *on_timeout(struct us_socket_t *s) {
    sockx_t *x = X(s);
    unsigned it = SRV(x)->cfg.idle_timeout;
    if (x->state == ST_WS && it && !x->ping_sent) {
        x->ping_sent = 1;
        queue_frame(x, NGWS_OP_PING, "", 0);
        us_socket_timeout(0, s, it);
        return s;
    }
    if (x->state == ST_WS && !it) return s;
    return us_socket_close(0, s, 0, NULL);
}
static struct us_socket_t *on_long_timeout(struct us_socket_t *s) { return s; }

/* ------------------------------------------------------------- loop ----- */
/* Load shedding: when the process-wide backlog passes 75% of
 * max_total_backlog, close this loop's slowest readers (largest backlog
 * first, only those above the drain watermark) until it is back under 50%.
 * Without this, a few clients that never read could pin the budget and keep
 * the relay refusing new work indefinitely. */
typedef struct { size_t pending; sockx_t *x; } shed_t;
static int shed_cmp(const void *a, const void *b) {
    size_t x = ((const shed_t *) a)->pending, y = ((const shed_t *) b)->pending;
    return x < y ? 1 : x > y ? -1 : 0;
}
static void shed_sweep(ngws_loop_t *l) {
    ngws_server_t *srv = l->srv;
    size_t cap = srv->cfg.max_total_backlog;
    if (!cap || atomic_load_explicit(&srv->backlog_total, memory_order_relaxed) < cap / 4 * 3) return;
    size_t n = 0, k = 0;
    for (sockx_t *x = l->blog; x; x = x->bnext) n++;
    shed_t *v = n ? (shed_t *) malloc(n * sizeof(*v)) : NULL;
    if (!v) return;
    for (sockx_t *x = l->blog; x; x = x->bnext) {
        size_t p = x->olen - x->ooff + x->qbytes;
        if (p > SEND_WATERMARK) { v[k].pending = p; v[k].x = x; k++; }
    }
    qsort(v, k, sizeof(*v), shed_cmp);
    for (size_t i = 0; i < k && atomic_load_explicit(&srv->backlog_total, memory_order_relaxed) > cap / 2; i++) {
        atomic_fetch_add_explicit(&srv->closed_total_limit, 1, memory_order_relaxed);
        ngws_terminate((ngws_socket_t *) v[i].x->s);
    }
    free(v);
}

static void loop_pre(struct us_loop_t *ul) { (void) ul; }
static void loop_post(struct us_loop_t *ul) {
    ngws_loop_t *l = *(ngws_loop_t **) us_loop_ext(ul);
    sockx_t *x = l->dirty;
    while (x) {
        sockx_t *next = x->dnext;
        dirty_del(x);
        if (!us_socket_is_closed(0, x->s)) flush(x);   /* partial: writable event resumes */
        x = next;
    }
    l->dirty = NULL;
    shed_sweep(l);
    for (uint32_t i = 0; i < l->n_defer; i++) l->defer[i].fn(l->defer[i].arg);
    l->n_defer = 0;
    if (l->n_nodes || l->arena_cur != l->arena || (l->arena && l->arena->used)) arena_reset(l);
}

/* Close the listener and every socket; the loop then runs out of polls. */
static void loop_stop_listening(ngws_loop_t *l) {
    if (!l->ctx || l->ctx_closed) return;
    if (l->ls) { us_listen_socket_close(0, l->ls); l->ls = NULL; }
    us_socket_context_close(0, l->ctx);
    l->ctx_closed = true;
}

static void wakeup_cb(struct us_loop_t *ul) {
    ngws_loop_t *l = *(ngws_loop_t **) us_loop_ext(ul);
    atomic_store(&l->wake_pending, false);
    pthread_mutex_lock(&l->mu);
    ngws_task_t *t = l->head;
    l->head = l->tail = NULL;
    pthread_mutex_unlock(&l->mu);
    while (t) { ngws_task_t *n = t->next; t->run(t, l); t = n; }
    if (atomic_load(&l->srv->stopping)) loop_stop_listening(l);
}

void ngws_loop_post(ngws_loop_t *l, ngws_task_t *t) {
    t->next = NULL;
    pthread_mutex_lock(&l->mu);
    if (l->tail) l->tail->next = t; else l->head = t;
    l->tail = t;
    pthread_mutex_unlock(&l->mu);
    if (!atomic_exchange(&l->wake_pending, true)) us_wakeup_loop(l->loop);
}

void ngws_loop_foreach(ngws_loop_t *l, void (*fn)(ngws_socket_t *, void *), void *arg) {
    for (sockx_t *x = l->all, *n; x; x = n) {
        n = x->anext;
        if (x->state == ST_WS) fn((ngws_socket_t *) x->s, arg);
    }
}
int ngws_loop_index(ngws_loop_t *l) { return l->idx; }
size_t ngws_loop_count(ngws_loop_t *l) { return l->n_open; }
void *ngws_loop_get_user(ngws_loop_t *l) { return l->user; }
void ngws_loop_set_user(ngws_loop_t *l, void *p) { l->user = p; }

static void *loop_thread(void *arg) {
    ngws_loop_t *l = (ngws_loop_t *) arg;
#ifdef __linux__
    char name[16]; snprintf(name, sizeof(name), "ng-io-%d", l->idx);
    pthread_setname_np(pthread_self(), name);
#endif
    if (l->srv->cfg.on_loop_start) l->srv->cfg.on_loop_start(l);
    /* A stop that arrived while later loops were still being created (the
     * first listeners already accept) skipped them in ngws_server_stop:
     * stopping was stored before it read the not-yet-set loop pointer, so it
     * is visible here. Without this check those loops never exited. */
    if (atomic_load(&l->srv->stopping)) loop_stop_listening(l);
    us_loop_run(l->loop);
    if (l->srv->cfg.on_loop_stop) l->srv->cfg.on_loop_stop(l);
    return NULL;
}

/* ------------------------------------------------------------- server --- */
ngws_server_t *ngws_server_create(const ngws_config_t *cfg) {
    ngws_server_t *srv = (ngws_server_t *) calloc(1, sizeof(*srv));
    if (!srv) return NULL;
    srv->cfg = *cfg;
#ifdef __GLIBC__
    /* Large frames / backlogs (64 KiB .. max_payload) would otherwise be
     * mmap'd and munmap'd per message by glibc (threshold 128 KiB), paying
     * page faults on every large send/receive. Serve them from the heap and
     * keep freed memory for reuse. NGWS_NO_MALLOPT=1 leaves glibc alone. */
    { const char *nm = getenv("NGWS_NO_MALLOPT"); if (!nm || strcmp(nm, "1") != 0) {
        mallopt(M_MMAP_THRESHOLD, (int) (srv->cfg.max_payload + (1u << 20) < (1u << 30) ? srv->cfg.max_payload + (1u << 20) : (1u << 30)));
        mallopt(M_TRIM_THRESHOLD, 256 << 20);
    } }
#endif
    { const char *c = getenv("NGWS_CORK"); srv->uncork = !(c && strcmp(c, "1") == 0); }
    if (!srv->cfg.max_payload) srv->cfg.max_payload = 16u << 20;
    if (!srv->cfg.max_backpressure) srv->cfg.max_backpressure = 16u << 20;
    if (!srv->cfg.handshake_timeout) srv->cfg.handshake_timeout = 12;
    srv->n_loops = cfg->loops > 0 ? (cfg->loops > MAX_LOOPS ? MAX_LOOPS : cfg->loops) : 1;
    return srv;
}

/* SO_REUSEPORT (used so every loop can accept) would also let a second
 * process silently share the port. Probe with a plain bind first. */
static bool port_free(const char *host, int port) {
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    bool v6 = fd >= 0;
    if (!v6) fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return true;
    int one = 1, zero = 0;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    int r;
    if (v6 && !host) {
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
        struct sockaddr_in6 a; memset(&a, 0, sizeof(a));
        a.sin6_family = AF_INET6; a.sin6_port = htons((uint16_t) port); a.sin6_addr = in6addr_any;
        r = bind(fd, (struct sockaddr *) &a, sizeof(a));
    } else {
        if (v6) { close(fd); fd = socket(AF_INET, SOCK_STREAM, 0); setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)); }
        struct sockaddr_in a; memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET; a.sin_port = htons((uint16_t) port);
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        if (host) inet_pton(AF_INET, host, &a.sin_addr);
        r = bind(fd, (struct sockaddr *) &a, sizeof(a));
    }
    bool ok = r == 0 || errno != EADDRINUSE;
    close(fd);
    return ok;
}

/* Effective listen backlog: configured, else the kernel maximum
 * (net.core.somaxconn), else 4096. Values above somaxconn are capped by the
 * kernel, so the result is also capped here to report the real value. */
int ngws_listen_backlog(const ngws_config_t *cfg) {
    int max = 0;
    FILE *f = fopen("/proc/sys/net/core/somaxconn", "r");
    if (f) { if (fscanf(f, "%d", &max) != 1) max = 0; fclose(f); }
    int b = cfg->listen_backlog > 0 ? cfg->listen_backlog : max > 0 ? max : 4096;
    if (max > 0 && b > max) b = max;
    return b;
}

bool ngws_server_run(ngws_server_t *srv) {
    signal(SIGPIPE, SIG_IGN);
    if (!port_free(srv->cfg.host, srv->cfg.port)) {
        fprintf(stderr, "ngws: port %d is already in use\n", srv->cfg.port);
        return false;
    }
    us_set_listen_backlog(ngws_listen_backlog(&srv->cfg));
    for (int i = 0; i < srv->n_loops; i++) {
        ngws_loop_t *l = &srv->loops[i];
        l->idx = i; l->srv = srv;
        pthread_mutex_init(&l->mu, NULL);
        l->loop = us_create_loop(NULL, wakeup_cb, loop_pre, loop_post, sizeof(ngws_loop_t *));
        *(ngws_loop_t **) us_loop_ext(l->loop) = l;
        struct us_socket_context_options_t opts; memset(&opts, 0, sizeof(opts));
        l->ctx = us_create_socket_context(0, l->loop, 0, opts);
        us_socket_context_on_open(0, l->ctx, on_open);
        us_socket_context_on_data(0, l->ctx, on_data);
        us_socket_context_on_writable(0, l->ctx, on_writable);
        us_socket_context_on_close(0, l->ctx, on_close);
        us_socket_context_on_end(0, l->ctx, on_end);
        us_socket_context_on_timeout(0, l->ctx, on_timeout);
        us_socket_context_on_long_timeout(0, l->ctx, on_long_timeout);
        l->ls = us_socket_context_listen(0, l->ctx, srv->cfg.host, srv->cfg.port, 0,
                                         (int) (USER_OFF + srv->cfg.user_size));
        if (!l->ls) { fprintf(stderr, "ngws: listen on :%d failed\n", srv->cfg.port); return false; }
    }
    for (int i = 0; i < srv->n_loops; i++) pthread_create(&srv->loops[i].th, NULL, loop_thread, &srv->loops[i]);
    for (int i = 0; i < srv->n_loops; i++) pthread_join(srv->loops[i].th, NULL);
    return true;
}

void ngws_server_stop(ngws_server_t *srv) {
    atomic_store(&srv->stopping, true);
    for (int i = 0; i < srv->n_loops; i++) if (srv->loops[i].loop) us_wakeup_loop(srv->loops[i].loop);
}

void ngws_server_free(ngws_server_t *srv) {
    if (!srv) return;
    for (int i = 0; i < srv->n_loops; i++) {
        ngws_loop_t *l = &srv->loops[i];
        if (!l->loop) continue;
        for (pool_item_t *p = l->msg_pool, *n; p; p = n) { n = p->next; free(p); }
        for (arena_chunk_t *c = l->arena, *n; c; c = n) { n = c->next; free(c); }
        free(l->nodes); free(l->defer);
        us_socket_context_free(0, l->ctx);
        us_loop_free(l->loop);
        pthread_mutex_destroy(&l->mu);
    }
    free(srv);
}

void *ngws_server_user(ngws_server_t *srv) { return srv->cfg.user; }
int ngws_server_loop_count(ngws_server_t *srv) { return srv->n_loops; }
size_t ngws_server_backlog_bytes(ngws_server_t *srv) { return atomic_load_explicit(&srv->backlog_total, memory_order_relaxed); }
void ngws_server_stats(ngws_server_t *srv, ngws_stats_t *o) {
    o->backlog_bytes = ngws_server_backlog_bytes(srv);
    o->closed_conn_limit = atomic_load(&srv->closed_conn_limit);
    o->closed_total_limit = atomic_load(&srv->closed_total_limit);
}
ngws_loop_t *ngws_server_loop(ngws_server_t *srv, int i) { return i >= 0 && i < srv->n_loops ? &srv->loops[i] : NULL; }
