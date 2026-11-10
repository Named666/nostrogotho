/* ngws_send - send queue (see ngws_internal.h). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ngws_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "../platform/ng_alloc.h"
#include "../ws_proto.h"

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
void nx_dirty_add(sockx_t *x) {
    if (x->dirty) return;
    ngws_loop_t *l = x->loop;
    x->dirty = 1; x->dprev = NULL; x->dnext = l->dirty;
    if (l->dirty) l->dirty->dprev = x;
    l->dirty = x;
}
void nx_dirty_del(sockx_t *x) {
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
    arena_chunk_t *a = (arena_chunk_t *) ng_malloc_add(sizeof(*a), cap);
    if (!a) return NULL;
    a->cap = cap; a->used = n;
    if (c) { a->next = c->next; c->next = a; } else { a->next = l->arena; l->arena = a; }
    l->arena_cur = a;
    return a->data;
}

void nx_arena_reset(ngws_loop_t *l) {
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
        if (l->cap_nodes > UINT32_MAX / 2) return false;          /* node index is 32-bit */
        uint32_t nc = l->cap_nodes ? l->cap_nodes * 2 : 4096;
        ionode_t *nn = (ionode_t *) ng_realloc_array(l->nodes, nc, sizeof(ionode_t));
        if (!nn) return false;
        l->nodes = nn; l->cap_nodes = nc;
    }
    uint32_t i = l->n_nodes++;
    l->nodes[i].p = p; l->nodes[i].len = n; l->nodes[i].next = 0;
    if (x->qtail) l->nodes[x->qtail - 1].next = i + 1; else x->qhead = i + 1;
    x->qtail = i + 1;
    x->qbytes += n;
    nx_dirty_add(x);
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
    if (pending + n > srv->cfg.max_backpressure) { ng_atomic_fetch_add_explicit(&srv->closed_conn_limit, 1, NG_MO_RELAXED); return false; }
    if (x->olen + n <= x->ocap) return true;
    if (x->ooff) { memmove(x->obuf, x->obuf + x->ooff, pending); x->olen = pending; x->ooff = 0; }
    size_t want;
    if (!ng_size_add(x->olen, n, &want)) return false;
    if (want <= x->ocap) return true;
    size_t nc = ng_grow_cap(x->ocap, want, 4096);
    size_t grow = nc - x->ocap;
    if (srv->cfg.max_total_backlog && pending + n > SEND_WATERMARK &&
        ng_atomic_load_explicit(&srv->backlog_total, NG_MO_RELAXED) + grow > srv->cfg.max_total_backlog) {
        ng_atomic_fetch_add_explicit(&srv->closed_total_limit, 1, NG_MO_RELAXED);
        return false;
    }
    char *nb = (char *) realloc(x->obuf, nc);
    if (!nb) return false;
    ng_atomic_fetch_add_explicit(&srv->backlog_total, grow, NG_MO_RELAXED);
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

void nx_out_release(sockx_t *x) {
    if (x->ocap) {
        ng_atomic_fetch_sub_explicit(&SRV(x)->backlog_total, x->ocap, NG_MO_RELAXED);
        if (x->bprev) x->bprev->bnext = x->bnext; else x->loop->blog = x->bnext;
        if (x->bnext) x->bnext->bprev = x->bprev;
        x->bprev = x->bnext = NULL;
    }
    free(x->obuf);
    x->obuf = NULL; x->olen = x->ooff = x->ocap = 0;
}

/* Reserve n writable bytes for this socket's output. NULL = limit/oom (socket terminated). */
char *nx_out_reserve(sockx_t *x, size_t n) {
    if (x->olen > x->ooff) {                       /* backlog: keep order */
        if (!obuf_room(x, n)) goto fail;
        char *p = x->obuf + x->olen; x->olen += n;
        return p;
    }
    if (x->qbytes + n > SRV(x)->cfg.max_backpressure) { ng_atomic_fetch_add_explicit(&SRV(x)->closed_conn_limit, 1, NG_MO_RELAXED); goto fail; }
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
bool nx_flush(sockx_t *x) {
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
        nx_out_release(x);
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
                if (x->ooff == x->olen) { nx_out_release(x); break; }
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
    if (total > SRV(x)->cfg.max_backpressure) { ng_atomic_fetch_add_explicit(&SRV(x)->closed_conn_limit, 1, NG_MO_RELAXED); ngws_terminate((ngws_socket_t *) s); return NGWS_SEND_DROPPED; }
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
    if (x->ooff == x->olen) { nx_out_release(x); return NGWS_SEND_OK; }
    return send_status(x);
}

int nx_queue_frame(sockx_t *x, int op, const void *data, size_t len) {
    if (len >= DIRECT_MIN && !x->qhead && x->olen == x->ooff && !us_socket_is_closed(0, x->s) &&
        !us_socket_is_shut_down(0, x->s))
        return send_direct(x, op, data, len);
    char *p = nx_out_reserve(x, len + ngws_frame_overhead(len));
    if (!p) return NGWS_SEND_DROPPED;
    size_t h = ws_frame_header((unsigned char *) p, op, len);
    memcpy(p + h, data, len);
    return send_status(x);
}

int ngws_send(ngws_socket_t *ws, const void *data, size_t len, int opcode) {
    struct us_socket_t *s = (struct us_socket_t *) ws;
    sockx_t *x = X(s);
    if (x->state != ST_WS) return NGWS_SEND_DROPPED;
    return nx_queue_frame(x, opcode, data, len);
}

int ngws_send_raw(ngws_socket_t *ws, const void *frame, size_t len) {
    struct us_socket_t *s = (struct us_socket_t *) ws;
    sockx_t *x = X(s);
    if (x->state != ST_WS) return NGWS_SEND_DROPPED;
    char *p = nx_out_reserve(x, len);
    if (!p) return NGWS_SEND_DROPPED;
    memcpy(p, frame, len);
    return send_status(x);
}

int ngws_send_raw3(ngws_socket_t *ws, const void *a, size_t an, const void *b, size_t bn, const void *c, size_t cn) {
    struct us_socket_t *s = (struct us_socket_t *) ws;
    sockx_t *x = X(s);
    if (x->state != ST_WS) return NGWS_SEND_DROPPED;
    char *p = nx_out_reserve(x, an + bn + cn);
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
        nx_dirty_add(x);
    } else {
        if (x->qbytes + len > SRV(x)->cfg.max_backpressure) { ng_atomic_fetch_add_explicit(&SRV(x)->closed_conn_limit, 1, NG_MO_RELAXED); ngws_terminate(ws); return NGWS_SEND_DROPPED; }
        ionode_t *t = x->qtail ? &x->loop->nodes[x->qtail - 1] : NULL;
        if (t && (const char *) t->p + t->len == (const char *) frame) { t->len += len; x->qbytes += len; }  /* contiguous: one iovec */
        else if (!node_add(x, frame, len)) { ngws_terminate(ws); return NGWS_SEND_DROPPED; }
    }
    return send_status(x);
}

void ngws_loop_defer(ngws_loop_t *l, void (*fn)(void *), void *arg) {
    if (l->n_defer == l->cap_defer) {
        uint32_t nc = l->cap_defer ? l->cap_defer * 2 : 256;
        defer_t *nd = l->cap_defer > UINT32_MAX / 2 ? NULL : (defer_t *) ng_realloc_array(l->defer, nc, sizeof(defer_t));
        if (!nd) { fn(arg); return; }      /* cannot defer: caller must not rely on it then */
        l->defer = nd; l->cap_defer = nc;
    }
    l->defer[l->n_defer].fn = fn; l->defer[l->n_defer].arg = arg; l->n_defer++;
}

void nx_close_after_flush(sockx_t *x) {
    x->state = ST_CLOSING;
    x->shutdown_after_flush = 1;
    if (x->olen == x->ooff && !x->qbytes) { if (!us_socket_is_closed(0, x->s)) us_socket_shutdown(0, x->s); }
    else nx_dirty_add(x);
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
    if (x->olen > x->ooff || x->qbytes) nx_dirty_add(x);
    us_socket_timeout(0, x->s, 8);
}

void nx_ws_fail(sockx_t *x, int code) {
    if (x->state == ST_WS) {
        unsigned char b[2] = { (unsigned char) (code >> 8), (unsigned char) code };
        nx_queue_frame(x, NGWS_OP_CLOSE, b, 2);
        if (!us_socket_is_closed(0, x->s)) close_wait_peer(x);
        return;
    }
    if (!us_socket_is_closed(0, x->s)) nx_close_after_flush(x);
}

void ngws_close(ngws_socket_t *ws, int code, const char *reason) {
    struct us_socket_t *s = (struct us_socket_t *) ws;
    sockx_t *x = X(s);
    if (x->state != ST_WS || us_socket_is_closed(0, s)) return;
    unsigned char b[125];
    size_t rl = reason ? strlen(reason) : 0; if (rl > 123) rl = 123;
    b[0] = (unsigned char) (code >> 8); b[1] = (unsigned char) code;
    if (rl) memcpy(b + 2, reason, rl);
    nx_queue_frame(x, NGWS_OP_CLOSE, b, 2 + rl);
    if (!us_socket_is_closed(0, s)) close_wait_peer(x);
}

void ngws_terminate(ngws_socket_t *ws) {
    struct us_socket_t *s = (struct us_socket_t *) ws;
    if (!us_socket_is_closed(0, s)) us_socket_close(0, s, 0, NULL);
}
