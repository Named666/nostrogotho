/* ngws - see ngws.h. MIT, in-tree. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ngws_internal.h"

#include <arpa/inet.h>
#ifdef __GLIBC__
#include <malloc.h>
#endif
#include <pthread.h>
#include <signal.h>
#include "../platform/ng_atomic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "libusockets.h"
#include "../platform/ng_alloc.h"

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
    /* "[v6]:port": a bare v6 address followed by ":port" is ambiguous. */
    return snprintf(buf, cap, iplen == 16 ? "[%s]:%d" : "%s:%d", txt, us_socket_remote_port(0, s));
}

void nx_ws_list_add(sockx_t *x) {
    ngws_loop_t *l = x->loop;
    x->aprev = NULL; x->anext = l->all;
    if (l->all) l->all->aprev = x;
    l->all = x; l->n_open++;
}
void nx_ws_list_del(sockx_t *x) {
    ngws_loop_t *l = x->loop;
    if (x->aprev) x->aprev->anext = x->anext; else if (l->all == x) l->all = x->anext; else return;
    if (x->anext) x->anext->aprev = x->aprev;
    x->aprev = x->anext = NULL; l->n_open--;
}

static struct us_socket_t *on_data(struct us_socket_t *s, char *data, int length) {
    sockx_t *x = X(s);
    if (length <= 0 || x->state == ST_CLOSED) return s;
    if (x->state == ST_CLOSING) {
        if (x->drain) nx_drain_input(x, (unsigned char *) data, (size_t) length);
        return s;
    }
    x->in_data = 1;
    if (x->state == ST_HTTP) {
        const char *b = data; size_t n = (size_t) length;
        {
            if (x->rlen + n > x->rcap) {        /* header block: bounded by MAX_HTTP_HEADER */
                size_t nc = ng_grow_cap(x->rcap, x->rlen + n, 1024);
                unsigned char *nb = (unsigned char *) realloc(x->rbuf, nc);
                if (!nb) { x->in_data = 0; return us_socket_close(0, s, 0, NULL); }
                x->rbuf = nb; x->rcap = nc;
            }
            memcpy(x->rbuf + x->rlen, b, n); x->rlen += n;
        }
        long used = nx_handle_http(x, (const char *) x->rbuf, x->rlen);
        if (used > 0 && !us_socket_is_closed(0, s) && x->state == ST_WS) {
            size_t rest = x->rlen - (size_t) used;
            unsigned char *hb = x->rbuf;
            x->rbuf = NULL; x->rlen = x->rcap = 0;
            if (rest) nx_ws_feed(x, hb + used, rest);
            free(hb);
        }
    } else {
        x->ping_sent = 0;
        if (SRV(x)->cfg.idle_timeout) us_socket_timeout(0, s, SRV(x)->cfg.idle_timeout);
        nx_ws_feed(x, (unsigned char *) data, (size_t) length);
    }
    x->in_data = 0;
    if (us_socket_is_closed(0, s)) { nx_free_inputs(x); return s; }
    /* Uncork: replies produced while handling this read go out now instead
     * of at the end of the loop iteration (lower latency; same writev
     * count, since a socket's frames from one read are already coalesced).
     * Sends from other sockets' callbacks/tasks still batch until loop_post. */
    if (x->dirty && SRV(x)->uncork) { nx_dirty_del(x); nx_flush(x); }
    return s;
}

static struct us_socket_t *on_writable(struct us_socket_t *s) {
    sockx_t *x = X(s);
    bool had = x->olen > x->ooff || x->qbytes;
    if (nx_flush(x)) {
        nx_dirty_del(x);
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
    nx_dirty_del(x);
    nx_out_release(x);
    if (!x->in_data) nx_free_inputs(x);
    if (was == ST_WS || x->aprev || x->loop->all == x) {
        nx_ws_list_del(x);
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
        nx_queue_frame(x, NGWS_OP_PING, "", 0);
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
    if (!cap || ng_atomic_load_explicit(&srv->backlog_total, NG_MO_RELAXED) < cap / 4 * 3) return;
    size_t n = 0, k = 0;
    for (sockx_t *x = l->blog; x; x = x->bnext) n++;
    shed_t *v = n ? (shed_t *) ng_malloc_array(n, sizeof(*v)) : NULL;
    if (!v) return;
    for (sockx_t *x = l->blog; x; x = x->bnext) {
        size_t p = x->olen - x->ooff + x->qbytes;
        if (p > SEND_WATERMARK) { v[k].pending = p; v[k].x = x; k++; }
    }
    qsort(v, k, sizeof(*v), shed_cmp);
    for (size_t i = 0; i < k && ng_atomic_load_explicit(&srv->backlog_total, NG_MO_RELAXED) > cap / 2; i++) {
        ng_atomic_fetch_add_explicit(&srv->closed_total_limit, 1, NG_MO_RELAXED);
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
        nx_dirty_del(x);
        if (!us_socket_is_closed(0, x->s)) nx_flush(x);   /* partial: writable event resumes */
        x = next;
    }
    l->dirty = NULL;
    shed_sweep(l);
    for (uint32_t i = 0; i < l->n_defer; i++) l->defer[i].fn(l->defer[i].arg);
    l->n_defer = 0;
    if (l->n_nodes || l->arena_cur != l->arena || (l->arena && l->arena->used)) nx_arena_reset(l);
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
    ng_atomic_store(&l->wake_pending, false);
    pthread_mutex_lock(&l->mu);
    ngws_task_t *t = l->head;
    l->head = l->tail = NULL;
    pthread_mutex_unlock(&l->mu);
    while (t) { ngws_task_t *n = t->next; t->run(t, l); t = n; }
    if (ng_atomic_load(&l->srv->stopping)) loop_stop_listening(l);
}

void ngws_loop_post(ngws_loop_t *l, ngws_task_t *t) {
    t->next = NULL;
    pthread_mutex_lock(&l->mu);
    if (l->tail) l->tail->next = t; else l->head = t;
    l->tail = t;
    pthread_mutex_unlock(&l->mu);
    if (!ng_atomic_exchange(&l->wake_pending, true)) us_wakeup_loop(l->loop);
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
    if (ng_atomic_load(&l->srv->stopping)) loop_stop_listening(l);
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
    ng_atomic_store(&srv->stopping, true);
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
size_t ngws_server_backlog_bytes(ngws_server_t *srv) { return ng_atomic_load_explicit(&srv->backlog_total, NG_MO_RELAXED); }
void ngws_server_stats(ngws_server_t *srv, ngws_stats_t *o) {
    o->backlog_bytes = ngws_server_backlog_bytes(srv);
    o->closed_conn_limit = ng_atomic_load(&srv->closed_conn_limit);
    o->closed_total_limit = ng_atomic_load(&srv->closed_total_limit);
}
ngws_loop_t *ngws_server_loop(ngws_server_t *srv, int i) { return i >= 0 && i < srv->n_loops ? &srv->loops[i] : NULL; }
