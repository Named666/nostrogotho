/* ngws_internal.h - shared by the ngws modules only (not a public API).
 *
 *   ngws.c            event loop and server: uSockets callbacks, per-loop
 *                     task queue and wakeup, end-of-iteration flush, load
 *                     shedding, listen/run/stop, socket accessors
 *   ngws_handshake.c  HTTP request parsing, WebSocket upgrade (101), plain
 *                     HTTP responses
 *   ngws_frame.c      frame input: header validation, unmasking, message
 *                     reassembly, control frames, close-drain
 *   ngws_send.c       send queue: per-iteration iovec queue in the loop
 *                     arena, private backlog, writev flush, close frames
 *
 * Every function here runs on the socket's loop thread.
 */
#ifndef NGWS_INTERNAL_H_
#define NGWS_INTERNAL_H_

#include "ngws.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "libusockets.h"
#include "../platform/ng_atomic.h"

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
    ng_atomic_bool wake_pending;
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
    ng_atomic_bool stopping;
    ng_atomic_size backlog_total;        /* sum of obuf capacities, all loops */
    ng_atomic_ullong closed_conn_limit, closed_total_limit;
    bool uncork;                        /* flush a socket at the end of its on_data */
};

static inline sockx_t *X(struct us_socket_t *s) { return (sockx_t *) us_socket_ext(0, s); }
static inline ngws_server_t *SRV(sockx_t *x) { return x->loop->srv; }

/* ngws_send.c */
void nx_dirty_add(sockx_t *x);
void nx_dirty_del(sockx_t *x);
void nx_arena_reset(ngws_loop_t *l);
char *nx_out_reserve(sockx_t *x, size_t n);        /* NULL: limit/OOM, socket terminated */
void nx_out_release(sockx_t *x);
bool nx_flush(sockx_t *x);                         /* true: everything written */
int nx_queue_frame(sockx_t *x, int op, const void *data, size_t len);
void nx_close_after_flush(sockx_t *x);
void nx_ws_fail(sockx_t *x, int code);             /* close frame + wait for the peer */

/* ngws_handshake.c: header bytes consumed, 0 incomplete, -1 answered/failed */
long nx_handle_http(sockx_t *x, const char *b, size_t n);

/* ngws_frame.c */
void nx_ws_feed(sockx_t *x, unsigned char *data, size_t len);
void nx_free_inputs(sockx_t *x);
void nx_drain_input(sockx_t *x, unsigned char *d, size_t n);

/* ngws.c: the loop's list of open WebSockets */
void nx_ws_list_add(sockx_t *x);
void nx_ws_list_del(sockx_t *x);

#endif /* NGWS_INTERNAL_H_ */
