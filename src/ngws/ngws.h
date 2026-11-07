/* ngws - small multithreaded WebSocket server in pure C (MIT, in-tree).
 *
 * Transport: uSockets (Apache-2.0, epoll, no TLS).
 * Framing:   in-tree zero-copy codec (ws_proto.c). wslay (MIT) was benchmarked
 *            as an alternative and lost on CPU per byte, see BENCHMARKS.md.
 * Handshake: in-tree SHA-1/base64 (ws_proto.c).
 *
 * Threading model: N event loops (one thread each), all listening on the same
 * port with SO_REUSEPORT. Every ngws_socket_t belongs to exactly one loop and
 * may only be touched on that loop's thread. Other threads talk to a loop with
 * ngws_loop_post(), which is thread-safe, allocation-free (intrusive task) and
 * coalesces wakeups.
 *
 * Writes are corked: ngws_send() appends to the socket's output buffer and the
 * buffer is flushed with one write() at the end of the current loop iteration,
 * so many messages to the same socket in one iteration cost one syscall. */
#ifndef NGWS_H_
#define NGWS_H_
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct ngws_server ngws_server_t;
typedef struct ngws_loop ngws_loop_t;
typedef struct ngws_socket ngws_socket_t;

enum { NGWS_OP_CONT = 0, NGWS_OP_TEXT = 1, NGWS_OP_BINARY = 2,
       NGWS_OP_CLOSE = 8, NGWS_OP_PING = 9, NGWS_OP_PONG = 10 };

/* Result of ngws_send(). */
enum { NGWS_SEND_OK = 0,        /* written to the kernel or corked */
       NGWS_SEND_BACKPRESSURE,  /* buffered: above drain watermark */
       NGWS_SEND_DROPPED };     /* socket closing/closed or limit exceeded */

typedef struct {
    const char *method; size_t method_len;
    const char *path;   size_t path_len;
    const char *headers; size_t headers_len;   /* raw header block */
} ngws_http_req_t;

typedef struct {
    /* WebSocket callbacks (loop thread). */
    void (*on_open)(ngws_socket_t *ws, const ngws_http_req_t *req);
    void (*on_message)(ngws_socket_t *ws, char *data, size_t len, int opcode);
    void (*on_close)(ngws_socket_t *ws, int code);
    void (*on_drain)(ngws_socket_t *ws);
    /* Plain HTTP request (non-upgrade). Must call ngws_http_respond().
     * NULL: reply 426 Upgrade Required. */
    void (*on_http)(ngws_socket_t *s, const ngws_http_req_t *req);
    /* Per-loop init/teardown on the loop thread (optional). */
    void (*on_loop_start)(ngws_loop_t *loop);
    void (*on_loop_stop)(ngws_loop_t *loop);

    int port;
    const char *host;            /* NULL = any */
    int loops;                   /* event-loop threads (default 1) */
    size_t max_payload;          /* max message size, close 1009 (default 16 MiB) */
    size_t max_backpressure;     /* buffered-bytes cutoff, close socket (default 16 MiB) */
    unsigned idle_timeout;       /* seconds; 0 = off. A ping is sent at timeout,
                                  * the socket is closed if nothing arrives by the
                                  * next one. Must be a multiple of 4. */
    unsigned handshake_timeout;  /* seconds (default 12) */
    size_t user_size;            /* bytes of per-socket user data */
    void *user;                  /* opaque, see ngws_server_user() */
    int skip_utf8_check;        /* 1: don't validate TEXT payloads as UTF-8 (RFC 6455 8.1 requires it) */
} ngws_config_t;

ngws_server_t *ngws_server_create(const ngws_config_t *cfg);
/* Runs all loops; blocks until ngws_server_stop(). Returns false if listen failed. */
bool ngws_server_run(ngws_server_t *srv);
void ngws_server_stop(ngws_server_t *srv);     /* thread-safe */
void ngws_server_free(ngws_server_t *srv);
void *ngws_server_user(ngws_server_t *srv);
int ngws_server_loop_count(ngws_server_t *srv);
ngws_loop_t *ngws_server_loop(ngws_server_t *srv, int idx);

/* --- loop thread only ----------------------------------------------------- */
int  ngws_send(ngws_socket_t *ws, const void *data, size_t len, int opcode);
/* Append an already-framed message (see ngws_frame_build). */
int  ngws_send_raw(ngws_socket_t *ws, const void *frame, size_t len);
/* Same, frame given as three consecutive pieces (copied into one region). */
int  ngws_send_raw3(ngws_socket_t *ws, const void *a, size_t an, const void *b, size_t bn, const void *c, size_t cn);
/* Zero-copy: queue caller memory holding a complete frame. It must stay valid
 * until the end of the current loop iteration (see ngws_loop_alloc/defer). */
int  ngws_send_shared(ngws_socket_t *ws, const void *frame, size_t len);
void ngws_close(ngws_socket_t *ws, int code, const char *reason);  /* graceful */
void ngws_terminate(ngws_socket_t *ws);                            /* abrupt */
bool ngws_is_closed(ngws_socket_t *ws);
size_t ngws_buffered(ngws_socket_t *ws);
void *ngws_user(ngws_socket_t *ws);
ngws_loop_t *ngws_socket_loop(ngws_socket_t *ws);
ngws_server_t *ngws_socket_server(ngws_socket_t *ws);
/* Peer address as text, e.g. "1.2.3.4:5678". Returns length. */
int  ngws_remote_address(ngws_socket_t *ws, char *buf, size_t cap);
/* Plain-HTTP reply; socket is closed after the body is flushed. */
void ngws_http_respond(ngws_socket_t *s, const char *status, const char *extra_headers,
                       const char *content_type, const void *body, size_t len);
/* Visit every open WebSocket on this loop (loop thread). */
void ngws_loop_foreach(ngws_loop_t *loop, void (*fn)(ngws_socket_t *ws, void *arg), void *arg);
/* Scratch memory valid until the end of the current loop iteration. */
void *ngws_loop_alloc(ngws_loop_t *loop, size_t n);
/* Same, unaligned: frames allocated back to back this way and passed to
 * ngws_send_shared() in order coalesce into one iovec per socket. */
void *ngws_loop_alloc_frame(ngws_loop_t *loop, size_t n);
/* Run fn(arg) at the end of the current iteration, after output is flushed
 * (e.g. to drop a reference on a frame passed to ngws_send_shared). */
void ngws_loop_defer(ngws_loop_t *loop, void (*fn)(void *), void *arg);
int  ngws_loop_index(ngws_loop_t *loop);
size_t ngws_loop_count(ngws_loop_t *loop);         /* open WebSockets */
void *ngws_loop_get_user(ngws_loop_t *loop);
void ngws_loop_set_user(ngws_loop_t *loop, void *p);

/* --- any thread -------------------------------------------------------------- */
typedef struct ngws_task {
    struct ngws_task *next;
    void (*run)(struct ngws_task *t, ngws_loop_t *loop);
} ngws_task_t;
/* Queue t->run(t, loop) on the loop's thread. Thread-safe, no allocation. */
void ngws_loop_post(ngws_loop_t *loop, ngws_task_t *t);

/* Serialize a server->client frame into out (needs len + 10 bytes).
 * Returns total frame length. Thread-safe; use it to frame a broadcast once
 * and ngws_send_raw() the same bytes to many sockets. */
size_t ngws_frame_build(void *out, int opcode, const void *data, size_t len);
size_t ngws_frame_overhead(size_t len);

#endif
