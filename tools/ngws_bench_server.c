/* Reference server for benchmarking the ngws layer (mirrors the uWS
 * reference in tools/bench/uws_ref.cpp).
 *   ngws_bench_server <port> <loops> echo|broadcast
 * echo:      every message is echoed back.
 * broadcast: every message is published to all sockets on the same loop
 *            (framed once, same bytes appended to every socket).        */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ngws/ngws.h"
#include <signal.h>
#include <unistd.h>

/* PGO training build (-fprofile-generate defines __gcov_dump): write the
 * profile when the benchmark harness kills us. Weak + unconditional so the
 * gen and use builds have the same control flow. */
extern void __gcov_dump(void) __attribute__((weak));
static void on_term(int sig) { (void) sig; __gcov_dump(); _exit(0); }

static int mode_bcast;
typedef struct { const char *f; size_t n; } bc_t;
static void bc_one(ngws_socket_t *ws, void *a) { bc_t *b = a; ngws_send_shared(ws, b->f, b->n); }

static void on_message(ngws_socket_t *ws, char *d, size_t n, int op) {
    if (!mode_bcast) { ngws_send(ws, d, n, op); return; }
    char *fbuf = ngws_loop_alloc_frame(ngws_socket_loop(ws), ngws_frame_overhead(n) + n);   /* frame once, share */
    bc_t b = { fbuf, ngws_frame_build(fbuf, op, d, n) };
    ngws_loop_foreach(ngws_socket_loop(ws), bc_one, &b);
}

int main(int argc, char **argv) {
    ngws_config_t c = {0};
    c.port = argc > 1 ? atoi(argv[1]) : 9001;
    c.loops = argc > 2 ? atoi(argv[2]) : 1;
    mode_bcast = argc > 3 && strcmp(argv[3], "broadcast") == 0;
    c.on_message = on_message;
    c.max_payload = 16u << 20;
    c.max_backpressure = 64u << 20;
    c.idle_timeout = 120;
    if (__gcov_dump) { signal(SIGTERM, on_term); signal(SIGINT, on_term); }
    ngws_server_t *s = ngws_server_create(&c);
    fprintf(stderr, "ngws bench server :%d loops=%d mode=%s\n", c.port, c.loops, mode_bcast ? "broadcast" : "echo");
    return ngws_server_run(s) ? 0 : 1;
}
