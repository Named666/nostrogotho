/* ngload - multithreaded epoll WebSocket / Nostr load generator (pure C, MIT).
 *
 *   ngload [options] <mode>
 * modes
 *   hold          open -c connections, hold them -d seconds, report memory/CPU
 *   echo          -c connections each keep -P messages of -m bytes in flight
 *   bcast         -c subscribers; -n publishers each send -R msgs/s (0 = closed
 *                 loop, -P in flight); payload carries a send timestamp, every
 *                 delivery's latency goes in a histogram
 *   nostr-pub     publish pre-signed events from -f (one ["EVENT",..] per line),
 *                 -c connections, -P in flight each; counts OK replies
 *   nostr-fanout  -c subscribers send REQ {"kinds":[1],"limit":0}; -n
 *                 publishers send events from -f at -R events/s total; latency
 *                 per delivery (content must be the decimal event index)
 * options
 *   -H host (127.0.0.1)  -p port (9001)  -c conns  -t threads (nproc/2)
 *   -i source IPs (127.0.0.2..; default conns/20000+1)  -d seconds (10)
 *   -m msg bytes (64)  -P pipeline (1)  -n publishers (1)  -R rate (0)
 *   -f events file  -x server pid (RSS/CPU sampling)  -w warmup s (1)
 *   -k connect batch per thread (256)  -q quiet
 * Output: one "key=value ..." summary line. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum { M_HOLD, M_ECHO, M_BCAST, M_NPUB, M_NFAN };
enum { C_CONNECTING, C_HANDSHAKE, C_OPEN, C_DEAD };
enum { R_SUB, R_PUB };

static const char *host = "127.0.0.1";
static int port = 9001, nconns = 100, nthreads, nsrc, duration = 10, msgsize = 64, pipel = 1, npubs = 1;
static double rate; static int warmup = 1, cbatch = 256, quiet, server_pid, mode;
static const char *evfile;
static char **events; static size_t nevents;
static uint64_t *ev_sent_ns;        /* fanout: send time per event index */
static atomic_size_t ev_next;        /* next event index to send */

static const uint8_t MASK[4] = { 0x37, 0xfa, 0x21, 0x3d };

static uint64_t now_ns(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint64_t) t.tv_sec * 1000000000ull + (uint64_t) t.tv_nsec; }

/* ---------------------------------------------------------- histogram -- */
#define HSUB 64
#define HB (40 * HSUB)
typedef struct { uint64_t b[HB]; uint64_t n, sum, max; } hist_t;
static int hidx(uint64_t v) {                 /* v in ns */
    if (v < HSUB) return (int) v;
    int e = 63 - __builtin_clzll(v);          /* >= 6 */
    int sub = (int) ((v >> (e - 6)) & (HSUB - 1));
    int i = (e - 5) * HSUB + sub;
    return i < HB ? i : HB - 1;
}
static uint64_t hval(int i) {
    if (i < HSUB) return (uint64_t) i;
    int e = i / HSUB + 5, sub = i % HSUB;
    return ((uint64_t) (HSUB + sub)) << (e - 6);
}
static void hadd(hist_t *h, uint64_t v) { h->b[hidx(v)]++; h->n++; h->sum += v; if (v > h->max) h->max = v; }
static double hq(const hist_t *h, double q) {
    if (!h->n) return 0;
    uint64_t want = (uint64_t) ceil(q * (double) h->n), acc = 0;
    for (int i = 0; i < HB; i++) { acc += h->b[i]; if (acc >= want) return (double) hval(i); }
    return (double) h->max;
}

/* ---------------------------------------------------------- connection -- */
typedef struct {
    int fd, state, role;
    uint8_t *rb; size_t rlen, rcap;
    uint8_t *wb; size_t wlen, woff, wcap;
    int inflight;
    bool want_out;
    uint64_t next_send_ns;
    size_t ev_lo, ev_hi, ev_pos;    /* nostr-pub slice */
    uint64_t sent[64]; unsigned sh, st;   /* nostr-pub: send times, OKs arrive in order */
} conn_t;

typedef struct {
    int idx, ep;
    pthread_t th;
    conn_t *c; int n;
    int open, failed, connecting;
    int next_to_connect;
    uint64_t msgs, bytes, oks, fails;
    hist_t hist;
    bool measuring;
    pthread_mutex_t hmu;
} thr_t;

static thr_t *T;
static atomic_int phase;          /* 0 connect, 1 run, 2 stop */
static atomic_int total_open, total_failed;
static atomic_bool measuring;
static struct sockaddr_in dst;

static void wb_append(conn_t *c, const void *p, size_t n) {
    if (c->wlen + n > c->wcap) {
        if (c->woff) { memmove(c->wb, c->wb + c->woff, c->wlen - c->woff); c->wlen -= c->woff; c->woff = 0; }
        if (c->wlen + n > c->wcap) {
            size_t nc = c->wcap ? c->wcap * 2 : 4096; while (nc < c->wlen + n) nc *= 2;
            c->wb = realloc(c->wb, nc); c->wcap = nc;
        }
    }
    memcpy(c->wb + c->wlen, p, n); c->wlen += n;
}

static void set_out(thr_t *t, conn_t *c, bool on) {
    if (c->want_out == on) return;
    c->want_out = on;
    struct epoll_event e = { .events = EPOLLIN | (on ? EPOLLOUT : 0), .data.ptr = c };
    epoll_ctl(t->ep, EPOLL_CTL_MOD, c->fd, &e);
}

static void kill_conn(thr_t *t, conn_t *c) {
    if (c->state == C_DEAD) return;
    if (c->state == C_OPEN) { t->open--; atomic_fetch_sub(&total_open, 1); }
    else { t->connecting--; }
    t->failed++; atomic_fetch_add(&total_failed, 1);
    epoll_ctl(t->ep, EPOLL_CTL_DEL, c->fd, NULL);
    close(c->fd); c->state = C_DEAD;
}

static void do_write(thr_t *t, conn_t *c) {
    while (c->woff < c->wlen) {
        ssize_t w = send(c->fd, c->wb + c->woff, c->wlen - c->woff, MSG_NOSIGNAL);
        if (w < 0) { if (errno == EAGAIN) { set_out(t, c, true); return; } kill_conn(t, c); return; }
        c->woff += (size_t) w;
    }
    c->woff = c->wlen = 0;
    set_out(t, c, false);
}

/* masked client frame */
static void send_frame(conn_t *c, int op, const uint8_t *p, size_t n) {
    uint8_t h[14]; size_t hl = 2;
    h[0] = (uint8_t) (0x80 | op);
    if (n < 126) h[1] = (uint8_t) (0x80 | n);
    else if (n <= 0xFFFF) { h[1] = 0x80 | 126; h[2] = (uint8_t) (n >> 8); h[3] = (uint8_t) n; hl = 4; }
    else { h[1] = 0x80 | 127; for (int i = 0; i < 8; i++) h[2 + i] = (uint8_t) ((uint64_t) n >> (56 - 8 * i)); hl = 10; }
    memcpy(h + hl, MASK, 4); hl += 4;
    if (c->wlen + hl + n > c->wcap) wb_append(c, h, 0);
    wb_append(c, h, hl);
    size_t o = c->wlen;
    wb_append(c, p, n);
    for (size_t i = 0; i < n; i++) c->wb[o + i] ^= MASK[i & 3];
}

static uint8_t *echo_payload;
static void send_echo(conn_t *c) { send_frame(c, 2, echo_payload, (size_t) msgsize); c->inflight++; }

static void send_bcast(conn_t *c) {
    uint8_t buf[65536]; size_t n = (size_t) msgsize < 8 ? 8 : (size_t) msgsize;
    if (n > sizeof(buf)) n = sizeof(buf);
    memset(buf, 'b', n);
    uint64_t ts = now_ns(); memcpy(buf, &ts, 8);
    send_frame(c, 2, buf, n); c->inflight++;
}

static bool send_next_event(conn_t *c, bool fanout) {
    size_t i;
    if (fanout) { i = atomic_fetch_add(&ev_next, 1); if (i >= nevents) return false; ev_sent_ns[i] = now_ns(); }
    else { if (c->ev_pos >= c->ev_hi) return false; i = c->ev_pos++; c->sent[c->st++ & 63] = now_ns(); }
    send_frame(c, 1, (const uint8_t *) events[i], strlen(events[i]));
    c->inflight++;
    return true;
}

static void on_open(thr_t *t, conn_t *c) {
    c->state = C_OPEN; t->connecting--; t->open++; atomic_fetch_add(&total_open, 1);
    if (mode == M_NFAN && c->role == R_SUB) {
        static const char req[] = "[\"REQ\",\"f\",{\"kinds\":[1],\"limit\":0}]";
        send_frame(c, 1, (const uint8_t *) req, sizeof(req) - 1);
    }
}

static void start_traffic(thr_t *t, conn_t *c) {
    if (c->state != C_OPEN) return;
    if (mode == M_ECHO) for (int i = 0; i < pipel; i++) send_echo(c);
    else if (mode == M_BCAST && c->role == R_PUB && rate <= 0) for (int i = 0; i < pipel; i++) send_bcast(c);
    else if (mode == M_NPUB) for (int i = 0; i < pipel; i++) if (!send_next_event(c, false)) break;
    do_write(t, c);
}

static long parse_index_from_event(const uint8_t *p, size_t n) {
    static const char key[] = "\"content\":\"";
    const uint8_t *e = memmem(p, n, key, sizeof(key) - 1);
    if (!e) return -1;
    e += sizeof(key) - 1;
    long v = 0; int d = 0;
    while (e < p + n && *e >= '0' && *e <= '9') { v = v * 10 + (*e - '0'); e++; d++; }
    return d ? v : -1;
}

static void on_message(thr_t *t, conn_t *c, int op, uint8_t *p, size_t n) {
    bool m = atomic_load_explicit(&measuring, memory_order_relaxed);
    if (op == 9) { send_frame(c, 10, p, n); return; }
    if (op >= 8) return;
    switch (mode) {
    case M_ECHO:
        c->inflight--;
        if (m) { t->msgs++; t->bytes += n; }
        if (atomic_load(&phase) == 1) send_echo(c);
        break;
    case M_BCAST:
        if (n >= 8) {
            uint64_t ts; memcpy(&ts, p, 8);
            if (m) { t->msgs++; t->bytes += n; hadd(&t->hist, now_ns() - ts); }
        }
        if (c->role == R_PUB && rate <= 0) {
            /* closed loop: each own message echoed back releases a slot */
            c->inflight--;
            if (atomic_load(&phase) == 1) send_bcast(c);
        }
        break;
    case M_NPUB:
        if (n > 5 && memcmp(p, "[\"OK\"", 5) == 0) {
            c->inflight--;
            bool ok = memmem(p, n, "\",true,", 7) != NULL;
            uint64_t sent_at = c->sh != c->st ? c->sent[c->sh++ & 63] : 0;
            if (m) { if (ok) t->oks++; else t->fails++; t->msgs++; if (sent_at) hadd(&t->hist, now_ns() - sent_at); }
            if (atomic_load(&phase) == 1) send_next_event(c, false);
        }
        break;
    case M_NFAN:
        if (n > 12 && memcmp(p, "[\"EVENT\",\"f\"", 12) == 0) {
            long i = parse_index_from_event(p, n);
            if (i >= 0 && (size_t) i < nevents && ev_sent_ns[i]) {
                if (m) { t->msgs++; hadd(&t->hist, now_ns() - ev_sent_ns[i]); }
            }
        } else if (n > 5 && memcmp(p, "[\"OK\"", 5) == 0) {
            c->inflight--;
            if (m) { if (memmem(p, n, "\",true,", 7)) t->oks++; else t->fails++; }
        }
        break;
    }
}

static void do_read(thr_t *t, conn_t *c) {
    for (;;) {
        if (c->rcap - c->rlen < 2048) { c->rcap = c->rcap ? c->rcap * 2 : 4096; c->rb = realloc(c->rb, c->rcap); }
        ssize_t r = recv(c->fd, c->rb + c->rlen, c->rcap - c->rlen, 0);
        if (r == 0) { kill_conn(t, c); return; }
        if (r < 0) { if (errno == EAGAIN) break; kill_conn(t, c); return; }
        c->rlen += (size_t) r;
        if ((size_t) r < c->rcap - c->rlen) break;
    }
    size_t off = 0;
    if (c->state == C_HANDSHAKE) {
        uint8_t *e = memmem(c->rb, c->rlen, "\r\n\r\n", 4);
        if (!e) return;
        if (c->rlen < 12 || memcmp(c->rb + 9, "101", 3) != 0) { kill_conn(t, c); return; }
        off = (size_t) (e + 4 - c->rb);
        on_open(t, c);
        if (atomic_load(&phase) == 1) start_traffic(t, c);
    }
    while (c->rlen - off >= 2) {
        uint8_t *b = c->rb + off; size_t avail = c->rlen - off;
        int op = b[0] & 0x0F; uint64_t len = b[1] & 0x7F; size_t hl = 2;
        if (len == 126) { if (avail < 4) break; len = (uint64_t) b[2] << 8 | b[3]; hl = 4; }
        else if (len == 127) { if (avail < 10) break; len = 0; for (int i = 0; i < 8; i++) len = len << 8 | b[2 + i]; hl = 10; }
        if (avail < hl + len) break;
        on_message(t, c, op, b + hl, (size_t) len);
        off += hl + (size_t) len;
        if (c->state == C_DEAD) return;
    }
    if (off) { memmove(c->rb, c->rb + off, c->rlen - off); c->rlen -= off; }
    if (c->rcap > 262144 && c->rlen < 4096) { c->rcap = 4096; c->rb = realloc(c->rb, c->rcap); }
    if (c->wlen > c->woff) do_write(t, c);
}

static void start_connect(thr_t *t, conn_t *c, int global_idx) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) { c->state = C_DEAD; t->failed++; atomic_fetch_add(&total_failed, 1); return; }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef IP_BIND_ADDRESS_NO_PORT
    setsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &one, sizeof(one));
#endif
    if (nsrc > 0) {
        struct sockaddr_in src = { .sin_family = AF_INET };
        src.sin_addr.s_addr = htonl(0x7F000002u + (uint32_t) (global_idx % nsrc));
        bind(fd, (struct sockaddr *) &src, sizeof(src));
    }
    c->fd = fd; c->state = C_CONNECTING; t->connecting++;
    int r = connect(fd, (struct sockaddr *) &dst, sizeof(dst));
    if (r < 0 && errno != EINPROGRESS) { close(fd); c->state = C_DEAD; t->connecting--; t->failed++; atomic_fetch_add(&total_failed, 1); return; }
    struct epoll_event e = { .events = EPOLLOUT | EPOLLIN, .data.ptr = c };
    c->want_out = true;
    epoll_ctl(t->ep, EPOLL_CTL_ADD, fd, &e);
}

static void handshake_send(thr_t *t, conn_t *c) {
    int err = 0; socklen_t el = sizeof(err);
    getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el);
    if (err) { kill_conn(t, c); return; }
    char req[256];
    int n = snprintf(req, sizeof(req), "GET / HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", host, port);
    c->state = C_HANDSHAKE;
    wb_append(c, req, (size_t) n);
    do_write(t, c);
}

static void *thr_main(void *arg) {
    thr_t *t = arg;
    t->ep = epoll_create1(0);
    struct epoll_event ev[512];
    bool started = false;
    uint64_t last_tick = now_ns();
    for (;;) {
        int ph = atomic_load(&phase);
        if (ph == 2) break;
        while (t->next_to_connect < t->n && t->connecting < cbatch) {
            int i = t->next_to_connect++;
            start_connect(t, &t->c[i], t->idx + i * nthreads);
        }
        if (ph == 1 && !started) {
            started = true;
            for (int i = 0; i < t->n; i++) start_traffic(t, &t->c[i]);
        }
        int timeout = 1;
        int n = epoll_wait(t->ep, ev, 512, timeout);
        for (int i = 0; i < n; i++) {
            conn_t *c = ev[i].data.ptr;
            if (c->state == C_DEAD) continue;
            if (ev[i].events & (EPOLLERR | EPOLLHUP)) { if (c->state == C_CONNECTING) { kill_conn(t, c); continue; } }
            if (c->state == C_CONNECTING) { if (ev[i].events & EPOLLOUT) handshake_send(t, c); continue; }
            if (ev[i].events & EPOLLOUT) do_write(t, c);
            if (c->state != C_DEAD && (ev[i].events & EPOLLIN)) do_read(t, c);
        }
        /* rate-driven publishers */
        if (ph == 1 && rate > 0 && (mode == M_BCAST || mode == M_NFAN)) {
            uint64_t now = now_ns();
            if (now - last_tick >= 200000) {
                last_tick = now;
                for (int i = 0; i < t->n; i++) {
                    conn_t *c = &t->c[i];
                    if (c->role != R_PUB || c->state != C_OPEN) continue;
                    double per = rate / npubs;
                    uint64_t gap = (uint64_t) (1e9 / per);
                    if (!c->next_send_ns) c->next_send_ns = now;
                    int burst = 0;
                    while (c->next_send_ns <= now && burst < 1000) {
                        if (mode == M_BCAST) send_bcast(c); else if (!send_next_event(c, true)) { c->next_send_ns = UINT64_MAX; break; }
                        c->next_send_ns += gap; burst++;
                    }
                    if (burst) do_write(t, c);
                }
            }
        }
    }
    return NULL;
}

/* ---------------------------------------------------------- proc stats -- */
static long rss_kb(int pid) {
    char p[64]; snprintf(p, sizeof(p), "/proc/%d/status", pid);
    FILE *f = fopen(p, "r"); if (!f) return -1;
    char line[256]; long v = -1;
    while (fgets(line, sizeof(line), f)) if (!strncmp(line, "VmRSS:", 6)) { v = atol(line + 6); break; }
    fclose(f); return v;
}
static double cpu_s(int pid) {
    char p[64]; snprintf(p, sizeof(p), "/proc/%d/stat", pid);
    FILE *f = fopen(p, "r"); if (!f) return -1;
    char buf[1024]; size_t n = fread(buf, 1, sizeof(buf) - 1, f); fclose(f); buf[n] = 0;
    char *s = strrchr(buf, ')'); if (!s) return -1;
    unsigned long ut = 0, st = 0;
    sscanf(s + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", &ut, &st);
    return (double) (ut + st) / (double) sysconf(_SC_CLK_TCK);
}
static double self_cpu_s(void) { struct rusage u; getrusage(RUSAGE_SELF, &u); return u.ru_utime.tv_sec + u.ru_stime.tv_sec + (u.ru_utime.tv_usec + u.ru_stime.tv_usec) / 1e6; }

static void load_events(void) {
    FILE *f = fopen(evfile, "r");
    if (!f) { perror(evfile); exit(1); }
    size_t cap = 1024; events = malloc(cap * sizeof(char *));
    char *line = NULL; size_t lc = 0; ssize_t n;
    while ((n = getline(&line, &lc, f)) > 0) {
        while (n && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = 0;
        if (!n) continue;
        if (nevents == cap) { cap *= 2; events = realloc(events, cap * sizeof(char *)); }
        events[nevents++] = strndup(line, (size_t) n);
    }
    free(line); fclose(f);
    ev_sent_ns = calloc(nevents, sizeof(uint64_t));
}

int main(int argc, char **argv) {
    nthreads = (int) sysconf(_SC_NPROCESSORS_ONLN) / 2; if (nthreads < 1) nthreads = 1;
    int opt; nsrc = -1;
    while ((opt = getopt(argc, argv, "H:p:c:t:i:d:m:P:n:R:f:x:w:k:q")) != -1) {
        switch (opt) {
        case 'H': host = optarg; break; case 'p': port = atoi(optarg); break;
        case 'c': nconns = atoi(optarg); break; case 't': nthreads = atoi(optarg); break;
        case 'i': nsrc = atoi(optarg); break; case 'd': duration = atoi(optarg); break;
        case 'm': msgsize = atoi(optarg); break; case 'P': pipel = atoi(optarg); break;
        case 'n': npubs = atoi(optarg); break; case 'R': rate = atof(optarg); break;
        case 'f': evfile = optarg; break; case 'x': server_pid = atoi(optarg); break;
        case 'w': warmup = atoi(optarg); break; case 'k': cbatch = atoi(optarg); break;
        case 'q': quiet = 1; break;
        default: fprintf(stderr, "see source header for usage\n"); return 2;
        }
    }
    if (optind >= argc) { fprintf(stderr, "mode required\n"); return 2; }
    const char *ms = argv[optind];
    mode = !strcmp(ms, "hold") ? M_HOLD : !strcmp(ms, "echo") ? M_ECHO : !strcmp(ms, "bcast") ? M_BCAST :
           !strcmp(ms, "nostr-pub") ? M_NPUB : !strcmp(ms, "nostr-fanout") ? M_NFAN : -1;
    if (mode < 0) { fprintf(stderr, "bad mode\n"); return 2; }
    if (mode == M_NPUB && pipel > 64) { fprintf(stderr, "nostr-pub: -P max 64\n"); return 2; }
    if ((mode == M_NPUB || mode == M_NFAN) && !evfile) { fprintf(stderr, "-f events file required\n"); return 2; }
    if (evfile) load_events();
    if (nsrc < 0) nsrc = nconns / 20000 + 1;
    if (strcmp(host, "127.0.0.1") != 0) nsrc = 0;
    struct rlimit rl; getrlimit(RLIMIT_NOFILE, &rl); rl.rlim_cur = rl.rlim_max; setrlimit(RLIMIT_NOFILE, &rl);
    if ((long) rl.rlim_cur < nconns + 64) fprintf(stderr, "warning: RLIMIT_NOFILE %ld < conns\n", (long) rl.rlim_cur);
    dst.sin_family = AF_INET; dst.sin_port = htons((uint16_t) port); inet_pton(AF_INET, host, &dst.sin_addr);
    echo_payload = malloc((size_t) msgsize + 1); memset(echo_payload, 'e', (size_t) msgsize);
    if (nthreads > nconns) nthreads = nconns;

    T = calloc((size_t) nthreads, sizeof(thr_t));
    conn_t *all = calloc((size_t) nconns, sizeof(conn_t));
    /* round-robin conns over threads; publishers are the first npubs conns */
    int *cnt = calloc((size_t) nthreads, sizeof(int));
    for (int i = 0; i < nconns; i++) cnt[i % nthreads]++;
    conn_t *p = all;
    for (int k = 0; k < nthreads; k++) { T[k].idx = k; T[k].c = p; T[k].n = cnt[k]; p += cnt[k]; }
    for (int k = 0, g = 0; k < nthreads; k++)
        for (int i = 0; i < T[k].n; i++, g++) {
            conn_t *c = &T[k].c[i];
            int gi = k + i * nthreads;
            c->role = (mode == M_BCAST || mode == M_NFAN) ? (gi < npubs ? R_PUB : R_SUB) : R_SUB;
            if (mode == M_NPUB) { size_t per = nevents / (size_t) nconns; c->ev_lo = c->ev_pos = per * (size_t) gi; c->ev_hi = c->ev_lo + per; }
            (void) g;
        }
    long rss0 = server_pid ? rss_kb(server_pid) : -1;
    uint64_t t0 = now_ns();
    for (int k = 0; k < nthreads; k++) pthread_create(&T[k].th, NULL, thr_main, &T[k]);
    /* wait for connect phase */
    int last = -1; uint64_t stall = now_ns();
    for (;;) {
        usleep(20000);
        int o = atomic_load(&total_open), f = atomic_load(&total_failed);
        if (o + f >= nconns) break;
        if (o != last) { last = o; stall = now_ns(); }
        if (now_ns() - stall > 15000000000ull) { fprintf(stderr, "connect stalled at %d/%d\n", o, nconns); break; }
    }
    double connect_s = (now_ns() - t0) / 1e9;
    if (mode == M_NFAN) usleep(500000 + (useconds_t) nconns * 20);   /* let REQs register */
    long rss1 = server_pid ? rss_kb(server_pid) : -1;
    if (!quiet) fprintf(stderr, "connected %d (failed %d) in %.2fs\n", atomic_load(&total_open), atomic_load(&total_failed), connect_s);

    atomic_store(&phase, 1);
    sleep((unsigned) warmup);
    uint64_t m0 = 0, b0 = 0;
    for (int k = 0; k < nthreads; k++) { m0 += T[k].msgs; b0 += T[k].bytes; }
    double sc0 = server_pid ? cpu_s(server_pid) : 0, cc0 = self_cpu_s();
    atomic_store(&measuring, true);
    uint64_t w0 = now_ns();
    for (int s = 0; s < duration * 10; s++) {
        usleep(100000);
        if (mode == M_NPUB) {     /* stop early when all events acked */
            uint64_t m = 0; for (int k = 0; k < nthreads; k++) m += T[k].msgs;
            if (m >= nevents - (nevents % (size_t) nconns)) break;
        }
        if (mode == M_NFAN && atomic_load(&ev_next) >= nevents) { usleep(300000); break; }
    }
    atomic_store(&measuring, false);
    double secs = (now_ns() - w0) / 1e9;
    double sc1 = server_pid ? cpu_s(server_pid) : 0, cc1 = self_cpu_s();
    long rss2 = server_pid ? rss_kb(server_pid) : -1;
    atomic_store(&phase, 2);
    for (int k = 0; k < nthreads; k++) pthread_join(T[k].th, NULL);

    uint64_t msgs = 0, bytes = 0, oks = 0, fails = 0;
    hist_t *h = calloc(1, sizeof(hist_t));
    for (int k = 0; k < nthreads; k++) {
        msgs += T[k].msgs; bytes += T[k].bytes; oks += T[k].oks; fails += T[k].fails;
        for (int i = 0; i < HB; i++) h->b[i] += T[k].hist.b[i];
        h->n += T[k].hist.n; h->sum += T[k].hist.sum; if (T[k].hist.max > h->max) h->max = T[k].hist.max;
    }
    (void) m0; (void) b0;
    printf("mode=%s conns=%d open=%d failed=%d threads=%d src_ips=%d connect_s=%.2f",
           ms, nconns, atomic_load(&total_open), atomic_load(&total_failed), nthreads, nsrc, connect_s);
    if (mode != M_HOLD)
        printf(" secs=%.2f msgs=%llu msgs_s=%.0f MB_s=%.1f", secs, (unsigned long long) msgs, msgs / secs, bytes / secs / 1e6);
    if (mode == M_NPUB || mode == M_NFAN) printf(" ok=%llu rejected=%llu", (unsigned long long) oks, (unsigned long long) fails);
    if (h->n) printf(" lat_us_p50=%.0f p99=%.0f p999=%.0f max=%.0f", hq(h, .5) / 1e3, hq(h, .99) / 1e3, hq(h, .999) / 1e3, h->max / 1e3);
    if (server_pid) {
        printf(" srv_rss_base_mb=%.1f srv_rss_conn_mb=%.1f bytes_per_conn=%.0f srv_rss_end_mb=%.1f srv_cpu_pct=%.0f",
               rss0 / 1024.0, rss1 / 1024.0, (rss1 - rss0) * 1024.0 / (atomic_load(&total_open) ? atomic_load(&total_open) : 1),
               rss2 / 1024.0, (sc1 - sc0) / secs * 100);
    }
    printf(" client_cpu_pct=%.0f\n", (cc1 - cc0) / secs * 100);
    return 0;
}
