/* ngws_frame - frame input (see ngws_internal.h). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ngws_internal.h"

#include <stdlib.h>
#include <string.h>

#include "../platform/ng_alloc.h"
#include "../ws_proto.h"

static void deliver(sockx_t *x, char *data, size_t len, int op) {
    ngws_server_t *srv = SRV(x);
    if (op == NGWS_OP_TEXT || op == NGWS_OP_BINARY) {
        if (op == NGWS_OP_TEXT && !srv->cfg.skip_utf8_check &&
            !ws_utf8_valid((const unsigned char *) data, len)) { nx_ws_fail(x, 1007); return; }
        if (srv->cfg.on_message) srv->cfg.on_message((ngws_socket_t *) x->s, data, len, op);
    } else if (op == NGWS_OP_PING) {
        nx_queue_frame(x, NGWS_OP_PONG, data, len);
    } else if (op == NGWS_OP_CLOSE) {
        unsigned char code[2] = { 0x03, 0xE8 };
        if (len == 1) { nx_ws_fail(x, 1002); return; }
        if (len >= 2) {
            unsigned c = (unsigned) (unsigned char) data[0] << 8 | (unsigned char) data[1];
            bool ok = (c >= 1000 && c <= 1003) || (c >= 1007 && c <= 1011) || (c >= 3000 && c <= 4999);
            if (!ok) { nx_ws_fail(x, 1002); return; }
            if (!ws_utf8_valid((const unsigned char *) data + 2, len - 2)) { nx_ws_fail(x, 1007); return; }
            code[0] = (unsigned char) data[0]; code[1] = (unsigned char) data[1];
        }
        nx_queue_frame(x, NGWS_OP_CLOSE, code, 2);
        nx_close_after_flush(x);
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
    if (x->mlen + n > x->mcap) {           /* mlen + n <= max_payload: checked by the caller */
        size_t want;
        if (!ng_size_add(x->mlen, n, &want)) return false;
        size_t nc = ng_grow_cap(x->mcap, want, n < MSG_CHUNK ? MSG_CHUNK : 1024);
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
    ng_status_t r = ws_parse_header(b, blen, &f);
    if (r == NG_E_INVALID) { nx_ws_fail(x, 1002); return -1; }
    if (r == NG_E_AGAIN) return 0;
    int code = frame_check(x, f.fin, 0, f.opcode, f.masked, f.len);
    if (code) {
        nx_ws_fail(x, code);
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
        if (!msg_append(x, p, n)) { nx_ws_fail(x, 1011); return -1; }
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
    if (ws_parse_header(b, n, &f) != NG_OK) return 4096;
    if (f.len > SRV(x)->cfg.max_payload) return 4096;   /* rejected anyway; never trust it */
    uint64_t t = f.header_len + f.len;
    return t < 4096 ? 4096 : (size_t) t;
}

void nx_ws_feed(sockx_t *x, unsigned char *data, size_t len) {
    unsigned char *b = data; size_t n = len;
    bool owned = false;
    if (x->rlen) {                        /* append to partial frame */
        if (x->rlen + len > x->rcap) {
            size_t want;
            if (!ng_size_add(x->rlen, len, &want)) { ngws_terminate((ngws_socket_t *) x->s); return; }
            size_t nc = ng_grow_cap(x->rcap, want, 4096);
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

void nx_free_inputs(sockx_t *x) {
    free(x->rbuf); x->rbuf = NULL; x->rlen = x->rcap = 0;
    msg_reset(x);
}

/* After a server-initiated close: discard frames until the peer's close frame
 * arrives, then close TCP (RFC 6455 7.1.1: the server closes first). */
void nx_drain_input(sockx_t *x, unsigned char *d, size_t n) {
    while (n) {
        if (x->skip) { size_t k = x->skip < n ? (size_t) x->skip : n; x->skip -= k; d += k; n -= k; continue; }
        unsigned char hb[14]; size_t have = x->rlen < 14 ? x->rlen : 14;
        if (have) memcpy(hb, x->rbuf, have);
        size_t take = 14 - have < n ? 14 - have : n;
        memcpy(hb + have, d, take);
        ws_frame_t f;
        ng_status_t r = ws_parse_header(hb, have + take, &f);
        if (r == NG_E_INVALID) { us_socket_close(0, x->s, 0, NULL); return; }
        if (r == NG_E_AGAIN) {                 /* keep partial header */
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
