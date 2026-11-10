/* ngws_handshake - HTTP and the WebSocket upgrade (see ngws_internal.h). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ngws_internal.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "../ws_proto.h"

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
    char *p = nx_out_reserve(x, (size_t) hl + len);
    if (!p) return;
    memcpy(p, head, (size_t) hl);
    if (len) memcpy(p + hl, body, len);
    nx_close_after_flush(x);
}

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

/* Returns header bytes consumed, 0 if incomplete, -1 if the request was answered/failed. */
long nx_handle_http(sockx_t *x, const char *b, size_t n) {
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
    char *p = nx_out_reserve(x, sizeof(r1) - 1 + 28 + 4);
    if (!p) return -1;
    memcpy(p, r1, sizeof(r1) - 1); p += sizeof(r1) - 1;
    memcpy(p, accept, 28); p += 28;
    memcpy(p, "\r\n\r\n", 4);
    x->state = ST_WS;
    us_socket_timeout(0, x->s, srv->cfg.idle_timeout);
    nx_ws_list_add(x);
    if (srv->cfg.on_open) srv->cfg.on_open((ngws_socket_t *) x->s, &req);
    if (us_socket_is_closed(0, x->s)) return -1;
    return (long) hn;
}
