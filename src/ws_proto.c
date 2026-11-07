#include "ws_proto.h"
#include <string.h>

#define ROL(v, b) (((v) << (b)) | ((v) >> (32 - (b))))

static void sha1_block(uint32_t h[5], const unsigned char *p) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) w[i] = (uint32_t) p[4*i] << 24 | (uint32_t) p[4*i+1] << 16 | (uint32_t) p[4*i+2] << 8 | p[4*i+3];
    for (int i = 16; i < 80; i++) w[i] = ROL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        uint32_t t = ROL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = ROL(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void ws_sha1(const unsigned char *data, size_t len, unsigned char out[20]) {
    uint32_t h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    size_t i = 0;
    for (; i + 64 <= len; i += 64) sha1_block(h, data + i);
    unsigned char tail[128] = {0};
    size_t rem = len - i;
    memcpy(tail, data + i, rem);
    tail[rem] = 0x80;
    size_t tl = rem + 9 <= 64 ? 64 : 128;
    uint64_t bits = (uint64_t) len * 8;
    for (int j = 0; j < 8; j++) tail[tl - 1 - j] = (unsigned char) (bits >> (8 * j));
    sha1_block(h, tail);
    if (tl == 128) sha1_block(h, tail + 64);
    for (int j = 0; j < 5; j++) { out[4*j] = h[j] >> 24; out[4*j+1] = h[j] >> 16; out[4*j+2] = h[j] >> 8; out[4*j+3] = h[j]; }
}

size_t ws_base64(const unsigned char *in, size_t len, char *out) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0, i = 0;
    for (; i + 2 < len; i += 3) {
        uint32_t v = (uint32_t) in[i] << 16 | (uint32_t) in[i+1] << 8 | in[i+2];
        out[o++] = t[v >> 18]; out[o++] = t[(v >> 12) & 63]; out[o++] = t[(v >> 6) & 63]; out[o++] = t[v & 63];
    }
    if (i < len) {
        uint32_t v = (uint32_t) in[i] << 16 | (i + 1 < len ? (uint32_t) in[i+1] << 8 : 0);
        out[o++] = t[v >> 18]; out[o++] = t[(v >> 12) & 63];
        out[o++] = i + 1 < len ? t[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

void ws_accept_key(const char *key, size_t key_len, char out[29]) {
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    unsigned char buf[128], dig[20];
    if (key_len > 64) key_len = 64;
    memcpy(buf, key, key_len);
    memcpy(buf + key_len, guid, 36);
    ws_sha1(buf, key_len + 36, dig);
    ws_base64(dig, 20, out);
}

size_t ws_frame_header(unsigned char *h, int opcode, size_t n) {
    h[0] = (unsigned char) (0x80 | (opcode & 0x0F));
    if (n < 126) { h[1] = (unsigned char) n; return 2; }
    if (n <= 0xFFFF) { h[1] = 126; h[2] = (unsigned char) (n >> 8); h[3] = (unsigned char) n; return 4; }
    h[1] = 127;
    for (int i = 0; i < 8; i++) h[2 + i] = (unsigned char) ((uint64_t) n >> (56 - 8 * i));
    return 10;
}

int ws_parse_header(const unsigned char *b, size_t n, ws_frame_t *f) {
    if (n < 2) return 0;
    f->fin = (b[0] & 0x80) != 0;
    if (b[0] & 0x70) return -1;                 /* RSV bits: no extensions negotiated */
    f->opcode = b[0] & 0x0F;
    f->masked = (b[1] & 0x80) != 0;
    uint64_t len = b[1] & 0x7F;
    size_t h = 2;
    if (len == 126) { if (n < 4) return 0; len = (uint64_t) b[2] << 8 | b[3]; h = 4; }
    else if (len == 127) {
        if (n < 10) return 0;
        len = 0; for (int i = 0; i < 8; i++) len = len << 8 | b[2 + i];
        if (len >> 63) return -1;
        h = 10;
    }
    if (f->masked) { if (n < h + 4) return 0; memcpy(f->mask, b + h, 4); h += 4; }
    if (f->opcode >= 8 && (!f->fin || len > 125)) return -1;   /* control frame rules */
    if ((f->opcode > 2 && f->opcode < 8) || f->opcode > 10) return -1;
    f->len = len;
    f->header_len = h;
    return 1;
}

void ws_unmask(unsigned char *p, size_t n, const unsigned char m[4]) {
    size_t i = 0;
    unsigned char m8[8] = { m[0], m[1], m[2], m[3], m[0], m[1], m[2], m[3] };
    uint64_t m64; memcpy(&m64, m8, 8);
    for (; i + 8 <= n; i += 8) { uint64_t v; memcpy(&v, p + i, 8); v ^= m64; memcpy(p + i, &v, 8); }
    for (; i < n; i++) p[i] ^= m[i & 3];
}
