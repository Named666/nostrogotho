/* Boundary tests for ws_proto.c (RFC 6455 helpers): frame header
 * encode/parse at every length boundary and every split point, protocol
 * error rules, SHA-1 / base64 / accept key vectors, UTF-8 validation and
 * SIMD unmask vs a scalar reference. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ws_proto.h"

static int fails;
#define CHECK(c) do { if (!(c)) { fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static void test_vectors(void) {
    unsigned char d[20]; char hex[41];
    ws_sha1((const unsigned char *) "abc", 3, d);
    for (int i = 0; i < 20; i++) snprintf(hex + 2 * i, 3, "%02x", d[i]);
    CHECK(strcmp(hex, "a9993e364706816aba3e25717850c26c9cd0d89d") == 0);
    ws_sha1((const unsigned char *) "", 0, d);
    for (int i = 0; i < 20; i++) snprintf(hex + 2 * i, 3, "%02x", d[i]);
    CHECK(strcmp(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709") == 0);
    /* 55/56/64 bytes: padding spills into a second block */
    unsigned char a[64]; memset(a, 'a', sizeof(a));
    ws_sha1(a, 56, d);
    for (int i = 0; i < 20; i++) snprintf(hex + 2 * i, 3, "%02x", d[i]);
    CHECK(strcmp(hex, "c2db330f6083854c99d4b5bfb6e8f29f201be699") == 0);

    char b64[16];
    CHECK(ws_base64((const unsigned char *) "f", 1, b64) == 4 && strcmp(b64, "Zg==") == 0);
    CHECK(ws_base64((const unsigned char *) "fo", 2, b64) == 4 && strcmp(b64, "Zm8=") == 0);
    CHECK(ws_base64((const unsigned char *) "foo", 3, b64) == 4 && strcmp(b64, "Zm9v") == 0);
    CHECK(ws_base64((const unsigned char *) "", 0, b64) == 0 && b64[0] == '\0');

    char acc[29];
    const char *key = "dGhlIHNhbXBsZSBub25jZQ==";                 /* RFC 6455 section 1.3 */
    ws_accept_key(key, strlen(key), acc);
    CHECK(strcmp(acc, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0);
}

/* Build a client (masked) frame header for len. */
static size_t client_header(unsigned char *h, int fin, int op, uint64_t len) {
    size_t n = 0;
    h[n++] = (unsigned char) ((fin ? 0x80 : 0) | op);
    if (len < 126) h[n++] = (unsigned char) (0x80 | len);
    else if (len <= 0xFFFF) { h[n++] = 0x80 | 126; h[n++] = (unsigned char) (len >> 8); h[n++] = (unsigned char) len; }
    else { h[n++] = 0x80 | 127; for (int i = 7; i >= 0; i--) h[n++] = (unsigned char) (len >> (8 * i)); }
    h[n++] = 0x11; h[n++] = 0x22; h[n++] = 0x33; h[n++] = 0x44;
    return n;
}

static void test_parse_lengths(void) {
    const uint64_t lens[] = { 0, 1, 125, 126, 127, 65535, 65536, 0xFFFFFFFFull, 0x100000000ull, 0x7FFFFFFFFFFFFFFFull };
    for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        unsigned char h[14]; ws_frame_t f;
        size_t hn = client_header(h, 1, WS_OP_TEXT, lens[i]);
        for (size_t split = 0; split < hn; split++)              /* every incomplete prefix */
            CHECK(ws_parse_header(h, split, &f) == NG_E_AGAIN);
        memset(&f, 0, sizeof(f));
        CHECK(ws_parse_header(h, hn, &f) == NG_OK);
        CHECK(f.fin && f.opcode == WS_OP_TEXT && f.masked && f.len == lens[i] && f.header_len == hn);
        CHECK(memcmp(f.mask, "\x11\x22\x33\x44", 4) == 0);
        CHECK(hn == (lens[i] < 126 ? 6u : lens[i] <= 0xFFFF ? 8u : 14u));
    }
    /* server headers: same boundaries, unmasked */
    const size_t slens[] = { 0, 125, 126, 65535, 65536 };
    for (size_t i = 0; i < sizeof(slens) / sizeof(slens[0]); i++) {
        unsigned char h[10]; ws_frame_t f;
        size_t hn = ws_frame_header(h, WS_OP_TEXT, slens[i]);
        CHECK(hn == (slens[i] < 126 ? 2u : slens[i] <= 0xFFFF ? 4u : 10u));
        CHECK(ws_parse_header(h, hn, &f) == NG_OK && !f.masked && f.len == slens[i] && f.header_len == hn && f.fin);
    }
}

static void test_parse_errors(void) {
    unsigned char h[14]; ws_frame_t f;
    size_t hn;
    /* 64-bit length with the MSB set */
    hn = client_header(h, 1, WS_OP_BIN, 0x8000000000000000ull);
    CHECK(ws_parse_header(h, hn, &f) == NG_E_INVALID);
    /* RSV1/2/3 */
    for (int r = 0x10; r <= 0x40; r <<= 1) {
        hn = client_header(h, 1, WS_OP_TEXT, 5); h[0] |= (unsigned char) r;
        CHECK(ws_parse_header(h, hn, &f) == NG_E_INVALID);
    }
    /* control frames: payload <= 125 and FIN required */
    hn = client_header(h, 1, WS_OP_PING, 125); CHECK(ws_parse_header(h, hn, &f) == NG_OK);
    hn = client_header(h, 1, WS_OP_PING, 126); CHECK(ws_parse_header(h, hn, &f) == NG_E_INVALID);
    hn = client_header(h, 0, WS_OP_PING, 5);   CHECK(ws_parse_header(h, hn, &f) == NG_E_INVALID);
    hn = client_header(h, 0, WS_OP_CLOSE, 2);  CHECK(ws_parse_header(h, hn, &f) == NG_E_INVALID);
    hn = client_header(h, 1, WS_OP_PONG, 0);   CHECK(ws_parse_header(h, hn, &f) == NG_OK);
    /* reserved opcodes 3..7 and 11..15 */
    for (int op = 3; op <= 7; op++) { hn = client_header(h, 1, op, 1); CHECK(ws_parse_header(h, hn, &f) == NG_E_INVALID); }
    for (int op = 11; op <= 15; op++) { hn = client_header(h, 1, op, 1); CHECK(ws_parse_header(h, hn, &f) == NG_E_INVALID); }
    /* continuation and non-FIN data frames are fine at this layer */
    hn = client_header(h, 0, WS_OP_TEXT, 3); CHECK(ws_parse_header(h, hn, &f) == NG_OK && !f.fin);
    hn = client_header(h, 1, WS_OP_CONT, 3); CHECK(ws_parse_header(h, hn, &f) == NG_OK && f.opcode == WS_OP_CONT);
}

static void test_utf8(void) {
    struct { const char *s; size_t n; int ok; } c[] = {
        { "", 0, 1 }, { "ascii", 5, 1 }, { "\xc3\xa9", 2, 1 }, { "\xe2\x82\xac", 3, 1 },
        { "\xf0\x9f\x98\x80", 4, 1 }, { "\xf4\x8f\xbf\xbf", 4, 1 },
        { "\xc3", 1, 0 },                       /* truncated */
        { "\xc0\xaf", 2, 0 },                   /* overlong */
        { "\xe0\x80\xaf", 3, 0 },               /* overlong */
        { "\xed\xa0\x80", 3, 0 },               /* surrogate */
        { "\xf4\x90\x80\x80", 4, 0 },           /* > U+10FFFF */
        { "\xff", 1, 0 }, { "\x80", 1, 0 },
        { "abc\xe2\x82", 5, 0 },                /* truncated at the end */
    };
    for (size_t i = 0; i < sizeof(c) / sizeof(c[0]); i++)
        CHECK(ws_utf8_valid((const unsigned char *) c[i].s, c[i].n) == (c[i].ok != 0));
    /* long valid text crossing any SIMD block boundary, then one bad byte at each position */
    unsigned char buf[200];
    for (size_t i = 0; i < sizeof(buf); i++) buf[i] = (unsigned char) ('a' + i % 26);
    CHECK(ws_utf8_valid(buf, sizeof(buf)));
    for (size_t p = 0; p < sizeof(buf); p++) {
        unsigned char save = buf[p]; buf[p] = 0xff;
        CHECK(!ws_utf8_valid(buf, sizeof(buf)));
        buf[p] = save;
    }
}

static void test_unmask(void) {
    const unsigned char m[4] = { 0xA1, 0x5B, 0x3C, 0xD7 };
    unsigned char buf[300], ref[300];
    for (size_t off = 0; off < 8; off++) {
        for (size_t n = 0; n + off <= sizeof(buf) && n < 200; n++) {
            for (size_t i = 0; i < sizeof(buf); i++) buf[i] = ref[i] = (unsigned char) (i * 37 + 11);
            for (size_t i = 0; i < n; i++) ref[off + i] ^= m[i & 3];
            ws_unmask(buf + off, n, m);
            CHECK(memcmp(buf, ref, sizeof(buf)) == 0);   /* also: no bytes touched outside */
        }
    }
}

int main(void) {
    test_vectors();
    test_parse_lengths();
    test_parse_errors();
    test_utf8();
    test_unmask();
    if (fails) { printf("FAIL %d checks\n", fails); return 1; }
    printf("test_ws_proto: all passed\n");
    return 0;
}
