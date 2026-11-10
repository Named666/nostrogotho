/* Unit tests for relay_wire.c: overload replies and raw EVENT sig triples,
 * including truncated input at every length and output capacity limits. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "relay_wire.h"

static int fails;
#define CHECK(c) do { if (!(c)) { fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

#define ID  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define PK  "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
#define SIG "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
            "00000000000000000000000000000000000000000000000000000000000000ee"
static const char why[] = "error: relay overloaded, try again later";

static size_t reply(const char *m, char *out, size_t cap) {
    return relay_wire_overload_reply(m, strlen(m), why, out, cap);
}
static int eq(const char *out, size_t n, const char *want) { return n == strlen(want) && memcmp(out, want, n) == 0; }

static void test_overload_reply(void) {
    char out[RELAY_WIRE_REPLY_MAX];
    size_t n;
    n = reply("[\"EVENT\",{\"kind\":1,\"id\":\"" ID "\"}]", out, sizeof(out));
    CHECK(eq(out, n, "[\"OK\",\"" ID "\",false,\"error: relay overloaded, try again later\"]"));
    n = reply("  \n[\"EVENT\",{\"id\":\"" ID "\"}]", out, sizeof(out));              /* leading ws */
    CHECK(eq(out, n, "[\"OK\",\"" ID "\",false,\"error: relay overloaded, try again later\"]"));
    n = reply("[\"EVENT\",{\"id\":\"AAAA" ID "\"}]", out, sizeof(out));               /* bad id */
    CHECK(eq(out, n, "[\"NOTICE\",\"error: relay overloaded, try again later\"]"));
    n = reply("[\"REQ\",\"sub1\",{}]", out, sizeof(out));
    CHECK(eq(out, n, "[\"CLOSED\",\"sub1\",\"error: relay overloaded, try again later\"]"));
    n = reply("[\"COUNT\",\"c\",{}]", out, sizeof(out));
    CHECK(eq(out, n, "[\"CLOSED\",\"c\",\"error: relay overloaded, try again later\"]"));
    n = reply("[\"REQ\",\"a\\\"b\",{}]", out, sizeof(out));                          /* escaped sub id: not echoed */
    CHECK(eq(out, n, "[\"NOTICE\",\"error: relay overloaded, try again later\"]"));
    n = reply("[\"REQ\",\"x\x01y\",{}]", out, sizeof(out));                          /* control byte */
    CHECK(eq(out, n, "[\"NOTICE\",\"error: relay overloaded, try again later\"]"));
    n = reply("[\"CLOSE\",\"s\"]", out, sizeof(out));
    CHECK(eq(out, n, "[\"NOTICE\",\"error: relay overloaded, try again later\"]"));
    n = reply("garbage", out, sizeof(out));
    CHECK(eq(out, n, "[\"NOTICE\",\"error: relay overloaded, try again later\"]"));
    n = relay_wire_overload_reply("", 0, why, out, sizeof(out));
    CHECK(eq(out, n, "[\"NOTICE\",\"error: relay overloaded, try again later\"]"));

    /* longest echoed sub id (200 bytes) still fits the documented max */
    char m[300]; char sub[201]; memset(sub, 's', 200); sub[200] = 0;
    snprintf(m, sizeof(m), "[\"REQ\",\"%s\",{}]", sub);
    n = reply(m, out, sizeof(out));
    CHECK(n > 0 && memcmp(out, "[\"CLOSED\",\"ssss", 15) == 0);
    snprintf(m, sizeof(m), "[\"REQ\",\"%ss\",{}]", sub);                            /* 201: NOTICE */
    n = reply(m, out, sizeof(out));
    CHECK(eq(out, n, "[\"NOTICE\",\"error: relay overloaded, try again later\"]"));

    /* small capacities: falls back to NOTICE, then to 0, never overflows */
    char small[64]; memset(small, 'Z', sizeof(small));
    n = reply("[\"EVENT\",{\"id\":\"" ID "\"}]", small, 60);
    CHECK(eq(small, n, "[\"NOTICE\",\"error: relay overloaded, try again later\"]") && small[60] == 'Z');
    n = reply("[\"EVENT\",{\"id\":\"" ID "\"}]", small, 10);
    CHECK(n == 0);
    n = reply("x", small, 0);
    CHECK(n == 0);

    /* every truncation of a valid EVENT: no crash, a valid reply */
    const char *full = "[\"EVENT\",{\"id\":\"" ID "\",\"pubkey\":\"" PK "\"}]";
    for (size_t l = 0; l <= strlen(full); l++) {
        char *cp = (char *) malloc(l ? l : 1); memcpy(cp, full, l);               /* exact-size: ASan catches over-reads */
        n = relay_wire_overload_reply(cp, l, why, out, sizeof(out));
        CHECK(n > 0 && out[0] == '[' && out[n - 1] == ']');
        free(cp);
    }
}

static void test_event_sig(void) {
    unsigned char id[32], pk[32], sig[64];
    const char *m = "[\"EVENT\",{\"id\":\"" ID "\",\"pubkey\":\"" PK "\",\"sig\":\"" SIG "\",\"kind\":1}]";
    CHECK(relay_wire_event_sig(m, strlen(m), id, pk, sig));
    CHECK(id[0] == 0xaa && id[31] == 0xaa && pk[0] == 0x01 && pk[31] == 0x20 && sig[0] == 0xff && sig[63] == 0xee);

    const char *m2 = " [\"EVENT\",{\"sig\":\"" SIG "\",\"pubkey\":\"" PK "\",\"id\":\"" ID "\"}]";   /* any order */
    CHECK(relay_wire_event_sig(m2, strlen(m2), id, pk, sig));

    memset(id, 0x55, sizeof(id));
    const char *bad[] = {
        "[\"EVENT\",{\"id\":\"" ID "\",\"pubkey\":\"" PK "\"}]",                       /* no sig */
        "[\"EVENT\",{\"id\":\"zz" ID "\",\"pubkey\":\"" PK "\",\"sig\":\"" SIG "\"}]",    /* id too long */
        "[\"EVENT\",{\"id\":\"" ID "\",\"pubkey\":\"" PK "\",\"sig\":\"" SIG "0\"}]",   /* sig too long */
        "[\"REQ\",\"s\",{}]",
        "[\"EVENT\",\"x\"]",
        "[\"EVENT\"",
        "",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        CHECK(!relay_wire_event_sig(bad[i], strlen(bad[i]), id, pk, sig));
    CHECK(id[0] == 0x55);                                                         /* untouched on failure */

    for (size_t l = 0; l < strlen(m); l++) {                                      /* truncations */
        char *cp = (char *) malloc(l ? l : 1); memcpy(cp, m, l);
        CHECK(!relay_wire_event_sig(cp, l, id, pk, sig));
        free(cp);
    }
}

int main(void) {
    test_overload_reply();
    test_event_sig();
    if (fails) { printf("FAIL %d checks\n", fails); return 1; }
    printf("test_relay_wire: all passed\n");
    return 0;
}
