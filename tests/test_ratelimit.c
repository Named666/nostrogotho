/* Unit tests for ratelimit.c: GCRA buckets with injected time, peer keys,
 * ban lists (inline and file). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ratelimit.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL: %s (line %d)\n", #c, __LINE__); fails++; } else printf("PASS: %s\n", #c); } while (0)

#define SEC 1000000000ull

static void test_bucket(void) {
    rl_config_t c; memset(&c, 0, sizeof c);
    c.per_min[RL_EVENT_IP] = 60; c.burst[RL_EVENT_IP] = 3;     /* 1/s, burst 3 */
    CHECK(rl_configure(&c, NULL) == NG_OK);
    CHECK(rl_enabled(RL_EVENT_IP) && !rl_enabled(RL_REQ_IP));
    uint64_t t = 100 * SEC;
    const char *k = "a";
    int ok = 0;
    for (int i = 0; i < 10; i++) ok += rl_allow_at(RL_EVENT_IP, k, 1, t);
    CHECK(ok == 3);                                          /* burst */
    CHECK(!rl_allow_at(RL_EVENT_IP, k, 1, t + SEC / 2));
    CHECK(rl_allow_at(RL_EVENT_IP, k, 1, t + SEC + 1));      /* refilled one */
    CHECK(!rl_allow_at(RL_EVENT_IP, k, 1, t + SEC + 2));
    CHECK(rl_allow_at(RL_EVENT_IP, "b", 1, t));              /* other keys unaffected */
    ok = 0;                                                  /* after idle: full burst again, not more */
    for (int i = 0; i < 10; i++) ok += rl_allow_at(RL_EVENT_IP, k, 1, t + 100 * SEC);
    CHECK(ok == 3);
    /* many distinct keys never throttle each other (two-row count-min) */
    char key[16]; int denied = 0;
    for (int i = 0; i < 5000; i++) { int n = snprintf(key, sizeof key, "k%d", i); denied += !rl_allow_at(RL_EVENT_IP, key, (size_t) n, t + 200 * SEC); }
    CHECK(denied == 0);
    CHECK(rl_allow_at(RL_REQ_IP, k, 1, t));                  /* unlimited class */
    rl_shutdown();
}

static void test_peer_key(void) {
    unsigned char a[16], b[16];
    CHECK(rl_peer_key("10.1.2.3:4567", a) == 4 && a[0] == 10 && a[3] == 3);
    CHECK(rl_peer_key("10.1.2.3", b) == 4 && !memcmp(a, b, 4));
    CHECK(rl_peer_key("::ffff:10.1.2.3:99", b) == 4 && !memcmp(a, b, 4));
    CHECK(rl_peer_key("2001:db8:1:2:aaaa::1:443", a) == 8);
    CHECK(rl_peer_key("[2001:db8:1:2:bbbb::9]:443", b) == 8 && !memcmp(a, b, 8));   /* same /64 */
    CHECK(rl_peer_key("nonsense", a) == 0 && rl_peer_key("", a) == 0);
}

static void test_bans(void) {
    const char *pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const char *pk2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    char path[] = "/tmp/ng_bans_XXXXXX";
    int fd = mkstemp(path);
    FILE *f = fd >= 0 ? fdopen(fd, "w") : NULL;
    if (!f) { CHECK(0); return; }
    fprintf(f, "# bans\npubkey %s\n\nip 192.0.2.7  # spammer\nip 2001:db8::5\n", pk2);
    fclose(f);
    rl_config_t c; memset(&c, 0, sizeof c);
    c.banned_pubkeys = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    c.banned_ips = "198.51.100.1, 198.51.100.2";
    c.ban_file = path;
    CHECK(rl_configure(&c, NULL) == NG_OK);
    CHECK(rl_pubkey_banned(pk) && rl_pubkey_banned(pk2));
    CHECK(!rl_pubkey_banned("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"));
    CHECK(rl_peer_banned("198.51.100.2:5555") && rl_peer_banned("192.0.2.7:1"));
    CHECK(rl_peer_banned("[2001:db8::5]:80") && !rl_peer_banned("[2001:db8::6]:80"));
    CHECK(!rl_peer_banned("198.51.100.3:5555"));
    f = fopen(path, "w"); if (f) { fprintf(f, "ip 1.2.3.4\nuser nobody\n"); fclose(f); }
    unsigned line = 0;
    CHECK(rl_configure(&c, &line) == NG_E_INVALID && line == 2);
    c.ban_file = "/nonexistent/bans";
    CHECK(rl_configure(&c, NULL) == NG_E_IO);
    c.ban_file = NULL; c.banned_pubkeys = "abc";
    CHECK(rl_configure(&c, NULL) == NG_E_INVALID);
    rl_shutdown();
    unlink(path);
}

#define H(x) x "\r\n"
static bool cip(const char *peer, const char *hdrs, char *out) {
    return rl_client_ip(peer, hdrs, hdrs ? strlen(hdrs) : 0, out, 64);
}

static void test_forwarded(void) {
    rl_config_t c; memset(&c, 0, sizeof c);              /* trusted_proxies NULL: 127.0.0.1, ::1 */
    CHECK(rl_configure(&c, NULL) == NG_OK);
    char o[64];
    CHECK(rl_trusted_proxy("127.0.0.1:5000") && rl_trusted_proxy("[::1]:5000") && !rl_trusted_proxy("10.0.0.1:1"));
    /* untrusted peer: headers ignored */
    CHECK(!cip("203.0.113.9:4000", H("X-Forwarded-For: 198.51.100.1") H("X-Real-IP: 198.51.100.2"), o) &&
          !strcmp(o, "203.0.113.9:4000"));
    /* trusted peer, single entry */
    CHECK(cip("127.0.0.1:4000", H("Host: x") H("X-Forwarded-For: 198.51.100.1") H("Upgrade: websocket"), o) &&
          !strcmp(o, "198.51.100.1"));
    /* client-supplied left part is not believed: rightmost untrusted wins */
    CHECK(cip("127.0.0.1:4000", H("x-forwarded-for: 6.6.6.6, 198.51.100.1"), o) && !strcmp(o, "198.51.100.1"));
    /* trusted hops on the right are skipped */
    CHECK(cip("[::1]:4000", H("X-Forwarded-For: 6.6.6.6, 198.51.100.1, 127.0.0.1 ,::1"), o) && !strcmp(o, "198.51.100.1"));
    /* several header lines: later lines are nearer proxies */
    CHECK(cip("127.0.0.1:1", H("X-Forwarded-For: 6.6.6.6") H("X-Forwarded-For: 198.51.100.4, 127.0.0.1"), o) &&
          !strcmp(o, "198.51.100.4"));
    CHECK(cip("127.0.0.1:1", H("X-Forwarded-For: 198.51.100.4") H("X-Forwarded-For: 127.0.0.1"), o) &&
          !strcmp(o, "198.51.100.4"));
    /* all trusted: the leftmost */
    CHECK(cip("127.0.0.1:1", H("X-Forwarded-For: 127.0.0.1, ::1"), o) && !strcmp(o, "127.0.0.1"));
    /* garbage stops the walk at the last good hop; garbage only: header unusable */
    CHECK(cip("127.0.0.1:1", H("X-Forwarded-For: 6.6.6.6, bogus, 127.0.0.1"), o) && !strcmp(o, "127.0.0.1"));
    CHECK(!cip("127.0.0.1:1", H("X-Forwarded-For: bogus"), o) && !strcmp(o, "127.0.0.1:1"));
    /* IPv6, ports and brackets, mapped v4: canonical text */
    CHECK(cip("127.0.0.1:1", H("X-Forwarded-For: [2001:DB8::7]:443"), o) && !strcmp(o, "2001:db8::7"));
    CHECK(cip("127.0.0.1:1", H("X-Forwarded-For: ::ffff:198.51.100.9"), o) && !strcmp(o, "198.51.100.9"));
    /* X-Real-IP when there is no X-Forwarded-For */
    CHECK(cip("127.0.0.1:1", H("X-Real-IP:  198.51.100.3"), o) && !strcmp(o, "198.51.100.3"));
    CHECK(cip("127.0.0.1:1", H("X-Real-IP: 198.51.100.3") H("X-Forwarded-For: 198.51.100.5"), o) && !strcmp(o, "198.51.100.5"));
    CHECK(!cip("127.0.0.1:1", H("X-Real-IP: nope"), o) && !strcmp(o, "127.0.0.1:1"));
    CHECK(!cip("127.0.0.1:1", NULL, o) && !strcmp(o, "127.0.0.1:1"));
    /* a header whose name merely starts the same is not it */
    CHECK(!cip("127.0.0.1:1", H("X-Forwarded-For-Evil: 198.51.100.1"), o));
    /* configured list with CIDRs; the forwarded address feeds bans and keys */
    c.trusted_proxies = "10.0.0.0/8, 2001:db8:ffff::/48";
    c.banned_ips = "198.51.100.1";
    CHECK(rl_configure(&c, NULL) == NG_OK);
    CHECK(!rl_trusted_proxy("127.0.0.1:1") && rl_trusted_proxy("10.200.3.4:1") && !rl_trusted_proxy("11.0.0.1:1"));
    CHECK(rl_trusted_proxy("[2001:db8:ffff:12::1]:9") && !rl_trusted_proxy("[2001:db8:fffe::1]:9"));
    CHECK(!cip("127.0.0.1:1", H("X-Forwarded-For: 198.51.100.1"), o));
    CHECK(cip("10.9.9.9:1", H("X-Forwarded-For: 198.51.100.1, 10.1.1.1"), o) && rl_peer_banned(o));
    unsigned char k1[16], k2[16];
    CHECK(rl_peer_key(o, k1) == 4 && rl_peer_key("198.51.100.1:77", k2) == 4 && !memcmp(k1, k2, 4));
    c.trusted_proxies = "";                               /* none */
    CHECK(rl_configure(&c, NULL) == NG_OK && !rl_trusted_proxy("127.0.0.1:1") &&
          !cip("127.0.0.1:1", H("X-Forwarded-For: 198.51.100.1"), o));
    c.trusted_proxies = "10.0.0.0/33";
    CHECK(rl_configure(&c, NULL) == NG_E_INVALID);
    c.trusted_proxies = "10.0.0.0/x";
    CHECK(rl_configure(&c, NULL) == NG_E_INVALID);
    rl_shutdown();
}

int main(void) {
    test_bucket();
    test_forwarded();
    test_peer_key();
    test_bans();
    if (fails) { printf("%d failure(s)\n", fails); return 1; }
    printf("test_ratelimit: all passed\n");
    return 0;
}
