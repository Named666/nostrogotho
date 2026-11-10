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

int main(void) {
    test_bucket();
    test_peer_key();
    test_bans();
    if (fails) { printf("%d failure(s)\n", fails); return 1; }
    printf("test_ratelimit: all passed\n");
    return 0;
}
