/* test_memidx - the in-memory tag index (memidx.c) on its own: encoding,
 * ordering, filters, collisions, tombstones and reclaim, the overflow list,
 * the memory cap, snapshot round-trip / corruption, and concurrent readers
 * against the writer (run under TSan by the gate). */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "memidx.h"

static int failures;
static void check(const char *name, int ok) {
    if (!ok) { printf("FAIL: %s\n", name); failures++; }
    else printf("ok: %s\n", name);
}

static const char *H(int n) {        /* a 64-hex value; distinct first 8 bytes per n */
    static __thread char buf[8][65];
    static __thread int r;
    char *b = buf[r++ & 7];
    snprintf(b, 65, "%016x%048d", n, 0);
    return b;
}

static bool add1(char letter, const char *v, uint64_t seq, uint32_t ca, int kind) {
    char tags[256];
    snprintf(tags, sizeof(tags), "[[\"%c\",\"%s\"]]", letter, v);
    return memidx_add_event(tags, 0, seq, ca, kind);
}

static size_t cands(char letter, const char *v, const int *kinds, size_t nk, int64_t since, int64_t until,
                    size_t skip, size_t max, memidx_cand_t *out) {
    char *vals[1] = { (char *) v };
    size_t got = 0;
    if (memidx_candidates(letter, vals, 1, kinds, nk, since, until, skip, max, out, &got) != NG_OK) return (size_t) -1;
    return got;
}

static bool open_default(size_t cap_bytes) {
    memidx_config_t c = { "ept", 3, cap_bytes };
    return memidx_open(&c);
}

/* -------- concurrency -------- */
static volatile int stop_readers;
static void *reader(void *arg) {
    (void) arg;
    memidx_cand_t out[64];
    size_t n = 0;
    while (!__atomic_load_n(&stop_readers, __ATOMIC_ACQUIRE)) {
        for (int k = 0; k < 8; k++) {
            size_t g = cands('p', H(k), NULL, 0, 0, 0, 0, 64, out);
            if (g != (size_t) -1) n += g;
            for (size_t i = 1; g != (size_t) -1 && i < g; i++)
                if (out[i - 1].ca < out[i].ca) { printf("FAIL: concurrent order\n"); failures++; }
        }
        memidx_stats_t st;
        memidx_stats(&st);
    }
    return (void *) n;
}

int main(void) {
    memidx_cand_t out[8192];
    check("open", open_default(0));

    /* in-order and out-of-order inserts on one key, big enough for blocks + tail */
    srand(7);
    const int N = 5000;
    for (int i = 0; i < N; i++) {
        uint32_t ca = (uint32_t) (1000000 + rand() % 3000);      /* many ties */
        if (!add1('e', H(1), (uint64_t) i + 1, ca, i % 3 == 0 ? 7 : 1)) { check("add", 0); break; }
    }
    size_t g = cands('e', H(1), NULL, 0, 0, 0, 0, 8192, out);
    bool sorted = g == (size_t) N;
    for (size_t i = 1; sorted && i < g; i++)
        sorted = out[i - 1].ca > out[i].ca || (out[i - 1].ca == out[i].ca && out[i - 1].seq > out[i].seq);
    check("random created_at: all postings, newest first, ties seq desc", sorted);
    size_t np = 0, nb = 0;
    memidx_key_stats('e', H(1), &np, &nb);
    printf("   key: %zu postings, %zu bytes (%.2f B/posting)\n", np, nb, (double) nb / (double) np);
    check("compact: <= 8 bytes per posting on a big key", np == (size_t) N && nb <= 8 * np);

    int k7[1] = { 7 };
    g = cands('e', H(1), k7, 1, 0, 0, 0, 8192, out);
    bool allk = g > 0;
    for (size_t i = 0; i < g; i++) allk = allk && out[i].kind == 7;
    check("kinds filter on the posting", allk && g == (size_t) ((N + 2) / 3));
    g = cands('e', H(1), NULL, 0, 1001000, 1001999, 0, 8192, out);
    bool win = g > 0;
    for (size_t i = 0; i < g; i++) win = win && out[i].ca >= 1001000 && out[i].ca <= 1001999;
    check("since/until window", win);
    memidx_cand_t a[10], b[20];
    size_t ga = cands('e', H(1), NULL, 0, 0, 0, 10, 10, a), gb = cands('e', H(1), NULL, 0, 0, 0, 0, 20, b);
    check("skip/max paging", ga == 10 && gb == 20 && memcmp(a, b + 10, sizeof(a)) == 0);

    /* duplicate posting (same event, same value twice) collapses */
    check("dup in one event", memidx_add_event("[[\"p\",\"x\"],[\"p\",\"x\"]]", 0, 90000, 5, 1));
    g = cands('p', "x", NULL, 0, 0, 0, 0, 10, out);
    check("dup collapses", g == 1);

    /* collisions: two values sharing the 8-byte prefix land on one key; the
     * index returns both (the storage layer's JSON recheck tells them apart) */
    char c1[65], c2[65];
    snprintf(c1, sizeof(c1), "%016x%048d", 0xabc, 1);
    snprintf(c2, sizeof(c2), "%016x%048d", 0xabc, 2);
    add1('p', c1, 90001, 10, 1);
    add1('p', c2, 90002, 11, 1);
    check("collision: both candidates", cands('p', c1, NULL, 0, 0, 0, 0, 10, out) == 2);

    /* multi-value: one event via two values appears once */
    check("two values one event", memidx_add_event("[[\"t\",\"a\"],[\"t\",\"b\"]]", 0, 90003, 20, 1));
    add1('t', "a", 90004, 21, 1);
    {
        char *vals[2] = { (char *) "a", (char *) "b" };
        size_t got = 0;
        check("multi-value dedupe", memidx_candidates('t', vals, 2, NULL, 0, 0, 0, 0, 10, out, &got) == NG_OK &&
              got == 2 && out[0].seq == 90004 && out[1].seq == 90003);
    }
    check("unindexed letter refused", cands('x', "a", NULL, 0, 0, 0, 0, 10, out) == (size_t) -1);

    /* overflow: cap 3 indexed tags per event; the event is listed for every query */
    check("overflow event", memidx_add_event("[[\"t\",\"1\"],[\"t\",\"2\"],[\"t\",\"3\"],[\"t\",\"4\"]]", 0, 90005, 30, 1));
    check("past-cap value: overflow candidate", cands('t', "4", NULL, 0, 0, 0, 0, 10, out) == 1 && out[0].seq == 90005);
    check("overflow also merged into other values", cands('t', "a", NULL, 0, 0, 0, 0, 10, out) == 3);

    /* tombstones: hidden at once, reclaimed by the sweep */
    memidx_stats_t s0, s1;
    memidx_stats(&s0);
    for (uint64_t q = 1; q <= (uint64_t) N; q += 2) memidx_tomb_set(q);
    g = cands('e', H(1), NULL, 0, 0, 0, 0, 8192, out);
    bool even = g == (size_t) N / 2 + 1;                      /* + the overflow event */
    for (size_t i = 0; i < g; i++) even = even && (out[i].seq % 2 == 0 || out[i].seq == 90005);
    check("tombstoned seqs hidden", even);
    memidx_maintain((size_t) -1);
    memidx_stats(&s1);
    check("sweep reclaims dead postings", s1.postings == s0.postings - (size_t) N / 2);
    memidx_key_stats('e', H(1), &np, NULL);
    check("key shrank", np == (size_t) N / 2);
    memidx_tomb_set(90002);
    memidx_maintain((size_t) -1);
    check("inline/small key reclaim", cands('p', c1, NULL, 0, 0, 0, 0, 10, out) == 2);   /* + overflow */

    /* snapshot round-trip */
    char path[] = "/tmp/test_memidx_snap";
    unlink(path);
    check("snapshot write", memidx_snapshot_write(path, 42) == NG_OK);
    memidx_stats(&s0);
    memidx_cand_t before[8192];
    size_t gbefore = cands('e', H(1), NULL, 0, 0, 0, 0, 8192, before);
    memidx_close();
    uint64_t cov = 0;
    check("reopen", open_default(0));
    check("snapshot missing token", memidx_snapshot_load(path, 43, &cov) == NG_E_INVALID);
    check("snapshot load", memidx_snapshot_load(path, 42, &cov) == NG_OK && cov == 90005);
    memidx_stats(&s1);
    g = cands('e', H(1), NULL, 0, 0, 0, 0, 8192, out);
    check("snapshot: same postings and results", s1.postings == s0.postings && s1.keys == s0.keys &&
          g == gbefore && memcmp(out, before, g * sizeof(out[0])) == 0);
    check("snapshot: overflow list kept", cands('t', "4", NULL, 0, 0, 0, 0, 10, out) == 1);
    memidx_close();
    {   /* flip one payload byte: checksum mismatch */
        FILE *f = fopen(path, "r+b");
        if (!f) { perror(path); return 1; }
        fseek(f, -5, SEEK_END);
        int ch = fgetc(f);
        fseek(f, -5, SEEK_END);
        fputc(ch ^ 0x40, f);
        fclose(f);
    }
    open_default(0);
    check("corrupt snapshot rejected", memidx_snapshot_load(path, 42, &cov) == NG_E_INVALID);
    memidx_stats(&s1);
    check("rejected load leaves an empty index", s1.postings == 0 && s1.keys == 0);
    unlink(path);
    check("missing snapshot", memidx_snapshot_load(path, 42, &cov) == NG_E_UNKNOWN);
    memidx_close();
    {   /* other letters: rejected */
        memidx_config_t c = { "ep", 3, 0 };
        memidx_open(&c);
        add1('e', "v", 1, 1, 1);
        memidx_snapshot_write(path, 1);
        memidx_close();
        open_default(0);
        check("snapshot with other letters rejected", memidx_snapshot_load(path, 1, &cov) == NG_E_INVALID);
        memidx_close();
        unlink(path);
    }

    /* memory cap: the unqueried letter goes first */
    check("open capped", open_default(1u << 20));
    for (int i = 0; i < 4000; i++) add1('e', H(i % 50), (uint64_t) i + 1, (uint32_t) i, 1);
    for (int i = 0; i < 4000; i++) cands('e', H(i % 50), NULL, 0, 0, 0, 0, 1, out);
    for (int i = 0; i < 60000; i++) add1('t', H(1000 + i), (uint64_t) (10000 + i), (uint32_t) i, 1);
    memidx_enforce_cap();
    memidx_stats(&s1);
    check("cap: dropped the least-queried letter", !memidx_letter('t') && memidx_letter('e') && s1.degraded >= 1);
    check("cap: under the cap", s1.bytes <= (1u << 20));
    check("cap: dropped letter refused (fallback)", cands('t', H(1000), NULL, 0, 0, 0, 0, 10, out) == (size_t) -1);
    check("cap: kept letter intact", cands('e', H(3), NULL, 0, 0, 0, 0, 1000, out) == 80);
    memidx_close();

    /* concurrent readers vs the writer */
    open_default(0);
    pthread_t th[4];
    for (int i = 0; i < 4; i++) pthread_create(&th[i], NULL, reader, NULL);
    for (int i = 0; i < 60000; i++) {
        add1('p', H(i % 8), (uint64_t) i + 1, (uint32_t) (5000 + (i * 7919) % 20000), 1);
        if (i % 1000 == 999) { memidx_tomb_set((uint64_t) i - 500); memidx_maintain(4096); }
        if (i == 30000) memidx_snapshot_write(path, 9);
    }
    __atomic_store_n(&stop_readers, 1, __ATOMIC_RELEASE);
    for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
    size_t total = 0;
    for (int k = 0; k < 8; k++) total += cands('p', H(k), NULL, 0, 0, 0, 0, 8192, out);
    if (total != 60000 - 60) printf("   concurrent total %zu\n", total);
    check("concurrent: every live posting present", total == 60000 - 60);
    memidx_stats(&s1);
    printf("   60k postings on 8 keys: %zu bytes total (%.2f B/posting)\n", s1.bytes, (double) s1.bytes / (double) s1.postings);
    memidx_close();
    unlink(path);
    printf("%s\n", failures ? "FAILED" : "all memidx tests passed");
    return failures ? 1 : 0;
}
