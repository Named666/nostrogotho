/* memidx_scale - RAM / speed of the in-memory tag index at relay scale.
 *
 *   cc -O2 -std=gnu99 -D_GNU_SOURCE -Isrc tools/bench/memidx_scale.c src/memidx.c -lpthread -lm
 *   memidx_scale N_EVENTS [snapshot_path]
 *
 * Feeds N synthetic events with the tag mix of
 * bench/gate-results/realload-model.md (kind 7: e+p; kind 1: e/p/t replies;
 * kind 3: lognormal ~250 p tags; 1059 / 9735: p; zipf hot targets), then
 * reports memidx_stats, process RSS, add rate, a query sample, snapshot
 * write / load time and size, and RSS after reload. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "memidx.h"

static uint64_t rs = 0x9e3779b97f4a7c15ull;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static double urand(void) { return (double) (rnd() >> 11) / 9007199254740992.0; }
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }
static long rss_kb(void) {
    FILE *f = fopen("/proc/self/status", "r"); char l[256]; long v = -1;
    if (!f) return -1;
    while (fgets(l, sizeof(l), f)) if (!strncmp(l, "VmRSS:", 6)) v = atol(l + 6);
    fclose(f); return v;
}
static uint64_t mix(uint64_t x) { x += 0x9e3779b97f4a7c15ull; x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull; x = (x ^ (x >> 27)) * 0x94d049bb133111ebull; return x ^ (x >> 31); }
/* zipf-ish index in [0, n): heavy head */
static uint64_t zipf(uint64_t n) { double u = urand(); return (uint64_t) (pow((double) n, u)) - 1; }
static char *hex(char *p, uint64_t id) {
    static const char *d = "0123456789abcdef";
    for (int w = 0; w < 4; w++) { uint64_t x = mix(id * 4 + (uint64_t) w); for (int i = 0; i < 16; i++) { *p++ = d[x & 15]; x >>= 4; } }
    return p;
}
static char *tag(char *p, char l, uint64_t id) { p += sprintf(p, "[\"%c\",\"", l); p = hex(p, id); return p + sprintf(p, "\"],"); }

int main(int argc, char **argv) {
    size_t n = argc > 1 ? strtoull(argv[1], 0, 10) : 1000000;
    const char *snap = argc > 2 ? argv[2] : "/tmp/memidx_scale.snap";
    memidx_config_t c = { "epaqtdhk", 2000, 0 };
    if (!memidx_open(&c)) return 1;
    long rss0 = rss_kb();
    const uint64_t users = 2000000, notes = n / 3 + 1;
    char *buf = malloc(2000 * 90 + 64);
    size_t tags = 0; double t0 = now();
    for (size_t i = 1; i <= n; i++) {
        double k = urand(); int kind; char *p = buf; *p++ = '[';
        uint64_t me = zipf(users);
        if (k < .35) { kind = 7; p = tag(p, 'e', 1000000000 + zipf(notes)); p = tag(p, 'p', zipf(users)); tags += 2; }
        else if (k < .65) { kind = 1; if (urand() < .5) { p = tag(p, 'e', 1000000000 + zipf(notes)); p = tag(p, 'p', zipf(users)); tags += 2; }
                            if (urand() < .2) { p += sprintf(p, "[\"t\",\"tag%llu\"],", (unsigned long long) zipf(50000)); tags++; } }
        else if (k < .71) { kind = 6; p = tag(p, 'e', 1000000000 + zipf(notes)); p = tag(p, 'p', zipf(users)); tags += 2; }
        else if (k < .76) { kind = 9735; p = tag(p, 'p', zipf(users)); p = tag(p, 'e', 1000000000 + zipf(notes)); tags += 2; }
        else if (k < .81) { kind = 1059; p = tag(p, 'p', zipf(users)); tags++; }
        else if (k < .825) { kind = 3; int m = (int) exp(log(250.0) + 1.0 * sqrt(-2 * log(urand() + 1e-12)) * cos(6.283185 * urand()));
                             if (m > 2000) m = 2000;
                             if (m < 1) m = 1;
                             for (int j = 0; j < m; j++) p = tag(p, 'p', zipf(users));
                             tags += (size_t) m; }
        else if (k < .85) { kind = 5; p = tag(p, 'e', 1000000000 + zipf(notes)); tags++; }
        else if (k < .88) { kind = 1111; p = tag(p, 'e', 1000000000 + zipf(notes)); p = tag(p, 'p', zipf(users)); tags += 2; }
        else if (k < .895) { kind = 10002; }
        else if (k < .90) { kind = 30023; p += sprintf(p, "[\"d\",\"art%llu\"],", (unsigned long long) i); tags++; }
        else if (k < .93) { kind = 0; }
        else { kind = 30078; p += sprintf(p, "[\"d\",\"app%llu\"],", (unsigned long long) (me % 100000)); tags++; }
        if (p[-1] == ',') p--;
        *p++ = ']'; *p = 0;
        if (!memidx_add_event(buf, (size_t) (p - buf), i, (uint32_t) (1700000000 + i / 10), kind)) { fprintf(stderr, "oom at %zu\n", i); return 1; }
        if (i % 4096 == 0) memidx_maintain(4096);
        if (i % 5000000 == 0) { memidx_stats_t s; memidx_stats(&s); fprintf(stderr, "  %zu ev: %zu postings %.1f MB rss %.1f MB %.1fs\n", i, s.postings, s.bytes / 1e6, rss_kb() / 1024.0, now() - t0); }
    }
    double tadd = now() - t0;
    memidx_stats_t s; memidx_stats(&s);
    long rss1 = rss_kb();
    printf("events %zu  tags %zu (%.2f/ev)  add %.1fs = %.0f ev/s\n", n, tags, (double) tags / (double) n, tadd, n / tadd);
    printf("keys %zu postings %zu  bytes %.1f MB (frozen %.1f tail %.1f table %.1f tomb %.1f)  %.2f B/posting  %.1f B/event\n",
           s.keys, s.postings, s.bytes / 1e6, s.frozen_bytes / 1e6, s.tail_bytes / 1e6, s.table_bytes / 1e6, s.tomb_bytes / 1e6,
           (double) s.bytes / (double) s.postings, (double) s.bytes / (double) n);
    printf("rss before %.1f MB after %.1f MB (delta %.1f MB)\n", rss0 / 1024.0, rss1 / 1024.0, (rss1 - rss0) / 1024.0);
    /* query sample: hot and cold #e / #p, limit 500 */
    memidx_cand_t *out = malloc(sizeof(*out) * 500); double tq = now(); size_t q = 0, got = 0, tot = 0;
    for (int r = 0; r < 20000; r++) {
        char v[65]; hex(v, r & 1 ? zipf(users) : 1000000000 + zipf(notes)); v[64] = 0; char *vals[1] = { v };
        if (memidx_candidates(r & 1 ? 'p' : 'e', vals, 1, 0, 0, 0, 0, 0, 500, out, &got) == NG_OK) { q++; tot += got; }
    }
    double tqs = now() - tq;
    printf("queries %zu limit 500: %.1f us/query, avg %.1f cands\n", q, tqs / 20000 * 1e6, (double) tot / (double) (q ? q : 1));
    double ts = now(); if (memidx_snapshot_write(snap, 42) != NG_OK) { fprintf(stderr, "snapshot write failed\n"); return 1; }
    double tsw = now() - ts; FILE *f = fopen(snap, "rb"); fseek(f, 0, SEEK_END); long sz = ftell(f); fclose(f);
    memidx_close();
    long rss2 = rss_kb();
    if (!memidx_open(&c)) return 1;
    uint64_t cov = 0; ts = now();
    ng_status_t st = memidx_snapshot_load(snap, 42, &cov);
    double tsl = now() - ts; memidx_stats_t s2; memidx_stats(&s2);
    printf("snapshot %.1f MB write %.2fs load %.2fs (st %d covered %llu)  rss after close %.1f MB after load %.1f MB  postings %zu\n",
           sz / 1e6, tsw, tsl, (int) st, (unsigned long long) cov, rss2 / 1024.0, rss_kb() / 1024.0, s2.postings);
    memidx_close(); remove(snap); free(out); free(buf);
    return 0;
}
