/* ratelimit - see ratelimit.h. */
#include "ratelimit.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "platform/ng_alloc.h"
#include "platform/ng_atomic.h"

#define RL_SLOTS (1u << 16)     /* per row; two rows per enabled class */

typedef struct {
    unsigned long long interval_ns; /* T: one unit every interval */
    unsigned long long window_ns;   /* T * burst: how far TAT may run ahead */
    ng_atomic_ullong *tat;      /* 2 * RL_SLOTS theoretical arrival times */
} rl_bucket_t;

static rl_bucket_t classes[RL_CLASSES];
static uint64_t seed[2];

static unsigned char (*ban_pk)[32];
static size_t ban_pk_n;
static unsigned char (*ban_ip)[16];
static size_t ban_ip_n;
/* trusted proxies: 16-byte ip_entry form + prefix bits (on the 4- or
 * 16-byte address); a short list, scanned linearly. */
typedef struct { unsigned char e[16]; unsigned bits; } rl_net_t;
static rl_net_t *trust;
static size_t trust_n;

static uint64_t mono_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    /* +1 s: 0 means "never used" in the table */
    return (uint64_t) t.tv_sec * 1000000000u + (uint64_t) t.tv_nsec + 1000000000u;
}

static uint64_t hash(const void *key, size_t len, uint64_t s) {
    const unsigned char *p = (const unsigned char *) key;
    uint64_t h = 0xcbf29ce484222325ull ^ s;
    for (size_t i = 0; i < len; i++) { h ^= p[i]; h *= 0x100000001b3ull; }
    h ^= h >> 33; h *= 0xff51afd7ed558ccdull; h ^= h >> 33;
    return h;
}

bool rl_enabled(rl_class_t c) { return c < RL_CLASSES && classes[c].tat != NULL; }

/* GCRA step on one bucket. commit=false: only test. */
static bool gcra(ng_atomic_ullong *slot, const rl_bucket_t *b, uint64_t now, bool commit) {
    unsigned long long tat = ng_atomic_load_explicit(slot, NG_MO_RELAXED);
    for (;;) {
        unsigned long long start = tat > now ? tat : now;
        unsigned long long next = start + b->interval_ns;
        bool ok = next - now <= b->window_ns;
        if (!commit) return ok;
        /* A row that is already full (collision) is not pushed further. */
        if (!ok) next = now + b->window_ns;
        if (ng_atomic_cas_weak_explicit(slot, &tat, next, NG_MO_RELAXED, NG_MO_RELAXED))
            return ok;
    }
}

bool rl_allow_at(rl_class_t c, const void *key, size_t len, uint64_t now) {
    if (!rl_enabled(c)) return true;
    const rl_bucket_t *b = &classes[c];
    ng_atomic_ullong *s0 = &b->tat[hash(key, len, seed[0]) & (RL_SLOTS - 1)];
    ng_atomic_ullong *s1 = &b->tat[RL_SLOTS + (hash(key, len, seed[1]) & (RL_SLOTS - 1))];
    if (!gcra(s0, b, now, false) && !gcra(s1, b, now, false)) return false;
    (void) gcra(s0, b, now, true);
    (void) gcra(s1, b, now, true);
    return true;
}

bool rl_allow(rl_class_t c, const void *key, size_t len) {
    return !rl_enabled(c) || rl_allow_at(c, key, len, mono_ns());
}

/* ---- addresses ---------------------------------------------------------- */

/* Parse "1.2.3.4", "1.2.3.4:5", "::1", "[::1]:5", "fe80::1:443"? The last
 * is ambiguous; peers from ngws are "ip:port", so a trailing ":<digits>"
 * after an IPv6 address is only stripped when the rest still parses. */
static bool parse_ip(const char *s, unsigned char out[16], bool *v4) {
    char buf[80];
    size_t n = strlen(s);
    if (n == 0 || n >= sizeof buf) return false;
    memcpy(buf, s, n + 1);
    if (buf[0] == '[') {
        char *e = strchr(buf, ']');
        if (!e) return false;
        *e = '\0';
        memmove(buf, buf + 1, strlen(buf + 1) + 1);
    }
    struct in_addr a4; struct in6_addr a6;
    memset(out, 0, 16);
    if (inet_pton(AF_INET, buf, &a4) == 1) { memcpy(out, &a4, 4); *v4 = true; return true; }
    if (inet_pton(AF_INET6, buf, &a6) == 1) { memcpy(out, &a6, 16); *v4 = false; goto mapped; }
    char *colon = strrchr(buf, ':');
    if (!colon || colon == buf) return false;
    for (const char *p = colon + 1; *p; p++) if (*p < '0' || *p > '9') return false;
    *colon = '\0';
    if (inet_pton(AF_INET, buf, &a4) == 1) { memcpy(out, &a4, 4); *v4 = true; return true; }
    if (inet_pton(AF_INET6, buf, &a6) == 1) { memcpy(out, &a6, 16); *v4 = false; goto mapped; }
    return false;
mapped:   /* ::ffff:a.b.c.d is IPv4 */
    {
        static const unsigned char pre[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        if (!memcmp(out, pre, 12)) { memmove(out, out + 12, 4); memset(out + 4, 0, 12); *v4 = true; }
    }
    return true;
}

size_t rl_peer_key(const char *peer, unsigned char out[16]) {
    bool v4;
    if (!peer || !parse_ip(peer, out, &v4)) return 0;
    return v4 ? 4 : 8;
}

/* Ban entries are 16 bytes: IPv4 as 4 bytes + 12 zero, tagged by byte 15
 * = 4 so it cannot equal an IPv6 address with the same leading bytes. */
static void ip_entry(const unsigned char a[16], bool v4, unsigned char e[16]) {
    memcpy(e, a, 16);
    if (v4) { memset(e + 4, 0, 12); e[15] = 4; }
}

static int cmp32(const void *a, const void *b) { return memcmp(a, b, 32); }
static int cmp16(const void *a, const void *b) { return memcmp(a, b, 16); }

bool rl_pubkey_banned(const char *hex) {
    if (!ban_pk_n || !hex) return false;
    unsigned char k[32];
    for (int i = 0; i < 32; i++) {
        unsigned v = 0;
        for (int j = 0; j < 2; j++) {
            char c = hex[2 * i + j];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= (unsigned) (c - '0');
            else if (c >= 'a' && c <= 'f') v |= (unsigned) (c - 'a' + 10);
            else return false;
        }
        k[i] = (unsigned char) v;
    }
    return bsearch(k, ban_pk, ban_pk_n, 32, cmp32) != NULL;
}

bool rl_peer_banned(const char *peer) {
    if (!ban_ip_n || !peer) return false;
    unsigned char a[16], e[16]; bool v4;
    if (!parse_ip(peer, a, &v4)) return false;
    ip_entry(a, v4, e);
    return bsearch(e, ban_ip, ban_ip_n, 16, cmp16) != NULL;
}

/* ---- trusted proxies / forwarded client address --------------------- */

static bool net_match(const rl_net_t *n, const unsigned char e[16]) {
    bool nv4 = n->e[15] == 4 && !memcmp(n->e + 4, "\0\0\0\0\0\0\0\0\0\0\0", 11);
    bool av4 = e[15] == 4 && !memcmp(e + 4, "\0\0\0\0\0\0\0\0\0\0\0", 11);
    if (nv4 != av4) return false;
    unsigned full = n->bits / 8, rem = n->bits % 8;
    if (memcmp(n->e, e, full)) return false;
    if (rem) {
        unsigned char m = (unsigned char) (0xff << (8 - rem));
        if ((n->e[full] & m) != (e[full] & m)) return false;
    }
    return true;
}

static bool entry_trusted(const unsigned char e[16]) {
    for (size_t i = 0; i < trust_n; i++) if (net_match(&trust[i], e)) return true;
    return false;
}

bool rl_trusted_proxy(const char *addr) {
    unsigned char a[16], e[16]; bool v4;
    if (!trust_n || !addr || !parse_ip(addr, a, &v4)) return false;
    ip_entry(a, v4, e);
    return entry_trusted(e);
}

/* s[0..n) trimmed of spaces/tabs; parse into a (ip_entry form) + v4. */
static bool parse_token(const char *s, size_t n, unsigned char a[16], unsigned char e[16], bool *v4) {
    while (n && (*s == ' ' || *s == '\t')) { s++; n--; }
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) n--;
    char buf[80];
    if (n == 0 || n >= sizeof buf) return false;
    memcpy(buf, s, n); buf[n] = '\0';
    if (!parse_ip(buf, a, v4)) return false;
    ip_entry(a, *v4, e);
    return true;
}

static void format_ip(const unsigned char a[16], bool v4, char *out, size_t cap) {
    char txt[INET6_ADDRSTRLEN] = "";
    inet_ntop(v4 ? AF_INET : AF_INET6, a, txt, sizeof txt);
    snprintf(out, cap, "%s", txt);
}

/* The value of the LAST header line `name` (case-insensitive) before
 * position `end` in the block, or NULL. */
static const char *header_before(const char *h, const char *end, const char *name, size_t nlen,
                                 const char **vend, const char **line_start) {
    const char *found = NULL;
    for (const char *p = h; p < end;) {
        const char *eol = memchr(p, '\n', (size_t) (end - p));
        if (!eol) eol = end;
        if ((size_t) (eol - p) > nlen && strncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
            found = p + nlen + 1; *vend = eol; *line_start = p;
        }
        p = eol + 1;
    }
    return found;
}

bool rl_client_ip(const char *peer, const char *headers, size_t headers_len, char *out, size_t cap) {
    char saved[80];
    snprintf(saved, sizeof saved, "%s", peer ? peer : "");
    snprintf(out, cap, "%s", saved);
    if (!headers || !headers_len || !rl_trusted_proxy(saved)) return false;
    const char *hend = headers + headers_len;
    /* X-Forwarded-For: walk the entries right to left across all its
     * header lines (later lines were appended by nearer proxies). */
    unsigned char a[16], e[16], best[16]; bool v4, best_v4 = false, have = false;
    const char *limit = hend, *vend, *ls;
    const char *v;
    while ((v = header_before(headers, limit, "X-Forwarded-For", 15, &vend, &ls)) != NULL) {
        const char *q = vend;
        while (q > v) {
            const char *c = q;
            while (c > v && c[-1] != ',') c--;
            if (!parse_token(c, (size_t) (q - c), a, e, &v4)) {
                /* garbage (or an empty item): stop at the last good hop */
                bool blank = true;
                for (const char *z = c; z < q; z++) if (*z != ' ' && *z != '\t' && *z != '\r') blank = false;
                if (!blank) goto done;
            } else {
                memcpy(best, a, 16); best_v4 = v4; have = true;
                if (!entry_trusted(e)) goto done;
            }
            q = c > v ? c - 1 : v;
        }
        limit = ls;
    }
done:
    if (have) { format_ip(best, best_v4, out, cap); return true; }
    v = header_before(headers, hend, "X-Real-IP", 9, &vend, &ls);
    if (v && parse_token(v, (size_t) (vend - v), a, e, &v4)) { format_ip(a, v4, out, cap); return true; }
    return false;
}

/* ---- configuration ------------------------------------------------------ */

typedef struct { unsigned char *p; size_t n, cap, w; } vec_t;

static bool vec_push(vec_t *v, const unsigned char *item) {
    if (v->n == v->cap) {
        size_t cap = v->cap ? v->cap : 16, bytes;
        if (v->cap && !ng_size_mul(cap, 2, &cap)) return false;
        if (!ng_size_mul(cap, v->w, &bytes)) return false;
        unsigned char *p = (unsigned char *) realloc(v->p, bytes);
        if (!p) return false;
        v->p = p; v->cap = cap;
    }
    memcpy(v->p + v->n * v->w, item, v->w);
    v->n++;
    return true;
}

static ng_status_t add_pubkey(vec_t *v, const char *s, size_t n) {
    unsigned char k[32];
    if (n != 64) return NG_E_INVALID;
    for (size_t i = 0; i < 32; i++) {
        unsigned x = 0;
        for (int j = 0; j < 2; j++) {
            char c = s[2 * i + (size_t) j];
            x <<= 4;
            if (c >= '0' && c <= '9') x |= (unsigned) (c - '0');
            else if (c >= 'a' && c <= 'f') x |= (unsigned) (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') x |= (unsigned) (c - 'A' + 10);
            else return NG_E_INVALID;
        }
        k[i] = (unsigned char) x;
    }
    return vec_push(v, k) ? NG_OK : NG_E_NOMEM;
}

static ng_status_t add_ip(vec_t *v, const char *s, size_t n) {
    char buf[80]; unsigned char a[16], e[16]; bool v4;
    if (n == 0 || n >= sizeof buf) return NG_E_INVALID;
    memcpy(buf, s, n); buf[n] = '\0';
    if (!parse_ip(buf, a, &v4)) return NG_E_INVALID;
    ip_entry(a, v4, e);
    return vec_push(v, e) ? NG_OK : NG_E_NOMEM;
}

static ng_status_t add_list(vec_t *v, const char *list, ng_status_t (*add)(vec_t *, const char *, size_t)) {
    const char *p = list ? list : "";
    while (*p) {
        while (*p == ',' || *p == ' ' || *p == '\t') p++;
        const char *s = p;
        while (*p && *p != ',' && *p != ' ' && *p != '\t') p++;
        if (p > s) { ng_status_t st = add(v, s, (size_t) (p - s)); if (st != NG_OK) return st; }
    }
    return NG_OK;
}

static ng_status_t load_file(const char *path, vec_t *pk, vec_t *ip, unsigned *bad_line) {
    FILE *f = fopen(path, "r");
    if (!f) return NG_E_IO;
    char line[512];
    unsigned no = 0;
    ng_status_t st = NG_OK;
    while (st == NG_OK && fgets(line, sizeof line, f)) {
        no++;
        char *h = strchr(line, '#'); if (h) *h = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        char *e = p + strlen(p);
        while (e > p && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t')) *--e = '\0';
        if (!*p) continue;
        if (!strncmp(p, "pubkey", 6) && (p[6] == ' ' || p[6] == '\t')) st = add_list(pk, p + 7, add_pubkey);
        else if (!strncmp(p, "ip", 2) && (p[2] == ' ' || p[2] == '\t')) st = add_list(ip, p + 3, add_ip);
        else st = NG_E_INVALID;
        if (st == NG_E_INVALID) *bad_line = no;
    }
    fclose(f);
    return st;
}

static void dedup_sorted(vec_t *v) {
    if (v->n < 2) return;
    size_t k = 1;
    for (size_t i = 1; i < v->n; i++)
        if (memcmp(v->p + i * v->w, v->p + (k - 1) * v->w, v->w))
            memmove(v->p + k++ * v->w, v->p + i * v->w, v->w);
    v->n = k;
}

void rl_shutdown(void) {
    for (int c = 0; c < RL_CLASSES; c++) { free(classes[c].tat); classes[c].tat = NULL; }
    free(ban_pk); ban_pk = NULL; ban_pk_n = 0;
    free(ban_ip); ban_ip = NULL; ban_ip_n = 0;
    free(trust); trust = NULL; trust_n = 0;
}

/* "addr" or "addr/bits" -> rl_net_t (vec width sizeof(rl_net_t)). */
static ng_status_t add_net(vec_t *v, const char *s, size_t n) {
    char buf[80]; unsigned char a[16]; bool v4;
    if (n == 0 || n >= sizeof buf) return NG_E_INVALID;
    memcpy(buf, s, n); buf[n] = '\0';
    char *slash = strchr(buf, '/');
    long bits = -1;
    if (slash) {
        char *end = NULL;
        *slash = '\0';
        bits = strtol(slash + 1, &end, 10);
        if (end == slash + 1 || *end || bits < 0) return NG_E_INVALID;
    }
    if (!parse_ip(buf, a, &v4)) return NG_E_INVALID;
    long max = v4 ? 32 : 128;
    if (bits < 0) bits = max;
    if (bits > max) return NG_E_INVALID;
    rl_net_t net;
    memset(&net, 0, sizeof net);
    ip_entry(a, v4, net.e);
    net.bits = (unsigned) bits;
    return vec_push(v, (const unsigned char *) &net) ? NG_OK : NG_E_NOMEM;
}

ng_status_t rl_configure(const rl_config_t *cfg, unsigned *bad_line) {
    unsigned dummy;
    if (!bad_line) bad_line = &dummy;
    *bad_line = 0;
    rl_shutdown();
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || read(fd, seed, sizeof seed) != (ssize_t) sizeof seed) {
        seed[0] = (uint64_t) time(NULL) ^ ((uint64_t) getpid() << 32); seed[1] = ~seed[0] * 0x9e3779b97f4a7c15ull;
    }
    if (fd >= 0) close(fd);
    for (int c = 0; c < RL_CLASSES; c++) {
        if (cfg->per_min[c] <= 0) continue;
        int burst = cfg->burst[c] > 0 ? cfg->burst[c] : 1;
        classes[c].interval_ns = 60000000000ull / (unsigned long long) cfg->per_min[c];
        classes[c].window_ns = classes[c].interval_ns * (unsigned long long) burst;
        classes[c].tat = (ng_atomic_ullong *) calloc(2u * RL_SLOTS, sizeof(ng_atomic_ullong));
        if (!classes[c].tat) { rl_shutdown(); return NG_E_NOMEM; }
    }
    vec_t pk = { NULL, 0, 0, 32 }, ip = { NULL, 0, 0, 16 };
    ng_status_t st = add_list(&pk, cfg->banned_pubkeys, add_pubkey);
    if (st == NG_OK) st = add_list(&ip, cfg->banned_ips, add_ip);
    if (st == NG_OK && cfg->ban_file && *cfg->ban_file) st = load_file(cfg->ban_file, &pk, &ip, bad_line);
    vec_t tn = { NULL, 0, 0, sizeof(rl_net_t) };
    if (st == NG_OK)
        st = add_list(&tn, cfg->trusted_proxies ? cfg->trusted_proxies : RL_TRUSTED_PROXIES_DEFAULT, add_net);
    if (st != NG_OK) { free(pk.p); free(ip.p); free(tn.p); rl_shutdown(); return st; }
    trust = (rl_net_t *) (void *) tn.p; trust_n = tn.n;
    if (pk.n) qsort(pk.p, pk.n, 32, cmp32);
    if (ip.n) qsort(ip.p, ip.n, 16, cmp16);
    dedup_sorted(&pk); dedup_sorted(&ip);
    ban_pk = (unsigned char (*)[32]) pk.p; ban_pk_n = pk.n;
    ban_ip = (unsigned char (*)[16]) ip.p; ban_ip_n = ip.n;
    return NG_OK;
}
