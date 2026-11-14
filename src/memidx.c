/* memidx - in-memory NIP-01 tag index (see memidx.h). */
#include "memidx.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "json_lite.h"
#include "platform/ng_alloc.h"
#include "platform/ng_atomic.h"
#include "platform/ng_platform.h"
#include "storage_query.h"

/* ------------------------------------------------------------ postings --- */
/* 12 bytes: seq is 48 bits (2.8e14 events). Ordered by (created_at, seq). */
typedef struct { uint32_t ca; uint32_t seq_lo; uint16_t kind; uint16_t seq_hi; } post_t;
NG_STATIC_ASSERT(sizeof(post_t) == 12, post_t_is_12_bytes);

static inline uint64_t pseq(const post_t *p) { return (uint64_t) p->seq_hi << 32 | p->seq_lo; }
static inline post_t mkpost(uint32_t ca, uint64_t seq, int kind) {
    post_t p;
    p.ca = ca; p.seq_lo = (uint32_t) seq; p.seq_hi = (uint16_t) (seq >> 32); p.kind = (uint16_t) kind;
    return p;
}
static inline int pcmp(const post_t *a, const post_t *b) {
    if (a->ca != b->ca) return a->ca < b->ca ? -1 : 1;
    uint64_t x = pseq(a), y = pseq(b);
    return x < y ? -1 : x > y;
}

/* Block encoding (ascending postings): the first posting raw (created_at
 * u32 LE, seq varint, kind varint), then per posting varint(dca << 1 |
 * same_kind), varint(zigzag(dseq)) and, if the kind changed, varint(kind).
 * Typically 3-5 bytes per posting. */
#define BLK_MAX_BYTES ((size_t) MEMIDX_BLOCK * 24)

static size_t put_var(uint8_t *o, uint64_t v) {
    size_t n = 0;
    while (v >= 0x80) { o[n++] = (uint8_t) (v | 0x80); v >>= 7; }
    o[n++] = (uint8_t) v;
    return n;
}
/* Bounded varint read: bytes consumed, 0 on truncation / overlong. */
static size_t get_var(const uint8_t *p, const uint8_t *end, uint64_t *v) {
    uint64_t r = 0;
    for (size_t i = 0; i < 10 && p + i < end; i++) {
        r |= (uint64_t) (p[i] & 0x7f) << (7 * i);
        if (!(p[i] & 0x80)) { *v = r; return i + 1; }
    }
    return 0;
}

static size_t blk_encode(const post_t *p, size_t k, uint8_t *o) {
    size_t n = 0;
    uint32_t ca = p[0].ca;
    o[n++] = (uint8_t) ca; o[n++] = (uint8_t) (ca >> 8); o[n++] = (uint8_t) (ca >> 16); o[n++] = (uint8_t) (ca >> 24);
    n += put_var(o + n, pseq(&p[0]));
    n += put_var(o + n, p[0].kind);
    for (size_t i = 1; i < k; i++) {
        bool same = p[i].kind == p[i - 1].kind;
        n += put_var(o + n, (uint64_t) (p[i].ca - p[i - 1].ca) << 1 | (same ? 1u : 0u));
        uint64_t d = pseq(&p[i]) - pseq(&p[i - 1]);            /* mod 2^64 */
        uint64_t z = (d << 1) ^ ((d >> 63) ? ~(uint64_t) 0 : 0);
        n += put_var(o + n, z);
        if (!same) n += put_var(o + n, p[i].kind);
    }
    return n;
}

/* Decode k postings; false on malformed input (snapshot loading). */
static bool blk_decode(const uint8_t *d, const uint8_t *end, size_t k, post_t *out) {
    if (k == 0) return true;
    if (end - d < 4) return false;
    uint32_t ca = (uint32_t) d[0] | (uint32_t) d[1] << 8 | (uint32_t) d[2] << 16 | (uint32_t) d[3] << 24;
    d += 4;
    uint64_t seq, kind, v;
    size_t c;
    if (!(c = get_var(d, end, &seq))) return false;
    d += c;
    if (!(c = get_var(d, end, &kind)) || kind > 0xffff) return false;
    d += c;
    out[0] = mkpost(ca, seq, (int) kind);
    for (size_t i = 1; i < k; i++) {
        if (!(c = get_var(d, end, &v))) return false;
        d += c;
        uint64_t dca = v >> 1;
        if (dca > 0xffffffffull - ca) return false;
        ca += (uint32_t) dca;
        uint64_t z;
        if (!(c = get_var(d, end, &z))) return false;
        d += c;
        seq += (z >> 1) ^ (0 - (z & 1));
        if (!(v & 1)) {
            if (!(c = get_var(d, end, &kind)) || kind > 0xffff) return false;
            d += c;
        }
        out[i] = mkpost(ca, seq, (int) kind);
    }
    return true;
}

/* --------------------------------------------------------------- keys --- */
/* rep: how a key's postings are held.
 *   REP_ONE   one posting inline in the slot
 *   REP_SMALL <= SMALL_MAX postings, one malloc: [u8 count][one block]
 *   REP_BODY  frozen blocks (data + directory) plus a sorted raw tail */
enum { REP_ONE = 1, REP_SMALL = 2, REP_BODY = 3 };
#define SMALL_MAX 32
NG_STATIC_ASSERT(SMALL_MAX <= MEMIDX_BLOCK && SMALL_MAX < 256, small_fits_one_block);

typedef struct { uint32_t off; uint32_t last_ca; } blkdir_t;
typedef struct {
    uint8_t *data;
    blkdir_t *dir;
    uint32_t nfz, dlen, dcap, nblk, blkcap;
    post_t fz_last;                  /* last frozen posting (nfz > 0) */
    uint16_t tn, tcap;
    post_t tail[];                   /* sorted ascending */
} body_t;

typedef struct {
    uint64_t key;
    uint32_t n;                      /* postings; 0 = free slot */
    uint8_t letter;                  /* 0x7f = the overflow list (see OVF_LETTER) */
    uint8_t rep;
    uint16_t pad;
    union { body_t *b; uint8_t *small; post_t one; } u;
} slot_t;
NG_STATIC_ASSERT(sizeof(slot_t) == 32, slot_t_is_32_bytes);

/* Events with more indexed tags than max_per_event are listed under this
 * pseudo key; every query merges it in (their JSON is rechecked). */
#define OVF_LETTER 0x7f
#define OVF_KEY 0

typedef struct {
    pthread_rwlock_t lock;
    slot_t *tab;
    size_t cap, n;
    uint64_t gen;                    /* bumped when slots move (written under the write lock) */
} NG_ALIGNED(NG_CACHELINE) shard_t;

static shard_t shards[MEMIDX_SHARDS];
static bool mi_open;
static ng_atomic_bool letter_on[128];
static char letters_str[64];
static size_t per_event_cap;
static size_t mem_cap;
static ng_atomic_size n_keys, n_posts, n_bytes;
static ng_atomic_size letter_bytes[128], letter_keys[128];
static ng_atomic_ullong letter_hits[128];
static ng_atomic_ullong max_seq_added;
static ng_atomic_ullong changes;     /* adds + deletes: the snapshot thread skips idle periods */
static ng_atomic_size n_degraded;
static ng_atomic_ullong tombs_pending;
/* Set when an update failed (OOM): the index may miss postings, so every
 * query falls back to SQL until the next start rebuilds it. */
static ng_atomic_bool broken;

static inline uint64_t mix(uint64_t key, unsigned letter) {
    uint64_t h = key ^ ((uint64_t) letter * 0x9e3779b97f4a7c15ull);
    h ^= h >> 33; h *= 0xff51afd7ed558ccdull;
    h ^= h >> 33; h *= 0xc4ceb9fe1a85ec53ull;
    h ^= h >> 33;
    return h;
}
static inline shard_t *shard_of(uint64_t h) { return &shards[h >> 58]; }
NG_STATIC_ASSERT(MEMIDX_SHARDS == 64, shards_are_top_6_bits);

static uint64_t key8(const char *v, size_t len) {
    unsigned char b[8];
    sq_tag_key8(v, len, b);
    uint64_t x = 0;
    for (int i = 0; i < 8; i++) x = x << 8 | b[i];
    return x;
}

static void mem_acct(unsigned letter, size_t before, size_t after) {
    size_t d = after - before;                               /* mod 2^N */
    ng_atomic_fetch_add_explicit(&n_bytes, d, NG_MO_RELAXED);
    ng_atomic_fetch_add_explicit(&letter_bytes[letter & 127], d, NG_MO_RELAXED);
}
static void posts_add(long long d) { ng_atomic_fetch_add_explicit(&n_posts, (size_t) d, NG_MO_RELAXED); }

/* REP_SMALL buffer: [count u8][len u16 LE][len bytes: one block]. */
#define SMALL_HDR 3
static inline size_t small_len(const uint8_t *sm) { return (size_t) sm[1] | (size_t) sm[2] << 8; }

static size_t body_size(const body_t *b) {
    return sizeof(body_t) + (size_t) b->tcap * sizeof(post_t) + b->dcap + (size_t) b->blkcap * sizeof(blkdir_t);
}
/* Heap bytes a slot owns (the slot itself is counted with the table). */
static size_t rep_bytes(const slot_t *s) {
    if (!s->n) return 0;
    if (s->rep == REP_SMALL) return SMALL_HDR + small_len(s->u.small);
    if (s->rep == REP_BODY) return body_size(s->u.b);
    return 0;
}

/* --------------------------------------------------------- tombstones --- */
/* Deleted seqs: a two-level bitmap, 2^20 seqs (128 KiB) per chunk,
 * allocated on first use. Only the writer sets bits; readers load them
 * relaxed (a just-set bit not seen yet only costs the SQL recheck). */
#define TB_CHUNK_SHIFT 20
#define TB_TOP ((size_t) 1 << 16)    /* seqs < 2^36 */
#define TB_WORDS (((size_t) 1 << TB_CHUNK_SHIFT) / 64)
static ng_atomic_ptr tb_top[TB_TOP];
static ng_atomic_size tb_bytes;

static inline bool dead(uint64_t seq) {
    size_t c = (size_t) (seq >> TB_CHUNK_SHIFT);
    if (c >= TB_TOP) return false;
    ng_atomic_ullong *w = (ng_atomic_ullong *) ng_atomic_load_explicit(&tb_top[c], NG_MO_ACQUIRE);
    if (!w) return false;
    unsigned long long bits = ng_atomic_load_explicit(&w[(seq >> 6) & (TB_WORDS - 1)], NG_MO_RELAXED);
    return (bits >> (seq & 63)) & 1;
}

void memidx_tomb_set(uint64_t seq) {
    size_t c = (size_t) (seq >> TB_CHUNK_SHIFT);
    if (!mi_open || c >= TB_TOP) return;
    ng_atomic_ullong *w = (ng_atomic_ullong *) ng_atomic_load_explicit(&tb_top[c], NG_MO_ACQUIRE);
    if (!w) {
        w = (ng_atomic_ullong *) calloc(TB_WORDS, sizeof(*w));
        if (!w) return;                                      /* the recheck still hides it */
        ng_atomic_store_explicit(&tb_top[c], (void *) w, NG_MO_RELEASE);
        ng_atomic_fetch_add_explicit(&tb_bytes, TB_WORDS * sizeof(*w), NG_MO_RELAXED);
        ng_atomic_fetch_add_explicit(&n_bytes, TB_WORDS * sizeof(*w), NG_MO_RELAXED);
    }
    ng_atomic_ullong *word = &w[(seq >> 6) & (TB_WORDS - 1)];
    unsigned long long bit = 1ull << (seq & 63), old = ng_atomic_load_explicit(word, NG_MO_RELAXED);
    if (old & bit) return;
    ng_atomic_store_explicit(word, old | bit, NG_MO_RELAXED);
    ng_atomic_fetch_add_explicit(&tombs_pending, 1, NG_MO_RELAXED);
    ng_atomic_fetch_add_explicit(&changes, 1, NG_MO_RELAXED);
}

void memidx_tomb_range(uint64_t from, uint64_t to) {
    for (uint64_t s = from; s <= to && s >= from; s++) memidx_tomb_set(s);
}

/* ----------------------------------------------------------- the table --- */
static slot_t *slot_find(const shard_t *sh, uint64_t key, unsigned letter, uint64_t h) {
    if (!sh->cap) return NULL;
    size_t m = sh->cap - 1, i = (size_t) h & m;
    while (sh->tab[i].n) {
        if (sh->tab[i].key == key && sh->tab[i].letter == letter) return &sh->tab[i];
        i = (i + 1) & m;
    }
    return NULL;
}

static bool shard_rehash(shard_t *sh, size_t ncap, unsigned drop_letter) {
    slot_t *nt = (slot_t *) calloc(ncap, sizeof(slot_t));
    if (!nt) return false;
    size_t m = ncap - 1, n = 0;
    for (size_t i = 0; i < sh->cap; i++) {
        slot_t *s = &sh->tab[i];
        if (!s->n) continue;
        if (s->letter == drop_letter) {                     /* memory cap: letter dropped */
            mem_acct(s->letter, rep_bytes(s), 0);
            posts_add(-(long long) s->n);
            ng_atomic_fetch_sub_explicit(&n_keys, 1, NG_MO_RELAXED);
            if (s->rep == REP_SMALL) free(s->u.small);
            else if (s->rep == REP_BODY) { free(s->u.b->data); free(s->u.b->dir); free(s->u.b); }
            continue;
        }
        size_t j = (size_t) mix(s->key, s->letter) & m;
        while (nt[j].n) j = (j + 1) & m;
        nt[j] = *s;
        n++;
    }
    ng_atomic_fetch_add_explicit(&n_bytes, ncap * sizeof(slot_t) - sh->cap * sizeof(slot_t), NG_MO_RELAXED);
    free(sh->tab);
    sh->tab = nt; sh->cap = ncap; sh->n = n;
    sh->gen++;
    return true;
}

/* The slot for (key, letter), created empty (n = 0, caller fills it) if
 * absent; NULL on OOM. Write lock held. */
static slot_t *slot_get(shard_t *sh, uint64_t key, unsigned letter, uint64_t h) {
    if ((sh->n + 1) * 4 > sh->cap * 3 && !shard_rehash(sh, sh->cap ? sh->cap * 2 : 64, 0)) return NULL;
    size_t m = sh->cap - 1, i = (size_t) h & m;
    while (sh->tab[i].n) {
        if (sh->tab[i].key == key && sh->tab[i].letter == letter) return &sh->tab[i];
        i = (i + 1) & m;
    }
    slot_t *s = &sh->tab[i];
    memset(s, 0, sizeof(*s));
    s->key = key; s->letter = (uint8_t) letter;
    return s;
}

/* Remove slot i (linear probing, backward shift). Write lock held; the
 * slot's heap is already freed. */
static void slot_remove(shard_t *sh, size_t i) {
    ng_atomic_fetch_sub_explicit(&letter_keys[sh->tab[i].letter & 127], 1, NG_MO_RELAXED);
    size_t m = sh->cap - 1, j = i;
    for (;;) {
        j = (j + 1) & m;
        if (!sh->tab[j].n) break;
        size_t home = (size_t) mix(sh->tab[j].key, sh->tab[j].letter) & m;
        bool stays = i <= j ? (home > i && home <= j) : (home > i || home <= j);
        if (!stays) { sh->tab[i] = sh->tab[j]; i = j; }
    }
    memset(&sh->tab[i], 0, sizeof(sh->tab[i]));
    sh->n--;
    sh->gen++;
    ng_atomic_fetch_sub_explicit(&n_keys, 1, NG_MO_RELAXED);
}

/* ------------------------------------------------- reading a key's run --- */
/* All postings of a slot, ascending, into out (capacity s->n). For the
 * snapshot and for rewrites. false only if a block fails to decode. */
static bool slot_all(const slot_t *s, post_t *out, size_t *n) {
    if (s->rep == REP_ONE) { out[0] = s->u.one; *n = 1; return true; }
    if (s->rep == REP_SMALL) {
        const uint8_t *sm = s->u.small;
        if (!blk_decode(sm + SMALL_HDR, sm + SMALL_HDR + small_len(sm), sm[0], out)) return false;
        *n = sm[0];
        return true;
    }
    const body_t *b = s->u.b;
    post_t *fz = out + b->tn;                                /* decode frozen past the tail's room */
    for (uint32_t i = 0; i < b->nblk; i++) {
        size_t k = i + 1 < b->nblk ? MEMIDX_BLOCK : b->nfz - (size_t) i * MEMIDX_BLOCK;
        const uint8_t *d = b->data + b->dir[i].off, *e = b->data + (i + 1 < b->nblk ? b->dir[i + 1].off : b->dlen);
        if (!blk_decode(d, e, k, fz + (size_t) i * MEMIDX_BLOCK)) return false;
    }
    /* merge tail (b->tail) and frozen (fz) into out from the front: fz
     * starts tn entries in, so writes never overtake unread frozen data. */
    size_t a = 0, f = 0, o = 0;
    while (a < b->tn || f < b->nfz) {
        if (f >= b->nfz || (a < b->tn && pcmp(&b->tail[a], &fz[f]) < 0)) out[o++] = b->tail[a++];
        else out[o++] = fz[f++];
    }
    *n = o;
    return true;
}

typedef struct {
    const int *kinds; size_t nk;
    int64_t since, until;
} qf_t;

static inline bool qf_pass(const qf_t *q, const post_t *p) {
    if (q->until > 0 && (int64_t) p->ca > q->until) return false;
    if (q->nk) {
        size_t k = 0;
        while (k < q->nk && q->kinds[k] != (int) p->kind) k++;
        if (k == q->nk) return false;
    }
    return !dead(pseq(p));
}

/* Up to want passing postings of slot s, newest first, into out. Read lock held. */
static size_t slot_collect(const slot_t *s, const qf_t *q, size_t want, post_t *out) {
    size_t got = 0;
    post_t tmp[MEMIDX_BLOCK];
    if (s->rep == REP_ONE) {
        if (want && qf_pass(q, &s->u.one) && !(q->since > 0 && (int64_t) s->u.one.ca < q->since)) out[got++] = s->u.one;
        return got;
    }
    if (s->rep == REP_SMALL) {
        const uint8_t *sm = s->u.small;
        if (!blk_decode(sm + SMALL_HDR, sm + SMALL_HDR + small_len(sm), sm[0], tmp)) return 0;
        for (size_t i = sm[0]; i-- > 0 && got < want;) {
            if (q->since > 0 && (int64_t) tmp[i].ca < q->since) break;
            if (qf_pass(q, &tmp[i])) out[got++] = tmp[i];
        }
        return got;
    }
    const body_t *b = s->u.b;
    /* frozen blocks from the newest down; with until, start at the first
     * block whose last created_at passes it. */
    long blk = (long) b->nblk - 1;
    if (q->until > 0) {
        uint32_t lo = 0, hi = b->nblk;                      /* first block with last_ca > until */
        while (lo < hi) { uint32_t mid = lo + (hi - lo) / 2; if ((int64_t) b->dir[mid].last_ca > q->until) hi = mid; else lo = mid + 1; }
        blk = lo < b->nblk ? (long) lo : (long) b->nblk - 1;
    }
    size_t fk = 0;                                           /* undelivered postings in tmp[0..fk) */
    long ti = (long) b->tn - 1;
    for (;;) {
        if (fk == 0 && blk >= 0) {
            size_t k = (size_t) blk + 1 < b->nblk ? MEMIDX_BLOCK : b->nfz - (size_t) blk * MEMIDX_BLOCK;
            const uint8_t *d = b->data + b->dir[blk].off;
            const uint8_t *e = b->data + ((uint32_t) blk + 1 < b->nblk ? b->dir[blk + 1].off : b->dlen);
            if (!blk_decode(d, e, k, tmp)) return got;
            fk = k;
            blk--;
        }
        const post_t *p;
        if (fk && (ti < 0 || pcmp(&tmp[fk - 1], &b->tail[ti]) > 0)) p = &tmp[--fk];
        else if (ti >= 0) p = &b->tail[ti--];
        else break;
        if (q->since > 0 && (int64_t) p->ca < q->since) break;
        if (qf_pass(q, p)) { out[got++] = *p; if (got >= want) break; }
    }
    return got;
}

/* ------------------------------------------------------------- writing --- */
/* Per-thread scratch postings (the writer's merges, the snapshot thread). */
static NG_THREAD_LOCAL post_t *ws;
static NG_THREAD_LOCAL size_t ws_cap;
static NG_THREAD_LOCAL char *vbuf;
static NG_THREAD_LOCAL size_t vbuf_cap;

static post_t *ws_get(size_t n) {
    if (n > ws_cap) {
        size_t c = ng_grow_cap(ws_cap, n, 256);
        post_t *p = (post_t *) ng_realloc_array(ws, c, sizeof(post_t));
        if (!p) return NULL;
        ws = p; ws_cap = c;
    }
    return ws;
}

void memidx_thread_done(void) {
    free(ws); ws = NULL; ws_cap = 0;
    free(vbuf); vbuf = NULL; vbuf_cap = 0;
}

static void heap_free(slot_t *s) {
    if (s->rep == REP_SMALL) free(s->u.small);
    else if (s->rep == REP_BODY) { free(s->u.b->data); free(s->u.b->dir); free(s->u.b); }
}

/* Append ascending postings p[0..n) as full blocks (the last may be
 * partial) to body b's frozen run. false on OOM (b unchanged in meaning:
 * the blocks appended so far stay valid). */
static bool body_append(body_t *b, const post_t *p, size_t n) {
    for (size_t i = 0; i < n; i += MEMIDX_BLOCK) {
        size_t k = n - i < MEMIDX_BLOCK ? n - i : MEMIDX_BLOCK;
        if ((size_t) b->dlen + BLK_MAX_BYTES > b->dcap) {
            size_t c = ng_grow_cap(b->dcap, (size_t) b->dlen + BLK_MAX_BYTES, 256);
            if (c > UINT32_MAX) return false;
            uint8_t *d = (uint8_t *) realloc(b->data, c);
            if (!d) return false;
            b->data = d; b->dcap = (uint32_t) c;
        }
        if (b->nblk == b->blkcap) {
            size_t c = ng_grow_cap(b->blkcap, (size_t) b->nblk + 1, 4);
            blkdir_t *d = (blkdir_t *) ng_realloc_array(b->dir, c, sizeof(blkdir_t));
            if (!d) return false;
            b->dir = d; b->blkcap = (uint32_t) c;
        }
        b->dir[b->nblk].off = b->dlen;
        b->dir[b->nblk].last_ca = p[i + k - 1].ca;
        b->dlen += (uint32_t) blk_encode(p + i, k, b->data + b->dlen);
        b->nblk++;
        b->nfz += (uint32_t) k;
        b->fz_last = p[i + k - 1];
    }
    return true;
}

/* Trim a body's frozen buffers to what they hold (after a rewrite). */
static void body_trim(body_t *b) {
    if (b->dcap > b->dlen + BLK_MAX_BYTES && b->dlen) {
        uint8_t *d = (uint8_t *) realloc(b->data, b->dlen + BLK_MAX_BYTES / 4);
        if (d) { b->data = d; b->dcap = b->dlen + (uint32_t) (BLK_MAX_BYTES / 4); }
    }
}

/* Make slot s hold exactly the ascending, distinct postings p[0..n), n >= 1,
 * in the smallest representation. Write lock held. false on OOM (s unchanged). */
static bool slot_set(slot_t *s, const post_t *p, size_t n) {
    size_t before = rep_bytes(s), old_n = s->n;
    if (n == 1) {
        heap_free(s);
        s->rep = REP_ONE; s->u.one = p[0];
    } else if (n <= SMALL_MAX) {
        uint8_t tmp[SMALL_HDR + BLK_MAX_BYTES];
        size_t len = blk_encode(p, n, tmp + SMALL_HDR);
        tmp[0] = (uint8_t) n; tmp[1] = (uint8_t) len; tmp[2] = (uint8_t) (len >> 8);
        uint8_t *sm = (uint8_t *) realloc(s->rep == REP_SMALL ? s->u.small : NULL, SMALL_HDR + len);
        if (!sm) return false;
        memcpy(sm, tmp, SMALL_HDR + len);
        if (s->rep == REP_BODY) heap_free(s);
        s->rep = REP_SMALL; s->u.small = sm;
    } else {
        body_t *b = (body_t *) calloc(1, sizeof(body_t));
        if (!b) return false;
        if (!body_append(b, p, n)) { free(b->data); free(b->dir); free(b); return false; }
        body_trim(b);
        heap_free(s);
        s->rep = REP_BODY; s->u.b = b;
    }
    s->n = (uint32_t) n;
    mem_acct(s->letter, before, rep_bytes(s));
    posts_add((long long) n - (long long) old_n);
    return true;
}

static uint32_t tail_limit(uint32_t n) {
    uint32_t r = 2;
    while ((uint64_t) r * r < n) r <<= 1;
    uint32_t t = r * 2;
    return t < 8 ? 8 : t > 4096 ? 4096 : t;
}

/* Merge the tail into the frozen run (and drop dead postings in the
 * rewritten blocks); all = rewrite every block. The slot may end up
 * empty (s->n == 0: the caller removes it) or smaller. Write lock held. */
static bool body_merge(slot_t *s, bool all) {
    body_t *b = s->u.b;
    uint32_t j = 0;
    if (!all) {
        if (!b->tn) return true;
        uint32_t lo = 0, hi = b->nblk;
        while (lo < hi) { uint32_t mid = lo + (hi - lo) / 2; if (b->dir[mid].last_ca >= b->tail[0].ca) hi = mid; else lo = mid + 1; }
        j = lo;
        if (j == b->nblk && b->nblk && b->nfz % MEMIDX_BLOCK) j = b->nblk - 1;   /* refill the partial block */
    }
    size_t old_fz = b->nfz - (size_t) j * MEMIDX_BLOCK, m = old_fz + b->tn;
    post_t *buf = ws_get(2 * m + 1);
    if (!buf) return false;
    post_t *fz = buf, *out = buf + m;
    for (uint32_t i = j; i < b->nblk; i++) {
        size_t k = i + 1 < b->nblk ? MEMIDX_BLOCK : b->nfz - (size_t) i * MEMIDX_BLOCK;
        const uint8_t *d = b->data + b->dir[i].off, *e = b->data + (i + 1 < b->nblk ? b->dir[i + 1].off : b->dlen);
        if (!blk_decode(d, e, k, fz + (size_t) (i - j) * MEMIDX_BLOCK)) return false;
    }
    size_t a = 0, f = 0, o = 0;
    while (a < b->tn || f < old_fz) {
        const post_t *p = (f >= old_fz || (a < b->tn && pcmp(&b->tail[a], &fz[f]) < 0)) ? &b->tail[a++] : &fz[f++];
        if (dead(pseq(p)) || (o && pcmp(&out[o - 1], p) == 0)) continue;
        out[o++] = *p;
    }
    size_t before = rep_bytes(s), old_n = s->n;
    size_t keep = (size_t) j * MEMIDX_BLOCK;
    if (keep + o <= SMALL_MAX) {               /* shrank (keep is 0 here: blocks hold 64) */
        if (o == 0) {
            mem_acct(s->letter, before, 0);
            posts_add(-(long long) old_n);
            heap_free(s);
            s->n = 0;
            return true;
        }
        return slot_set(s, out, o);
    }
    b->dlen = j < b->nblk ? b->dir[j].off : b->dlen;
    b->nblk = j; b->nfz = (uint32_t) keep;
    if (j) {                                                 /* fz_last = end of block j-1 */
        post_t blk[MEMIDX_BLOCK];
        if (!blk_decode(b->data + b->dir[j - 1].off, b->data + b->dlen, MEMIDX_BLOCK, blk)) return false;
        b->fz_last = blk[MEMIDX_BLOCK - 1];
    }
    b->tn = 0;
    bool ok = body_append(b, out, o);
    if (b->tcap > 4) {                                        /* tails regrow on demand */
        body_t *nb = (body_t *) realloc(b, sizeof(body_t) + 4 * sizeof(post_t));
        if (nb) { b = nb; b->tcap = 4; s->u.b = b; }
    }
    if (all) body_trim(b);
    s->n = b->nfz;
    mem_acct(s->letter, before, rep_bytes(s));
    posts_add((long long) s->n - (long long) old_n);
    return ok;
}

/* Is p already in body b? */
static bool body_has(const body_t *b, const post_t *p) {
    uint32_t lo = 0, hi = b->tn;
    while (lo < hi) { uint32_t mid = lo + (hi - lo) / 2; if (pcmp(&b->tail[mid], p) < 0) lo = mid + 1; else hi = mid; }
    if (lo < b->tn && pcmp(&b->tail[lo], p) == 0) return true;
    if (!b->nfz || pcmp(p, &b->fz_last) > 0) return false;
    lo = 0; hi = b->nblk;
    while (lo < hi) { uint32_t mid = lo + (hi - lo) / 2; if (b->dir[mid].last_ca >= p->ca) hi = mid; else lo = mid + 1; }
    post_t blk[MEMIDX_BLOCK];
    for (uint32_t i = lo; i < b->nblk; i++) {
        size_t k = i + 1 < b->nblk ? MEMIDX_BLOCK : b->nfz - (size_t) i * MEMIDX_BLOCK;
        if (!blk_decode(b->data + b->dir[i].off, b->data + (i + 1 < b->nblk ? b->dir[i + 1].off : b->dlen), k, blk))
            return false;
        if (blk[0].ca > p->ca) return false;
        for (size_t x = 0; x < k; x++) if (pcmp(&blk[x], p) == 0) return true;
    }
    return false;
}

static bool body_add(slot_t *s, const post_t *p) {
    body_t *b = s->u.b;
    if (body_has(b, p)) return true;
    size_t before = rep_bytes(s);
    if (b->tn == b->tcap) {
        size_t c = ng_grow_cap(b->tcap, (size_t) b->tn + 1, 4);
        if (c > 0xffff) c = 0xffff;
        body_t *nb = (body_t *) ng_malloc_flex(sizeof(body_t), c, sizeof(post_t));
        if (!nb) return false;
        memcpy(nb, b, sizeof(body_t) + (size_t) b->tn * sizeof(post_t));
        free(b);
        b = nb; b->tcap = (uint16_t) c; s->u.b = b;
    }
    uint32_t lo = 0, hi = b->tn;
    while (lo < hi) { uint32_t mid = lo + (hi - lo) / 2; if (pcmp(&b->tail[mid], p) < 0) lo = mid + 1; else hi = mid; }
    memmove(&b->tail[lo + 1], &b->tail[lo], (size_t) (b->tn - lo) * sizeof(post_t));
    b->tail[lo] = *p;
    b->tn++;
    s->n++;
    mem_acct(s->letter, before, rep_bytes(s));
    posts_add(1);
    if (b->tn >= tail_limit(s->n)) return body_merge(s, false);
    return true;
}

static bool add_posting(unsigned letter, uint64_t key, const post_t *p) {
    uint64_t h = mix(key, letter);
    shard_t *sh = shard_of(h);
    pthread_rwlock_wrlock(&sh->lock);
    bool ok = true;
    slot_t *s = slot_get(sh, key, letter, h);
    if (!s) ok = false;
    else if (!s->n) {
        s->rep = REP_ONE; s->u.one = *p; s->n = 1;
        sh->n++;
        ng_atomic_fetch_add_explicit(&n_keys, 1, NG_MO_RELAXED);
        ng_atomic_fetch_add_explicit(&letter_keys[letter & 127], 1, NG_MO_RELAXED);
        posts_add(1);
    } else if (s->rep == REP_ONE) {
        int c = pcmp(p, &s->u.one);
        if (c) {
            post_t two[2];
            two[c < 0 ? 0 : 1] = *p; two[c < 0 ? 1 : 0] = s->u.one;
            ok = slot_set(s, two, 2);
        }
    } else if (s->rep == REP_SMALL) {
        post_t tmp[SMALL_MAX + 1];
        size_t n = s->u.small[0];
        const uint8_t *sm = s->u.small;
        if (!blk_decode(sm + SMALL_HDR, sm + SMALL_HDR + small_len(sm), n, tmp)) ok = false;
        else {
            size_t i = n;
            while (i > 0 && pcmp(p, &tmp[i - 1]) < 0) i--;
            if (!(i > 0 && pcmp(p, &tmp[i - 1]) == 0)) {
                memmove(&tmp[i + 1], &tmp[i], (n - i) * sizeof(post_t));
                tmp[i] = *p;
                ok = slot_set(s, tmp, n + 1);
            }
        }
    } else {
        ok = body_add(s, p);
        if (ok && !s->n) {                                   /* every posting was dead */
            size_t i = (size_t) (s - sh->tab);
            slot_remove(sh, i);
        }
    }
    pthread_rwlock_unlock(&sh->lock);
    return ok;
}

bool memidx_letter(char c) {
    unsigned L = (unsigned char) c;
    return mi_open && L < 128 && ng_atomic_load_explicit(&letter_on[L], NG_MO_ACQUIRE) &&
           !ng_atomic_load_explicit(&broken, NG_MO_ACQUIRE);
}

static void mark_broken(void) {
    if (!ng_atomic_exchange(&broken, true))
        fprintf(stderr, "memidx: out of memory updating the tag index; tag queries use the JSON scan until restart\n");
}

bool memidx_add_event(const char *tags_json, size_t len, uint64_t seq, uint32_t created_at, int kind) {
    if (!mi_open || seq >= ((uint64_t) 1 << 48)) return false;
    bool ok = true;
    if (tags_json && tags_json[0]) {
        if (!len) len = strlen(tags_json);
        if (len + 1 > vbuf_cap) {                            /* unescaped values never exceed the JSON */
            size_t c = ng_grow_cap(vbuf_cap, len + 1, 1024);
            char *nb = (char *) realloc(vbuf, c);
            if (!nb) return false;
            vbuf = nb; vbuf_cap = c;
        }
        post_t p = mkpost(created_at, seq, kind);
        jstr_t key, tag, tags = jl_str_n(tags_json, len);
        size_t off = 0, n = 0;
        bool overflow = false;
        while (ok && (off = jl_next(tags, off, &key, &tag)) != 0) {
            jstr_t k2, nm, v;
            size_t to = jl_next(tag, 0, &k2, &nm);
            if (!to || nm.len != 3 || nm.buf[0] != '"' || !memidx_letter(nm.buf[1])) continue;
            if (jl_next(tag, to, &k2, &v) == 0 || !v.buf || v.buf[0] != '"') continue;
            if (n >= per_event_cap) { overflow = true; break; }
            size_t vl;
            if (!jl_unescape(v, vbuf, &vl) || memchr(vbuf, '\0', vl)) continue;
            ok = add_posting((unsigned char) nm.buf[1], key8(vbuf, vl), &p);
            n++;
        }
        if (ok && overflow) ok = add_posting(OVF_LETTER, OVF_KEY, &p);
        if (!ok) mark_broken();
    }
    if (seq > ng_atomic_load_explicit(&max_seq_added, NG_MO_RELAXED))
        ng_atomic_store_explicit(&max_seq_added, seq, NG_MO_RELEASE);
    ng_atomic_fetch_add_explicit(&changes, 1, NG_MO_RELAXED);
    return ok;
}

/* ------------------------------------------------------------- reading --- */
typedef struct { post_t *p; size_t n, pos; } run_t;

/* Max-heap of runs by their head posting (newest first). */
static bool run_less(const run_t *a, const run_t *b) { return pcmp(&a->p[a->pos], &b->p[b->pos]) < 0; }
static void heap_down(run_t **h, size_t n, size_t i) {
    for (;;) {
        size_t l = 2 * i + 1, r = l + 1, m = i;
        if (l < n && run_less(h[m], h[l])) m = l;
        if (r < n && run_less(h[m], h[r])) m = r;
        if (m == i) return;
        run_t *t = h[i]; h[i] = h[m]; h[m] = t;
        i = m;
    }
}

ng_status_t memidx_candidates(char letter, char *const *values, size_t n, const int *kinds, size_t nk,
                              int64_t since, int64_t until, size_t skip, size_t max,
                              memidx_cand_t *out, size_t *got) {
    unsigned L = (unsigned char) letter;
    if (!memidx_letter(letter)) return NG_E_UNKNOWN;
    if (n > 256) return NG_E_TOOBIG;
    size_t want;
    if (!ng_size_add(skip, max, &want)) return NG_E_TOOBIG;
    ng_atomic_fetch_add_explicit(&letter_hits[L], 1, NG_MO_RELAXED);
    qf_t q = { kinds, nk, since, until };
    run_t runs[257];
    run_t *heap[257];
    size_t nr = 0;
    ng_status_t st = NG_OK;
    for (size_t i = 0; i <= n && st == NG_OK; i++) {        /* i == n: the overflow list */
        unsigned let = i < n ? L : OVF_LETTER;
        uint64_t key = i < n ? key8(values[i], strlen(values[i])) : OVF_KEY;
        uint64_t h = mix(key, let);
        shard_t *sh = shard_of(h);
        pthread_rwlock_rdlock(&sh->lock);
        if (!ng_atomic_load_explicit(&letter_on[L], NG_MO_ACQUIRE)) st = NG_E_UNKNOWN;   /* dropped meanwhile */
        const slot_t *s = st == NG_OK ? slot_find(sh, key, let, h) : NULL;
        if (s) {
            size_t cap = want < s->n ? want : s->n;
            post_t *buf = cap ? (post_t *) ng_malloc_array(cap, sizeof(post_t)) : NULL;
            if (cap && !buf) st = NG_E_NOMEM;
            else if (cap) {
                size_t k = slot_collect(s, &q, cap, buf);
                if (k) { runs[nr].p = buf; runs[nr].n = k; runs[nr].pos = 0; heap[nr] = &runs[nr]; nr++; }
                else free(buf);
            }
        }
        pthread_rwlock_unlock(&sh->lock);
    }
    size_t o = 0, passed = 0;
    if (st == NG_OK) {
        for (size_t i = nr / 2; i-- > 0;) heap_down(heap, nr, i);
        size_t hn = nr;
        bool have_last = false;
        uint64_t last = 0;
        while (hn && o < max) {
            run_t *r = heap[0];
            const post_t *p = &r->p[r->pos++];
            if (r->pos == r->n) heap[0] = heap[--hn];
            heap_down(heap, hn, 0);
            uint64_t sq = pseq(p);
            if (have_last && sq == last) continue;           /* same event via two values */
            have_last = true; last = sq;
            if (passed++ < skip) continue;
            out[o].seq = sq; out[o].ca = p->ca; out[o].kind = p->kind;
            o++;
        }
    }
    for (size_t i = 0; i < nr; i++) free(runs[i].p);
    if (st != NG_OK) return st;
    *got = o;
    return NG_OK;
}

size_t memidx_estimate(char letter, char *const *values, size_t n) {
    if (!memidx_letter(letter)) return 0;
    size_t total = 0;
    for (size_t i = 0; i <= n; i++) {
        unsigned let = i < n ? (unsigned char) letter : OVF_LETTER;
        uint64_t key = i < n ? key8(values[i], strlen(values[i])) : OVF_KEY;
        uint64_t h = mix(key, let);
        shard_t *sh = shard_of(h);
        pthread_rwlock_rdlock(&sh->lock);
        const slot_t *s = slot_find(sh, key, let, h);
        if (s) total += s->n;
        pthread_rwlock_unlock(&sh->lock);
    }
    return total;
}

bool memidx_key_stats(char letter, const char *value, size_t *postings, size_t *bytes) {
    if (!mi_open || !value) return false;
    uint64_t key = key8(value, strlen(value));
    uint64_t h = mix(key, (unsigned char) letter);
    shard_t *sh = shard_of(h);
    pthread_rwlock_rdlock(&sh->lock);
    const slot_t *s = slot_find(sh, key, (unsigned char) letter, h);
    if (s) { if (postings) *postings = s->n; if (bytes) *bytes = rep_bytes(s); }
    pthread_rwlock_unlock(&sh->lock);
    return s != NULL;
}

void memidx_stats(memidx_stats_t *o) {
    memset(o, 0, sizeof(*o));
    if (!mi_open) return;
    for (size_t i = 0; i < MEMIDX_SHARDS; i++) {
        shard_t *sh = &shards[i];
        pthread_rwlock_rdlock(&sh->lock);
        o->table_bytes += sh->cap * sizeof(slot_t);
        for (size_t k = 0; k < sh->cap; k++) {
            const slot_t *s = &sh->tab[k];
            if (!s->n) continue;
            o->keys++;
            o->postings += s->n;
            if (s->rep == REP_ONE) o->inline_postings++;
            else if (s->rep == REP_SMALL) { o->frozen_postings += s->n; o->frozen_bytes += rep_bytes(s); }
            else {
                const body_t *b = s->u.b;
                o->frozen_postings += b->nfz; o->tail_postings += b->tn;
                o->tail_bytes += (size_t) b->tcap * sizeof(post_t);
                o->frozen_bytes += body_size(b) - (size_t) b->tcap * sizeof(post_t);
            }
        }
        pthread_rwlock_unlock(&sh->lock);
    }
    o->tomb_bytes = ng_atomic_load_explicit(&tb_bytes, NG_MO_RELAXED);
    o->bytes = o->table_bytes + o->frozen_bytes + o->tail_bytes + o->tomb_bytes;
    o->degraded = ng_atomic_load_explicit(&n_degraded, NG_MO_RELAXED);
    o->max_seq = ng_atomic_load_explicit(&max_seq_added, NG_MO_ACQUIRE);
}

/* ------------------------------------------------------- maintenance --- */
static size_t sweep_shard, sweep_slot;
static unsigned long long sweep_base;    /* tombs_pending when this pass started */

/* Rewrite slot s without its dead postings. Write lock held; may remove it. */
static size_t sweep_one(shard_t *sh, size_t i) {
    slot_t *s = &sh->tab[i];
    size_t n = s->n;
    if (s->rep == REP_ONE) {
        if (dead(pseq(&s->u.one))) { posts_add(-1); slot_remove(sh, i); }
        return 1;
    }
    post_t *buf = ws_get(n);
    size_t got = 0, live = 0;
    if (!buf || !slot_all(s, buf, &got)) return n;
    for (size_t k = 0; k < got; k++) if (!dead(pseq(&buf[k]))) buf[live++] = buf[k];
    if (live == got) return n;
    if (live == 0) {
        mem_acct(s->letter, rep_bytes(s), 0);
        posts_add(-(long long) s->n);
        heap_free(s);
        s->n = 0;
        slot_remove(sh, i);
    } else if (!slot_set(s, buf, live)) {
        mark_broken();
    }
    return n;
}

void memidx_maintain(size_t budget) {
    if (!mi_open) return;
    unsigned long long pend = ng_atomic_load_explicit(&tombs_pending, NG_MO_RELAXED);
    if (pend == sweep_base && sweep_shard == 0 && sweep_slot == 0) return;   /* nothing deleted */
    while (budget) {
        shard_t *sh = &shards[sweep_shard];
        pthread_rwlock_wrlock(&sh->lock);
        size_t steps = 0;
        while (sweep_slot < sh->cap && budget && steps < 4096) {
            if (sh->tab[sweep_slot].n) {
                uint64_t k0 = sh->tab[sweep_slot].key;
                uint8_t l0 = sh->tab[sweep_slot].letter;
                size_t cost = sweep_one(sh, sweep_slot);
                budget = cost >= budget ? 0 : budget - cost;
                const slot_t *now = &sh->tab[sweep_slot];
                /* removed and another slot shifted in: examine that one next */
                if (!(now->n && (now->key != k0 || now->letter != l0))) sweep_slot++;
            } else {
                sweep_slot++;
            }
            steps++;
        }
        bool done = sweep_slot >= sh->cap;
        pthread_rwlock_unlock(&sh->lock);
        if (!done) { if (steps >= 4096) continue; break; }
        sweep_slot = 0;
        if (++sweep_shard == MEMIDX_SHARDS) {               /* a full pass: reclaimed what it saw */
            sweep_shard = 0;
            sweep_base = pend;
            return;
        }
    }
}

/* A letter's share of the index: its heap postings plus its table slots at the 75% load bound. */
static size_t letter_weight(int c) {
    return ng_atomic_load_explicit(&letter_bytes[c], NG_MO_RELAXED) +
           ng_atomic_load_explicit(&letter_keys[c], NG_MO_RELAXED) * (sizeof(slot_t) * 4 / 3);
}

void memidx_enforce_cap(void) {
    if (!mi_open || !mem_cap) return;
    while (ng_atomic_load_explicit(&n_bytes, NG_MO_RELAXED) > mem_cap) {
        int pick = -1;
        for (int c = 'A'; c <= 'z'; c++) {
            if (!ng_atomic_load_explicit(&letter_on[c], NG_MO_RELAXED) || !letter_weight(c)) continue;
            if (pick < 0) { pick = c; continue; }               /* skip letters that hold nothing */
            unsigned long long hc = ng_atomic_load_explicit(&letter_hits[c], NG_MO_RELAXED);
            unsigned long long hp = ng_atomic_load_explicit(&letter_hits[pick], NG_MO_RELAXED);
            if (hc < hp || (hc == hp && letter_weight(c) > letter_weight(pick))) pick = c;
        }
        if (pick < 0) return;
        size_t before = ng_atomic_load_explicit(&n_bytes, NG_MO_RELAXED);
        ng_atomic_store_explicit(&letter_on[pick], false, NG_MO_RELEASE);
        for (size_t i = 0; i < MEMIDX_SHARDS; i++) {
            shard_t *sh = &shards[i];
            pthread_rwlock_wrlock(&sh->lock);
            size_t keep = 0;
            for (size_t k = 0; k < sh->cap; k++) keep += sh->tab[k].n && sh->tab[k].letter != (unsigned) pick;
            size_t ncap = 64;
            while (ncap * 3 < (keep + 1) * 4) ncap *= 2;     /* the smallest table under 75% */
            if (sh->cap && !shard_rehash(sh, ncap, (unsigned) pick)) mark_broken();
            pthread_rwlock_unlock(&sh->lock);
        }
        ng_atomic_store_explicit(&letter_keys[pick], 0, NG_MO_RELAXED);
        size_t o = 0;
        for (const char *c = letters_str; *c; c++) if (*c != (char) pick) letters_str[o++] = *c;
        letters_str[o] = '\0';
        ng_atomic_fetch_add_explicit(&n_degraded, 1, NG_MO_RELAXED);
        ng_atomic_fetch_add_explicit(&changes, 1, NG_MO_RELAXED);
        fprintf(stderr, "memidx: warning: over tag_index_memory_mb (%zu MiB): dropped letter '%c' "
                        "(%llu queries, %.1f MiB -> %.1f MiB); its queries use the JSON scan. Indexed now: \"%s\"\n",
                mem_cap >> 20, pick, ng_atomic_load_explicit(&letter_hits[pick], NG_MO_RELAXED),
                (double) before / 1048576.0, (double) ng_atomic_load_explicit(&n_bytes, NG_MO_RELAXED) / 1048576.0,
                letters_str);
    }
}

/* ---------------------------------------------------------- lifecycle --- */
bool memidx_open(const memidx_config_t *cfg) {
    if (mi_open || !cfg || !cfg->letters || cfg->max_per_event < 1) return false;
    for (size_t i = 0; i < MEMIDX_SHARDS; i++) {
        pthread_rwlockattr_t at;
        pthread_rwlockattr_init(&at);
#ifdef __GLIBC__
        /* The one writer must not starve behind a stream of readers. */
        pthread_rwlockattr_setkind_np(&at, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif
        if (pthread_rwlock_init(&shards[i].lock, &at) != 0) {
            pthread_rwlockattr_destroy(&at);
            while (i-- > 0) pthread_rwlock_destroy(&shards[i].lock);
            return false;
        }
        pthread_rwlockattr_destroy(&at);
        shards[i].tab = NULL; shards[i].cap = shards[i].n = 0; shards[i].gen = 0;
    }
    size_t o = 0;
    for (int c = 0; c < 128; c++) {
        ng_atomic_init(&letter_on[c], false);
        ng_atomic_init(&letter_bytes[c], 0);
        ng_atomic_init(&letter_keys[c], 0);
        ng_atomic_init(&letter_hits[c], 0);
    }
    for (const char *c = cfg->letters; *c && o + 1 < sizeof(letters_str); c++) {
        unsigned L = (unsigned char) *c;
        if (!((L >= 'a' && L <= 'z') || (L >= 'A' && L <= 'Z')) || ng_atomic_load_explicit(&letter_on[L], NG_MO_RELAXED)) continue;
        ng_atomic_init(&letter_on[L], true);
        letters_str[o++] = (char) L;
    }
    letters_str[o] = '\0';
    per_event_cap = cfg->max_per_event;
    mem_cap = cfg->mem_cap;
    ng_atomic_init(&n_keys, 0); ng_atomic_init(&n_posts, 0); ng_atomic_init(&n_bytes, 0);
    ng_atomic_init(&max_seq_added, 0); ng_atomic_init(&changes, 0); ng_atomic_init(&n_degraded, 0);
    ng_atomic_init(&tombs_pending, 0); ng_atomic_init(&broken, false); ng_atomic_init(&tb_bytes, 0);
    sweep_shard = sweep_slot = 0; sweep_base = 0;
    mi_open = true;
    return true;
}

void memidx_close(void) {
    if (!mi_open) return;
    memidx_snapshot_stop();
    for (size_t i = 0; i < MEMIDX_SHARDS; i++) {
        shard_t *sh = &shards[i];
        for (size_t k = 0; k < sh->cap; k++) if (sh->tab[k].n) heap_free(&sh->tab[k]);
        free(sh->tab);
        sh->tab = NULL; sh->cap = sh->n = 0;
        pthread_rwlock_destroy(&sh->lock);
    }
    for (size_t c = 0; c < TB_TOP; c++) {
        void *w = ng_atomic_load_explicit(&tb_top[c], NG_MO_RELAXED);
        if (w) { free(w); ng_atomic_store_explicit(&tb_top[c], NULL, NG_MO_RELAXED); }
    }
    memidx_thread_done();
    mi_open = false;
}

/* ----------------------------------------------------------- snapshot --- */
/* File: header (host byte order; the endian mark rejects a foreign host),
 * then one record per key:
 *   letter u8, pad u8[3], n u32, key u64, nblk u32, dlen u32,
 *   nblk x { off u32, last_ca u32 }, dlen bytes of blocks
 * holding the key's live postings ascending (dead ones dropped). The
 * header checksum covers the header; payload_sum (FNV-1a 64) the records. */
#define SNAP_MAGIC "NGMIDX\x00\x01"
#define SNAP_VERSION 1
typedef struct {
    char magic[8];
    uint32_t version, hdr_size;
    uint64_t endian;
    uint64_t token, covered, keys, postings, payload_len, payload_sum;
    uint32_t max_per_event, block;
    char letters[64];
    uint64_t hdr_sum;
} snap_hdr_t;
typedef struct { uint8_t letter, pad[3]; uint32_t n; uint64_t key; uint32_t nblk, dlen; } snap_rec_t;
NG_STATIC_ASSERT(sizeof(snap_rec_t) == 24, snap_rec_is_24_bytes);

static uint64_t fnv(uint64_t h, const void *p, size_t n) {
    const uint8_t *b = (const uint8_t *) p;
    for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 0x100000001b3ull; }
    return h;
}
#define FNV0 0xcbf29ce484222325ull

typedef struct { uint8_t *p; size_t n, cap; bool oom; } sbuf_t;
static void sb_put(sbuf_t *b, const void *d, size_t n) {
    if (b->oom) return;
    if (b->n + n > b->cap) {
        size_t c = ng_grow_cap(b->cap, b->n + n, 1 << 16);
        uint8_t *np = (uint8_t *) realloc(b->p, c);
        if (!np) { b->oom = true; return; }
        b->p = np; b->cap = c;
    }
    memcpy(b->p + b->n, d, n);
    b->n += n;
}

/* Serialise one slot (read lock held). Returns live postings written. */
static size_t snap_slot(const slot_t *s, sbuf_t *out) {
    post_t *all = ws_get(s->n);
    size_t n = 0, live = 0;
    if (!all || !slot_all(s, all, &n)) { out->oom = true; return 0; }
    for (size_t k = 0; k < n; k++) if (!dead(pseq(&all[k]))) all[live++] = all[k];
    if (!live) return 0;
    snap_rec_t r;
    memset(&r, 0, sizeof(r));
    r.letter = s->letter; r.n = (uint32_t) live; r.key = s->key;
    r.nblk = (uint32_t) ((live + MEMIDX_BLOCK - 1) / MEMIDX_BLOCK);
    uint8_t enc[BLK_MAX_BYTES];
    size_t rec_at = out->n;
    sb_put(out, &r, sizeof(r));
    size_t dir_at = out->n;
    blkdir_t zero = { 0, 0 };
    for (uint32_t i = 0; i < r.nblk; i++) sb_put(out, &zero, sizeof(zero));
    uint32_t dlen = 0;
    for (uint32_t i = 0; i < r.nblk && !out->oom; i++) {
        size_t k = live - (size_t) i * MEMIDX_BLOCK < MEMIDX_BLOCK ? live - (size_t) i * MEMIDX_BLOCK : MEMIDX_BLOCK;
        size_t len = blk_encode(all + (size_t) i * MEMIDX_BLOCK, k, enc);
        blkdir_t d = { dlen, all[(size_t) i * MEMIDX_BLOCK + k - 1].ca };
        memcpy(out->p + dir_at + i * sizeof(blkdir_t), &d, sizeof(d));
        sb_put(out, enc, len);
        dlen += (uint32_t) len;
    }
    if (out->oom) return 0;
    r.dlen = dlen;
    memcpy(out->p + rec_at, &r, sizeof(r));
    return live;
}

static int fsync_dir_of(const char *path) {
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) { if (slash == dir) slash[1] = '\0'; else *slash = '\0'; } else snprintf(dir, sizeof(dir), ".");
    int fd = open(dir, O_RDONLY);
    if (fd < 0) return -1;
    int rc = fsync(fd);
    close(fd);
    return rc;
}

static bool write_all(int fd, const void *p, size_t n) {
    const uint8_t *b = (const uint8_t *) p;
    while (n) {
        ssize_t w = write(fd, b, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        b += w; n -= (size_t) w;
    }
    return true;
}

static pthread_mutex_t snap_mu = PTHREAD_MUTEX_INITIALIZER;   /* one snapshot at a time */

ng_status_t memidx_snapshot_write(const char *path, uint64_t token) {
    if (!mi_open || !path || !path[0]) return NG_E_INVALID;
    if (ng_atomic_load_explicit(&broken, NG_MO_ACQUIRE)) return NG_E_INVALID;
    char tmp[1100];
    int w = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (w < 0 || (size_t) w >= sizeof(tmp)) return NG_E_RANGE;
    pthread_mutex_lock(&snap_mu);
    /* Everything added up to `covered` is in the index now (add_event
     * publishes max_seq after its postings); later adds may or may not be
     * included, and the loader replays seq > covered either way. */
    uint64_t covered = ng_atomic_load_explicit(&max_seq_added, NG_MO_ACQUIRE);
    ng_status_t st = NG_OK;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { pthread_mutex_unlock(&snap_mu); return NG_E_IO; }
    snap_hdr_t h;
    memset(&h, 0, sizeof(h));
    if (!write_all(fd, &h, sizeof(h))) st = NG_E_IO;         /* placeholder */
    uint64_t sum = FNV0, keys = 0, posts = 0, plen = 0;
    sbuf_t b = { NULL, 0, 0, false };
    for (size_t i = 0; i < MEMIDX_SHARDS && st == NG_OK; i++) {
        shard_t *sh = &shards[i];
        b.n = 0;
        pthread_rwlock_rdlock(&sh->lock);
        for (size_t k = 0; k < sh->cap && !b.oom; k++) {
            if (!sh->tab[k].n) continue;
            size_t live = snap_slot(&sh->tab[k], &b);
            if (live) { keys++; posts += live; }
        }
        pthread_rwlock_unlock(&sh->lock);
        if (b.oom) { st = NG_E_NOMEM; break; }
        sum = fnv(sum, b.p, b.n);
        plen += b.n;
        if (!write_all(fd, b.p, b.n)) st = NG_E_IO;
    }
    free(b.p);
    if (st == NG_OK) {
        memcpy(h.magic, SNAP_MAGIC, 8);
        h.version = SNAP_VERSION; h.hdr_size = (uint32_t) sizeof(h);
        h.endian = 0x0102030405060708ull;
        h.token = token; h.covered = covered; h.keys = keys; h.postings = posts;
        h.payload_len = plen; h.payload_sum = sum;
        h.max_per_event = (uint32_t) per_event_cap; h.block = MEMIDX_BLOCK;
        snprintf(h.letters, sizeof(h.letters), "%s", letters_str);
        h.hdr_sum = fnv(FNV0, &h, offsetof(snap_hdr_t, hdr_sum));
        if (pwrite(fd, &h, sizeof(h), 0) != (ssize_t) sizeof(h) || fsync(fd) != 0) st = NG_E_IO;
    }
    if (close(fd) != 0 && st == NG_OK) st = NG_E_IO;
    if (st == NG_OK && (rename(tmp, path) != 0 || fsync_dir_of(path) != 0)) st = NG_E_IO;
    if (st != NG_OK) unlink(tmp);
    pthread_mutex_unlock(&snap_mu);
    return st;
}

/* Install one record's postings as a slot (init thread, no concurrency). */
static bool snap_install(const snap_rec_t *r, const blkdir_t *dir, const uint8_t *data) {
    uint64_t h = mix(r->key, r->letter);
    shard_t *sh = shard_of(h);
    if (slot_find(sh, r->key, r->letter, h)) return false;  /* duplicate key: corrupt */
    slot_t *s = slot_get(sh, r->key, r->letter, h);
    if (!s) return false;
    bool ok;
    if (r->n <= SMALL_MAX) {
        post_t p[SMALL_MAX];
        ok = r->nblk == 1 && blk_decode(data, data + r->dlen, r->n, p);
        for (uint32_t i = 1; ok && i < r->n; i++) ok = pcmp(&p[i - 1], &p[i]) < 0;
        if (ok && r->n == 1) { s->rep = REP_ONE; s->u.one = p[0]; s->n = 1; posts_add(1); }
        else if (ok) { s->rep = REP_ONE; s->n = 0; ok = slot_set(s, p, r->n); }
    } else {
        body_t *b = (body_t *) calloc(1, sizeof(body_t));
        ok = b != NULL;
        if (ok) {
            b->data = (uint8_t *) malloc(r->dlen ? r->dlen : 1);
            b->dir = (blkdir_t *) ng_malloc_array(r->nblk, sizeof(blkdir_t));
            ok = b->data && b->dir;
        }
        if (ok) {
            memcpy(b->data, data, r->dlen);
            memcpy(b->dir, dir, (size_t) r->nblk * sizeof(blkdir_t));
            b->dlen = b->dcap = r->dlen; b->nblk = b->blkcap = r->nblk; b->nfz = r->n;
            /* validate the directory and find fz_last */
            post_t blk[MEMIDX_BLOCK];
            for (uint32_t i = 0; ok && i < r->nblk; i++) {
                uint32_t end = i + 1 < r->nblk ? dir[i + 1].off : r->dlen;
                size_t k = i + 1 < r->nblk ? MEMIDX_BLOCK : r->n - (size_t) i * MEMIDX_BLOCK;
                ok = dir[i].off < end && end <= r->dlen && blk_decode(data + dir[i].off, data + end, k, blk) &&
                     blk[k - 1].ca == dir[i].last_ca;
                if (ok) b->fz_last = blk[k - 1];
            }
        }
        if (ok) { s->rep = REP_BODY; s->u.b = b; s->n = r->n; mem_acct(r->letter, 0, body_size(b)); posts_add(r->n); }
        else if (b) { free(b->data); free(b->dir); free(b); }
    }
    if (!ok) { memset(s, 0, sizeof(*s)); return false; }
    sh->n++;
    ng_atomic_fetch_add_explicit(&n_keys, 1, NG_MO_RELAXED);
    return true;
}

static void reset_all(void) {
    for (size_t i = 0; i < MEMIDX_SHARDS; i++) {
        shard_t *sh = &shards[i];
        for (size_t k = 0; k < sh->cap; k++) if (sh->tab[k].n) heap_free(&sh->tab[k]);
        free(sh->tab);
        sh->tab = NULL; sh->cap = sh->n = 0; sh->gen++;
    }
    ng_atomic_store(&n_keys, 0); ng_atomic_store(&n_posts, 0);
    ng_atomic_store(&n_bytes, ng_atomic_load(&tb_bytes));
    for (int c = 0; c < 128; c++) { ng_atomic_store(&letter_bytes[c], 0); ng_atomic_store(&letter_keys[c], 0); }
}

ng_status_t memidx_snapshot_load(const char *path, uint64_t token, uint64_t *covered) {
    if (!mi_open || !path || !covered) return NG_E_INVALID;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return errno == ENOENT ? NG_E_UNKNOWN : NG_E_IO;
    struct stat stt;
    if (fstat(fd, &stt) != 0 || (size_t) stt.st_size < sizeof(snap_hdr_t)) { close(fd); return NG_E_INVALID; }
    size_t size = (size_t) stt.st_size;
    void *map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return NG_E_IO;
    const uint8_t *base = (const uint8_t *) map;
    snap_hdr_t h;
    memcpy(&h, base, sizeof(h));
    ng_status_t st = NG_OK;
    if (memcmp(h.magic, SNAP_MAGIC, 8) != 0 || h.version != SNAP_VERSION || h.hdr_size != sizeof(h) ||
        h.endian != 0x0102030405060708ull || h.hdr_sum != fnv(FNV0, &h, offsetof(snap_hdr_t, hdr_sum)) ||
        h.token != token || h.block != MEMIDX_BLOCK || h.max_per_event != per_event_cap ||
        memchr(h.letters, '\0', sizeof(h.letters)) == NULL || strcmp(h.letters, letters_str) != 0 ||
        h.payload_len != size - sizeof(h) || fnv(FNV0, base + sizeof(h), h.payload_len) != h.payload_sum)
        st = NG_E_INVALID;
    const uint8_t *p = base + sizeof(h), *end = base + size;
    uint64_t keys = 0, posts = 0;
    while (st == NG_OK && p < end) {
        snap_rec_t r;
        if ((size_t) (end - p) < sizeof(r)) { st = NG_E_INVALID; break; }
        memcpy(&r, p, sizeof(r));
        p += sizeof(r);
        size_t dirb;
        if (!r.n || r.nblk != (r.n + MEMIDX_BLOCK - 1) / MEMIDX_BLOCK || !ng_size_mul(r.nblk, sizeof(blkdir_t), &dirb) ||
            (size_t) (end - p) < dirb || (size_t) (end - p) - dirb < r.dlen ||
            !(r.letter == OVF_LETTER || memidx_letter((char) r.letter))) { st = NG_E_INVALID; break; }
        blkdir_t *dir = (blkdir_t *) ng_malloc_array(r.nblk, sizeof(blkdir_t));
        if (!dir) { st = NG_E_NOMEM; break; }
        memcpy(dir, p, dirb);                                /* aligned copy */
        if (!snap_install(&r, dir, p + dirb)) st = NG_E_INVALID;
        free(dir);
        p += dirb + r.dlen;
        keys++; posts += r.n;
    }
    if (st == NG_OK && (keys != h.keys || posts != h.postings)) st = NG_E_INVALID;
    munmap(map, size);
    if (st != NG_OK) { reset_all(); return st; }
    if (h.covered > ng_atomic_load(&max_seq_added)) ng_atomic_store(&max_seq_added, h.covered);
    *covered = h.covered;
    return NG_OK;
}

/* ------------------------------------------------ background snapshots --- */
static pthread_t snap_th;
static bool snap_running;
static pthread_mutex_t snap_wait_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t snap_cv = PTHREAD_COND_INITIALIZER;
static bool snap_stop;
static char snap_path[1024];
static uint64_t snap_token;
static int snap_interval;

static void *snap_thread(void *arg) {
    (void) arg;
    sigset_t block;                 /* SIGINT is for the main thread (sigint_handler -> server_stop) */
    sigemptyset(&block); sigaddset(&block, SIGINT);
    pthread_sigmask(SIG_BLOCK, &block, NULL);
#ifdef __linux__
    pthread_setname_np(pthread_self(), "ng-tagsnap");
#endif
    unsigned long long done = ng_atomic_load_explicit(&changes, NG_MO_RELAXED);
    pthread_mutex_lock(&snap_wait_mu);
    while (!snap_stop) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += snap_interval;
        while (!snap_stop && pthread_cond_timedwait(&snap_cv, &snap_wait_mu, &ts) == 0) {}
        if (snap_stop) break;
        unsigned long long now = ng_atomic_load_explicit(&changes, NG_MO_RELAXED);
        if (now == done) continue;
        pthread_mutex_unlock(&snap_wait_mu);
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        ng_status_t st = memidx_snapshot_write(snap_path, snap_token);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (st == NG_OK) done = now;
        else fprintf(stderr, "memidx: snapshot %s failed: %s\n", snap_path, ng_status_str(st));
        if (getenv("NG_MEMIDX_VERBOSE"))
            fprintf(stderr, "memidx: snapshot written in %.2f s\n",
                    (double) (t1.tv_sec - t0.tv_sec) + (double) (t1.tv_nsec - t0.tv_nsec) / 1e9);
        memidx_thread_done();
        pthread_mutex_lock(&snap_wait_mu);
    }
    pthread_mutex_unlock(&snap_wait_mu);
    return NULL;
}

bool memidx_snapshot_start(const char *path, uint64_t token, int interval_s) {
    if (!mi_open || snap_running || !path || interval_s <= 0) return interval_s <= 0;
    snprintf(snap_path, sizeof(snap_path), "%s", path);
    snap_token = token;
    snap_interval = interval_s;
    snap_stop = false;
    snap_running = pthread_create(&snap_th, NULL, snap_thread, NULL) == 0;
    return snap_running;
}

void memidx_snapshot_stop(void) {
    if (!snap_running) return;
    pthread_mutex_lock(&snap_wait_mu);
    snap_stop = true;
    pthread_cond_broadcast(&snap_cv);
    pthread_mutex_unlock(&snap_wait_mu);
    pthread_join(snap_th, NULL);
    snap_running = false;
}
