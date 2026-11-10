#include "dedupe.h"
#include "platform/ng_alloc.h"
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define STRIPES 64
typedef struct { uint8_t id[32]; uint8_t state; } slot_t;
typedef struct {
    pthread_mutex_t mu;
    slot_t *slots; size_t mask, used;
    uint8_t (*ring)[32]; size_t ring_cap, ring_head, ring_len;   /* known ids, FIFO */
    char pad[64];
} stripe_t;

static stripe_t stripes[STRIPES];
static bool enabled;

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static bool parse_id(const char *h, uint8_t out[32]) {
    if (!h) return false;
    for (int i = 0; i < 32; i++) {
        int a = hexv(h[2 * i]), b = a < 0 ? -1 : hexv(h[2 * i + 1]);
        if (a < 0 || b < 0) return false;
        out[i] = (uint8_t) (a << 4 | b);
    }
    return h[64] == '\0';
}
static uint64_t h64(const uint8_t id[32]) { uint64_t x; memcpy(&x, id, 8); return x; }   /* ids are sha256 */

static size_t find(stripe_t *s, const uint8_t id[32]) {           /* slot index of id or of the empty slot */
    size_t i = (h64(id) >> 6) & s->mask;
    while (s->slots[i].state && memcmp(s->slots[i].id, id, 32) != 0) i = (i + 1) & s->mask;
    return i;
}
static void erase(stripe_t *s, size_t i) {                        /* backward-shift deletion */
    s->slots[i].state = 0; s->used--;
    for (size_t j = (i + 1) & s->mask; s->slots[j].state; j = (j + 1) & s->mask) {
        size_t home = (h64(s->slots[j].id) >> 6) & s->mask;
        if (((j - home) & s->mask) >= ((j - i) & s->mask)) {
            s->slots[i] = s->slots[j]; s->slots[j].state = 0; i = j;
        }
    }
}

void dedupe_init(size_t cap) {
    enabled = cap > 0;
    if (!enabled) return;
    size_t per = cap / STRIPES + 1, n = 1;
    while (n < per * 2 + 1024) n <<= 1;                           /* load <= ~50% + in-flight headroom */
    for (int k = 0; k < STRIPES; k++) {
        stripe_t *s = &stripes[k];
        pthread_mutex_init(&s->mu, NULL);
        s->slots = calloc(n, sizeof(slot_t)); s->mask = n - 1; s->used = 0;
        s->ring = ng_malloc_array(per, 32); s->ring_cap = per; s->ring_head = s->ring_len = 0;
        if (!s->slots || !s->ring) { dedupe_free(); enabled = false; return; }   /* all or nothing */
    }
}

static stripe_t *stripe_of(const uint8_t id[32]) { return &stripes[id[31] & (STRIPES - 1)]; }

int dedupe_lookup(const char *hex) {
    uint8_t id[32];
    if (!enabled || !parse_id(hex, id)) return DEDUPE_ABSENT;
    stripe_t *s = stripe_of(id);
    pthread_mutex_lock(&s->mu);
    int st = s->slots[find(s, id)].state;
    pthread_mutex_unlock(&s->mu);
    return st;
}

bool dedupe_claim(const char *hex) {
    uint8_t id[32];
    if (!enabled || !parse_id(hex, id)) return true;              /* no set: DB guards still apply */
    stripe_t *s = stripe_of(id);
    bool ok = false;
    pthread_mutex_lock(&s->mu);
    size_t i = find(s, id);
    if (!s->slots[i].state) {
        if (s->used + 1 < s->mask - s->mask / 8) {                 /* keep probing bounded */
            memcpy(s->slots[i].id, id, 32); s->slots[i].state = DEDUPE_INFLIGHT; s->used++;
        }
        ok = true;   /* full table: let it through; batch + UNIQUE guards still apply */
    }
    pthread_mutex_unlock(&s->mu);
    return ok;
}

void dedupe_resolve(const char *hex) {
    uint8_t id[32];
    if (!enabled || !parse_id(hex, id)) return;
    stripe_t *s = stripe_of(id);
    pthread_mutex_lock(&s->mu);
    size_t i = find(s, id);
    if (s->slots[i].state != DEDUPE_KNOWN) {
        if (!s->slots[i].state) {
            if (s->used + 1 >= s->mask - s->mask / 8) { pthread_mutex_unlock(&s->mu); return; }
            memcpy(s->slots[i].id, id, 32); s->used++;
        }
        s->slots[i].state = DEDUPE_KNOWN;
        if (s->ring_len == s->ring_cap) {                          /* evict the oldest known id */
            size_t old = find(s, s->ring[s->ring_head]);
            if (s->slots[old].state == DEDUPE_KNOWN) erase(s, old);
            s->ring_head = (s->ring_head + 1) % s->ring_cap; s->ring_len--;
            i = find(s, id);                                       /* erase may have shifted us */
        }
        memcpy(s->ring[(s->ring_head + s->ring_len) % s->ring_cap], id, 32);
        s->ring_len++;
    }
    pthread_mutex_unlock(&s->mu);
}

void dedupe_release(const char *hex) {
    uint8_t id[32];
    if (!enabled || !parse_id(hex, id)) return;
    stripe_t *s = stripe_of(id);
    pthread_mutex_lock(&s->mu);
    size_t i = find(s, id);
    if (s->slots[i].state == DEDUPE_INFLIGHT) erase(s, i);
    pthread_mutex_unlock(&s->mu);
}

void dedupe_forget(const char *hex) {
    uint8_t id[32];
    if (!enabled || !parse_id(hex, id)) return;
    stripe_t *s = stripe_of(id);
    pthread_mutex_lock(&s->mu);
    size_t i = find(s, id);
    if (s->slots[i].state == DEDUPE_KNOWN) erase(s, i);   /* its ring entry ages out harmlessly */
    pthread_mutex_unlock(&s->mu);
}

void dedupe_free(void) {
    if (!enabled) return;
    for (int k = 0; k < STRIPES; k++) { free(stripes[k].slots); free(stripes[k].ring); pthread_mutex_destroy(&stripes[k].mu); }
    enabled = false;
}
