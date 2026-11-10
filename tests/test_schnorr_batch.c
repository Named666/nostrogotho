/* Batch Schnorr verification (src/schnorr_batch.c, crypto_batch_verify):
 * agreement with individual BIP-340 verification on valid, corrupted and
 * malformed inputs, the thread-local pre-verified cache, and a timing
 * comparison. Exit status 0 = all checks passed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include "crypto.h"
#include "schnorr_batch.h"

#define N 256
static unsigned char sig[N][64], msg[N][32], pk[N][32];
static const unsigned char *ps[N], *pm[N], *pp[N];
static int fails, checks;
#define CHECK(c, ...) do { checks++; if (!(c)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

static void make(secp256k1_context *ctx, int i, unsigned seed) {
    unsigned char sk[32], aux[32];
    for (;;) {
        for (int k = 0; k < 32; k++) { sk[k] = (unsigned char) (seed * 2654435761u >> (k % 24)) ^ (unsigned char) (k * 131 + i); msg[i][k] = (unsigned char) (seed + k * 7 + i * 13); aux[k] = (unsigned char) (k ^ i); }
        secp256k1_keypair kp; secp256k1_xonly_pubkey x;
        if (secp256k1_keypair_create(ctx, &kp, sk) && secp256k1_keypair_xonly_pub(ctx, &x, NULL, &kp) &&
            secp256k1_xonly_pubkey_serialize(ctx, pk[i], &x) && secp256k1_schnorrsig_sign32(ctx, sig[i], msg[i], &kp, aux)) break;
        seed++;
    }
    ps[i] = sig[i]; pm[i] = msg[i]; pp[i] = pk[i];
}

static int single(secp256k1_context *ctx, int i) {
    secp256k1_xonly_pubkey x;
    return secp256k1_xonly_pubkey_parse(ctx, &x, pk[i]) && secp256k1_schnorrsig_verify(ctx, sig[i], msg[i], 32, &x);
}

static bool via_api(int i) {   /* crypto.c signature_verify (hex), consults the cache */
    char *s = bytes_to_hex(sig[i], 64), *p = bytes_to_hex(pk[i], 32);
    bool ok = signature_verify(s, p, msg[i]);
    free(s); free(p);
    return ok;
}

static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }

int main(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!crypto_init()) { printf("FAIL: crypto_init\n"); return 1; }
    for (int i = 0; i < N; i++) make(ctx, i, 1000u + (unsigned) i);
    ng_batch_scratch_t *b = ng_batch_scratch_create(ctx, 64);
    CHECK(b != NULL, "scratch");

    int sizes[] = { 1, 2, 3, 5, 16, 31, 44, 45, 63, 64 };   /* Strauss and Pippenger (>= 88 points) */
    for (size_t k = 0; k < sizeof(sizes) / sizeof(*sizes); k++)
        CHECK(ng_schnorrsig_verify_batch(ctx, b, ps, pm, pp, (size_t) sizes[k]) == 1, "valid batch of %d rejected", sizes[k]);
    CHECK(ng_schnorrsig_verify_batch(ctx, b, ps, pm, pp, 65) == 0, "n above scratch capacity must fail closed");

    /* Corruptions: every class must make the batch fail, at any position. */
    for (int pos = 0; pos < 64; pos += 9) {
        unsigned char save[64]; memcpy(save, sig[pos], 64);
        sig[pos][63] ^= 1;                                            /* s changed */
        CHECK(!ng_schnorrsig_verify_batch(ctx, b, ps, pm, pp, 64), "bad s at %d accepted", pos);
        memcpy(sig[pos], save, 64); sig[pos][5] ^= 0x10;              /* r changed */
        CHECK(!ng_schnorrsig_verify_batch(ctx, b, ps, pm, pp, 64), "bad r at %d accepted", pos);
        memcpy(sig[pos], save, 64); msg[pos][0] ^= 1;                 /* message changed */
        CHECK(!ng_schnorrsig_verify_batch(ctx, b, ps, pm, pp, 64), "bad msg at %d accepted", pos);
        msg[pos][0] ^= 1;
        memset(sig[pos] + 32, 0xff, 32);                              /* s >= n */
        CHECK(!ng_schnorrsig_verify_batch(ctx, b, ps, pm, pp, 64), "s>=n at %d accepted", pos);
        memset(sig[pos], 0xff, 32);                                   /* r >= p */
        CHECK(!ng_schnorrsig_verify_batch(ctx, b, ps, pm, pp, 64), "r>=p at %d accepted", pos);
        memcpy(sig[pos], save, 64);
        unsigned char savepk[32]; memcpy(savepk, pk[pos], 32); pk[pos][31] ^= 1;   /* other key */
        CHECK(single(ctx, pos) || !ng_schnorrsig_verify_batch(ctx, b, ps, pm, pp, 64), "bad key at %d accepted", pos);
        memcpy(pk[pos], savepk, 32);
    }
    /* Two invalid signatures crafted to cancel without randomizers:
     * swap s between two signatures with identical R... not constructible
     * here; instead swap whole signatures between messages. */
    { unsigned char t[64]; memcpy(t, sig[3], 64); memcpy(sig[3], sig[4], 64); memcpy(sig[4], t, 64);
      CHECK(!ng_schnorrsig_verify_batch(ctx, b, ps, pm, pp, 64), "swapped signatures accepted");
      memcpy(t, sig[3], 64); memcpy(sig[3], sig[4], 64); memcpy(sig[4], t, 64); }

    /* Randomized agreement with the individual verifier. */
    srand(7);
    for (int round = 0; round < 300; round++) {
        int n = 2 + rand() % 63, bad = rand() % 3;
        int idx[64]; unsigned char save[64][64];
        for (int i = 0; i < n; i++) idx[i] = rand() % N;
        for (int i = 0; i < n; i++) { ps[i] = sig[idx[i]]; pm[i] = msg[idx[i]]; pp[i] = pk[idx[i]]; }
        int expect = 1;
        for (int k = 0; k < bad; k++) { int j = idx[rand() % n]; memcpy(save[k], sig[j], 64); sig[j][32 + rand() % 32] ^= (unsigned char) (1 + rand() % 255); idx[60 + (k & 3)] = j; }
        for (int i = 0; i < n; i++) if (!single(ctx, idx[i])) expect = 0;
        CHECK(ng_schnorrsig_verify_batch(ctx, b, ps, pm, pp, (size_t) n) == expect, "round %d: batch != individual", round);
        for (int k = bad - 1; k >= 0; k--) memcpy(sig[idx[60 + (k & 3)]], save[k], 64);
    }
    for (int i = 0; i < N; i++) { ps[i] = sig[i]; pm[i] = msg[i]; pp[i] = pk[i]; }

    /* crypto_batch_verify + cache: one bad signature in 200; everything else
     * except its small bisection group is proven, the bad one never is. */
    sig[77][40] ^= 4;
    size_t proven = crypto_batch_verify(ps, pm, pp, 200);
    CHECK(proven >= 200 - 4 && proven < 200, "crypto_batch_verify proved %zu of 200 (1 bad)", proven);
    CHECK(!crypto_preverified(sig[77], pk[77], msg[77]), "bad signature cached");
    CHECK(!via_api(77), "bad signature accepted by signature_verify");
    int cached = 0; for (int i = 0; i < 200; i++) if (i != 77) cached += crypto_preverified(sig[i], pk[i], msg[i]);
    CHECK((size_t) cached == proven, "cache has %d, proven %zu", cached, proven);
    for (int i = 0; i < 200; i++) if (i != 77) CHECK(via_api(i), "valid %d rejected", i);
    unsigned char m2[32]; memcpy(m2, msg[5], 32); m2[0] ^= 1;
    CHECK(!crypto_preverified(sig[5], pk[5], m2), "cache hit for a different message");
    crypto_preverified_clear();
    CHECK(!crypto_preverified(sig[5], pk[5], msg[5]), "cache survived clear");
    sig[77][40] ^= 4;
    CHECK(via_api(77), "restored signature rejected");

    /* Timing: 64-signature batches vs individual verification. */
    int reps = 40; double t0 = now(); int ok = 0;
    for (int r = 0; r < reps; r++) for (int i = 0; i < 64; i++) ok += single(ctx, i);
    double t1 = now();
    for (int r = 0; r < reps; r++) ok += ng_schnorrsig_verify_batch(ctx, b, ps, pm, pp, 64) * 64;
    double t2 = now();
    for (int r = 0; r < reps; r++) ok += ng_schnorrsig_verify_batch(ctx, b, ps, pm, pp, 16) * 16;
    double t3 = now();
    CHECK(ok == reps * (64 + 64 + 16), "timing loop results");
    printf("INFO: individual %.0f sig/s, batch64 %.0f sig/s (%.2fx), batch16 %.0f sig/s (%.2fx)\n",
           reps * 64 / (t1 - t0), reps * 64 / (t2 - t1), (t1 - t0) / (t2 - t1),
           reps * 16 / (t3 - t2), (t1 - t0) / 4 / (t3 - t2));

    ng_batch_scratch_destroy(ctx, b); crypto_thread_cleanup(); crypto_deinit(); secp256k1_context_destroy(ctx);
    printf("%s: %d/%d schnorr batch checks\n", fails ? "FAIL" : "PASS", checks - fails, checks);
    return fails ? 1 : 0;
}
