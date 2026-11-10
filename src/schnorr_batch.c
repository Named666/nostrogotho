/* BIP-340 Schnorr batch verification (pure C, MIT like the library).
 *
 * This translation unit *is* the vendored libsecp256k1 build: it includes
 * thirdparty/secp256k1/src/secp256k1.c (the library's single-TU source) so
 * it can use the library-internal multi-scalar multiplication
 * (secp256k1_ecmult_multi_var: Strauss / Pippenger). No vendored file is
 * modified and no new dependency is added.
 *
 * For signatures (r_i, s_i) on 32-byte messages m_i by x-only keys P_i, with
 * e_i = H_BIP0340/challenge(r_i || P_i || m_i), R_i = lift_x(r_i), random
 * a_1 = 1, a_2..a_n, the batch is valid iff
 *     -(sum a_i s_i) G + sum a_i R_i + sum (a_i e_i) P_i = infinity.
 * One shared doubling chain for all 2n points instead of one per
 * signature. Randomizers are derived by hashing every input (BIP-340
 * "batch verification" recommendation), so an attacker cannot choose
 * signatures that cancel. A false result says only that at least one
 * signature (or encoding) is invalid; callers then verify individually.
 * Rejects exactly what secp256k1_schnorrsig_verify rejects: r >= p, s >= n,
 * keys/R not on the curve. Randomizers are 128-bit (a forged batch passes
 * with probability ~2^-128, the usual batch-verification choice; it halves
 * the a_i * R_i work). Lifted public keys are cached per scratch. */
/* Angle brackets: found through -isystem thirdparty/secp256k1, so the
 * vendored code is compiled as a system header (its warnings are not ours). */
#include <src/secp256k1.c>
#include "schnorr_batch.h"

typedef struct { const secp256k1_scalar *sc; const secp256k1_ge *pt; } ng_batch_cb_t;
static int ng_batch_cb(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    const ng_batch_cb_t *d = (const ng_batch_cb_t *) data;
    *sc = d->sc[idx]; *pt = d->pt[idx];
    return 1;
}

#define PK_CACHE 1024   /* lifted x-only keys (authors repeat), direct mapped */
struct ng_batch_scratch {
    secp256k1_scratch_space *scratch;
    struct { unsigned char x[32]; secp256k1_ge ge; int used; } pkc[PK_CACHE];
    size_t cap;                      /* signatures */
    secp256k1_scalar *sc;            /* 2 * cap */
    secp256k1_ge *pt;                /* 2 * cap */
};

ng_batch_scratch_t *ng_batch_scratch_create(const secp256k1_context *ctx, size_t max_sigs) {
    ng_batch_scratch_t *b = (ng_batch_scratch_t *) calloc(1, sizeof(*b));
    if (!b) return NULL;
    b->cap = max_sigs;
    b->sc = (secp256k1_scalar *) malloc(2 * max_sigs * sizeof(*b->sc));
    b->pt = (secp256k1_ge *) malloc(2 * max_sigs * sizeof(*b->pt));
    /* Enough for Pippenger over all 2n points in one pass. */
    size_t bytes = secp256k1_pippenger_scratch_size(2 * max_sigs, secp256k1_pippenger_bucket_window(2 * max_sigs))
                 + PIPPENGER_SCRATCH_OBJECTS * ALIGNMENT + secp256k1_strauss_scratch_size(2 * max_sigs) + 4096;
    b->scratch = secp256k1_scratch_space_create(ctx, bytes);
    if (!b->sc || !b->pt || !b->scratch) { ng_batch_scratch_destroy(ctx, b); return NULL; }
    return b;
}

void ng_batch_scratch_destroy(const secp256k1_context *ctx, ng_batch_scratch_t *b) {
    if (!b) return;
    if (b->scratch) secp256k1_scratch_space_destroy(ctx, b->scratch);
    free(b->sc); free(b->pt); free(b);
}

int ng_schnorrsig_verify_batch(const secp256k1_context *ctx, ng_batch_scratch_t *b,
                               const unsigned char *const *sig64, const unsigned char *const *msg32,
                               const unsigned char *const *pk32, size_t n) {
    if (!ctx || !b || n == 0 || n > b->cap) return 0;
    /* Seed: tagged hash over every (sig, key, msg); a_i = H(seed || i). */
    secp256k1_sha256 sha;
    unsigned char seed[32];
    static const unsigned char tag[] = "nostrogotho/schnorr-batch";
    secp256k1_sha256_initialize_tagged(&ctx->hash_ctx, &sha, tag, sizeof(tag) - 1);
    for (size_t i = 0; i < n; i++) {
        secp256k1_sha256_write(&ctx->hash_ctx, &sha, sig64[i], 64);
        secp256k1_sha256_write(&ctx->hash_ctx, &sha, pk32[i], 32);
        secp256k1_sha256_write(&ctx->hash_ctx, &sha, msg32[i], 32);
    }
    secp256k1_sha256_finalize(&ctx->hash_ctx, &sha, seed);

    secp256k1_scalar gsum = secp256k1_scalar_zero;
    for (size_t i = 0; i < n; i++) {
        secp256k1_fe rx, px;
        secp256k1_scalar s, e, a;
        int overflow;
        if (!secp256k1_fe_set_b32_limit(&rx, sig64[i])) return 0;
        secp256k1_scalar_set_b32(&s, sig64[i] + 32, &overflow);
        if (overflow) return 0;
        {   /* P_i = lift_x(pk), even y; cached per key (one square root saved) */
            unsigned slot = ((unsigned) pk32[i][0] | (unsigned) pk32[i][1] << 8 | (unsigned) pk32[i][2] << 16) % PK_CACHE;
            if (b->pkc[slot].used && memcmp(b->pkc[slot].x, pk32[i], 32) == 0) b->pt[2 * i + 1] = b->pkc[slot].ge;
            else {
                if (!secp256k1_fe_set_b32_limit(&px, pk32[i])) return 0;
                if (!secp256k1_ge_set_xo_var(&b->pt[2 * i + 1], &px, 0)) return 0;
                memcpy(b->pkc[slot].x, pk32[i], 32); b->pkc[slot].ge = b->pt[2 * i + 1]; b->pkc[slot].used = 1;
            }
        }
        if (!secp256k1_ge_set_xo_var(&b->pt[2 * i], &rx, 0)) return 0;       /* R_i, even y */
        secp256k1_schnorrsig_challenge(&ctx->hash_ctx, &e, sig64[i], msg32[i], 32, pk32[i]);
        if (i == 0) a = secp256k1_scalar_one;
        else {
            unsigned char buf[36], h[32];
            memcpy(buf, seed, 32);
            buf[32] = (unsigned char) (i >> 24); buf[33] = (unsigned char) (i >> 16);
            buf[34] = (unsigned char) (i >> 8); buf[35] = (unsigned char) i;
            secp256k1_sha256 hs; secp256k1_sha256_initialize(&hs);
            secp256k1_sha256_write(&ctx->hash_ctx, &hs, buf, sizeof(buf));
            secp256k1_sha256_finalize(&ctx->hash_ctx, &hs, h);
            memset(h, 0, 16);                     /* 128-bit randomizer (forgery bound 2^-128) */
            secp256k1_scalar_set_b32(&a, h, NULL);
            if (secp256k1_scalar_is_zero(&a)) a = secp256k1_scalar_one;
        }
        b->sc[2 * i] = a;                                    /* a_i * R_i */
        secp256k1_scalar_mul(&b->sc[2 * i + 1], &a, &e);     /* a_i e_i * P_i */
        secp256k1_scalar_mul(&s, &s, &a);
        secp256k1_scalar_add(&gsum, &gsum, &s);
    }
    secp256k1_scalar_negate(&gsum, &gsum);
    ng_batch_cb_t d = { b->sc, b->pt };
    secp256k1_gej r;
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, b->scratch, &r, &gsum, ng_batch_cb, &d, 2 * n)) return 0;
    return secp256k1_gej_is_infinity(&r);
}
