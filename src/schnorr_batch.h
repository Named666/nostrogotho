#ifndef SCHNORR_BATCH_H_
#define SCHNORR_BATCH_H_
/* BIP-340 batch verification over the vendored libsecp256k1 (see
 * schnorr_batch.c). Not thread-safe per scratch: one scratch per thread. */
#include <stddef.h>
#include <secp256k1.h>

typedef struct ng_batch_scratch ng_batch_scratch_t;
ng_batch_scratch_t *ng_batch_scratch_create(const secp256k1_context *ctx, size_t max_sigs);
void ng_batch_scratch_destroy(const secp256k1_context *ctx, ng_batch_scratch_t *b);
/* 1: all n signatures valid. 0: at least one invalid (or bad input). */
int ng_schnorrsig_verify_batch(const secp256k1_context *ctx, ng_batch_scratch_t *b,
                               const unsigned char *const *sig64, const unsigned char *const *msg32,
                               const unsigned char *const *pk32, size_t n);
#endif
