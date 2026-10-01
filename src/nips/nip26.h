#ifndef NIP26_H_
#define NIP26_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "nostrogotho.h"
#include "storage.h"

/* ============================================================================
 * NIP-26: Delegated Event Signing — Public API
 * 
 * This header exposes only the NIP-26 helper functions needed by the relay
 * core (crypto.c signature verification, nhr_module.c storage adapter).
 * The NIP-26 capability registration and internal logic remain in nip26.c.
 * ============================================================================ */

/* Verify a delegation tag (conditions + signature). */
bool nip26_check_delegation(const event_t *ev, const char *delegator_pubkey,
                            const char *conditions, const char *delegation_sig);

/* Generic tag-index pairs making delegated authors discoverable.
 * Caller owns the returned array and strings; free with nip26_free_index_tags. */
bool nip26_extract_index_tags(const event_t *event,
                              storage_tag_match_t **matches, size_t *count);
void nip26_free_index_tags(storage_tag_match_t *matches, size_t count);

/* Build tag-index match arrays from a query filter for indexed lookups. */
bool nip26_query_index_tags(const filter_t *filters, size_t filters_count,
                            storage_tag_match_t **matches, size_t *count);

/* Set crypto services for delegation verification.
 * Called by host at startup to inject SHA256 + signature verify functions. */
void nip26_set_crypto_services(
    void (*hash_fn)(const uint8_t *, size_t, uint8_t[32]),
    bool (*verify_fn)(const char *, const char *, const uint8_t[32]));

#endif /* NIP26_H_ */