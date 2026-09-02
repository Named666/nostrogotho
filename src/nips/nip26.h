#ifndef NIP26_H_
#define NIP26_H_

#include <stdbool.h>
#include "cagliostr.h"

/* ============================================================================
 * NIP-26: Delegated Event Signing
 * 
 * Allows a key to delegate signing authority to another key with optional
 * restrictions on the kinds of events or time ranges that can be signed.
 * ============================================================================ */

/* check_delegation - Verify a delegation tag (NIP-26)
 * 
 * Validates a delegation tag that allows one key to act on behalf of another.
 * Checks both delegation conditions (time, kind restrictions) and the 
 * delegation signature itself.
 * 
 * Args:
 *   ev                  - event being signed (must not be NULL)
 *   delegator_pubkey    - original key's pubkey (64-char hex, must not be NULL)
 *   conditions          - restriction string (may be NULL or empty for none)
 *   delegation_sig      - signature authorizing delegation (64-char hex, must not be NULL)
 * 
 * Returns: true if delegation is valid and event conditions match, false otherwise
 * 
 * Conditions Format (NIP-26):
 *   - Empty string or NULL           -> no restrictions
 *   - "kind=1"                       -> event kind must be 1
 *   - "kind=0&kind=1"                -> event kind must be 0 or 1 (multiple values OR'd)
 *   - "created_at<1000000"           -> event created_at must be less than timestamp
 *   - "created_at>1000000"           -> event created_at must be greater than timestamp
 *   - Multiple conditions are AND'd together (all must pass)
 *   - Multiple values for same key are OR'd together (any can pass)
 * 
 * Process:
 *   1. Parses and validates delegation conditions against the event
 *   2. Builds delegation message: "nostr:delegation:" + pubkey + ":" + conditions
 *   3. Computes SHA256 of message
 *   4. Verifies the delegation_sig signature with delegator's pubkey
 * 
 * Requirements:
 *   - crypto_init() must have been called before this function
 *   - ev->pubkey and ev->created_at must be initialized
 * 
 * Example:
 *   // Event signed by key B on behalf of key A
 *   // A's delegation tag: ["delegation", "A_pubkey", "kind=1&created_at<9999999", "signature"]
 *   if (nip26_check_delegation(ev, A_pubkey, "kind=1&created_at<9999999", signature)) {
 *       // Delegation is valid and conditions met
 *   }
 */
bool nip26_check_delegation(const event_t *ev, const char *delegator_pubkey,
                            const char *conditions, const char *delegation_sig);

#endif /* NIP26_H_ */
