#ifndef NIP40_H_
#define NIP40_H_

#include <stdbool.h>
#include "cagliostr.h"

/* ============================================================================
 * NIP-40: Expiration Timestamp
 * 
 * Allows events to be marked with an expiration timestamp after which
 * the relay may or must discard them.
 * ============================================================================ */

/* nip40_is_expired - Check if an event has expired
 * 
 * Searches an event's tags for an ["expiration", "<timestamp>"] tag and
 * checks if the current time has passed that timestamp.
 * 
 * According to NIP-40, expiration is an optional tag containing an absolute
 * Unix timestamp in seconds. Events with an expiration tag that are older
 * than the current time should be treated as expired.
 * 
 * Args: 
 *   tags - parsed tags array (NULL-safe, will return false if NULL)
 * 
 * Returns: 
 *   true if event has an expiration tag and current time > expiration
 *   false if no expiration tag or current time <= expiration
 * 
 * Implementation:
 *   - Iterates through tags looking for name "expiration"
 *   - Parses timestamp value as decimal integer
 *   - Compares against current time from time(NULL)
 * 
 * Note: This function is typically called by storage layer before 
 * returning events from queries (NIP-67 storage queries skip expired events)
 */
bool nip40_is_expired(const tags_array_t *tags);

#endif /* NIP40_H_ */
