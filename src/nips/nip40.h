#ifndef NIP40_H_
#define NIP40_H_

#include <stdbool.h>
#include "nostrogotho.h"

/* ============================================================================
 * NIP-40: Expiration Timestamp
 * 
 * Allows events to be marked with an expiration timestamp after which
 * the relay may or must discard them.
 * ============================================================================ */

/* nip40_event_is_expired - Check whether an event's expiration tag has passed.
 *
 * Scans the event's raw tags JSON for an ["expiration", "<timestamp>"] tag
 * and compares the parsed unix timestamp against the current time.
 *
 * Per NIP-40 relay behaviour:
 *   - drop already-expired events on publication (accept path),
 *   - refrain from serving expired events, even if stored (query path).
 *
 * Args:
 *   event - event to check (NULL-safe, returns false if NULL)
 *
 * Returns:
 *   true if the event has an expiration tag whose timestamp has passed
 */
bool nip40_event_is_expired(const event_t *event);

/* nip40_is_expired - Parsed-tags variant used by the storage layer.
 *
 * Searches a parsed tags array for an ["expiration", "<timestamp>"] tag and
 * checks if the current time has passed that timestamp.
 *
 * Args:
 *   tags - parsed tags array (NULL-safe, returns false if NULL)
 *
 * Returns:
 *   true if a tag named "expiration" carries a timestamp <= now
 */
bool nip40_is_expired(const tags_array_t *tags);

/* nip40_garbage_collect - Background sweep of NIP-40 expired events.
 *
 * Runs inside the single-threaded event loop and asks the storage layer (arg)
 * to delete every stored event whose expiration timestamp has passed.
 *
 * This is invoked automatically by the plugin registry's generic `timer` hook
 * (see nip_plugin.h): the relay schedules a timer for any plugin that provides
 * one and calls it periodically. No server-side wiring references NIP-40.
 *
 * Args:
 *   arg - pointer to an initialized storage_context_t. NULL-safe; a context
 *         without purge_expired() is a no-op.
 */
void nip40_garbage_collect(void *arg);

#endif /* NIP40_H_ */
