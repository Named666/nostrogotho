#ifndef NIP67_H_
#define NIP67_H_

#include <stdbool.h>

/* ============================================================================
 * NIP-67: Efficiently Returning All Events Stored at a Relay
 * 
 * Provides metadata about query completeness, allowing clients to know
 * when a relay has returned all matching events or if there are more
 * available (typically due to result set limits).
 * ============================================================================ */

/* nip67_build_eose_response - Build an EOSE response with completeness hint
 * 
 * Constructs a JSON-formatted EOSE (End Of Stored Events) response message.
 * This message signals that the relay has finished sending all events
 * matching a subscription and may optionally indicate if more events exist
 * beyond the relay's query limit.
 * 
 * Format: ["EOSE", <subscription_id>, [<hint>]]
 * 
 * Where hint can be:
 *   - "finish"  -> no more events available (all matched events sent)
 *   - "more"    -> more events exist but weren't sent (hit result limit)
 * 
 * Args:
 *   sub_id   - subscription ID from client's REQ (must not be NULL)
 *   has_more - true if more events exist, false if all sent
 * 
 * Returns: malloc'd JSON string, or NULL if memory allocation fails
 * 
 * Caller responsibility: Must free result with free()
 * 
 * Example:
 *   char *eose = nip67_build_eose_response("my-sub", false);
 *   // eose: ["EOSE","my-sub",["finish"]]
 *   free(eose);
 *   
 *   char *eose2 = nip67_build_eose_response("big-query", true);
 *   // eose2: ["EOSE","big-query",["more"]]
 *   free(eose2);
 * 
 * Relay behavior:
 *   - When querying stored events, relay fetches limit+1 events
 *   - If limit+1 events found, has_more=true (hit limit)
 *   - If <= limit events found, has_more=false (exhausted results)
 *   - Relay sends EOSE with appropriate hint after final event
 * 
 * Client interpretation:
 *   - "finish" means relay sent all matching events (query complete)
 *   - "more"   means relay hit its limit and may have more (client should
 *              create a narrower filter or use pagination if supported)
 */
char *nip67_build_eose_response(const char *sub_id, bool has_more);

/* nip67_build_eose_response_ex - Build an EOSE response with an "auth" hint.
 *
 * NIP-67 defines a third hint value "auth": the relay may have more stored
 * events matching the subscription's filters if the user performs AUTH
 * (NIP-42). Relays MUST ensure an AUTH message (containing a challenge) is
 * sent before the EOSE containing an "auth" hint — the caller is responsible
 * for that ordering.
 *
 * Args:
 *   sub_id    - subscription ID from client's REQ (must not be NULL)
 *   has_more  - true if more events exist beyond the relay's limit
 *   auth_hint - true to include the "auth" hint in the hint array
 *
 * Returns: malloc'd JSON string, or NULL if memory allocation fails
 */
char *nip67_build_eose_response_ex(const char *sub_id, bool has_more,
                                   bool auth_hint);

#endif /* NIP67_H_ */
