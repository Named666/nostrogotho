#ifndef NIP45_H_
#define NIP45_H_

#include <stdbool.h>
#include "nostrogotho.h"

/* ============================================================================
 * NIP-45: COUNT Request / Response
 * 
 * Allows clients to query the relay for the count of events matching
 * specific filters without retrieving the full events.
 * ============================================================================ */

/* nip45_build_count_response - Build a COUNT response message
 * 
 * Constructs a JSON-formatted COUNT response message for a relay to send.
 * The response includes the subscription ID, count, and optional filters
 * matched.
 * 
 * Format: ["COUNT", <subscription_id>, {"count": <integer>}]
 * 
 * Args:
 *   sub_id - subscription ID from the client's COUNT request (must not be NULL)
 *   count  - number of events matching the filter
 * 
 * Returns: malloc'd JSON string, or NULL if memory allocation fails
 * 
 * Caller responsibility: Must free result with free()
 * 
 * Example:
 *   char *response = nip45_build_count_response("my-count-1", 42);
 *   // response: ["COUNT","my-count-1",{"count":42}]
 *   free(response);
 * 
 * Note: This module is typically used in conjunction with storage layer
 * COUNT queries which provide the count value.
 */
char *nip45_build_count_response(const char *sub_id, unsigned long count);

#endif /* NIP45_H_ */
