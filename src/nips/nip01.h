#ifndef NIP01_H_
#define NIP01_H_

#include <stdbool.h>
#include <time.h>
#include <mongoose.h>
#include "cagliostr.h"

/* ============================================================================
 * NIP-01: Basic Protocol Flow, Events and Signatures
 * 
 * Core Nostr protocol: Event creation, validation, and basic message types
 * (EVENT, REQ, CLOSE, AUTH, OK, EOSE, NOTICE).
 * 
 * This module provides:
 * - Event validation and cryptographic verification
 * - Event kind processing dispatch system
 * - Plugin-style handlers for different event kinds
 * ============================================================================ */

typedef struct storage_context storage_context_t;

/* ============================================================================
 * Event Validation
 * ============================================================================ */

/* nip01_validate_event - Comprehensive event validation (NIP-01)
 * 
 * Performs full validation of a Nostr event for protocol compliance:
 * 1. Verifies event ID is the correct SHA256 hash
 * 2. Verifies Schnorr signature with public key
 * 3. Validates any delegation tags present (NIP-26)
 * 
 * This is the primary validation function used when accepting events
 * from clients via EVENT messages.
 * 
 * Args: ev - event to validate (must not be NULL)
 * 
 * Returns: 
 *   true if event passes all validation checks
 *   false if any check fails (id, signature, delegation, etc.)
 * 
 * Requirements:
 *   - crypto_init() must have been called
 *   - event fields must be properly initialized
 * 
 * Limitations (checked elsewhere):
 *   - Timestamp validity (NIP-22 with time windows)
 *   - Proof-of-work difficulty (NIP-13)
 *   - Event size limits (application-specific)
 * 
 * Related:
 *   - check_event() in crypto.c (lower-level implementation)
 *   - crypto_init() must be called first
 */
bool nip01_validate_event(const event_t *ev);

/* nip01_can_accept_event - Check if relay should accept an event
 * 
 * Determines whether a relay should accept and store an event based on
 * NIP-01 basic protocol rules. This includes:
 * - Event validation (ID, signature, delegation)
 * - Content size limits
 * - Timestamp limits (if configured)
 * - Proof-of-work difficulty (if required)
 * 
 * Args:
 *   ev                          - event to evaluate
 *   max_content_length          - maximum allowed content length (0 = unlimited)
 *   created_at_lower_limit      - minimum allowed created_at age in seconds (0 = no limit)
 *   created_at_upper_limit      - maximum allowed created_at future in seconds (0 = no limit)
 *   min_pow_difficulty          - minimum proof-of-work difficulty required (0 = none)
 * 
 * Returns: true if relay should accept event, false otherwise
 */
bool nip01_can_accept_event(const event_t *ev, size_t max_content_length,
                            time_t created_at_lower_limit,
                            time_t created_at_upper_limit,
                            int min_pow_difficulty);

/* ============================================================================
 * Event Kind Processing (Dispatch System)
 * ============================================================================ */

/* Event processing result - returned by kind handlers
 * 
 * Indicates success, failure, and what action relay should take with the event.
 */
typedef struct {
    bool accepted;              /* true if event accepted, false if rejected */
    bool should_broadcast;      /* true if event should be sent to subscribers */
    char response_msg[256];     /* Human-readable reason (OK or rejection message) */
} nip01_process_result_t;

/* Handler function type for processing events of a specific kind or kind range
 * 
 * Args:
 *   connection - WebSocket connection (for auth checks, etc.)
 *   event      - the event to process
 *   storage    - storage context for database operations
 *   relay_url  - relay's URL (for delegation/auth checks)
 * 
 * Returns: nip01_process_result_t with acceptance decision and message
 * 
 * Handler responsibility:
 *   1. Perform kind-specific validation
 *   2. Handle storage (insert, replace, delete old events, etc.)
 *   3. Decide if event should broadcast to subscribers
 *   4. Return result with success/failure and message
 * 
 * Constraints:
 *   - General validation (ID, signature, size, timestamp, PoW) is already done
 *   - Handler should NOT broadcast; caller will decide based on should_broadcast
 *   - Should NOT send response to client; caller will send OK/NOTICE
 */
typedef nip01_process_result_t (*nip01_kind_handler_t)(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url
);

/* nip01_process_event - Main entry point for event processing
 * 
 * Performs comprehensive event processing:
 * 1. Validates event (ID, signature, delegation)
 * 2. Checks content size limit
 * 3. Checks timestamp limits
 * 4. Checks proof-of-work difficulty
 * 5. Checks for auth-required tag
 * 6. Dispatches to kind-specific handler
 * 
 * Args:
 *   connection                  - WebSocket connection
 *   event                       - event to process
 *   storage                     - storage context
 *   relay_url                   - relay's URL
 *   max_content_length          - maximum content size (0 = unlimited)
 *   created_at_lower_limit      - max event age in seconds (0 = no limit)
 *   created_at_upper_limit      - max event future in seconds (0 = no limit)
 *   min_pow_difficulty          - minimum PoW difficulty (0 = none)
 * 
 * Returns: nip01_process_result_t with decision and message
 * 
 * Example usage:
 *   event_t event;
 *   // ... parse event ...
 *   
 *   nip01_process_result_t result = nip01_process_event(
 *       connection, &event, storage_ctx, relay_url,
 *       MAX_CONTENT, 2*3600, 15*60, 20);
 *   
 *   send_status(connection, "OK", event.id, result.accepted, result.response_msg);
 *   
 *   if (result.accepted && result.should_broadcast) {
 *       broadcast_event(&event);
 *   }
 */
nip01_process_result_t nip01_process_event(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url,
    size_t max_content_length,
    time_t created_at_lower_limit,
    time_t created_at_upper_limit,
    int min_pow_difficulty
);

#endif /* NIP01_H_ */
