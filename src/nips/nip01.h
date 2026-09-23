#ifndef NIP01_H_
#define NIP01_H_

#include <stdbool.h>
#include <time.h>
#include <mongoose.h>
#include "nostrogotho.h"
#include "../storage.h"

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

/* ============================================================================
 * Event Stream Listener System (Plugin Architecture)
 * ============================================================================ */

/* Event processing result - returned by event listeners
 * 
 * Indicates success, failure, and what action relay should take with the event.
 */
typedef struct {
    bool accepted;              /* true if event accepted, false if rejected */
    bool should_broadcast;      /* true if event should be sent to subscribers */
    char response_msg[256];     /* Human-readable reason (OK or rejection message) */
} nip01_process_result_t;

/* Listener function type - called when event of registered kind arrives
 * 
 * Each plugin can declare kind ranges it listens for (nip_plugin_t.kinds)
 * and provide one of these as its on_event hook. When an event arrives, all
 * plugins whose declared ranges cover its kind are called in registration
 * order. The first listener to return accepted=true stops further processing.
 * 
 * Args:
 *   connection - WebSocket connection (for auth checks, etc.)
 *   event      - the event that arrived
 *   storage    - storage context for database operations
 *   relay_url  - relay's URL (for relay-specific filtering)
 * 
 * Returns: nip01_process_result_t with acceptance decision and message
 * 
 * Listener responsibility:
 *   1. Check if this event is relevant to this listener
 *   2. Perform kind-specific validation and processing
 *   3. Handle storage operations (insert, replace, delete, etc.)
 *   4. Decide if event should broadcast to subscribers
 *   5. Return result with success/failure/decision
 * 
 * Important:
 *   - General validation (ID, signature, size, timestamp, PoW) is done before listeners are called
 *   - Listener should NOT broadcast; caller decides based on should_broadcast
 *   - Listener should NOT send response to client; caller sends OK/NOTICE
 *   - Multiple listeners can be registered for the same kind
 * 
 * See nip_plugin.h for the ergonomic result constructors (nip_plugin_accept,
 * nip_plugin_reject, nip_plugin_store_and_broadcast, ...).
 */
typedef nip01_process_result_t (*nip01_event_listener_t)(
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
 * 5. Dispatches to every plugin whose declared kind ranges cover this kind
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
 *   nip_plugin_send_status(connection, "OK", event.id, result.accepted, result.response_msg);
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
