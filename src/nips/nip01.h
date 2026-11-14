#ifndef NIP01_H_
#define NIP01_H_

#include <stdbool.h>
#include <time.h>
#include "json_lite.h"
#include "relay_conn.h"
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
 *
 * Threading: validation is pure and thread-safe; kind dispatch
 * (nip01_dispatch_event and the registered handlers) runs on the writer.
 * Results are returned by value (nip01_process_result_t, response_msg is
 * an inline buffer); nothing is allocated for the caller.
 * ============================================================================ */

/* ============================================================================
 * Event Validation
 * ============================================================================ */


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
    bool duplicate;             /* already known / superseded: OK true, never broadcast */
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
    relay_conn_t *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url
);

/* Event processing in two steps (relay_core runs precheck on the worker,
 * dispatch on the writer):
 *   nip01_precheck_event  - size, created_at window and PoW limits
 *   nip01_dispatch_event  - every plugin whose declared kind ranges cover
 *                           the kind; default NIP-01 store and broadcast
 * Both return a nip01_process_result_t (decision and OK message). */
nip01_process_result_t nip01_precheck_event(
    const event_t *event,
    size_t max_content_length,
    time_t created_at_lower_limit,
    time_t created_at_upper_limit,
    int min_pow_difficulty);

nip01_process_result_t nip01_dispatch_event(
    relay_conn_t *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url);


#endif /* NIP01_H_ */
