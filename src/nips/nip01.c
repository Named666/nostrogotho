#include "nip01.h"
#include "../crypto.h"
#include "../nips/nip09.h"
#include "../nips/nip13.h"
#include "../nips/nip16.h"
#include "../nips/nip33.h"
#include "../nips/nip62.h"
#include "../storage.h"
#include <time.h>

/* ============================================================================
 * NIP-01: Basic Protocol Flow, Events and Signatures
 * 
 * Implementation of core event validation and kind-based dispatch system.
 * Each event kind (or range) has a handler registered that processes it.
 * ============================================================================ */

bool nip01_validate_event(const event_t *ev) {
    if (!ev) return false;
    
    /* Delegate to crypto layer for full validation
     * (ID verification, signature verification, delegation checking) */
    return check_event(ev);
}

bool nip01_can_accept_event(const event_t *ev, size_t max_content_length,
                            time_t created_at_lower_limit,
                            time_t created_at_upper_limit,
                            int min_pow_difficulty) {
    if (!ev) return false;
    
    /* Validate event ID and signature */
    if (!nip01_validate_event(ev)) return false;
    
    /* Check content size limit */
    if (max_content_length > 0 && ev->content_len > max_content_length) {
        return false;
    }
    
    /* Check timestamp limits (NIP-22) */
    time_t now = time(NULL);
    if (created_at_lower_limit > 0 && ev->created_at < now - created_at_lower_limit) {
        return false;
    }
    if (created_at_upper_limit > 0 && ev->created_at > now + created_at_upper_limit) {
        return false;
    }
    
    /* Check proof-of-work (NIP-13) */
    if (min_pow_difficulty > 0 && !nip13_meets_difficulty(ev, min_pow_difficulty)) {
        return false;
    }
    
    return true;
}

/* ============================================================================
 * Kind-Specific Handlers (Plugin System)
 * ============================================================================ */

/* Handler for kind 5 (Event Deletion - NIP-09)
 * 
 * Deletes events by ID or addressable event coordinates.
 * All deletion events and the old versions of replaced events are stored.
 */
static nip01_process_result_t handle_kind_deletion(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {
    
    nip01_process_result_t result = {0};
    
    if (!storage) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "error: storage unavailable");
        return result;
    }
    
    bool deleted = nip09_delete_targets(event, storage);
    result.accepted = true;
    result.should_broadcast = false;  /* Deletion events are typically not broadcast */
    snprintf(result.response_msg, sizeof(result.response_msg), "%s",
            deleted ? "" : "deletion failed");
    
    return result;
}

/* Handler for kind 62 (Request to Vanish - NIP-62)
 * 
 * Deletes all events by the signer that were published before the event's created_at.
 * The vanish event itself is stored.
 */
static nip01_process_result_t handle_kind_vanish(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {
    
    nip01_process_result_t result = {0};
    
    if (!storage) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "error: storage unavailable");
        return result;
    }
    
    /* Check if this vanish event targets this relay */
    if (nip62_should_vanish(event, relay_url)) {
        int deleted = storage->delete_all_events_by_pubkey(event->pubkey, event->created_at);
        if (deleted < 0) {
            result.accepted = false;
            snprintf(result.response_msg, sizeof(result.response_msg),
                    "error: failed to vanish events");
            return result;
        }
    }
    
    /* Store the vanish event itself */
    if (!storage->insert_record(event)) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "duplicate: event already exists");
        return result;
    }
    
    result.accepted = true;
    result.should_broadcast = true;
    result.response_msg[0] = '\0';
    
    return result;
}

/* Handler for replaceable events (kinds 0, 3, 10000-20000 - NIP-16)
 * 
 * Replaces older events for the same (pubkey, kind) pair.
 */
static nip01_process_result_t handle_kind_replaceable(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {
    
    nip01_process_result_t result = {0};
    
    if (!storage) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "error: storage unavailable");
        return result;
    }
    
    if (!nip16_replace_event(event, storage)) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "error: failed to replace event");
        return result;
    }
    
    result.accepted = true;
    result.should_broadcast = true;
    result.response_msg[0] = '\0';
    
    return result;
}

/* Handler for addressable replaceable events (kinds 30000-40000 - NIP-33)
 * 
 * Replaces older events for the same (pubkey, kind, d-tag) combination.
 */
static nip01_process_result_t handle_kind_addressable(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {
    
    nip01_process_result_t result = {0};
    
    if (!storage) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "error: storage unavailable");
        return result;
    }
    
    if (!nip33_replace_event(event, storage)) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "error: failed to replace event");
        return result;
    }
    
    result.accepted = true;
    result.should_broadcast = true;
    result.response_msg[0] = '\0';
    
    return result;
}

/* Handler for ephemeral events (kinds 20000-30000)
 * 
 * Ephemeral events are not stored by relays; only broadcast to subscribers.
 */
static nip01_process_result_t handle_kind_ephemeral(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {
    
    nip01_process_result_t result = {0};
    
    /* Ephemeral events are never stored, only broadcast */
    result.accepted = true;
    result.should_broadcast = true;
    result.response_msg[0] = '\0';
    
    return result;
}

/* Handler for regular events (default case)
 * 
 * Regular events are stored and broadcast to subscribers.
 */
static nip01_process_result_t handle_kind_regular(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {
    
    nip01_process_result_t result = {0};
    
    if (!storage) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "error: storage unavailable");
        return result;
    }
    
    if (!storage->insert_record(event)) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "duplicate: event already exists");
        return result;
    }
    
    result.accepted = true;
    result.should_broadcast = true;
    result.response_msg[0] = '\0';
    
    return result;
}

/* ============================================================================
 * Main Event Processing Dispatcher
 * ============================================================================ */

nip01_process_result_t nip01_process_event(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url,
    size_t max_content_length,
    time_t created_at_lower_limit,
    time_t created_at_upper_limit,
    int min_pow_difficulty) {
    
    nip01_process_result_t result = {0};
    
    if (!event) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "error: invalid event");
        return result;
    }
    
    /* Step 1: Validate event (ID, signature, delegation) */
    if (!nip01_validate_event(event)) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "invalid: event id, signature or delegation is invalid");
        return result;
    }
    
    /* Step 2: Check content size */
    if (max_content_length > 0 && event->content_len > max_content_length) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "invalid: content too large");
        return result;
    }
    
    /* Step 3: Check timestamp limits */
    time_t now = time(NULL);
    if ((created_at_lower_limit && event->created_at < now - created_at_lower_limit) ||
        (created_at_upper_limit && event->created_at > now + created_at_upper_limit)) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "invalid: created_at is out of the acceptable range");
        return result;
    }
    
    /* Step 4: Check proof-of-work */
    if (!nip13_meets_difficulty(event, min_pow_difficulty)) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "pow: insufficient difficulty");
        return result;
    }
    
    /* Step 5: Check for auth-required tag (NIP-42 authenticated pubkey needed) */
    /* This check is deferred to server.c where we have access to nip42_authenticated_pubkey() */
    
    /* Step 6: Dispatch to kind-specific handler */
    if (event->kind == 5) {
        return handle_kind_deletion(connection, event, storage, relay_url);
    } else if (event->kind == 62) {
        return handle_kind_vanish(connection, event, storage, relay_url);
    } else if (event->kind == 0 || event->kind == 3 || 
               (event->kind >= 10000 && event->kind < 20000)) {
        return handle_kind_replaceable(connection, event, storage, relay_url);
    } else if (event->kind >= 20000 && event->kind < 30000) {
        return handle_kind_ephemeral(connection, event, storage, relay_url);
    } else if (event->kind >= 30000 && event->kind < 40000) {
        return handle_kind_addressable(connection, event, storage, relay_url);
    } else {
        /* Regular events (1-4, 6-9999, and all other kinds not explicitly handled) */
        return handle_kind_regular(connection, event, storage, relay_url);
    }
}

