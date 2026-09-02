#include "nip01.h"
#include "../crypto.h"
#include "../storage.h"
#include <time.h>
#include <stdio.h>

/* ============================================================================
 * NIP-01: Basic Protocol Flow, Events and Signatures
 * 
 * Implementation of core event validation and event listener system.
 * Each NIP registers listeners for the event kinds it cares about.
 * When an event arrives, registered listeners are called to process it.
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
    if (min_pow_difficulty > 0) {
        extern bool nip13_meets_difficulty(const event_t *ev, int difficulty);
        if (!nip13_meets_difficulty(ev, min_pow_difficulty)) {
            return false;
        }
    }
    
    return true;
}

/* ============================================================================
 * Event Listener Registry
 * 
 * Purely mechanical: stores (kind range -> listener) entries. It has no
 * knowledge of any specific NIP; each NIP module registers itself via
 * __attribute__((constructor)) in its own .c file.
 * ============================================================================ */

#define MAX_LISTENERS 64

typedef struct {
    int kind_min;
    int kind_max;
    nip01_event_listener_t listener;
} listener_entry_t;

static listener_entry_t listener_registry[MAX_LISTENERS];
static int registry_size = 0;

bool nip01_register_listener(int kind_min, int kind_max, nip01_event_listener_t listener) {
    if (!listener || kind_min > kind_max) return false;
    if (registry_size >= MAX_LISTENERS) return false;

    listener_registry[registry_size].kind_min = kind_min;
    listener_registry[registry_size].kind_max = kind_max;
    listener_registry[registry_size].listener = listener;
    registry_size++;

    return true;
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
    if (min_pow_difficulty > 0) {
        extern bool nip13_meets_difficulty(const event_t *ev, int difficulty);
        if (!nip13_meets_difficulty(event, min_pow_difficulty)) {
            result.accepted = false;
            snprintf(result.response_msg, sizeof(result.response_msg),
                    "pow: insufficient difficulty");
            return result;
        }
    }
    
    /* Step 5: Call every registered listener whose range covers this kind,
     * in registration order. The first listener to accept wins. */
    bool any_listener_matched = false;
    for (int i = 0; i < registry_size; i++) {
        if (event->kind < listener_registry[i].kind_min ||
            event->kind > listener_registry[i].kind_max) {
            continue;
        }
        any_listener_matched = true;
        result = listener_registry[i].listener(connection, event, storage, relay_url);
        if (result.accepted) {
            return result;
        }
    }
    if (any_listener_matched) {
        /* All matching listeners rejected this event */
        if (result.response_msg[0] == '\0') {
            snprintf(result.response_msg, sizeof(result.response_msg),
                    "invalid: event rejected by all handlers");
        }
        return result;
    }
    
    /* Step 6: No listener claimed this kind - fall back to default NIP-01
     * behavior. Ephemeral events (kinds 20000-29999) are broadcast without
     * storage; everything else is stored and broadcast. */
    if (event->kind >= 20000 && event->kind < 30000) {
        result.accepted = true;
        result.should_broadcast = true;
        result.response_msg[0] = '\0';
        return result;
    }
    
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

