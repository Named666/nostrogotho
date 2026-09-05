#include "nip01.h"
#include "../crypto.h"
#include "../storage.h"
#include "nip_event.h"
#include "nip_plugin.h"
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ============================================================================
 * NIP-01: Basic Protocol Flow, Events and Signatures
 * 
 * Implementation of core event validation and event listener system.
 * Each NIP registers listeners for the event kinds it cares about.
 * When an event arrives, registered listeners are called to process it.
 *
 * Consolidated here per the reference specs:
 *   - NIP-16 (Event Treatment) is `final mandatory` and "Moved to NIP-01":
 *     replaceable-event handling for kinds 0, 3, 10000-19999 lives here.
 *   - NIP-33 (Parameterized Replaceable Events) is `final mandatory` and
 *     "Moved to NIP-01": addressable-event handling for kinds 30000-39999
 *     (with the "d" tag) lives here.
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
    (void) min_pow_difficulty; /* PoW is enforced by the nip13 plugin hook. */
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

    /* Proof-of-work (NIP-13) is enforced by the nip13 plugin's
     * accept_publish hook before dispatch, so it is not re-checked here. */

    return true;
}

/* ============================================================================
 * Event Listener Registry
 * 
 * Purely mechanical: stores (kind range -> listener) entries. It has no
 * knowledge of any specific NIP; each NIP module registers itself via
 * __attribute__((constructor)) in its own .c file.
 * 
 * The registry grows dynamically as listeners are registered, so there is no
 * fixed ceiling on the number of NIPs that can be supported.
 * ============================================================================ */

typedef struct {
    int kind_min;
    int kind_max;
    nip01_event_listener_t listener;
} listener_entry_t;

static listener_entry_t *listener_registry;
static size_t registry_size = 0;
static size_t registry_capacity = 0;

bool nip01_register_listener(int kind_min, int kind_max, nip01_event_listener_t listener) {
    if (!listener || kind_min > kind_max) return false;

    /* Grow the registry when full (start at 16, double as needed). */
    if (registry_size >= registry_capacity) {
        size_t new_capacity = registry_capacity ? registry_capacity * 2 : 16;
        listener_entry_t *resized = (listener_entry_t *) realloc(
            listener_registry, new_capacity * sizeof(*resized));
        if (!resized) return false;
        listener_registry = resized;
        registry_capacity = new_capacity;
    }

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

    (void) min_pow_difficulty; /* PoW is enforced by the nip13 plugin hook. */
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
    
    /* Step 4: Proof-of-work (NIP-13) is enforced by the nip13 plugin's
     * accept_publish hook, which the server runs before dispatching here. */

    /* Step 4b: NIP-module publish policies (e.g. NIP-40 expiry, NIP-42
     * auth-required tags) are enforced by the server before dispatch via
     * plugin accept_publish() hooks, so this dispatcher stays NIP-agnostic. */

    /* Step 5: Call every registered listener whose range covers this kind,
     * in registration order. The first listener to accept wins. */
    bool any_listener_matched = false;
    for (size_t i = 0; i < registry_size; i++) {
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

/* ============================================================================
 * NIP-16 (moved to NIP-01): Replaceable Events
 *
 * Kinds 0, 3 and 10000-19999 are replaceable: for each (kind, pubkey) only
 * the latest event is retained. When a newer event arrives, the previous
 * record is deleted before the new one is stored. On equal created_at the
 * storage layer performs the lexical id tie-break (lowest id wins).
 * ============================================================================ */

static bool nip01_replace_event(const event_t *event, storage_context_t *storage) {
    return storage->delete_record_by_kind_and_pubkey(event->kind, event->pubkey,
                                                     event->created_at) >= 0;
}

static nip01_process_result_t nip01_replaceable_listener(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {

    (void)connection;
    (void)relay_url;

    nip01_process_result_t result = {0};

    if (!storage) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "error: storage unavailable");
        return result;
    }

    if (!nip01_replace_event(event, storage)) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "error: failed to replace event");
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
 * NIP-33 (moved to NIP-01): Addressable (Parameterized Replaceable) Events
 *
 * Kinds 30000-39999 are addressable: for each (kind, pubkey, "d" tag value)
 * only the latest event is stored. The "d" tag value is the addressable
 * identifier; an event without a "d" tag is treated as having an empty one.
 * ============================================================================ */

static bool nip01_replace_addressable_event(const event_t *event,
                                            storage_context_t *storage) {
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    char *dvalue = NULL;
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = nip_tag_element(tag, 0);
        bool is_d = name && strcmp(name, "d") == 0;
        free(name);
        if (is_d) {
            dvalue = nip_tag_element(tag, 1);
            break;
        }
    }
    /* NIP-01: an event without a "d" tag is treated as having an empty one. */
    tag_t dtag = {(char *[]) {"d", dvalue ? dvalue : ""}, 2, 2};
    bool replaced = storage->delete_record_by_kind_and_pubkey_and_dtag(
                        event->kind, event->pubkey, &dtag,
                        event->created_at) >= 0;
    free(dvalue);
    return replaced;
}

static nip01_process_result_t nip01_addressable_listener(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {

    (void)connection;
    (void)relay_url;

    nip01_process_result_t result = {0};

    if (!storage) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "error: storage unavailable");
        return result;
    }

    if (!nip01_replace_addressable_event(event, storage)) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "error: failed to replace event");
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
 * Built-in listener registration (NIP-16 / NIP-33 consolidated into NIP-01)
 * ============================================================================ */

void nip01_init_listeners(void) {
    /* NIP-16 replaceable events (kinds 0, 3, 10000-19999). */
    nip01_register_listener(0, 0, nip01_replaceable_listener);
    nip01_register_listener(3, 3, nip01_replaceable_listener);
    nip01_register_listener(10000, 19999, nip01_replaceable_listener);
    /* NIP-33 addressable events (kinds 30000-39999). */
    nip01_register_listener(30000, 39999, nip01_addressable_listener);
}

/* Auto-register the built-in NIP-16 / NIP-33 listeners at program startup,
 * matching the self-registration pattern used by every other NIP module. */
__attribute__((constructor)) static void nip01_register_at_startup(void) {
    nip01_init_listeners();
}

