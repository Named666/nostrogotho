/* ============================================================================
 * NIP-01: Basic Protocol Flow (+ NIP-16 replaceable, NIP-33 addressable kinds)
 *
 * Single-file NIP: replaceable/addressable kind handling + capability table
 * + self-registration. Compiling this file enables the NIP; deleting it
 * removes it. No header, no registration list, no build edits.
 * ============================================================================ */

#include "nip_capability.h"
#include "model/tag_iter.h"
#include "storage.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * NIP-01 Capability Implementation
 * 
 * Core protocol logic for replaceable/addressable events.
 * Uses the new transport-agnostic capability interface.
 * ============================================================================ */

static bool nip01_kind_handler_handles_kind(int kind, void *ctx);
static nip01_process_result_t nip01_kind_handler_process_event(
    connection_id_t connection_id, const event_t *event,
    storage_context_t *storage, const char *relay_url, void *ctx);
static nip01_process_result_t nip01_replaceable_listener(const event_t *event, storage_context_t *storage);
static nip01_process_result_t nip01_addressable_listener(const event_t *event, storage_context_t *storage);

/* Single capability table: one entry per capability type. Hooks ignore ctx,
 * so .ctx is NULL (no allocation, nothing to leak across reloads). */
static nip_capability_t nip01_caps[] = {
    {
        .name = "nip01-kind-handler",
        .type = NIP_CAP_KIND_HANDLER,
        .ctx = NULL,
        .caps.kind_handler = {
            .handles_kind = nip01_kind_handler_handles_kind,
            .process_event = nip01_kind_handler_process_event,
        },
        .next = NULL,
    },
};

/* ============================================================================
 * Implementation
 * ============================================================================ */

static bool nip01_kind_handler_handles_kind(int kind, void *ctx) {
    (void)ctx;
    /* NIP-16 replaceable: kinds 0, 3, 10000-19999 */
    /* NIP-33 addressable: kinds 30000-39999 */
    return (kind == 0 || kind == 3 || 
            (kind >= 10000 && kind <= 19999) ||
            (kind >= 30000 && kind <= 39999));
}

static nip01_process_result_t nip01_kind_handler_process_event(
    connection_id_t connection_id, const event_t *event,
    storage_context_t *storage, const char *relay_url, void *ctx) {
    (void)connection_id;
    (void)ctx;
    (void)relay_url;
    
    nip01_process_result_t result = {0};
    
    if (!storage) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "error: storage unavailable");
        return result;
    }
    
    if (event->kind >= 30000 && event->kind < 40000) {
        /* NIP-33 addressable events */
        return nip01_addressable_listener(event, storage);
    }
    
    /* NIP-16 replaceable events */
    return nip01_replaceable_listener(event, storage);
}

/* ============================================================================
 * NIP-16 Replaceable Events (moved to NIP-01)
 * ============================================================================ */

static bool nip01_replace_event(const event_t *event, storage_context_t *storage) {
    storage_delete_result_t result = storage->delete_record_by_kind_and_pubkey(event->kind, event->pubkey, event->created_at);
    return result.result == STORAGE_OK && result.deleted_count >= 0;
}

static nip01_process_result_t nip01_replaceable_listener(const event_t *event, storage_context_t *storage) {
    if (!storage) {
        nip01_process_result_t result = {0};
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "error: storage unavailable");
        return result;
    }
    
    if (!nip01_replace_event(event, storage)) {
        nip01_process_result_t result = {0};
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "error: failed to replace event");
        return result;
    }
    
    /* Store the event and indicate it should be broadcast */
    storage_insert_result_t insert_result = storage->insert_record(event, NULL, 0);
    nip01_process_result_t result = {0};
    if (insert_result.result == STORAGE_OK || insert_result.result == STORAGE_DUPLICATE) {
        result.accepted = true;
        result.should_store = true;
        result.should_broadcast = true;
        result.response_msg[0] = '\0';
    } else {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "error: %s", insert_result.error_message);
    }
    return result;
}

/* ============================================================================
 * NIP-33 Addressable (Parameterized Replaceable) Events
 * ============================================================================ */

static bool nip01_delete_addressable(const event_t *event, storage_context_t *storage, const char *identifier) {
    storage_event_scope_t scope = {0};
    char cursor[MAX_ID_SIZE + 1] = "";
    bool more;
    
    if (!storage || !storage->delete_matching) return false;
    scope.pubkey = event->pubkey;
    scope.has_kind = true;
    scope.kind = event->kind;
    scope.has_created_at_before = true;
    scope.created_at_before = event->created_at;
    
    do {
        size_t deleted = 0;
        char next_id[MAX_ID_SIZE + 1] = "";
        scope.after_id = cursor[0] ? cursor : NULL;
        if (!storage->delete_matching(&scope, tag_predicate_match_d_tag, (void *)identifier, &deleted, next_id, sizeof(next_id), &more)) return false;
        (void)deleted;
        snprintf(cursor, sizeof(cursor), "%s", next_id);
    } while (more);
    return true;
}

static bool nip01_replace_addressable_event(const event_t *event, storage_context_t *storage) {
    char *dvalue = tag_find_value(event, "d");
    bool replaced = nip01_delete_addressable(event, storage, dvalue);
    free(dvalue);
    return replaced;
}

static nip01_process_result_t nip01_addressable_listener(const event_t *event, storage_context_t *storage) {
    nip01_process_result_t result = {0};
    if (!storage) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "error: storage unavailable");
        return result;
    }
    
    if (!nip01_replace_addressable_event(event, storage)) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "error: failed to replace event");
        return result;
    }
    
    /* Store the event and indicate it should be broadcast */
    storage_insert_result_t insert_result = storage->insert_record(event, NULL, 0);
    result.accepted = true;
    result.should_store = true;
    result.should_broadcast = true;
    if (insert_result.result != STORAGE_OK && insert_result.result != STORAGE_DUPLICATE) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "error: %s", insert_result.error_message);
    }
    return result;
}

/* ============================================================================
 * Registration (using macro to eliminate boilerplate)
 * ============================================================================ */

NIP_REGISTER(nip01, nip01_caps)