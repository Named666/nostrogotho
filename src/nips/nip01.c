/* ============================================================================
 * NIP-01: Basic Protocol Flow (+ NIP-16 replaceable, NIP-33 addressable kinds)
 *
 * Single-file NIP: replaceable/addressable kind handling + capability table
 * + self-registration. Compiling this file enables the NIP; deleting it
 * removes it. No header, no registration list, no build edits.
 * ============================================================================ */

#include "nip_capability.h"
#include "protocol/event_tags.h"
#include "protocol/tag_iter.h"
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

/* Helper: Extract indexable tags (e, p, a) from event for tag index */
static void nip01_extract_indexed_tags(const event_t *event,
                                       storage_tag_match_t *indexed_tags,
                                       size_t *indexed_tags_count) {
    char **tags_e = event_tag_get(event, "e");
    if (tags_e) {
        for (size_t i = 0; tags_e[i]; i++) {
            if (*indexed_tags_count < 64) {
                indexed_tags[*indexed_tags_count].tag_name = "e";
                indexed_tags[*indexed_tags_count].tag_value = tags_e[i];
                indexed_tags[*indexed_tags_count].filter_index = 0;
                (*indexed_tags_count)++;
            }
        }
        event_tag_free(tags_e);
    }
    
    char **tags_p = event_tag_get(event, "p");
    if (tags_p) {
        for (size_t i = 0; tags_p[i]; i++) {
            if (*indexed_tags_count < 64) {
                indexed_tags[*indexed_tags_count].tag_name = "p";
                indexed_tags[*indexed_tags_count].tag_value = tags_p[i];
                indexed_tags[*indexed_tags_count].filter_index = 0;
                (*indexed_tags_count)++;
            }
        }
        event_tag_free(tags_p);
    }
    
    char **tags_a = event_tag_get(event, "a");
    if (tags_a) {
        for (size_t i = 0; tags_a[i]; i++) {
            if (*indexed_tags_count < 64) {
                indexed_tags[*indexed_tags_count].tag_name = "a";
                indexed_tags[*indexed_tags_count].tag_value = tags_a[i];
                indexed_tags[*indexed_tags_count].filter_index = 0;
                (*indexed_tags_count)++;
            }
        }
        event_tag_free(tags_a);
    }
}

static nip01_process_result_t nip01_replaceable_listener(const event_t *event, storage_context_t *storage) {
    if (!storage) {
        nip01_process_result_t result = {0};
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "error: storage unavailable");
        return result;
    }
    
    /* Extract indexed tags for tag index */
    storage_tag_match_t indexed_tags[64];
    size_t indexed_tags_count = 0;
    nip01_extract_indexed_tags(event, indexed_tags, &indexed_tags_count);
    
    /* Use new atomic upsert for replaceable events */
    storage_insert_result_t insert_result = storage_upsert_replaceable(event, indexed_tags, indexed_tags_count);
    
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

static nip01_process_result_t nip01_addressable_listener(const event_t *event, storage_context_t *storage) {
    nip01_process_result_t result = {0};
    if (!storage) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "error: storage unavailable");
        return result;
    }
    
    /* Extract d tag value */
    char *dvalue = event_tag_value(event, "d");
    if (!dvalue) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "error: missing d tag");
        return result;
    }
    
    /* Extract indexed tags for tag index */
    storage_tag_match_t indexed_tags[64];
    size_t indexed_tags_count = 0;
    nip01_extract_indexed_tags(event, indexed_tags, &indexed_tags_count);
    
    /* Use new atomic upsert for addressable events */
    storage_insert_result_t insert_result = storage_upsert_addressable(event, dvalue, indexed_tags, indexed_tags_count);
    free(dvalue);
    
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