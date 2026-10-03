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
    if (!event) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "error: invalid event");
        return result;
    }
    if (!storage || !storage->upsert_replaceable || !storage->upsert_addressable) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "error: storage unavailable");
        return result;
    }
    if (event->kind >= 30000 && event->kind < 40000) {
        /* NIP-33 addressable events */
        return nip01_addressable_listener(event, storage);
    }
    if (event->kind == 0 || event->kind == 3 || (event->kind >= 10000 && event->kind <= 19999)) {
        return nip01_replaceable_listener(event, storage);
    }
    result.accepted = false;
    snprintf(result.response_msg, sizeof(result.response_msg), "error: unhandled kind");
    return result;
}

/* ============================================================================
 * NIP-16 Replaceable Events (moved to NIP-01)
 * ============================================================================ */

/* Helper: Extract indexable tags (e, p, a) from event for tag index.
 * Intentional deviation from NIP-01 (index first value of all a-zA-Z): we index e/p/a (the relay's
 * queryable tags) with ALL values tag[1..] so multi-value filters match event_tag_has_value() semantics.
 * Relay-collected tags mirror this set; expanding to all single-letters is future work, not a silent miss.
 * Uses event_tag_get_all so EVERY tag with a matching name is indexed,
 * not just the first one. The old event_tag_get() version dropped values
 * from repeated tags (e.g. two ["p", ...] tags), making stored multi-value
 * filters unmatchable. All values (tag[1..]) of each tag are indexed so
 * they agree with event_tag_has_value() semantics. */
static void nip01_index_tag_name(const event_t *event, const char *name,
                                 storage_tag_match_t *indexed_tags,
                                 size_t *indexed_tags_count) {
    size_t tag_count = 0;
    char ***all = event_tag_get_all(event, name, &tag_count);
    if (!all) return;
    for (size_t t = 0; t < tag_count; t++) {
        if (!all[t]) continue;
        for (size_t i = 0; all[t][i]; i++) {
            char *copy;
            if (*indexed_tags_count >= 64) break;
            copy = strdup(all[t][i]);
            if (!copy) { event_tag_free_all(all, tag_count); return; }
            indexed_tags[*indexed_tags_count].tag_name = (char *)name;
            /* Own the copy: event_tag_free_all() below releases the
             * get_all buffers, so borrowed pointers would dangle. */
            indexed_tags[*indexed_tags_count].tag_value = copy;
            indexed_tags[*indexed_tags_count].filter_index = 0;
            (*indexed_tags_count)++;
        }
        if (*indexed_tags_count >= 64) break;
    }
    event_tag_free_all(all, tag_count);
}

static void nip01_extract_indexed_tags(const event_t *event,
                                       storage_tag_match_t *indexed_tags,
                                       size_t *indexed_tags_count) {
    nip01_index_tag_name(event, "e", indexed_tags, indexed_tags_count);
    nip01_index_tag_name(event, "p", indexed_tags, indexed_tags_count);
    nip01_index_tag_name(event, "a", indexed_tags, indexed_tags_count);
}

/* Release copies made by nip01_extract_indexed_tags (call after insert). */
static void nip01_free_indexed_tags(storage_tag_match_t *indexed_tags,
                                    size_t indexed_tags_count) {
    size_t i;
    if (!indexed_tags) return;
    for (i = 0; i < indexed_tags_count; i++) free(indexed_tags[i].tag_value);
}

static nip01_process_result_t nip01_upsert_common(storage_tag_match_t *indexed_tags, size_t indexed_tags_count,
                                                   storage_insert_result_t insert_result) {
    nip01_process_result_t result = {0};
    nip01_free_indexed_tags(indexed_tags, indexed_tags_count);
    if (insert_result.result == STORAGE_OK) {
        result.accepted = true;
        result.should_store = true;
        result.should_broadcast = true;
        result.response_msg[0] = '\0';
    } else if (insert_result.result == STORAGE_DUPLICATE) {
        result.accepted = true;
        result.should_store = true;
        result.should_broadcast = true;
        snprintf(result.response_msg, sizeof(result.response_msg), "duplicate: already have this event");
    } else {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "error: %s",
                 insert_result.error_message[0] ? insert_result.error_message : "storage error");
    }
    return result;
}

static nip01_process_result_t nip01_replaceable_listener(const event_t *event, storage_context_t *storage) {
    storage_tag_match_t indexed_tags[64];
    size_t indexed_tags_count = 0;
    if (!event || !storage || !storage->upsert_replaceable) {
        nip01_process_result_t result = {0};
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "error: storage unavailable");
        return result;
    }
    /* Extract indexed tags for tag index */
    nip01_extract_indexed_tags(event, indexed_tags, &indexed_tags_count);
    /* Use new atomic upsert for replaceable events */
    return nip01_upsert_common(indexed_tags, indexed_tags_count,
                               storage->upsert_replaceable(event, indexed_tags, indexed_tags_count));
}

/* ============================================================================
 * NIP-33 Addressable (Parameterized Replaceable) Events
 * ============================================================================ */

static nip01_process_result_t nip01_addressable_listener(const event_t *event, storage_context_t *storage) {
    char *dvalue;
    storage_tag_match_t indexed_tags[64];
    size_t indexed_tags_count = 0;
    storage_insert_result_t insert_result;
    nip01_process_result_t result;
    if (!event || !storage || !storage->upsert_addressable) {
        nip01_process_result_t r = {0};
        r.accepted = false;
        snprintf(r.response_msg, sizeof(r.response_msg), "error: storage unavailable");
        return r;
    }
    /* NIP-33: addressable key is (kind, pubkey, d). Missing or valueless ["d"] means empty identifier. */
    dvalue = event_tag_value(event, "d");
    if (!dvalue) {
        dvalue = strdup("");
        if (!dvalue) {
            nip01_process_result_t r = {0};
            r.accepted = false;
            snprintf(r.response_msg, sizeof(r.response_msg), "error: out of memory");
            return r;
        }
    }
    /* Extract indexed tags for tag index */
    nip01_extract_indexed_tags(event, indexed_tags, &indexed_tags_count);
    /* Storage matches deletions on tag_name='d': index it or old versions never get replaced. */
    if (indexed_tags_count < 64) {
        char *dcopy = strdup(dvalue);
        if (dcopy) {
            indexed_tags[indexed_tags_count].tag_name = (char *)"d";
            indexed_tags[indexed_tags_count].tag_value = dcopy;
            indexed_tags[indexed_tags_count].filter_index = 0;
            indexed_tags_count++;
        }
    }
    /* Use new atomic upsert for addressable events */
    insert_result = storage->upsert_addressable(event, dvalue, indexed_tags, indexed_tags_count);
    free(dvalue);
    result = nip01_upsert_common(indexed_tags, indexed_tags_count, insert_result);
    return result;
}

/* ============================================================================
 * Registration (using macro to eliminate boilerplate)
 * ============================================================================ */

NIP_REGISTER(nip01, nip01_caps)