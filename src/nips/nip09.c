/* ============================================================================
 * NIP-09: Event Deletion (kind 5)
 *
 * Single-file NIP: deletion authorization + target handling + capability
 * table + self-registration. Compiling this file enables the NIP; deleting
 * it removes it. No header, no registration list, no build edits.
 * ============================================================================ */

#include "nip_capability.h"
#include "protocol/event_tags.h"
#include "protocol/tag_iter.h"
#include "storage.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ============================================================================
 * NIP-09 Capability Implementation
 * 
 * Event deletion using the new transport-agnostic capability interface.
 * ============================================================================ */

static bool nip09_kind_handler_handles_kind(int kind, void *ctx);
static nip01_process_result_t nip09_kind_handler_process_event(
    connection_id_t connection_id, const event_t *event,
    storage_context_t *storage, const char *relay_url, void *ctx);

/* Single capability table. Hooks ignore ctx, so .ctx is NULL (no
 * allocation, nothing to leak across reloads). */
static nip_capability_t nip09_caps[] = {
    {
        .name = "nip09-kind-handler",
        .type = NIP_CAP_KIND_HANDLER,
        .ctx = NULL,
        .caps.kind_handler = {
            .handles_kind = nip09_kind_handler_handles_kind,
            .process_event = nip09_kind_handler_process_event,
        },
        .next = NULL,
    },
};

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static bool kind_is_requested(const event_t *event, int kind) {
    return tag_predicate_match_k_tag(event, &kind);
}

static bool parse_a_tag(const char *a, int *kind, char *pubkey,
                        size_t pubkey_size, const char **d_identifier) {
    const char *first = strchr(a, ':');
    const char *second;
    long parsed;
    char *end = NULL;
    size_t len;

    if (!first) return false;
    parsed = strtol(a, &end, 10);
    if (end != first || parsed < 0) return false;

    second = strchr(first + 1, ':');
    if (!second) {
        len = strlen(first + 1);
        if (len == 0 || len >= pubkey_size) return false;
        memcpy(pubkey, first + 1, len);
        pubkey[len] = '\0';
        *kind = (int)parsed;
        *d_identifier = "";
        return true;
    }

    len = (size_t)(second - (first + 1));
    if (len == 0 || len >= pubkey_size) return false;
    memcpy(pubkey, first + 1, len);
    pubkey[len] = '\0';

    *kind = (int)parsed;
    *d_identifier = second + 1;
    return true;
}

static bool deletion_authorized(const event_t *event, const event_t *target) {
    if (strcmp(target->pubkey, event->pubkey) == 0) return true;
    return event_tag_has_value(target, "delegation", event->pubkey);
}

static bool delete_e_target(const event_t *event, storage_context_t *storage,
                            const char *id) {
    event_t *target = storage->get_event_by_id(id);
    bool ok = true;

    if (!target) return true;

    if (deletion_authorized(event, target) &&
        kind_is_requested(event, target->kind)) {
        if (target->kind == 1059) {
            /* Kind 1059 (live event): also check 'p' tag */
            storage_event_scope_t scope = {0};
            scope.id = id;
            scope.has_kind = true;
            scope.kind = 1059;
            scope.pubkey = event->pubkey;  /* Only delete if p tag matches */
            
            event_t **events = NULL;
            size_t count = 0;
            if (!storage_find_events(&scope, &events, &count) || count == 0) {
                ok = false;
            } else {
                /* Verify p tag matches */
                bool p_matched = false;
                for (size_t i = 0; i < count; i++) {
                    if (event_tag_has_value(events[i], "p", event->pubkey)) {
                        p_matched = true;
                        break;
                    }
                }
                if (!p_matched) ok = false;
                
                for (size_t i = 0; i < count; i++) event_free(events[i]);
                free(events);
            }
            
            if (ok) {
                storage_event_scope_t del_scope = { .id = id };
                size_t deleted = 0;
                if (!storage_delete_events(&del_scope, &deleted) || deleted == 0) ok = false;
            }
        } else {
            /* Direct deletion by ID + pubkey authorization */
            storage_event_scope_t scope = {
                .id = id,
                .pubkey = event->pubkey
            };
            size_t deleted = 0;
            if (!storage_delete_events(&scope, &deleted) || deleted == 0) ok = false;
        }
    }
    event_free(target);
    return ok;
}

static bool delete_a_target(const event_t *event, storage_context_t *storage __attribute__((unused)),
                            const char *a) {
    int kind;
    char pubkey[MAX_PUBKEY_SIZE + 1];
    const char *d_identifier;

    if (!parse_a_tag(a, &kind, pubkey, sizeof(pubkey), &d_identifier)) {
        return true;
    }

    if (strcmp(pubkey, event->pubkey) != 0) return true;

    if (!kind_is_requested(event, kind)) return true;

    if (*d_identifier == '\0') {
        /* No 'd' tag: delete all replaceable events of this kind/pubkey older than this */
        storage_event_scope_t scope = {
            .pubkey = pubkey,
            .has_kind = true,
            .kind = kind,
            .has_created_at_before = true,
            .created_at_before = event->created_at
        };
        size_t deleted = 0;
        return storage_delete_events(&scope, &deleted);
    } else {
        /* Has 'd' tag: find addressable events matching pubkey+kind+created_at_before, 
         * then filter by 'd' tag value */
        storage_event_scope_t scope = {
            .pubkey = pubkey,
            .has_kind = true,
            .kind = kind,
            .has_created_at_before = true,
            .created_at_before = event->created_at
        };
        
        event_t **events = NULL;
        size_t count = 0;
        if (!storage_find_events(&scope, &events, &count)) {
            return false;
        }
        
        bool ok = true;
        for (size_t i = 0; i < count; i++) {
            if (event_tag_has_value(events[i], "d", d_identifier)) {
                storage_event_scope_t del_scope = { .id = events[i]->id };
                size_t deleted = 0;
                if (!storage_delete_events(&del_scope, &deleted) || deleted == 0) {
                    ok = false;
                }
            }
        }
        
        for (size_t i = 0; i < count; i++) event_free(events[i]);
        free(events);
        return ok;
    }
}

static bool nip09_delete_targets(const event_t *event, storage_context_t *storage) {
    if (!event->tags_json) return true;
    
    tag_iter_t it;
    tag_iter_init(&it, event);
    
    struct mg_str key, tag;
    bool failed = false;

    while (tag_iter_next(&it, &key, &tag)) {
        char *name = tag_iter_element(&it, 0);
        if (!name) continue;
        if (strcmp(name, "e") == 0) {
            for (size_t index = 1;; index++) {
                char *id = tag_iter_element(&it, index);
                if (!id) break;
                if (!delete_e_target(event, storage, id)) failed = true;
                free(id);
            }
        } else if (strcmp(name, "a") == 0) {
            for (size_t index = 1;; index++) {
                char *a = tag_iter_element(&it, index);
                if (!a) break;
                if (!delete_a_target(event, storage, a)) failed = true;
                free(a);
            }
        }
        free(name);
    }
    return !failed;
}

/* ============================================================================
 * Kind Handler Implementation
 * ============================================================================ */

static bool nip09_kind_handler_handles_kind(int kind, void *ctx) {
    (void)ctx;
    return kind == 5;  /* NIP-09: Event Deletion (kind 5) */
}

static nip01_process_result_t nip09_kind_handler_process_event(
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

    bool deleted = nip09_delete_targets(event, storage);
    /* Deletion events are accepted but not broadcast (NIP-09). */
    storage_insert_result_t insert_result = storage->insert_record(event, NULL, 0);
    result.accepted = true;
    result.should_store = true;
    result.should_broadcast = false;
    if (insert_result.result == STORAGE_OK || insert_result.result == STORAGE_DUPLICATE) {
        result.response_msg[0] = '\0';
    } else {
        snprintf(result.response_msg, sizeof(result.response_msg),
                 "deletion failed: %s", insert_result.error_message);
    }
    if (!deleted) {
        snprintf(result.response_msg, sizeof(result.response_msg),
                 "deletion failed");
    }
    return result;
}

/* ============================================================================
 * Registration (using macro to eliminate boilerplate)
 * ============================================================================ */

NIP_REGISTER(nip09, nip09_caps)