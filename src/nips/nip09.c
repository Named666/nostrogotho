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

/* NIP-09 says clients SHOULD include k and relays SHOULD delete same-pubkey refs. We enforce k when present
 * (absent k = allow; present k = require match) as anti-spam: a kind-5 without k cannot mass-delete across kinds. */
static bool kind_is_requested(const event_t *event, int kind) {
    return tag_predicate_match_k_tag(event, &kind);
}

static bool nip09_is_hex64(const char *str, size_t len) {
    if (len != 64) return false;
    for (size_t i = 0; i < len; i++) {
        char c = str[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
    }
    return true;
}

static bool nip09_kind_is_deletable(int kind) {
    if (kind == 0 || kind == 3) return true;
    if (kind >= 10000 && kind <= 19999) return true;
    if (kind >= 30000 && kind <= 39999) return true;
    return false;
}

static bool parse_a_tag(const char *a, int *kind, char *pubkey,
                        size_t pubkey_size, const char **d_identifier) {
    const char *first = strchr(a, ':');
    const char *second;
    long parsed;
    char *end = NULL;
    size_t len;

    if (!first || !a) return false;
    parsed = strtol(a, &end, 10);
    if (end != first || parsed < 0 || parsed > 999999999) return false;
    if (!nip09_kind_is_deletable((int)parsed)) return false;

    second = strchr(first + 1, ':');
    if (!second) {
        len = strlen(first + 1);
        if (len == 0 || len >= pubkey_size) return false;
        if (!nip09_is_hex64(first + 1, len)) return false;
        memcpy(pubkey, first + 1, len);
        pubkey[len] = '\0';
        *kind = (int)parsed;
        *d_identifier = "";
        return true;
    }

    len = (size_t)(second - (first + 1));
    if (len == 0 || len >= pubkey_size) return false;
    if (!nip09_is_hex64(first + 1, len)) return false;
    /* A trailing colon with empty d ("kind:pubkey:") is ambiguous: treat as malformed, ignore. */
    if (*(second + 1) == '\0') return false;
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
    event_t *target;
    bool ok = true;
    if (!storage || !storage->get_event_by_id || !storage->delete_events) return false;
    if (!id || !id[0]) return true;
    target = storage->get_event_by_id(id);
    if (!target) return true;

    /* NIP-09: deletion of a deletion (kind 5) has no effect. NIP-62: kind 5 vs kind 62 has no effect. */
    if (target->kind == 5 || target->kind == 62) {
        event_free(target);
        return true;
    }

    if (deletion_authorized(event, target) &&
        kind_is_requested(event, target->kind)) {
        /* Direct deletion by ID + pubkey authorization (uniform for all kinds incl. gift-wraps). */
        storage_event_scope_t scope = {
            .id = id,
            .pubkey = event->pubkey
        };
        size_t deleted = 0;
        if (!storage->delete_events(&scope, &deleted) || deleted == 0) ok = false;
    }
    event_free(target);
    return ok;
}

static bool delete_a_target(const event_t *event, storage_context_t *storage,
                            const char *a) {
    int kind;
    char pubkey[MAX_PUBKEY_SIZE + 1];
    const char *d_identifier;

    if (!parse_a_tag(a, &kind, pubkey, sizeof(pubkey), &d_identifier)) {
        return true;
    }

    /* NIP-09: deletion of deletion has no effect; NIP-62: kind 5 cannot delete kind 62. */
    if (kind == 5 || kind == 62) return true;

    if (strcmp(pubkey, event->pubkey) != 0) return true;

    if (!kind_is_requested(event, kind)) return true;

    if (*d_identifier == '\0') {
        /* No 'd' tag: delete all replaceable versions up to created_at (inclusive per NIP-09 "up to"). */
        storage_event_scope_t scope = {
            .pubkey = pubkey,
            .has_kind = true,
            .kind = kind,
            .has_created_at_at_or_before = true,
            .created_at_at_or_before = event->created_at
        };
        size_t deleted = 0;
        return storage->delete_events(&scope, &deleted);
    } else {
        /* Has 'd' tag: find addressable events matching pubkey+kind+created_at (inclusive),
         * then filter by 'd' tag value */
        storage_event_scope_t scope = {
            .pubkey = pubkey,
            .has_kind = true,
            .kind = kind,
            .has_created_at_at_or_before = true,
            .created_at_at_or_before = event->created_at
        };
        
        event_t **events = NULL;
        size_t count = 0;
        if (!storage->find_events(&scope, &events, &count)) {
            return false;
        }
        
        bool ok = true;
        for (size_t i = 0; i < count; i++) {
            if (event_tag_has_value(events[i], "d", d_identifier)) {
                storage_event_scope_t del_scope = { .id = events[i]->id };
                size_t deleted = 0;
                if (!storage->delete_events(&del_scope, &deleted) || deleted == 0) {
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
    tag_iter_t it;
    tag_iter_init(&it, event);
    struct mg_str key, tag;
    bool failed = false;
    if (!event || !storage) return false;
    if (!event->tags_json) return true;

    while (tag_iter_next(&it, &key, &tag)) {
        tag_iter_t sub;
        char *name;
        tag_iter_init_tag(&sub, tag);
        name = tag_iter_element(&sub, 0);
        if (!name) continue;
        /* NIP-09: only tag[1] is the reference. Trailing elements are relay hints/markers and MUST be ignored. */
        if (strcmp(name, "e") == 0) {
            char *id = tag_iter_element(&sub, 1);
            if (id) {
                if (!delete_e_target(event, storage, id)) failed = true;
                free(id);
            }
        } else if (strcmp(name, "a") == 0) {
            char *a = tag_iter_element(&sub, 1);
            if (a) {
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
    /* NIP-09: relays SHOULD continue to publish/share deletion requests. */
    storage_insert_result_t insert_result;
    if (!storage->insert_record) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "error: storage unavailable");
        return result;
    }
    insert_result = storage->insert_record(event, NULL, 0);
    result.accepted = true;
    result.should_store = true;
    result.should_broadcast = true;
    if (insert_result.result == STORAGE_OK) {
        result.response_msg[0] = '\0';
    } else if (insert_result.result == STORAGE_DUPLICATE) {
        snprintf(result.response_msg, sizeof(result.response_msg), "duplicate: already have this event");
    } else {
        snprintf(result.response_msg, sizeof(result.response_msg),
                 "error: %s", insert_result.error_message[0] ? insert_result.error_message : "storage error");
        result.accepted = false;
        result.should_broadcast = false;
        return result;
    }
    if (!deleted) {
        /* Targets missing or unauthorized: still accept (relay MAY validate), note it. */
        snprintf(result.response_msg, sizeof(result.response_msg), "duplicate: already have this event");
    }
    return result;
}

/* ============================================================================
 * Registration (using macro to eliminate boilerplate)
 * ============================================================================ */

NIP_REGISTER(nip09, nip09_caps)