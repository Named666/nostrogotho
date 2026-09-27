/* ============================================================================
 * NIP-09: Event Deletion (kind 5)
 *
 * Single-file NIP: deletion authorization + target handling + capability
 * table + self-registration. Compiling this file enables the NIP; deleting
 * it removes it. No header, no registration list, no build edits.
 * ============================================================================ */

#include "nip_capability.h"
#include "model/event_util.h"
#include "storage.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ============================================================================
 * NIP-09 Capability Implementation
 * 
 * Event deletion using the new transport-agnostic capability interface.
 * ============================================================================ */

/* Forward declarations */
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
 * Helper Functions (adapted from nip09.c)
 * ============================================================================ */

static bool kind_is_requested(const event_t *event, int kind) {
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    bool has_k = false;

    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = event_tag_element(tag.buf, 0);
        if (name && strcmp(name, "k") == 0) {
            has_k = true;
            char *value = event_tag_element(tag.buf, 1);
            if (value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end && *end == '\0' && parsed == kind) {
                    free(value);
                    free(name);
                    return true;
                }
                free(value);
            }
        }
        free(name);
    }
    return !has_k;
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

typedef struct {
    const char *tag_name;
    const char *tag_value;
    bool empty_value_when_missing;
} nip09_tag_match_t;

static bool nip09_event_has_exact_tag_value(const event_t *event, void *userdata) {
    const nip09_tag_match_t *match = (const nip09_tag_match_t *)userdata;
    struct mg_str key, tag, tags = mg_str(event->tags_json ? event->tags_json : "[]");
    size_t offset = 0;
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = event_tag_element(tag.buf, 0);
        if (name && strcmp(name, match->tag_name) == 0) {
            char *value = event_tag_element(tag.buf, 1);
            bool result = strcmp(value ? value : "", match->tag_value) == 0;
            free(value);
            free(name);
            return result;
        }
        free(name);
    }
    return match->empty_value_when_missing && match->tag_value[0] == '\0';
}

static bool nip09_delete_matching(storage_context_t *storage,
                                  const storage_event_scope_t *scope,
                                  storage_event_predicate_t predicate,
                                  void *userdata, size_t *deleted_total) {
    storage_event_scope_t page = *scope;
    char cursor[MAX_ID_SIZE + 1] = "";
    bool more = false;
    size_t total = 0;
    do {
        size_t deleted = 0;
        char next_id[MAX_ID_SIZE + 1] = "";
        page.after_id = cursor[0] ? cursor : NULL;
        if (!storage->delete_matching(&page, predicate, userdata, &deleted,
                                      next_id, sizeof(next_id), &more)) return false;
        total += deleted;
        snprintf(cursor, sizeof(cursor), "%s", next_id);
    } while (more);
    if (deleted_total) *deleted_total = total;
    return true;
}

static bool delete_a_target(const event_t *event, storage_context_t *storage,
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
        storage_delete_result_t result = storage->delete_record_by_kind_and_pubkey(kind, pubkey,
                                                           event->created_at);
        return result.result == STORAGE_OK && result.deleted_count >= 0;
    } else {
        storage_event_scope_t scope = {0};
        nip09_tag_match_t match = {"d", d_identifier, true};
        size_t deleted;
        scope.pubkey = pubkey;
        scope.has_kind = true;
        scope.kind = kind;
        scope.has_created_at_before = true;
        scope.created_at_before = event->created_at;
        return storage->delete_matching &&
               nip09_delete_matching(storage, &scope,
                                    nip09_event_has_exact_tag_value, &match,
                                    &deleted);
    }
}

static bool deletion_authorized(const event_t *event, const event_t *target) {
    if (strcmp(target->pubkey, event->pubkey) == 0) return true;
    return event_has_tag(target, "delegation", event->pubkey);
}

static bool delete_e_target(const event_t *event, storage_context_t *storage,
                            const char *id) {
    event_t *target = storage->get_event_by_id(id);
    bool ok = true;

    if (!target) return true;

    if (deletion_authorized(event, target) &&
        kind_is_requested(event, target->kind)) {
        if (target->kind == 1059) {
            storage_event_scope_t scope = {0};
            nip09_tag_match_t match = {"p", event->pubkey, false};
            size_t deleted = 0;
            scope.id = id;
            scope.has_kind = true;
            scope.kind = 1059;
            if (!storage->delete_matching ||
                !nip09_delete_matching(storage, &scope,
                                      nip09_event_has_exact_tag_value, &match,
                                      &deleted) || deleted == 0) ok = false;
        } else {
            storage_delete_result_t result = storage->delete_record_by_id_and_pubkey(id, event->pubkey);
            if (result.result != STORAGE_OK || result.deleted_count <= 0) ok = false;
        }
    }
    event_free(target);
    return ok;
}

static bool nip09_delete_targets(const event_t *event, storage_context_t *storage) {
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    bool failed = false;

    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = event_tag_element(tag.buf, 0);
        if (!name) continue;
        if (strcmp(name, "e") == 0) {
            for (size_t index = 1;; index++) {
                char *id = event_tag_element(tag.buf, index);
                if (!id) break;
                if (!delete_e_target(event, storage, id)) failed = true;
                free(id);
            }
        } else if (strcmp(name, "a") == 0) {
            for (size_t index = 1;; index++) {
                char *a = event_tag_element(tag.buf, index);
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
 * Registration
 * ============================================================================ */

void nip09_register(nip_registry_t *registry) {
    if (!registry) return;
    for (size_t i = 0; i < sizeof(nip09_caps) / sizeof(nip09_caps[0]); i++)
        nip_registry_register(registry, &nip09_caps[i]);
}

/* Self-registration: compiling this file enables the NIP; deleting it
 * removes the capability without touching protocol/transport code. */
__attribute__((constructor)) static void nip09_register_provider(void) {
    nip_capability_add_provider(nip09_register);
}