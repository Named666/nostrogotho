#include <mongoose.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "nip09.h"
#include "nip_event.h"
#include "nip01.h"

/* ---------------------------------------------------------------------------
 * NIP-09 — Event Deletion Request
 *
 * A kind 5 event references targets via "e" tags (specific events) and "a"
 * tags (replaceable/addressable events, "<kind>:<pubkey>:<d-identifier>").
 * The relay deletes a referenced event only when it has knowledge of it and
 * the referenced event shares the deletion request's author pubkey.
 *
 * Optional "k" tags list the kinds being deleted; when present, a target is
 * only deleted if its kind is among them (requested-vs-actual kind check).
 * ------------------------------------------------------------------------- */

/* Return true if the deletion event has no "k" tags, or if `kind` is listed
 * among them. Lets the relay validate requested-vs-actual kind. */
static bool kind_is_requested(const event_t *event, int kind) {
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    bool has_k = false;

    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = nip_tag_element(tag, 0);
        if (name && strcmp(name, "k") == 0) {
            has_k = true;
            char *value = nip_tag_element(tag, 1);
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

/* Parse an "a" tag value of the form "<kind>:<pubkey>:<d-identifier>".
 * Returns true on success. `d_identifier` points into `a` (may be empty). */
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
        /* No d-identifier — treat as a replaceable event with empty id. */
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

/* Delete a replaceable/addressable event referenced by an "a" tag.
 * Returns false only on a storage error; targets the relay has no knowledge
 * of, or that fail author/kind validation, are skipped without failing. */
static bool delete_a_target(const event_t *event, storage_context_t *storage,
                            const char *a) {
    int kind;
    char pubkey[MAX_PUBKEY_SIZE + 1];
    const char *d_identifier;
    int result;

    if (!parse_a_tag(a, &kind, pubkey, sizeof(pubkey), &d_identifier)) {
        return true;  /* Malformed "a" tag — nothing to act on. */
    }

    /* Author-scoped: the "a" tag pubkey must match the deletion author,
     * either directly or because the deletion author delegated to it
     * (NIP-26: the delegator may delete delegatee events). */
    if (strcmp(pubkey, event->pubkey) != 0) return true;

    /* Validate requested kind against any "k" tags. */
    if (!kind_is_requested(event, kind)) return true;

    if (*d_identifier == '\0') {
        /* Replaceable event (e.g. kind 0, 3, 10000-20000). */
        result = storage->delete_record_by_kind_and_pubkey(kind, pubkey,
                                                           event->created_at);
    } else {
        /* Addressable event (kind 30000-40000) with a "d" identifier. */
        char *elements[2] = {"d", (char *)d_identifier};
        tag_t dtag = {elements, 2, 2};
        result = storage->delete_record_by_kind_and_pubkey_and_dtag(
            kind, pubkey, &dtag, event->created_at);
    }
    return result >= 0;
}

/* Return true when `event` (the deletion author) is authorized to delete
 * `target`. Direct authorship matches, and per NIP-26 the delegator may
 * delete events published by their delegatee (target carries a delegation
 * tag naming the delegator). */
static bool deletion_authorized(const event_t *event, const event_t *target) {
    if (strcmp(target->pubkey, event->pubkey) == 0) return true;
    /* NIP-26: delegator can delete delegatee events. */
    return nip_event_has_tag(target, "delegation", event->pubkey);
}

/* Delete a specific event referenced by an "e" tag.
 * Returns false only on a storage error; targets the relay has no knowledge
 * of, or that fail author/kind validation, are skipped without failing. */
static bool delete_e_target(const event_t *event, storage_context_t *storage,
                            const char *id) {
    event_t *target = storage->get_event_by_id(id);
    int result;
    bool ok = true;

    if (!target) return true;  /* No knowledge of this event — nothing to do. */

    /* Author-scoped: only delete if the deletion author matches the target's
     * pubkey (directly or via NIP-26 delegation), and (when "k" tags are
     * present) the target's kind is requested. */
    if (deletion_authorized(event, target) &&
        kind_is_requested(event, target->kind)) {
        if (target->kind == 1059) {
            tag_t recipient = {(char *[]) {"p", (char *) event->pubkey}, 2, 2};
            result = storage->delete_record_by_id_and_kind_and_ptag(
                id, 1059, &recipient);
        } else {
            result = storage->delete_record_by_id_and_pubkey(id, event->pubkey);
        }
        if (result <= 0) ok = false;
    }
    event_free(target);
    return ok;
}

/* Apply the authorized targets in a NIP-09 deletion event. */
bool nip09_delete_targets(const event_t *event, storage_context_t *storage) {
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    bool failed = false;

    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = nip_tag_element(tag, 0);
        if (!name) continue;
        if (strcmp(name, "e") == 0) {
            for (size_t index = 1;; index++) {
                char *id = nip_tag_element(tag, index);
                if (!id) break;
                if (!delete_e_target(event, storage, id)) failed = true;
                free(id);
            }
        } else if (strcmp(name, "a") == 0) {
            for (size_t index = 1;; index++) {
                char *a = nip_tag_element(tag, index);
                if (!a) break;
                if (!delete_a_target(event, storage, a)) failed = true;
                free(a);
            }
        }
        free(name);
    }
    return !failed;
}

/* Listener for kind 5 (Event Deletion) events. */
static nip01_process_result_t nip09_listener(
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

    bool deleted = nip09_delete_targets(event, storage);
    result.accepted = true;
    result.should_broadcast = false;  /* Deletion events are typically not broadcast */
    snprintf(result.response_msg, sizeof(result.response_msg), "%s",
            deleted ? "" : "deletion failed");

    return result;
}

/* Auto-register this NIP's listener at program startup */
__attribute__((constructor)) static void nip09_register_at_startup(void) {
    nip01_register_listener(5, 5, nip09_listener);
}