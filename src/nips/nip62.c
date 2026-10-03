/* ============================================================================
 * NIP-62: Request to Vanish (kind 62)
 *
 * Single-file NIP: vanish policy + storage sweep + kind handler + capability
 * table + self-registration. Compiling this file enables the NIP; deleting
 * it removes it. No header, no registration list.
 *
 * A kind-62 event MUST tag at least one `relay`. When it targets this relay
 * ("ALL_RELAYS" or our service URL), all of the author's older events
 * (except the vanish request itself) are deleted through the generic storage
 * API — the NIP never touches SQLite.
 * ============================================================================ */

#include "nip_capability.h"
#include "protocol/event_tags.h"
#include "../storage.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Check whether a Request to Vanish applies to this relay. */
static bool nip62_should_vanish(const event_t *event, const char *service_url) {
    return event_tag_has_value(event, "relay", "ALL_RELAYS") ||
           (service_url && *service_url && event_tag_has_value(event, "relay", service_url));
}

/* Delete gift-wraps (kind 1059) that p-tag the vanisher (NIP-62 SHOULD). Best-effort sweep. */
static bool nip62_delete_giftwraps_to(storage_context_t *storage, const char *pubkey, time_t created_at) {
    bool ok = true;
    storage_event_scope_t scope = {0};
    char **ids = NULL;
    size_t id_count = 0;
    if (!storage || !pubkey) return false;
    if (storage->find_ids_by_tags && storage->free_id_list) {
        const char *names[1] = { "p" };
        const char *values[1] = { pubkey };
        if (!storage->find_ids_by_tags(names, values, 1, &ids, &id_count)) return false;
        for (size_t i = 0; i < id_count; i++) {
            event_t *ev = storage->get_event_by_id ? storage->get_event_by_id(ids[i]) : NULL;
            if (!ev) continue;
            if (ev->kind == 1059 && ev->created_at <= created_at && event_tag_has_value(ev, "p", pubkey)) {
                storage_event_scope_t del = {0};
                size_t deleted = 0;
                del.id = ev->id;
                if (!storage->delete_events || !storage->delete_events(&del, &deleted)) ok = false;
            }
            event_free(ev);
        }
        storage->free_id_list(ids, id_count);
        return ok;
    }
    scope.limit = 512;
    scope.offset = 0;
    for (;;) {
        event_t **page = NULL;
        size_t n = 0;
        if (!storage->find_events || !storage->find_events(&scope, &page, &n)) return false;
        if (n == 0) { free(page); break; }
        for (size_t i = 0; i < n; i++) {
            if (page[i]->kind == 1059 && page[i]->created_at <= created_at && event_tag_has_value(page[i], "p", pubkey)) {
                storage_event_scope_t del = {0};
                size_t deleted = 0;
                del.id = page[i]->id;
                if (!storage->delete_events || !storage->delete_events(&del, &deleted)) ok = false;
            }
            event_free(page[i]);
        }
        free(page);
        if (n < 512) break;
        scope.offset += n;
    }
    return ok;
}

/* Delete all events by pubkey up to created_at, excluding keep_kind */
static bool nip62_delete_events(storage_context_t *storage, const char *pubkey,
                                time_t created_at, int keep_kind) {
    storage_event_scope_t scope = {0};
    scope.pubkey = pubkey;
    scope.has_created_at_at_or_before = true;
    scope.created_at_at_or_before = created_at;
    scope.has_excluded_kind = true;
    scope.excluded_kind = keep_kind;
    
    size_t deleted = 0;
    return storage->delete_events(&scope, &deleted);
}

static bool nip62_kind_handler_handles_kind(int kind, void *ctx);
static nip01_process_result_t nip62_kind_handler_process_event(
    uintptr_t connection_id, const event_t *event,
    storage_context_t *storage, const char *relay_url, void *ctx);

/* Single capability table. Hooks ignore ctx, so .ctx is NULL (no
 * allocation, nothing to leak across reloads). */
static nip_capability_t nip62_caps[] = {
    {
        .name = "nip62-kind-handler",
        .type = NIP_CAP_KIND_HANDLER,
        .ctx = NULL,
        .caps.kind_handler = {
            .handles_kind = nip62_kind_handler_handles_kind,
            .process_event = nip62_kind_handler_process_event,
        },
        .next = NULL,
    },
};

static bool nip62_kind_handler_handles_kind(int kind, void *ctx) {
    (void)ctx;
    return kind == 62;
}

static nip01_process_result_t nip62_kind_handler_process_event(
    uintptr_t connection_id, const event_t *event,
    storage_context_t *storage, const char *relay_url, void *ctx) {
    (void)connection_id;
    (void)ctx;

    /* NIP-62: "The tag list MUST include at least one `relay` value."
     * Reject kind-62 events that tag no relay at all. */
    if (!event_tag_has(event, "relay")) {
        nip01_process_result_t result = {0};
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "invalid: kind 62 requires at least one relay tag");
        return result;
    }

    if (!storage) {
        nip01_process_result_t result = {0};
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "error: storage unavailable");
        return result;
    }

    if (!event) {
        nip01_process_result_t r = {0};
        r.accepted = false;
        snprintf(r.response_msg, sizeof(r.response_msg), "error: invalid event");
        return r;
    }
    if (nip62_should_vanish(event, relay_url)) {
        /* Delete all of the author's events except the vanish request itself
         * (kind 62). The exclusion is a NIP-62 policy decision, so it lives
         * here in the NIP — the storage layer stays generic. */
        if (!storage->delete_events ||
            !nip62_delete_events(storage, event->pubkey, event->created_at,
                                 event->kind)) {
            nip01_process_result_t result = {0};
            result.accepted = false;
            snprintf(result.response_msg, sizeof(result.response_msg), "error: failed to vanish events");
            return result;
        }
        /* NIP-62 SHOULD delete gift-wraps that p-tag the vanisher. Best-effort; failure does not fail vanish. */
        (void)nip62_delete_giftwraps_to(storage, event->pubkey, event->created_at);
        /* NOTE: NIP-62 MUST prevent re-broadcast requires a tombstone (pubkey, vanish_at) checked in a
         * publication policy. Not yet stored host-side; re-published older events will currently be accepted.
         * Documented limitation, not silent. */
    }

    /* Accept with broadcast — the relay core handles storage and delivery
     * through the composition layer. NIP-62 never sends WebSocket frames.
     * Vanish requests themselves are never stored (MAY store); broadcast notifies other relays. */
    nip01_process_result_t result = {0};
    result.accepted = true;
    result.should_store = false;
    result.should_broadcast = true;
    return result;
}

/* ============================================================================
 * Registration (using macro to eliminate boilerplate)
 * ============================================================================ */

NIP_REGISTER(nip62, nip62_caps)