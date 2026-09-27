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
#include "model/event_util.h"
#include "../storage.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Check whether a Request to Vanish applies to this relay. */
static bool nip62_should_vanish(const event_t *event, const char *service_url) {
    return event_has_tag(event, "relay", "ALL_RELAYS") ||
           (service_url && *service_url && event_has_relay_tag(event, service_url));
}

static bool nip62_select_all(const event_t *event, void *userdata) {
    (void)event;
    (void)userdata;
    return true;
}

static bool nip62_delete_events(storage_context_t *storage, const char *pubkey,
                                time_t created_at, int keep_kind) {
    storage_event_scope_t scope = {0};
    char cursor[MAX_ID_SIZE + 1] = "";
    bool more = false;
    scope.pubkey = pubkey;
    scope.has_created_at_at_or_before = true;
    scope.created_at_at_or_before = created_at;
    scope.has_excluded_kind = true;
    scope.excluded_kind = keep_kind;
    do {
        size_t deleted = 0;
        char next_id[MAX_ID_SIZE + 1] = "";
        scope.after_id = cursor[0] ? cursor : NULL;
        if (!storage->delete_matching(&scope, nip62_select_all, NULL, &deleted,
                                      next_id, sizeof(next_id), &more)) return false;
        snprintf(cursor, sizeof(cursor), "%s", next_id);
    } while (more);
    return true;
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
    if (!event_has_tag(event, "relay", NULL)) {
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

    if (nip62_should_vanish(event, relay_url)) {
        /* Delete all of the author's events except the vanish request itself
         * (kind 62). The exclusion is a NIP-62 policy decision, so it lives
         * here in the NIP — the storage layer stays generic. */
        if (!storage->delete_matching ||
            !nip62_delete_events(storage, event->pubkey, event->created_at,
                                 event->kind)) {
            nip01_process_result_t result = {0};
            result.accepted = false;
            snprintf(result.response_msg, sizeof(result.response_msg), "error: failed to vanish events");
            return result;
        }
    }

    /* Accept with broadcast — the relay core handles storage and delivery
     * through the composition layer. NIP-62 never sends WebSocket frames. */
    nip01_process_result_t result = {0};
    result.accepted = true;
    result.should_broadcast = true;
    return result;
}

void nip62_register(nip_registry_t *registry) {
    if (!registry) return;
    for (size_t i = 0; i < sizeof(nip62_caps) / sizeof(nip62_caps[0]); i++)
        nip_registry_register(registry, &nip62_caps[i]);
}

/* Self-registration: compiling this file enables the NIP; deleting it
 * removes the capability without touching protocol/transport code. */
__attribute__((constructor)) static void nip62_register_provider(void) {
    nip_capability_add_provider(nip62_register);
}
