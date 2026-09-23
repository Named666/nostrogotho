#include <stdio.h>
#include "nip62.h"
#include "nip_event.h"
#include "nip01.h"
#include "nip_plugin.h"
#include "../storage.h"

bool nip62_should_vanish(const event_t *event, const char *service_url) {
    return nip_event_has_tag(event, "relay", "ALL_RELAYS") ||
           (service_url && *service_url && nip_event_has_relay_tag(event, service_url));
}

/* Listener for kind 62 (Request to Vanish) events. */
static nip01_process_result_t nip62_listener(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {

    (void)connection;

    /* NIP-62: "The tag list MUST include at least one `relay` value."
     * Reject kind-62 events that tag no relay at all. */
    if (!nip_event_has_tag(event, "relay", NULL)) {
        return nip_plugin_reject("invalid: kind 62 requires at least one relay tag");
    }

    if (!storage) {
        return nip_plugin_reject("error: storage unavailable");
    }

    if (nip62_should_vanish(event, relay_url)) {
        /* Delete all of the author's events except the vanish request itself
         * (kind 62). The exclusion is a NIP-62 policy decision, so it lives
         * here in the plugin — the storage layer stays generic. */
        int deleted = storage->delete_all_events_by_pubkey(event->pubkey,
                                                           event->created_at,
                                                           event->kind);
        if (deleted < 0) {
            return nip_plugin_reject("error: failed to vanish events");
        }
    }

    return nip_plugin_store_and_broadcast(storage, event);
}

/* ============================================================================
 * Plugin registration
 *
 * NIP-62 listens for kind 62 (Request to Vanish) events. Declaring the kind
 * in the plugin struct is the only wiring needed — nip_plugin_register()
 * hands it to the NIP-01 dispatcher.
 * ============================================================================ */

static nip_plugin_t nip62_plugin = {
    .name = "nip62",
    .kinds = { NIP_PLUGIN_KIND(62) },
    .kinds_count = 1,
    .on_event = nip62_listener,
};

/* Auto-register this NIP's plugin at program startup */
__attribute__((constructor)) static void nip62_register_at_startup(void) {
    nip_plugin_register(&nip62_plugin);
}