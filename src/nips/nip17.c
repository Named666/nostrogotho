#include "nip17.h"
#include "nip_event.h"
#include "nip_plugin.h"
#include "nip42.h"

bool nip17_can_deliver(const event_t *event, const char *authenticated_pubkey) {
    return (event->kind != 1059 && event->kind != 21059) ||
           (authenticated_pubkey && nip_event_has_tag(event, "p", authenticated_pubkey));
}

/* ============================================================================
 * NIP-17: Private Direct Messages (plugin registration)
 *
 * Gift-wrapped events (kinds 1059 / 21059) are only delivered to the "p"-tag
 * recipient after NIP-42 authentication. Unauthenticated subscribers querying
 * gift-wrap kinds additionally get a fresh NIP-42 AUTH challenge plus the
 * NIP-67 "auth" completeness hint on EOSE.
 * ============================================================================ */

static bool nip17_plugin_can_deliver(const event_t *event, struct mg_connection *connection) {
    return nip17_can_deliver(event, nip42_authenticated_pubkey(connection));
}

static bool nip17_filter_targets_gift_wraps(const filter_t *filter) {
    for (size_t i = 0; i < filter->kinds_count; i++) {
        if (filter->kinds[i] == 1059 || filter->kinds[i] == 21059) return true;
    }
    return false;
}

/* Before EOSE: when an unauthenticated client subscribes to gift-wrap kinds,
 * more results may exist behind NIP-42 auth. Send a fresh AUTH challenge and
 * ask the server to flag the EOSE with the "auth" hint. */
static bool nip17_plugin_eose_auth_hint(struct mg_connection *connection,
                                        const filter_t *filters, size_t count) {
    if (nip42_authenticated_pubkey(connection)) return false;
    for (size_t i = 0; i < count; i++) {
        if (nip17_filter_targets_gift_wraps(&filters[i])) {
            char challenge[17];
            if (nip42_open_challenge(connection, challenge)) {
                json_builder_t builder;
                json_builder_start(&builder);
                json_builder_append_string(&builder, "AUTH");
                json_builder_append_string(&builder, challenge);
                nip_plugin_send_json(connection, json_builder_finish(&builder));
            }
            return true;
        }
    }
    return false;
}

static nip_plugin_t nip17_plugin = {
    .name = "nip17",
    .can_deliver = nip17_plugin_can_deliver,
    .eose_auth_hint = nip17_plugin_eose_auth_hint,
};

__attribute__((constructor)) static void nip17_register_at_startup(void) {
    nip_plugin_register(&nip17_plugin);
}