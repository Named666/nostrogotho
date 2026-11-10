#include "nip17.h"
#include "nip_event.h"
#include "nip_plugin.h"
#include "nip42.h"
#include <stdio.h>
#include <string.h>

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

static bool nip17_plugin_can_deliver(const event_t *event, relay_conn_t *connection,
                                     void *ctx) {
    (void) ctx;
    return nip17_can_deliver(event, nip42_authenticated_pubkey(connection));
}

static bool nip17_filter_targets_gift_wraps(const filter_t *filter) {
    for (size_t i = 0; i < filter->kinds_count; i++) {
        if (filter->kinds[i] == 1059 || filter->kinds[i] == 21059) return true;
    }
    return false;
}

/* The filter's "#p" values are exactly [pubkey]. */
static bool nip17_filter_only_p(const filter_t *filter, const char *pubkey) {
    bool found = false;
    for (size_t t = 0; t < filter->tags_count; t++) {
        const tag_t *tag = &filter->tags[t];
        if (strcmp(tag->elements[0], "p") != 0) continue;
        if (tag->count != 2 || strcmp(tag->elements[1], pubkey) != 0) return false;
        found = true;
    }
    return found;
}

/* COUNT is gated like REQ delivery (NIP-45 "Relay refuses to count"):
 * gift wraps are counted only for their authenticated recipient, and a
 * filter without kinds does not count anyone's gift wraps. */
static bool nip17_plugin_accept_query(relay_conn_t *connection, filter_t *filters, size_t count,
                                      bool is_count, char *reason, size_t reason_size, void *ctx) {
    (void) ctx;
    const char *me = nip42_authenticated_pubkey(connection);
    if (!is_count) {
        /* NIP-42 flow: a subscription to gift wraps before AUTH is closed
         * with "auth-required:" and a fresh challenge; after AUTH only the
         * recipient's own wraps are delivered (can_deliver). */
        for (size_t i = 0; i < count && !me; i++) {
            if (!nip17_filter_targets_gift_wraps(&filters[i])) continue;
            nip42_send_challenge(connection);
            snprintf(reason, reason_size, "auth-required: we can't serve DMs to unauthenticated users");
            return false;
        }
        return true;
    }
    for (size_t i = 0; i < count; i++) {
        filter_t *f = &filters[i];
        if (!nip17_filter_targets_gift_wraps(f)) {
            if (f->kinds_count == 0) f->hide_gift_wraps = true;
            continue;
        }
        if (!me) {
            nip42_send_challenge(connection);
            snprintf(reason, reason_size, "auth-required: cannot count other people's DMs");
            return false;
        }
        if (!nip17_filter_only_p(f, me)) {
            snprintf(reason, reason_size, "restricted: gift wraps can only be counted with \"#p\": [<your pubkey>]");
            return false;
        }
    }
    return true;
}

/* Before EOSE (NIP-67 "auth" hint): explicit gift-wrap kinds were already
 * refused by accept_query, so this is a kind-less filter from an
 * unauthenticated client, from which gift wraps were withheld (can_deliver).
 * The AUTH challenge NIP-42 sent on connect precedes this EOSE. */
static bool nip17_plugin_eose_auth_hint(relay_conn_t *connection,
                                        const filter_t *filters, size_t count,
                                        void *ctx) {
    (void) ctx;
    if (nip42_authenticated_pubkey(connection)) return false;
    for (size_t i = 0; i < count; i++) {
        if (filters[i].kinds_count == 0) return true;
    }
    return false;
}

static nip_plugin_t nip17_plugin = {
    .name = "nip17",
    .can_deliver = nip17_plugin_can_deliver,
    .accept_query = nip17_plugin_accept_query,
    .eose_auth_hint = nip17_plugin_eose_auth_hint,
};

__attribute__((constructor)) static void nip17_register_at_startup(void) {
    nip_plugin_register(&nip17_plugin);
}