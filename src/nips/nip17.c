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

/* Send a fresh NIP-42 challenge (the client may have ignored the first). */
static void nip17_send_challenge(relay_conn_t *connection) {
    char challenge[17];
    if (!nip42_open_challenge(connection, challenge)) return;
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "AUTH");
    json_builder_append_string(&builder, challenge);
    const char *j = json_builder_finish(&builder);
    nip_plugin_send_json(connection, j ? j : "[\"NOTICE\",\"error: server out of memory\"]");
    json_builder_free(&builder);
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
            nip17_send_challenge(connection);
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
            nip17_send_challenge(connection);
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

/* Before EOSE: when an unauthenticated client subscribes to gift-wrap kinds,
 * more results may exist behind NIP-42 auth. Send a fresh AUTH challenge and
 * ask the server to flag the EOSE with the "auth" hint. */
static bool nip17_plugin_eose_auth_hint(relay_conn_t *connection,
                                        const filter_t *filters, size_t count,
                                        void *ctx) {
    (void) ctx;
    if (nip42_authenticated_pubkey(connection)) return false;
    for (size_t i = 0; i < count; i++) {
        if (nip17_filter_targets_gift_wraps(&filters[i])) {
            nip17_send_challenge(connection);
            return true;
        }
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