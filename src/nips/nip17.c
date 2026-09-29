/* ============================================================================
 * NIP-17: Private Direct Messages (gift-wrap gating)
 *
 * Single-file NIP: gift-wrap delivery rules + auth-hint decision + capability
 * table + self-registration. Compiling this file enables the NIP; deleting
 * it removes it. No header, no registration list, no build edits.
 * ============================================================================ */

#include "nip_capability.h"
#include "model/event_tags.h"
#include "protocol/protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Gift-wrap kinds whose visibility may require NIP-42 auth. */
static bool nip17_targets_gift_wraps(const filter_t *filter) {
    if (!filter) return false;
    for (size_t i = 0; i < filter->kinds_count; i++) {
        if (filter->kinds[i] == 1059 || filter->kinds[i] == 21059) return true;
    }
    return false;
}

/* Enforce authenticated-recipient delivery for gift-wrap events. */
static bool nip17_is_visible_to(const event_t *event, const char *authenticated_pubkey) {
    return (event->kind != 1059 && event->kind != 21059) ||
           (authenticated_pubkey && event_tag_has_value(event, "p", authenticated_pubkey));
}

static bool nip17_delivery_policy_can_deliver(const event_t *event, uintptr_t connection_id, void *ctx);
static bool nip17_protocol_response_needs_auth_hint(const filter_t *filters, size_t filters_count,
                                                    uintptr_t connection_id, void *ctx);

/* Single capability table. Hooks ignore ctx, so .ctx is NULL (no
 * allocation, nothing to leak across reloads). */
static nip_capability_t nip17_caps[] = {
    {
        .name = "nip17-delivery-policy",
        .type = NIP_CAP_DELIVERY_POLICY,
        .ctx = NULL,
        .caps.delivery_policy = { .can_deliver = nip17_delivery_policy_can_deliver },
        .next = NULL,
    },
    /* NIP-17 contributes only the auth-hint decision; EOSE framing is owned
     * by NIP-67 (sole build_eose provider, so composition is
     * order-independent). */
    {
        .name = "nip17-protocol-response",
        .type = NIP_CAP_PROTOCOL_RESPONSE,
        .ctx = NULL,
        .caps.protocol_response = { .build_eose = NULL, .build_count = NULL,
                                    .needs_auth_hint = nip17_protocol_response_needs_auth_hint,
                                    .send_auth_challenge = NULL },
        .next = NULL,
    },
};

static bool nip17_delivery_policy_can_deliver(const event_t *event, uintptr_t connection_id, void *ctx) {
    (void)ctx;
    const char *authenticated_pubkey = nip42_authenticated_pubkey_by_id(connection_id);
    return nip17_is_visible_to(event, authenticated_pubkey);
}

static bool nip17_protocol_response_needs_auth_hint(const filter_t *filters, size_t filters_count,
                                                    uintptr_t connection_id, void *ctx) {
    (void)ctx;
    /* Unauthenticated gift-wrap subscriptions may hide results behind NIP-42
     * auth: hint the client (and refresh its challenge) before EOSE. */
    if (nip42_authenticated_pubkey_by_id(connection_id)) return false;
    if (!filters) return false;
    for (size_t i = 0; i < filters_count; i++) {
        if (nip17_targets_gift_wraps(&filters[i])) return true;
    }
    return false;
}

/* ============================================================================
 * Registration (using macro to eliminate boilerplate)
 * ============================================================================ */

NIP_REGISTER(nip17, nip17_caps)