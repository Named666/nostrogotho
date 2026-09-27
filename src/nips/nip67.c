/* ============================================================================
 * NIP-67: EOSE Completeness Hints ("finish" / "more" / "auth")
 *
 * Single-file NIP: EOSE response builder + protocol-response capability +
 * self-registration. Compiling this file enables the NIP; deleting it
 * removes it. No header, no registration list.
 *
 * The relay owns the limit+1 query algorithm and calls build_eose with the
 * outcome; this NIP only formats the reply. Relays MUST send an AUTH
 * challenge before an EOSE carrying the "auth" hint — the caller owns that
 * ordering (see NIP-17 hint + NIP-42 challenge hooks).
 * ============================================================================ */

#include "nip_capability.h"
#include "../json_util.h"
#include "model/event_util.h"
#include <stdlib.h>
#include <string.h>

/* Build an EOSE response. `has_more` selects "more" vs "finish"; `auth_hint`
 * adds the "auth" hint. Returns malloc'd JSON (caller frees). */
static char *nip67_build_eose_response_ex(const char *sub_id, bool has_more,
                                          bool auth_hint) {
    if (!sub_id) return NULL;

    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "EOSE");
    json_builder_append_string(&builder, sub_id);
    json_builder_start_array(&builder);
    if (auth_hint) {
        json_builder_append_string(&builder, "auth");
    }
    json_builder_append_string(&builder, has_more ? "more" : "finish");
    json_builder_end_array(&builder);

    const char *result = json_builder_finish(&builder);
    if (!result) return NULL;

    /* json_builder_finish returns a pointer to internal buffer,
     * so duplicate it for the caller to own. */
    return string_dup(result);
}

/* Function must be defined before the static table below that references it. */
static char *nip67_build_eose_for_relay(const char *sub, bool has_more, bool auth_hint, void *ctx) {
    (void)ctx;
    return nip67_build_eose_response_ex(sub, has_more, auth_hint);
}

/* Single capability table. The hook ignores ctx, so .ctx is NULL (no
 * allocation, nothing to leak across reloads). */
static nip_capability_t nip67_caps[] = {
    {
        .name = "nip67-protocol-response",
        .type = NIP_CAP_PROTOCOL_RESPONSE,
        .ctx = NULL,
        .caps.protocol_response = { .build_eose = nip67_build_eose_for_relay },
        .next = NULL,
    },
};

void nip67_register(nip_registry_t *registry) {
    if (!registry) return;
    for (size_t i = 0; i < sizeof(nip67_caps) / sizeof(nip67_caps[0]); i++)
        nip_registry_register(registry, &nip67_caps[i]);
}

/* Self-registration: compiling this file enables the NIP; deleting it
 * removes the capability without touching protocol/transport code. */
__attribute__((constructor)) static void nip67_register_provider(void) {
    nip_capability_add_provider(nip67_register);
}
