/* ============================================================================
 * NIP-45: COUNT Request / Response
 *
 * Single-file NIP: COUNT response builder + protocol-response capability +
 * self-registration. Compiling this file enables the NIP; deleting it
 * removes it. No header, no registration list.
 *
 * Format: ["COUNT", <subscription_id>, {"count": <integer>}]
 * The storage layer supplies the count; this NIP only formats the reply.
 * ============================================================================ */

#include "nip_capability.h"
#include "../json_util.h"
#include <stdlib.h>

/* Build a COUNT response message. Returns malloc'd JSON (caller frees). */
static char *nip45_build_count_response(const char *sub_id, unsigned long count) {
    if (!sub_id) return NULL;

    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "COUNT");
    json_builder_append_string(&builder, sub_id);
    json_builder_start_object(&builder);
    json_builder_object_key_number(&builder, "count", (long long)count);
    json_builder_end_object(&builder);

    const char *result = json_builder_finish(&builder);
    if (!result) return NULL;

    /* json_builder_finish returns a pointer to internal buffer,
     * so duplicate it for the caller to own. */
    char *dup = malloc(strlen(result) + 1);
    if (!dup) return NULL;
    strcpy(dup, result);
    return dup;
}

static char *nip45_protocol_response_build_count(const char *sub, unsigned long count, void *ctx) {
    (void)ctx;
    return nip45_build_count_response(sub, count);
}

/* Single capability table. The hook ignores ctx, so .ctx is NULL (no
 * allocation, nothing to leak across reloads). */
static nip_capability_t nip45_caps[] = {
    {
        .name = "nip45-protocol-response",
        .type = NIP_CAP_PROTOCOL_RESPONSE,
        .ctx = NULL,
        .caps.protocol_response = { .build_count = nip45_protocol_response_build_count },
        .next = NULL,
    },
};

void nip45_register(nip_registry_t *registry) {
    if (!registry) return;
    for (size_t i = 0; i < sizeof(nip45_caps) / sizeof(nip45_caps[0]); i++)
        nip_registry_register(registry, &nip45_caps[i]);
}

/* Self-registration: compiling this file enables the NIP; deleting it
 * removes the capability without touching protocol/transport code. */
__attribute__((constructor)) static void nip45_register_provider(void) {
    nip_capability_add_provider(nip45_register);
}
