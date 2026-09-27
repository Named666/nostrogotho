/* ============================================================================
 * NIP-13: Proof of Work
 *
 * Single-file NIP: PoW verification + minimum-difficulty policy + capability
 * table + self-registration. Compiling this file enables the NIP; deleting
 * it removes it. No header, no registration list, no build edits.
 * ============================================================================ */

#include "nip_capability.h"
#include "crypto.h"
#include "model/event_util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ============================================================================
 * NIP-13 Capability Implementation
 * 
 * Proof of Work using the new transport-agnostic capability interface.
 * ============================================================================ */

typedef struct {
    int min_difficulty;
} nip13_ctx_t;

/* Shared static ctx: re-derived in lifecycle init on every startup/reload,
 * so no heap allocation and nothing to leak or migrate. */
static nip13_ctx_t nip13_ctx;

/* Forward declarations */
static void nip13_lifecycle_init(const relay_config_t *config, void *ctx);
static bool nip13_publication_policy_accept_publish(
    connection_id_t connection_id, const event_t *event,
    char *reason, size_t reason_size, void *ctx);

/* Single capability table. */
static nip_capability_t nip13_caps[] = {
    {
        .name = "nip13-lifecycle",
        .type = NIP_CAP_LIFECYCLE,
        .ctx = &nip13_ctx,
        .caps.lifecycle = { .init = nip13_lifecycle_init, .shutdown = NULL },
        .next = NULL,
    },
    {
        .name = "nip13-publication-policy",
        .type = NIP_CAP_PUBLICATION_POLICY,
        .ctx = &nip13_ctx,
        .caps.publication_policy = { .accept_publish = nip13_publication_policy_accept_publish },
        .next = NULL,
    },
};

/* ============================================================================
 * Helper Functions (adapted from nip13.c)
 * ============================================================================ */

static int nip13_committed_target(const event_t *event) {
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    int target = 0;

    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = event_tag_element(tag.buf, 0);
        if (name && strcmp(name, "nonce") == 0) {
            char *value = event_tag_element(tag.buf, 2);
            free(name);
            if (value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end && *end == '\0' && parsed > 0 && parsed <= 256) {
                    target = (int) parsed;
                }
                free(value);
            }
            return target;
        }
        free(name);
    }
    return target;
}

/* ============================================================================
 * Lifecycle Implementation
 * ============================================================================ */

static void nip13_lifecycle_init(const relay_config_t *config, void *ctx) {
    nip13_ctx_t *cap_ctx = (nip13_ctx_t *)ctx;
    if (cap_ctx) {
        cap_ctx->min_difficulty = config->min_pow_difficulty;
    }
}

/* ============================================================================
 * Publication Policy Implementation
 * ============================================================================ */

static bool nip13_publication_policy_accept_publish(
    connection_id_t connection_id, const event_t *event,
    char *reason, size_t reason_size, void *ctx) {
    (void)connection_id;
    
    nip13_ctx_t *cap_ctx = (nip13_ctx_t *)ctx;
    int min_difficulty = cap_ctx ? cap_ctx->min_difficulty : 0;
    
    if (min_difficulty <= 0) return true;

    int committed = nip13_committed_target(event);
    int required = committed > min_difficulty ? committed : min_difficulty;
    int bits = count_leading_zero_bits(event->id);
    if (bits >= required) return true;

    snprintf(reason, reason_size, "pow: difficulty %d>=%d", bits, required);
    return false;
}

/* ============================================================================
 * Registration
 * ============================================================================ */

void nip13_register(nip_registry_t *registry) {
    if (!registry) return;
    for (size_t i = 0; i < sizeof(nip13_caps) / sizeof(nip13_caps[0]); i++)
        nip_registry_register(registry, &nip13_caps[i]);
}

/* Self-registration: compiling this file enables the NIP; deleting it
 * removes the capability without touching protocol/transport code. */
__attribute__((constructor)) static void nip13_register_provider(void) {
    nip_capability_add_provider(nip13_register);
}