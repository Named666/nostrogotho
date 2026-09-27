/* ============================================================================
 * NIP-11: Relay Information Document
 *
 * Single-file NIP: document rendering + lifecycle/metadata capabilities +
 * self-registration. Compiling this file enables the NIP; deleting it
 * removes it. No header, no registration list, no build edits.
 *
 * The supported_nips list is derived from the NIPs actually wired into the
 * server, and the limitation block from the real runtime constants passed in
 * via lifecycle init. Keeping protocol claims next to their implementation
 * prevents the document from drifting out of sync with the code.
 * ============================================================================ */

#include "nip_capability.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

static char information_document[1024];

/* NIPs implemented and wired into the request path:
 *   01 basic protocol, 09 deletion, 11 this document, 13 PoW,
 *   16 replaceable (via NIP-01), 17 gift-wrap gating, 26 delegation,
 *   33 addressable (via NIP-01), 40 expiration, 42 auth, 45 COUNT,
 *   62 vanish, 67 EOSE hints. */
static const int supported_nips[] = {1, 9, 11, 13, 16, 17, 26, 33, 40, 42, 45, 62, 67};
#define SUPPORTED_NIPS_COUNT (sizeof(supported_nips) / sizeof(supported_nips[0]))

/* NIP-11 wire-key names for the limitation block; filled from the canonical
 * relay_config_t in lifecycle init (no legacy config aliases). */
static struct {
    int max_message_length;
    int max_subscriptions;
    int max_filters;
    int max_subid_length;
    int max_event_tags;
    int max_content_length;
    int min_pow_difficulty;
    int max_limit;
    long long created_at_lower_limit;
    long long created_at_upper_limit;
} nip11_config;

static const char *nip11_information_document(void) {
    size_t offset = 0;
    size_t capacity = sizeof(information_document);
    int written;

    written = snprintf(information_document, capacity,
                       "{\"name\":\"nostrogotho\",\"supported_nips\":[");
    if (written < 0 || (size_t) written >= capacity) return "{}";
    offset = (size_t) written;

    for (size_t i = 0; i < SUPPORTED_NIPS_COUNT; i++) {
        written = snprintf(information_document + offset, capacity - offset,
                           "%s%d", i ? "," : "", supported_nips[i]);
        if (written < 0 || offset + (size_t) written >= capacity) return "{}";
        offset += (size_t) written;
    }

    written = snprintf(information_document + offset, capacity - offset,
                       "],\"limitation\":{");
    if (written < 0 || offset + (size_t) written >= capacity) return "{}";
    offset += (size_t) written;

    bool first = true;
    struct { const char *key; int value; bool enabled; } int_fields[] = {
        {"max_message_length", nip11_config.max_message_length, nip11_config.max_message_length > 0},
        {"max_subscriptions", nip11_config.max_subscriptions, nip11_config.max_subscriptions > 0},
        {"max_filters", nip11_config.max_filters, nip11_config.max_filters > 0},
        {"max_subid_length", nip11_config.max_subid_length, nip11_config.max_subid_length > 0},
        {"max_event_tags", nip11_config.max_event_tags, nip11_config.max_event_tags > 0},
        {"max_content_length", nip11_config.max_content_length, nip11_config.max_content_length > 0},
        {"min_pow_difficulty", nip11_config.min_pow_difficulty, nip11_config.min_pow_difficulty > 0},
        {"max_limit", nip11_config.max_limit, nip11_config.max_limit > 0},
    };
    for (size_t i = 0; i < sizeof(int_fields) / sizeof(int_fields[0]); i++) {
        if (!int_fields[i].enabled) continue;
        written = snprintf(information_document + offset, capacity - offset,
                           "%s\"%s\":%d", first ? "" : ",", int_fields[i].key,
                           int_fields[i].value);
        if (written < 0 || offset + (size_t) written >= capacity) return "{}";
        offset += (size_t) written;
        first = false;
    }
    if (nip11_config.created_at_lower_limit > 0) {
        written = snprintf(information_document + offset, capacity - offset,
                           "%s\"created_at_lower_limit\":%lld", first ? "" : ",",
                           nip11_config.created_at_lower_limit);
        if (written < 0 || offset + (size_t) written >= capacity) return "{}";
        offset += (size_t) written;
        first = false;
    }
    if (nip11_config.created_at_upper_limit > 0) {
        written = snprintf(information_document + offset, capacity - offset,
                           "%s\"created_at_upper_limit\":%lld", first ? "" : ",",
                           nip11_config.created_at_upper_limit);
        if (written < 0 || offset + (size_t) written >= capacity) return "{}";
        offset += (size_t) written;
        first = false;
    }
    /* The relay has no authenticated-only mode; always advertise false. */
    written = snprintf(information_document + offset, capacity - offset,
                       "%s\"auth_required\":false}", first ? "" : ",");
    if (written < 0 || offset + (size_t) written >= capacity) return "{}";
    offset += (size_t) written;

    if (offset + 2 <= capacity) {
        information_document[offset++] = '}';
        information_document[offset] = '\0';
    }
    return information_document;
}

/* ============================================================================
 * Capabilities: lifecycle captures runtime limits; metadata serves them.
 * ============================================================================ */

static void nip11_lifecycle_init(const relay_config_t *config, void *ctx) {
    (void)ctx;
    if (!config) return;
    nip11_config.max_message_length = config->max_ws_message_length;
    nip11_config.max_subscriptions = config->max_subscriptions_per_connection;
    nip11_config.max_filters = config->max_filters_per_subscription;
    nip11_config.max_subid_length = config->max_subscription_id_length;
    nip11_config.max_event_tags = config->max_event_tags;
    nip11_config.max_content_length = config->max_event_content_length;
    nip11_config.min_pow_difficulty = config->min_pow_difficulty;
    nip11_config.max_limit = config->max_query_limit;
    nip11_config.created_at_lower_limit = (long long)config->created_at_lower_limit;
    nip11_config.created_at_upper_limit = (long long)config->created_at_upper_limit;
}

static void nip11_lifecycle_shutdown(void *ctx) {
    (void)ctx;
}

static const char *nip11_metadata_info_document(void *ctx) {
    (void)ctx;
    return nip11_information_document();
}

static nip_capability_t nip11_caps[] = {
    {
        .name = "nip11-lifecycle",
        .type = NIP_CAP_LIFECYCLE,
        .ctx = NULL,
        .caps.lifecycle = { .init = nip11_lifecycle_init,
                            .shutdown = nip11_lifecycle_shutdown },
        .next = NULL,
    },
    {
        .name = "nip11-metadata",
        .type = NIP_CAP_METADATA,
        .ctx = NULL,
        .caps.metadata = { .info_document = nip11_metadata_info_document },
        .next = NULL,
    },
};

/* ============================================================================
 * Registration (using macro to eliminate boilerplate)
 * ============================================================================ */

NIP_REGISTER(nip11, nip11_caps)
