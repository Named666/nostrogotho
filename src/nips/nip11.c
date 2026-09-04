#include "nip11.h"
#include "nip_plugin.h"
#include <stdio.h>
#include <stdbool.h>

/* ============================================================================
 * NIP-11: Relay Information Document
 *
 * The supported_nips list is derived from the NIPs actually wired into the
 * server, and the limitation block from the real runtime constants passed in
 * via nip11_configure(). Keeping protocol claims next to their implementations
 * prevents the document from drifting out of sync with the code.
 * ============================================================================ */

static char information_document[1024];

/* NIPs implemented and wired into the request path:
 *   01 basic protocol, 09 deletion, 11 this document, 13 PoW,
 *   16 replaceable (via NIP-01), 17 gift-wrap gating, 26 delegation,
 *   33 addressable (via NIP-01), 40 expiration, 42 auth, 45 COUNT,
 *   62 vanish, 67 EOSE hints. */
static const int supported_nips[] = {1, 9, 11, 13, 16, 17, 26, 33, 40, 42, 45, 62, 67};
#define SUPPORTED_NIPS_COUNT (sizeof(supported_nips) / sizeof(supported_nips[0]))

static struct {
    int max_message_length;
    int max_subscriptions;
    int max_filters;
    int max_subid_length;
    int max_event_tags;
    int max_content_length;
    int min_pow_difficulty;
    int max_limit;
    int default_limit;
    long long created_at_lower_limit;
    long long created_at_upper_limit;
    bool auth_required;
} nip11_config;

void nip11_configure(int max_message_length, int max_subscriptions,
                     int max_filters, int max_subid_length,
                     int max_event_tags, int max_content_length,
                     int min_pow_difficulty, int max_limit, int default_limit,
                     time_t created_at_lower_limit,
                     time_t created_at_upper_limit, bool auth_required) {
    nip11_config.max_message_length = max_message_length;
    nip11_config.max_subscriptions = max_subscriptions;
    nip11_config.max_filters = max_filters;
    nip11_config.max_subid_length = max_subid_length;
    nip11_config.max_event_tags = max_event_tags;
    nip11_config.max_content_length = max_content_length;
    nip11_config.min_pow_difficulty = min_pow_difficulty;
    nip11_config.max_limit = max_limit;
    nip11_config.default_limit = default_limit;
    nip11_config.created_at_lower_limit = (long long) created_at_lower_limit;
    nip11_config.created_at_upper_limit = (long long) created_at_upper_limit;
    nip11_config.auth_required = auth_required;
}

const char *nip11_information_document(void) {
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
        {"default_limit", nip11_config.default_limit, nip11_config.default_limit > 0},
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
    written = snprintf(information_document + offset, capacity - offset,
                       "%s\"auth_required\":%s}", first ? "" : ",",
                       nip11_config.auth_required ? "true" : "false");
    if (written < 0 || offset + (size_t) written >= capacity) return "{}";
    offset += (size_t) written;

    if (offset + 2 <= capacity) {
        information_document[offset++] = '}';
        information_document[offset] = '\0';
    }
    return information_document;
}

/* ============================================================================
 * Plugin registration
 *
 * NIP-11 consumes the relay's runtime configuration (populated by
 * server_configure() via the shared init hook) and serves the rendered
 * information document on HTTP requests with an appropriate Accept header.
 * ============================================================================ */

static void nip11_plugin_init(const relay_config_t *config) {
    nip11_configure(config->max_message_length, config->max_subscriptions,
                    config->max_filters, config->max_subid_length,
                    config->max_event_tags, config->max_content_length,
                    config->min_pow_difficulty, config->max_limit,
                    config->default_limit, config->created_at_lower_limit,
                    config->created_at_upper_limit, config->auth_required);
}

static const char *nip11_plugin_info_document(void) {
    return nip11_information_document();
}

static nip_plugin_t nip11_plugin = {
    .name = "nip11",
    .init = nip11_plugin_init,
    .info_document = nip11_plugin_info_document,
};

__attribute__((constructor)) static void nip11_register_at_startup(void) {
    nip_plugin_register(&nip11_plugin);
}