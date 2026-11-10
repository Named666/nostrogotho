#include "nip11.h"
#include "nip_plugin.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "../json_util.h"
#include "../ng_config.h"

/* ============================================================================
 * NIP-11: Relay Information Document
 *
 * The supported_nips list is derived from the NIPs actually wired into the
 * server, the identity fields from nostrogotho.conf (ng_relay_info) and the
 * limitation block from the runtime limits handed to init(). Keeping protocol claims next to their implementations
 * prevents the document from drifting out of sync with the code.
 * ============================================================================ */

/* Rendered once by init() (main thread, before serving); read-only after. */
static char *information_document;

/* NIPs implemented and wired into the request path:
 *   01 basic protocol, 09 deletion, 11 this document, 13 PoW,
 *   16 replaceable (via NIP-01), 17 gift-wrap gating,
 *   33 addressable (via NIP-01), 40 expiration, 42 auth, 45 COUNT,
 *   50 search (unless search = 0), 62 vanish. */
static const int supported_nips[] = {1, 9, 11, 13, 16, 17, 33, 40, 42, 45, 50, 62};
#define SUPPORTED_NIPS_COUNT (sizeof(supported_nips) / sizeof(supported_nips[0]))

static void key_str(json_builder_t *b, const char *key, const char *value) {
    if (value && *value) json_builder_object_key_string(b, key, value);
}

/* "a, b,c" -> ["a","b","c"] under key (omitted when empty). */
static void key_list(json_builder_t *b, const char *key, const char *csv) {
    if (!csv || !*csv) return;
    json_builder_object_key(b, key);
    json_builder_start_array(b);
    const char *p = csv;
    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        const char *e = p;
        while (*e && *e != ',') e++;
        const char *t = e;
        while (t > p && t[-1] == ' ') t--;
        if (t > p) {
            char item[256];
            size_t n = (size_t) (t - p) < sizeof(item) ? (size_t) (t - p) : sizeof(item) - 1;
            memcpy(item, p, n); item[n] = '\0';
            json_builder_append_string(b, item);
        }
        p = e;
    }
    json_builder_end_array(b);
}

static char *render(const relay_config_t *c) {
    const ng_relay_info_t *info = &ng_relay_info;
    json_builder_t b;
    json_builder_start(&b);
    json_builder_start_object(&b);
    key_str(&b, "name", info->name);
    key_str(&b, "description", info->description);
    key_str(&b, "banner", info->banner);
    key_str(&b, "icon", info->icon);
    key_str(&b, "pubkey", info->pubkey);
    key_str(&b, "self", info->self);
    key_str(&b, "contact", info->contact);
    json_builder_object_key(&b, "supported_nips");
    json_builder_start_array(&b);
    for (size_t i = 0; i < SUPPORTED_NIPS_COUNT; i++)
        if (supported_nips[i] != 50 || ng_limits.search) json_builder_append_number(&b, supported_nips[i]);
    json_builder_end_array(&b);
    key_str(&b, "software", info->software);
    key_str(&b, "version", info->version);
    key_str(&b, "terms_of_service", info->terms_of_service);
    key_str(&b, "privacy_policy", info->privacy_policy);
    key_str(&b, "posting_policy", info->posting_policy);
    key_str(&b, "payments_url", info->payments_url);
    key_list(&b, "relay_countries", info->relay_countries);
    key_list(&b, "language_tags", info->language_tags);
    key_list(&b, "tags", info->tags);
    json_builder_object_start_nested(&b, "limitation");
    json_builder_object_key_number(&b, "max_message_length", c->max_message_length);
    json_builder_object_key_number(&b, "max_subscriptions", c->max_subscriptions);
    json_builder_object_key_number(&b, "max_filters", c->max_filters);
    json_builder_object_key_number(&b, "max_limit", c->max_limit);
    json_builder_object_key_number(&b, "max_subid_length", c->max_subid_length);
    json_builder_object_key_number(&b, "max_event_tags", c->max_event_tags);
    json_builder_object_key_number(&b, "max_content_length", c->max_content_length);
    json_builder_object_key_number(&b, "min_pow_difficulty", c->min_pow_difficulty);
    json_builder_object_key_bool(&b, "auth_required", c->auth_required);
    json_builder_object_key_bool(&b, "payment_required", false);
    json_builder_object_key_bool(&b, "restricted_writes", c->restricted_writes);
    json_builder_object_key_number(&b, "created_at_lower_limit", (long long) c->created_at_lower_limit);
    json_builder_object_key_number(&b, "created_at_upper_limit", (long long) c->created_at_upper_limit);
    json_builder_object_key_number(&b, "default_limit", c->default_limit);
    json_builder_end_object(&b);
    json_builder_end_object(&b);
    const char *j = json_builder_finish(&b);         /* [{...}]: the builder wraps an array */
    size_t n = j ? json_builder_length(&b) : 0;
    char *out = n >= 2 ? (char *) malloc(n - 1) : NULL;
    if (out) { memcpy(out, j + 1, n - 2); out[n - 2] = '\0'; }
    json_builder_free(&b);
    return out;
}

const char *nip11_information_document(void) {
    return information_document ? information_document : "{}";
}

/* ============================================================================
 * Plugin registration
 *
 * NIP-11 consumes the relay's runtime configuration (populated by
 * server_configure() via the shared init hook) and serves the rendered
 * information document on HTTP requests with an appropriate Accept header.
 * ============================================================================ */

static void nip11_plugin_init(const relay_config_t *config, void *ctx) {
    (void) ctx;
    free(information_document);
    information_document = render(config);
}

static const char *nip11_plugin_info_document(void *ctx) {
    (void) ctx;
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