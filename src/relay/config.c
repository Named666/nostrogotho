#include "relay/config.h"
#include <stdio.h>
#include <string.h>

/* Default configuration values */
#define DEFAULT_DATABASE_PATH "./nostrogotho.sqlite"
#define DEFAULT_PORT 7447
#define DEFAULT_SERVICE_URL "wss://relay.example.com"
#define DEFAULT_VERBOSITY LOG_VERBOSITY_QUIET
#define DEFAULT_MAX_SUBSCRIPTIONS 50
#define DEFAULT_MAX_FILTERS 10
#define DEFAULT_MAX_SUB_ID_LENGTH 100
#define DEFAULT_MAX_WS_MESSAGE_LENGTH (5 * 1024 * 1024)
#define DEFAULT_MAX_EVENT_CONTENT_LENGTH 65536
#define DEFAULT_MAX_EVENT_TAGS 100
#define DEFAULT_MAX_LIMIT 500
#define DEFAULT_MIN_POW 0
#define DEFAULT_CREATED_AT_LOWER 0
#define DEFAULT_CREATED_AT_UPPER 900

#ifdef _WIN32
#define DEFAULT_MODULE_PATH "build/nostrogotho.dll"
#else
#define DEFAULT_MODULE_PATH "build/nostrogotho.so"
#endif

void relay_config_init(relay_config_t *config) {
    if (!config) return;
    memset(config, 0, sizeof(*config));
    snprintf(config->database_path, sizeof(config->database_path), "%s",
             DEFAULT_DATABASE_PATH);
    config->port = DEFAULT_PORT;
    snprintf(config->service_url, sizeof(config->service_url), "%s",
             DEFAULT_SERVICE_URL);
    config->verbosity = DEFAULT_VERBOSITY;
    config->min_pow_difficulty = DEFAULT_MIN_POW;
    config->created_at_lower_limit = DEFAULT_CREATED_AT_LOWER;
    config->created_at_upper_limit = DEFAULT_CREATED_AT_UPPER;
    config->max_ws_message_length = DEFAULT_MAX_WS_MESSAGE_LENGTH;
    config->max_event_content_length = DEFAULT_MAX_EVENT_CONTENT_LENGTH;
    config->max_event_tags = DEFAULT_MAX_EVENT_TAGS;
    config->max_subscriptions_per_connection = DEFAULT_MAX_SUBSCRIPTIONS;
    config->max_filters_per_subscription = DEFAULT_MAX_FILTERS;
    config->max_subscription_id_length = DEFAULT_MAX_SUB_ID_LENGTH;
    config->max_query_limit = DEFAULT_MAX_LIMIT;
    config->hot_reload_enabled = false;
    snprintf(config->hot_reload_module_path,
             sizeof(config->hot_reload_module_path), "%s",
             DEFAULT_MODULE_PATH);
    config->storage = NULL;
}

/* Range-check one int field; writes "name: message" on failure. */
#define CHECK_RANGE(value, lo, hi, name)                                   \
    do {                                                                   \
        if ((value) < (lo) || (value) > (hi)) {                             \
            snprintf(err, errsz, "%s: must be %d-%d (got %d)", name, lo,    \
                     hi, (int)(value));                                    \
            return false;                                                  \
        }                                                                  \
    } while (0)

#define CHECK_NONNEG(value, name)                                          \
    do {                                                                   \
        if ((value) < 0) {                                                 \
            snprintf(err, errsz, "%s: must be >= 0 (got %d)", name,        \
                     (int)(value));                                        \
            return false;                                                  \
        }                                                                  \
    } while (0)

bool relay_config_validate(const relay_config_t *config, char *err,
                           size_t errsz) {
    if (!config) {
        if (err && errsz > 0) snprintf(err, errsz, "config is null");
        return false;
    }
    if (!err || errsz == 0) return false;

    CHECK_RANGE(config->port, 1, 65535, "port");
    CHECK_RANGE(config->verbosity, LOG_VERBOSITY_QUIET, LOG_VERBOSITY_DEBUG,
                "verbosity");
    CHECK_NONNEG(config->min_pow_difficulty, "limits.min_pow_difficulty");
    CHECK_NONNEG((int)config->created_at_lower_limit,
                 "limits.created_at_lower_limit");
    CHECK_NONNEG((int)config->created_at_upper_limit,
                 "limits.created_at_upper_limit");
    CHECK_NONNEG(config->max_ws_message_length,
                 "limits.max_ws_message_length");
    CHECK_NONNEG(config->max_event_content_length,
                 "limits.max_event_content_length");
    CHECK_NONNEG(config->max_event_tags, "limits.max_event_tags");
    CHECK_RANGE(config->max_subscriptions_per_connection, 1, 100000,
                "limits.max_subscriptions_per_connection");
    CHECK_RANGE(config->max_filters_per_subscription, 1, 1000,
                "limits.max_filters_per_subscription");
    CHECK_RANGE(config->max_subscription_id_length, 1, 10000,
                "limits.max_subscription_id_length");
    CHECK_RANGE(config->max_query_limit, 1, 100000, "limits.max_query_limit");
    if (!config->database_path[0]) {
        snprintf(err, errsz, "database: must not be empty");
        return false;
    }
    if (!config->service_url[0]) {
        snprintf(err, errsz, "service_url: must not be empty (required for NIP-42 authentication)");
        return false;
    }
    if (strcmp(config->service_url, "wss://relay.example.com") == 0) {
        snprintf(err, errsz, "service_url: must be set to this relay's public URL (still the placeholder)");
        return false;
    }
    return true;
}
