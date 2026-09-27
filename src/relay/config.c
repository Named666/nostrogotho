#include "relay/config.h"
#include <string.h>

/* Default configuration values */
#define DEFAULT_MAX_SUBSCRIPTIONS 20
#define DEFAULT_MAX_FILTERS 10
#define DEFAULT_MAX_SUB_ID_LENGTH 100
#define DEFAULT_MAX_WS_MESSAGE_LENGTH (5 * 1024 * 1024)
#define DEFAULT_MAX_EVENT_CONTENT_LENGTH (16 * 1024)
#define DEFAULT_MAX_EVENT_TAGS 100
#define DEFAULT_MAX_LIMIT 500

void relay_config_init(relay_config_t *config) {
    if (!config) return;
    memset(config, 0, sizeof(*config));
    config->database_path = "./nostrogotho.sqlite";
    config->port = 7447;
    config->service_url = "";
    config->min_pow_difficulty = 0;
    config->created_at_lower_limit = 0;
    config->created_at_upper_limit = 900;
    config->debug_logging = false;
    config->max_ws_message_length = DEFAULT_MAX_WS_MESSAGE_LENGTH;
    config->max_event_content_length = DEFAULT_MAX_EVENT_CONTENT_LENGTH;
    config->max_event_tags = DEFAULT_MAX_EVENT_TAGS;
    config->max_subscriptions_per_connection = DEFAULT_MAX_SUBSCRIPTIONS;
    config->max_filters_per_subscription = DEFAULT_MAX_FILTERS;
    config->max_subscription_id_length = DEFAULT_MAX_SUB_ID_LENGTH;
    config->max_query_limit = DEFAULT_MAX_LIMIT;
}