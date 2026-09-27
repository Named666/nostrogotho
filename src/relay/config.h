#ifndef RELAY_CONFIG_H_
#define RELAY_CONFIG_H_

#include <stdbool.h>
#include <time.h>
#include "storage.h"

/* ============================================================================
 * RELAY_CONFIG.H - Single Authoritative Relay Configuration
 * 
 * This structure contains all relay configuration options. It is the single
 * source of truth for configuration across the entire codebase.
 * ============================================================================ */

/* Single authoritative configuration. Field names are canonical; NIP-11
 * renders them under its own wire-key names (see nip11_lifecycle_init).
 * No legacy aliases: every limit is set in relay_config_init and enforced
 * from this struct. */
typedef struct {
    const char *database_path;
    int port;
    const char *service_url;
    int min_pow_difficulty;
    time_t created_at_lower_limit;
    time_t created_at_upper_limit;
    bool debug_logging;
    int max_ws_message_length;
    int max_event_content_length;
    int max_event_tags;
    int max_subscriptions_per_connection;
    int max_filters_per_subscription;
    int max_subscription_id_length;
    int max_query_limit;
    storage_context_t *storage;
} relay_config_t;

/* Initialize relay configuration with defaults */
void relay_config_init(relay_config_t *config);

#endif /* RELAY_CONFIG_H_ */