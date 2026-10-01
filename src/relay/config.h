#ifndef RELAY_CONFIG_H_
#define RELAY_CONFIG_H_

#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include "storage.h"
#include "log.h"

/* ============================================================================
 * RELAY_CONFIG.H - Single Authoritative Relay Configuration
 *
 * This structure contains all relay configuration options. It is the single
 * source of truth for configuration across the entire codebase.
 *
 * OWNERSHIP: string fields are fixed-size buffers OWNED by the struct
 * (snprintf copies, never borrowed argv/env pointers), so configs survive
 * reload and outlive their source. `storage` is runtime state, never loaded
 * from file. NIPs read config read-only in lifecycle init.
 * ============================================================================ */

/* Composition policy — mirrors nip_composition_policy_t layout so we can
 * cast relay_config_t.composition to nip_composition_policy_t* safely. */
typedef struct {
    char publication_mode[16];      /* "and" | "or" */
    bool publication_enabled;
    char delivery_mode[16];         /* "and" | "or" */
    bool delivery_enabled;
    char kind_mode[16];             /* "all" */
    bool kind_enabled;
    char query_mode[16];            /* "and" | "or" */
    bool query_enabled;
    char protocol_response_mode[16]; /* "first" */
    bool protocol_response_enabled;
    char metadata_mode[16];          /* "first" */
    bool metadata_enabled;
    char auth_hint_mode[16];         /* "or" */
    bool auth_hint_enabled;
    char auth_challenge_mode[16];    /* "all" */
    bool auth_challenge_enabled;
    char maintenance_mode[16];       /* "all" */
    bool maintenance_enabled;
} relay_composition_config_t;

/* Single authoritative configuration. Field names are canonical; NIP-11
 * renders them under its own wire-key names (see nip11_lifecycle_init).
 * No legacy aliases: every limit is set in relay_config_init and enforced
 * from this struct. File keys nest (limits.*, nip42.*, hot_reload.*) and
 * are flattened into this struct by relay_config_load() — see CONFIG_PLAN.md. */
typedef struct {
    char database_path[1024];
    int port;
    char service_url[256];
    int verbosity; /* log_verbosity_t 0-3; replaces lossy bool debug_logging */
    int min_pow_difficulty;
    time_t created_at_lower_limit;
    time_t created_at_upper_limit;
    int max_ws_message_length;
    int max_event_content_length;
    int max_event_tags;
    int max_subscriptions_per_connection;
    int max_filters_per_subscription;
    int max_subscription_id_length;
    int max_query_limit;
    bool nip42_enabled;
    bool nip42_auth_required_for_write;
    bool hot_reload_enabled;
    char hot_reload_module_path[1024];
    /* Composition policy (optional — config.json "composition.*") */
    relay_composition_config_t composition;
    storage_context_t *storage;
} relay_config_t;

/* Initialize relay configuration with defaults */
void relay_config_init(relay_config_t *config);

/* Validate a fully-assembled config. Returns true when valid; on failure
 * writes a human-readable reason (e.g. "port: must be 1-65535"). */
bool relay_config_validate(const relay_config_t *config, char *err, size_t errsz);

/* Load config.json over defaults. Unknown keys are ignored (warns);
 * wrong-type values are hard errors. Precedence handled by caller:
 * defaults < file < env < CLI. */
bool relay_config_load(const char *path, relay_config_t *config, char *err, size_t errsz);

/* Write a default config.json. Never overwrites: fails if path exists. */
bool relay_config_write_defaults(const char *path);

/* Report unknown keys in path (warn level). Called by main() after log
 * verbosity is set; kept out of relay_config_load() so early warnings
 * aren't swallowed by the default-quiet logger. */
void relay_config_warn_unknown(const char *path);

#endif /* RELAY_CONFIG_H_ */