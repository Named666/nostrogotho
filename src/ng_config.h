/* ng_config - the runtime configuration contract (nostrogotho.conf).
 *
 * File format: one "key = value" per line; '#' starts a comment; blank
 * lines are ignored; surrounding whitespace is trimmed. Every key, its
 * range and its default is in the table in ng_config.c and documented in
 * nostrogotho.conf. Unknown keys and invalid values are errors (the relay
 * refuses to start). Byte values accept K/M/G (binary) suffixes; thread
 * and backlog values also accept "auto" (stored as 0).
 *
 * Layering: ng_config_parse_line, ng_config_set and ng_parse_size are pure
 * (no I/O, no globals, thread-safe on distinct objects). ng_config_load is
 * the only function that touches the filesystem.
 *
 * Environment overrides (benchmark knobs such as NG_IO_THREADS) are applied
 * by the consumer (backend_ngws.c), not here.
 */
#ifndef NG_CONFIG_H_
#define NG_CONFIG_H_

#include <stdbool.h>
#include <stddef.h>
#include "ng_status.h"

#define NG_MAX_IO_LOOPS 64      /* io_threads upper bound */
#define NG_MAX_WORKERS  64      /* workers upper bound (== RELAY_MAX_SHARDS) */

#define NG_MAX_FILTERS  64      /* max_filters upper bound (stack-sized index) */

typedef enum { NG_DB_SYNC_FULL = 0, NG_DB_SYNC_NORMAL = 1 } ng_db_sync_t;

/* Protocol limits (also published in the NIP-11 limitation object). */
typedef struct {
    size_t max_message_length;  /* max_message_length: bytes of one client message */
    size_t max_event_size;      /* max_event_size: bytes of the serialized event JSON */
    size_t max_content_length;  /* max_content_length: bytes of "content" */
    int max_event_tags;         /* max_event_tags: tags per event */
    int max_subscriptions;      /* max_subscriptions: open REQs per connection */
    int max_filters;            /* max_filters: filters per REQ/COUNT */
    int max_subid_length;       /* max_subid_length: subscription id bytes */
    int max_limit;              /* max_limit: cap on a filter's "limit" */
    int default_limit;          /* default_limit: stored events when no "limit" */
    int max_filter_items;       /* max_filter_items: ids/authors/kinds/#tag values per filter */
    int max_req_authors;        /* max_req_authors: authors summed over a REQ's filters */
    int search;                 /* search: 1 = NIP-50 full-text index on (default), 0 = off */
} ng_limits_t;

/* Relay identity and policy (NIP-11 document, NIP-42 relay tag, NIP-62).
 * Strings are "" when unset; lists are comma-separated. */
typedef struct {
    char relay_url[256];        /* relay_url: public ws(s):// URL of this relay */
    char name[128];             /* relay_name */
    char description[2048];     /* relay_description */
    char pubkey[65];            /* relay_pubkey: operator's pubkey (hex) */
    char self[65];              /* relay_self: the relay's own pubkey (hex) */
    char contact[256];          /* relay_contact */
    char icon[512];             /* relay_icon */
    char banner[512];           /* relay_banner */
    char software[256];         /* relay_software */
    char version[64];           /* relay_version */
    char terms_of_service[512]; /* terms_of_service */
    char privacy_policy[512];   /* privacy_policy */
    char posting_policy[512];   /* posting_policy */
    char payments_url[512];     /* payments_url */
    char relay_countries[256];  /* relay_countries: e.g. "US,CA" */
    char language_tags[256];    /* language_tags: e.g. "en,es" */
    char tags[256];             /* relay_tags: e.g. "sfw-only" */
    int min_pow_difficulty;     /* min_pow_difficulty: NIP-13 bits, 0 = off */
    int created_at_lower_limit; /* created_at_lower_limit: max age (s), 0 = off */
    int created_at_upper_limit; /* created_at_upper_limit: max future (s), 0 = off */
} ng_relay_info_t;

/* Rate limits (0 = off) and ban lists; see ratelimit.h. */
typedef struct {
    int event_ip_per_min;       /* rate_events_per_min_ip */
    int event_ip_burst;         /* rate_events_burst_ip */
    int event_pubkey_per_min;   /* rate_events_per_min_pubkey */
    int event_pubkey_burst;     /* rate_events_burst_pubkey */
    int req_ip_per_min;         /* rate_reqs_per_min_ip: REQ + COUNT */
    int req_ip_burst;           /* rate_reqs_burst_ip */
    char banned_pubkeys[480];   /* banned_pubkeys: hex, comma separated */
    char banned_ips[480];       /* banned_ips: comma separated */
    char ban_file[256];         /* ban_file: "pubkey <hex>" / "ip <addr>" lines */
} ng_policy_t;

#define NG_SOFTWARE_URL "https://github.com/Named666/nostrogotho"
#define NG_VERSION      "0.2.0"

/* The process-wide limits: compiled-in defaults until ng_limits_apply()
 * runs at startup (before any thread starts); read-only afterwards. */
extern ng_limits_t ng_limits;
void ng_limits_defaults(ng_limits_t *l);
void ng_limits_apply(const ng_limits_t *l);

typedef struct {
    ng_db_sync_t db_sync;       /* db_sync: full (default) | normal */
    int io_threads;             /* io_threads: 0 = auto */
    int workers;                /* workers: 0 = auto */
    int listen_backlog;         /* listen_backlog: 0 = auto (somaxconn) */
    size_t conn_outbound_max;   /* conn_outbound_max: per-connection output budget */
    size_t total_outbound_max;  /* total_outbound_max: process-wide output budget */
    size_t worker_queue_max;    /* worker_queue_max: queued inbound bytes per worker */
    int writer_queue_max;       /* writer_queue_max: EVENTs waiting for the writer */
    int conn_pending_max;       /* conn_pending_max: queued messages per connection */
    ng_limits_t limits;         /* protocol limits (see ng_limits_t) */
    ng_relay_info_t info;       /* identity and policy (see ng_relay_info_t) */
    ng_policy_t policy;         /* rate limits and bans (see ng_policy_t) */
} ng_config_t;

/* Process-wide relay info, like ng_limits: set once at startup. */
extern ng_relay_info_t ng_relay_info;
void ng_relay_info_defaults(ng_relay_info_t *info);
void ng_relay_info_apply(const ng_relay_info_t *info);

/* Fill *cfg with the defaults (db_sync full, 4M / 1G / 16M budgets,
 * writer queue 65536, 1024 pending per connection, everything else auto). */
void ng_config_defaults(ng_config_t *cfg);

/* Apply one key/value. NG_OK, NG_E_UNKNOWN (no such key), NG_E_INVALID
 * (unparsable) or NG_E_RANGE. On error *cfg is unchanged. */
ng_status_t ng_config_set(ng_config_t *cfg, const char *key, const char *value);

/* Split one line in place: strips the comment and whitespace, NUL-terminates
 * key and value inside line. NG_OK with *key and *value set, NG_E_AGAIN for a
 * blank/comment-only line (nothing to apply), NG_E_INVALID if there is no
 * '=' or the key is empty. */
ng_status_t ng_config_parse_line(char *line, char **key, char **value);

/* Decimal integer (strtoull syntax, no '-') with optional K/M/G suffix
 * (x1024^n) in [lo, hi]. false on syntax error, negative input, overflow
 * or out of range;
 * *out is written only on success. */
bool ng_parse_size(const char *text, size_t lo, size_t hi, size_t *out);

/* Where loading stopped. line is 1-based (0: the file itself failed). */
typedef struct {
    unsigned line;
    ng_status_t status;
    char key[64];
} ng_config_error_t;

/* Read path into *cfg (start from ng_config_defaults). A missing file is
 * NG_OK when !required. Stops at the first bad line: returns its status and
 * fills *err (may be NULL); keys before it are already applied. Lines over
 * 511 bytes are NG_E_INVALID. NG_E_IO for open/read errors (errno set). */
ng_status_t ng_config_load(ng_config_t *cfg, const char *path, bool required,
                           ng_config_error_t *err);

#endif /* NG_CONFIG_H_ */
