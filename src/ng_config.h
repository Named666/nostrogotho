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

typedef enum { NG_DB_SYNC_FULL = 0, NG_DB_SYNC_NORMAL = 1 } ng_db_sync_t;

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
} ng_config_t;

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
