/* ng_config - see ng_config.h. */
#include "ng_config.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ng_limits_t ng_limits = {
    (size_t) 5 << 20, (size_t) 512 << 10, (size_t) 256 << 10, 5000,
    100, 20, 100, 500, 500, 5000, 10000
};

void ng_limits_defaults(ng_limits_t *l) {
    l->max_message_length = (size_t) 5 << 20;
    l->max_event_size = (size_t) 512 << 10;
    l->max_content_length = (size_t) 256 << 10;
    l->max_event_tags = 5000;
    l->max_subscriptions = 100;
    l->max_filters = 20;
    l->max_subid_length = 100;
    l->max_limit = 500;
    l->default_limit = 500;
    l->max_filter_items = 5000;
    l->max_req_authors = 10000;
}

void ng_limits_apply(const ng_limits_t *l) {
    ng_limits = *l;
    if (ng_limits.default_limit > ng_limits.max_limit) ng_limits.default_limit = ng_limits.max_limit;
    if (ng_limits.max_event_size > ng_limits.max_message_length) ng_limits.max_event_size = ng_limits.max_message_length;
}

void ng_config_defaults(ng_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->db_sync = NG_DB_SYNC_FULL;
    cfg->conn_outbound_max = (size_t) 4 << 20;
    cfg->total_outbound_max = (size_t) 1 << 30;
    cfg->worker_queue_max = (size_t) 16 << 20;
    cfg->writer_queue_max = 65536;
    cfg->conn_pending_max = 1024;
    ng_limits_defaults(&cfg->limits);
}

bool ng_parse_size(const char *v, size_t lo, size_t hi, size_t *out) {
    char *end;
    if (!v || *v == '-') return false;      /* strtoull would wrap negatives */
    errno = 0;
    unsigned long long x = strtoull(v, &end, 10);
    if (end == v || errno) return false;
    unsigned long long m = 1;
    if (*end == 'K' || *end == 'k') { m = 1ull << 10; end++; }
    else if (*end == 'M' || *end == 'm') { m = 1ull << 20; end++; }
    else if (*end == 'G' || *end == 'g') { m = 1ull << 30; end++; }
    if (*end || x > (unsigned long long) hi / m) return false;
    if (x * m < lo) return false;
    *out = (size_t) (x * m);
    return true;
}

/* Value kinds of the key table. */
typedef enum { K_SYNC, K_THREADS, K_BACKLOG, K_SIZE, K_INT } kind_t;
typedef struct {
    const char *key;
    kind_t kind;
    size_t lo, hi;
    size_t off;              /* offsetof(ng_config_t, field) */
} cfg_key_t;

#define F(field) offsetof(ng_config_t, field)
static const cfg_key_t keys[] = {
    { "db_sync",            K_SYNC,    0, 0,                           F(db_sync) },
    { "io_threads",         K_THREADS, 1, NG_MAX_IO_LOOPS,             F(io_threads) },
    { "workers",            K_THREADS, 1, NG_MAX_WORKERS,              F(workers) },
    { "listen_backlog",     K_BACKLOG, 1, (size_t) 1 << 20,            F(listen_backlog) },
    { "conn_outbound_max",  K_SIZE,    (size_t) 64 << 10,  (size_t) 1 << 32, F(conn_outbound_max) },
    { "total_outbound_max", K_SIZE,    (size_t) 256 << 10, (size_t) 1 << 40, F(total_outbound_max) },
    { "worker_queue_max",   K_SIZE,    (size_t) 64 << 10,  (size_t) 1 << 36, F(worker_queue_max) },
    { "writer_queue_max",   K_INT,     1, (size_t) 1 << 24,            F(writer_queue_max) },
    { "conn_pending_max",   K_INT,     1, (size_t) 1 << 20,            F(conn_pending_max) },
    { "max_message_length", K_SIZE,    (size_t) 64 << 10, (size_t) 64 << 20,  F(limits.max_message_length) },
    { "max_event_size",     K_SIZE,    (size_t) 4 << 10,  (size_t) 4 << 20,   F(limits.max_event_size) },
    { "max_content_length", K_SIZE,    1,                 (size_t) 4 << 20,   F(limits.max_content_length) },
    { "max_event_tags",     K_INT,     1, 100000,                      F(limits.max_event_tags) },
    { "max_subscriptions",  K_INT,     1, 10000,                       F(limits.max_subscriptions) },
    { "max_filters",        K_INT,     1, NG_MAX_FILTERS,              F(limits.max_filters) },
    { "max_subid_length",   K_INT,     1, 1024,                        F(limits.max_subid_length) },
    { "max_limit",          K_INT,     1, 100000,                      F(limits.max_limit) },
    { "default_limit",      K_INT,     1, 100000,                      F(limits.default_limit) },
};
#undef F

ng_status_t ng_config_set(ng_config_t *cfg, const char *key, const char *value) {
    const cfg_key_t *k = NULL;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        if (strcmp(keys[i].key, key) == 0) { k = &keys[i]; break; }
    if (!k) return NG_E_UNKNOWN;
    char *field = (char *) cfg + k->off;
    size_t v = 0;
    switch (k->kind) {
    case K_SYNC:
        if (strcmp(value, "full") == 0) cfg->db_sync = NG_DB_SYNC_FULL;
        else if (strcmp(value, "normal") == 0) cfg->db_sync = NG_DB_SYNC_NORMAL;
        else return NG_E_INVALID;
        return NG_OK;
    case K_THREADS:
    case K_BACKLOG:
        if (strcmp(value, "auto") == 0) { *(int *) (void *) field = 0; return NG_OK; }
        /* fall through */
    case K_INT:
        if (!ng_parse_size(value, k->lo, k->hi, &v)) return NG_E_RANGE;
        *(int *) (void *) field = (int) v;          /* hi <= 2^24: fits */
        return NG_OK;
    case K_SIZE:
        if (!ng_parse_size(value, k->lo, k->hi, &v)) return NG_E_RANGE;
        *(size_t *) (void *) field = v;
        return NG_OK;
    }
    return NG_E_UNKNOWN;
}

static char *trim(char *s) {
    while (isspace((unsigned char) *s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char) e[-1])) e--;
    *e = '\0';
    return s;
}

ng_status_t ng_config_parse_line(char *line, char **key, char **value) {
    char *comment = strchr(line, '#');
    if (comment) *comment = '\0';
    char *k = trim(line);
    if (!*k) return NG_E_AGAIN;
    char *eq = strchr(k, '=');
    if (!eq) return NG_E_INVALID;
    *eq = '\0';
    k = trim(k);
    if (!*k) return NG_E_INVALID;
    *key = k;
    *value = trim(eq + 1);
    return NG_OK;
}

ng_status_t ng_config_load(ng_config_t *cfg, const char *path, bool required,
                           ng_config_error_t *err) {
    ng_config_error_t dummy;
    if (!err) err = &dummy;
    memset(err, 0, sizeof(*err));
    FILE *f = fopen(path, "r");
    if (!f) {
        if (!required && errno == ENOENT) return NG_OK;
        err->status = NG_E_IO;
        return NG_E_IO;
    }
    char line[512];
    ng_status_t st = NG_OK;
    while (fgets(line, sizeof(line), f)) {
        err->line++;
        if (!strchr(line, '\n') && !feof(f)) { st = NG_E_INVALID; break; }   /* overlong */
        char *k, *v;
        ng_status_t r = ng_config_parse_line(line, &k, &v);
        if (r == NG_E_AGAIN) continue;
        if (r == NG_OK) {
            snprintf(err->key, sizeof(err->key), "%s", k);
            r = ng_config_set(cfg, k, v);
        }
        if (r != NG_OK) { st = r; break; }
    }
    if (st == NG_OK && ferror(f)) st = NG_E_IO;
    fclose(f);
    err->status = st;
    if (st == NG_OK) { err->line = 0; err->key[0] = '\0'; }
    return st;
}
