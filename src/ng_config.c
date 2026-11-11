/* ng_config - see ng_config.h. */
#include "ng_config.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ng_limits_t ng_limits = {
    (size_t) 5 << 20, (size_t) 512 << 10, (size_t) 256 << 10, 5000,
    100, 20, 100, 500, 500, 5000, 10000, 1, "epaqtdhk", 2000
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
    l->search = 1;
    snprintf(l->tag_index_letters, sizeof(l->tag_index_letters), "%s", "epaqtdhk");
    l->tag_index_max_per_event = 2000;
}

void ng_limits_apply(const ng_limits_t *l) {
    ng_limits = *l;
    if (ng_limits.default_limit > ng_limits.max_limit) ng_limits.default_limit = ng_limits.max_limit;
    if (ng_limits.max_event_size > ng_limits.max_message_length) ng_limits.max_event_size = ng_limits.max_message_length;
}

ng_relay_info_t ng_relay_info = {
    .software = NG_SOFTWARE_URL, .version = NG_VERSION, .created_at_upper_limit = 900,
    .group_max_age = 3600
};

void ng_relay_info_defaults(ng_relay_info_t *info) {
    memset(info, 0, sizeof(*info));
    snprintf(info->name, sizeof(info->name), "%s", "nostrogotho");
    snprintf(info->software, sizeof(info->software), "%s", NG_SOFTWARE_URL);
    snprintf(info->version, sizeof(info->version), "%s", NG_VERSION);
    info->created_at_upper_limit = 900;
    info->group_max_age = 3600;
}

void ng_relay_info_apply(const ng_relay_info_t *info) { ng_relay_info = *info; }

void ng_config_defaults(ng_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->db_sync = NG_DB_SYNC_FULL;
    cfg->conn_outbound_max = (size_t) 4 << 20;
    cfg->total_outbound_max = (size_t) 1 << 30;
    cfg->worker_queue_max = (size_t) 16 << 20;
    cfg->writer_queue_max = 65536;
    cfg->conn_pending_max = 1024;
    ng_limits_defaults(&cfg->limits);
    ng_relay_info_defaults(&cfg->info);
    cfg->policy.event_ip_burst = 60;
    cfg->policy.event_pubkey_burst = 30;
    cfg->policy.req_ip_burst = 60;
    snprintf(cfg->policy.trusted_proxies, sizeof(cfg->policy.trusted_proxies), "%s", "127.0.0.1,::1");
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
typedef enum { K_SYNC, K_THREADS, K_BACKLOG, K_SIZE, K_INT, K_STR, K_HEX64 } kind_t;
typedef struct {
    const char *key;
    kind_t kind;
    size_t lo, hi;           /* K_STR / K_HEX64: hi = buffer size */
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
    { "relay_url",          K_STR,     0, sizeof(((ng_relay_info_t *) 0)->relay_url), F(info.relay_url) },
    { "relay_name",         K_STR,     0, sizeof(((ng_relay_info_t *) 0)->name), F(info.name) },
    { "relay_description",  K_STR,     0, sizeof(((ng_relay_info_t *) 0)->description), F(info.description) },
    { "relay_pubkey",       K_HEX64,   0, 65, F(info.pubkey) },
    { "relay_self",         K_HEX64,   0, 65, F(info.self) },
    { "relay_secret_key_file", K_STR,  0, sizeof(((ng_relay_info_t *) 0)->secret_key_file), F(info.secret_key_file) },
    { "relay_contact",      K_STR,     0, sizeof(((ng_relay_info_t *) 0)->contact), F(info.contact) },
    { "relay_icon",         K_STR,     0, sizeof(((ng_relay_info_t *) 0)->icon), F(info.icon) },
    { "relay_banner",       K_STR,     0, sizeof(((ng_relay_info_t *) 0)->banner), F(info.banner) },
    { "relay_software",     K_STR,     0, sizeof(((ng_relay_info_t *) 0)->software), F(info.software) },
    { "relay_version",      K_STR,     0, sizeof(((ng_relay_info_t *) 0)->version), F(info.version) },
    { "terms_of_service",   K_STR,     0, sizeof(((ng_relay_info_t *) 0)->terms_of_service), F(info.terms_of_service) },
    { "privacy_policy",     K_STR,     0, sizeof(((ng_relay_info_t *) 0)->privacy_policy), F(info.privacy_policy) },
    { "posting_policy",     K_STR,     0, sizeof(((ng_relay_info_t *) 0)->posting_policy), F(info.posting_policy) },
    { "payments_url",       K_STR,     0, sizeof(((ng_relay_info_t *) 0)->payments_url), F(info.payments_url) },
    { "relay_countries",    K_STR,     0, sizeof(((ng_relay_info_t *) 0)->relay_countries), F(info.relay_countries) },
    { "language_tags",      K_STR,     0, sizeof(((ng_relay_info_t *) 0)->language_tags), F(info.language_tags) },
    { "relay_tags",         K_STR,     0, sizeof(((ng_relay_info_t *) 0)->tags), F(info.tags) },
    { "min_pow_difficulty", K_INT,     0, 256,                         F(info.min_pow_difficulty) },
    { "created_at_lower_limit", K_INT, 0, (size_t) 1 << 30,            F(info.created_at_lower_limit) },
    { "created_at_upper_limit", K_INT, 0, (size_t) 1 << 30,            F(info.created_at_upper_limit) },
    { "group_max_age",      K_INT,     0, (size_t) 1 << 30,            F(info.group_max_age) },
    { "nip43",              K_INT,     0, 1,                           F(info.nip43) },
    { "members_only",       K_INT,     0, 1,                           F(info.members_only) },
    { "invite_codes",       K_STR,     0, sizeof(((ng_relay_info_t *) 0)->invite_codes), F(info.invite_codes) },
    { "max_filter_items",   K_INT,     1, 20000,                       F(limits.max_filter_items) },
    { "max_req_authors",    K_INT,     1, 100000,                      F(limits.max_req_authors) },
    { "search",             K_INT,     0, 1,                           F(limits.search) },
    { "tag_index_letters",  K_STR,     1, sizeof(((ng_limits_t *) 0)->tag_index_letters), F(limits.tag_index_letters) },
    { "tag_index_max_per_event", K_INT, 1, 100000,                     F(limits.tag_index_max_per_event) },
    { "rate_events_per_min_ip",     K_INT, 0, 10000000, F(policy.event_ip_per_min) },
    { "rate_events_burst_ip",       K_INT, 1, 1000000,  F(policy.event_ip_burst) },
    { "rate_events_per_min_pubkey", K_INT, 0, 10000000, F(policy.event_pubkey_per_min) },
    { "rate_events_burst_pubkey",   K_INT, 1, 1000000,  F(policy.event_pubkey_burst) },
    { "rate_reqs_per_min_ip",       K_INT, 0, 10000000, F(policy.req_ip_per_min) },
    { "rate_reqs_burst_ip",         K_INT, 1, 1000000,  F(policy.req_ip_burst) },
    { "banned_pubkeys",     K_STR,     0, sizeof(((ng_policy_t *) 0)->banned_pubkeys), F(policy.banned_pubkeys) },
    { "banned_ips",         K_STR,     0, sizeof(((ng_policy_t *) 0)->banned_ips), F(policy.banned_ips) },
    { "ban_file",           K_STR,     0, sizeof(((ng_policy_t *) 0)->ban_file), F(policy.ban_file) },
    { "trusted_proxies",    K_STR,     0, sizeof(((ng_policy_t *) 0)->trusted_proxies), F(policy.trusted_proxies) },
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
        *(int *) (void *) field = (int) v;          /* hi <= 2^30: fits */
        return NG_OK;
    case K_SIZE:
        if (!ng_parse_size(value, k->lo, k->hi, &v)) return NG_E_RANGE;
        *(size_t *) (void *) field = v;
        return NG_OK;
    case K_STR: {
        size_t n = strlen(value);
        if (n >= k->hi) return NG_E_RANGE;
        for (size_t i = 0; i < n; i++) if ((unsigned char) value[i] < 0x20) return NG_E_INVALID;
        memcpy(field, value, n + 1);
        return NG_OK;
    }
    case K_HEX64:
        if (*value && strlen(value) != 64) return NG_E_INVALID;
        for (const char *c = value; *c; c++)
            if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f'))) return NG_E_INVALID;
        memcpy(field, value, strlen(value) + 1);
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
