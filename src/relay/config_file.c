/* ============================================================================
 * CONFIG_FILE.C - config.json loader / defaults writer
 *
 * Targeted key scanner for the known schema (see CONFIG_PLAN.md), NOT a
 * general JSON parser: every value key is looked up by name, so key order
 * and whitespace don't matter. Nesting (limits.*, nip42.*, hot_reload.*)
 * is handled by scoping the two ambiguous "enabled" keys to their parent
 * object's brace span; all other keys are unique file-wide.
 *
 * Unknown keys are ignored with a warning (forward compatibility).
 * Wrong-type values are hard errors naming the field.
 * ============================================================================ */

#include "relay/config.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>

/* ---- file helpers ------------------------------------------------------ */

static bool file_exists(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0;
}

static char *read_entire_file(const char *path, size_t *out_len) {
    FILE *f;
    long size;
    char *buf;
    size_t got;
    if (!path || !out_len) return NULL;
    f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    size = ftell(f);
    if (size < 0 || size > (long)(8 * 1024 * 1024)) {
        fclose(f);
        return NULL; /* empty or absurdly large: refuse */
    }
    rewind(f);
    buf = (char *)malloc((size_t)size + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    got = fread(buf, 1, (size_t)size, f);
    fclose(f);
    if (got != (size_t)size) {
        free(buf);
        return NULL;
    }
    buf[size] = '\0';
    *out_len = (size_t)size;
    return buf;
}

/* ---- scanner ----------------------------------------------------------- */

static void skip_ws(const char **p, const char *end) {
    while (*p < end && (**p == ' ' || **p == '\t' || **p == '\n' ||
                        **p == '\r')) {
        (*p)++;
    }
}

/* Find `"key"` followed by optional ws and ':'.
 * Returns pointer just past ':' or NULL. */
static const char *find_key(const char *begin, const char *end,
                            const char *key) {
    size_t keylen = strlen(key);
    const char *p = begin;
    while (p < end) {
        if (*p != '"') {
            p++;
            continue;
        }
        p++; /* past opening quote */
        if ((size_t)(end - p) >= keylen && memcmp(p, key, keylen) == 0 &&
            p[keylen] == '"') {
            const char *q = p + keylen + 1;
            skip_ws(&q, end);
            if (q < end && *q == ':') return q + 1;
        }
    }
    return NULL;
}

/* Find `"key"` whose value is an object; return its inner span
 * [*inner_begin, *inner_end) (between the braces). */
static bool find_object_span(const char *begin, const char *end,
                             const char *key, const char **inner_begin,
                             const char **inner_end) {
    const char *p = find_key(begin, end, key);
    int depth;
    if (!p) return false;
    skip_ws(&p, end);
    if (p >= end || *p != '{') return false;
    p++;
    *inner_begin = p;
    depth = 1;
    while (p < end && depth > 0) {
        if (*p == '"') {
            /* skip string (keys and string values can't contain braces
             * that matter if we skip them) */
            p++;
            while (p < end && *p != '"') {
                if (*p == '\\' && p + 1 < end) p++;
                p++;
            }
            if (p < end) p++;
        } else if (*p == '{') {
            depth++;
            p++;
        } else if (*p == '}') {
            depth--;
            p++;
        } else {
            p++;
        }
    }
    if (depth != 0) return false;
    *inner_end = p - 1;
    return true;
}

/* Parse a JSON string value at *p (past any ws). Writes to dst (NUL
 * terminated, truncated safely). Returns false on type mismatch. */
static bool parse_string(const char **p, const char *end, char *dst,
                         size_t dstsz) {
    size_t out = 0;
    skip_ws(p, end);
    if (*p >= end || **p != '"') return false;
    (*p)++;
    while (*p < end && **p != '"') {
        char c = **p;
        if (c == '\\' && *p + 1 < end) {
            (*p)++;
            switch (**p) {
                case '"': c = '"'; break;
                case '\\': c = '\\'; break;
                case '/': c = '/'; break;
                case 'n': c = '\n'; break;
                case 't': c = '\t'; break;
                case 'r': c = '\r'; break;
                default: c = **p; break; /* pass through unknown escapes */
            }
        }
        if (out + 1 < dstsz) dst[out++] = c;
        (*p)++;
    }
    if (*p >= end) return false; /* unterminated */
    (*p)++;                      /* past closing quote */
    dst[out] = '\0';
    return true;
}

static bool parse_int(const char **p, const char *end, int *out) {
    long v;
    char *stop;
    skip_ws(p, end);
    if (*p >= end) return false;
    v = strtol(*p, &stop, 10);
    if (stop == *p || v < INT_MIN || v > INT_MAX) return false;
    *p = stop;
    *out = (int)v;
    return true;
}

static bool parse_bool(const char **p, const char *end, bool *out) {
    skip_ws(p, end);
    if (end - *p >= 4 && memcmp(*p, "true", 4) == 0) {
        *p += 4;
        *out = true;
        return true;
    }
    if (end - *p >= 5 && memcmp(*p, "false", 5) == 0) {
        *p += 5;
        *out = false;
        return true;
    }
    return false;
}

/* ---- field application -------------------------------------------------- */

#define FAIL(field, what)                                              \
    do {                                                               \
        snprintf(err, errsz, "%s: expected %s", field, what);          \
        return false;                                                  \
    } while (0)

static bool apply_string(const char *doc, const char *end, const char *key,
                         char *dst, size_t dstsz, char *err, size_t errsz) {
    const char *p = find_key(doc, end, key);
    const char *val;
    if (!p) return true; /* absent: keep default */
    val = p;
    if (!parse_string(&val, end, dst, dstsz)) FAIL(key, "string");
    return true;
}

static bool apply_int(const char *doc, const char *end, const char *key,
                      int *dst, char *err, size_t errsz) {
    const char *p = find_key(doc, end, key);
    const char *val;
    if (!p) return true;
    val = p;
    if (!parse_int(&val, end, dst)) FAIL(key, "integer");
    return true;
}

static bool apply_bool(const char *doc, const char *end, const char *key,
                       bool *dst, char *err, size_t errsz) {
    const char *p = find_key(doc, end, key);
    const char *val;
    if (!p) return true;
    val = p;
    if (!parse_bool(&val, end, dst)) FAIL(key, "true/false");
    return true;
}

/* Known keys for the unknown-key warning pass. */
static const char *known_keys[] = {
    "database", "port", "service_url", "verbosity",
    "max_subscriptions_per_connection", "max_filters_per_subscription",
    "max_subscription_id_length", "max_query_limit",
    "max_event_content_length", "max_event_tags", "max_ws_message_length",
    "min_pow_difficulty", "created_at_lower_limit", "created_at_upper_limit",
    "limits", "nip42", "hot_reload", "enabled", "auth_required_for_write",
    "module_path",
};

static bool is_known_key(const char *key, size_t len) {
    size_t i;
    for (i = 0; i < sizeof(known_keys) / sizeof(known_keys[0]); i++) {
        if (strlen(known_keys[i]) == len &&
            memcmp(known_keys[i], key, len) == 0) {
            return true;
        }
    }
    return false;
}

/* Warn once per unknown "key": occurrence. Only treats quoted strings
 * followed by ':' as keys, so string values are never flagged. */
static void warn_unknown_keys(const char *doc, const char *end) {
    const char *p = doc;
    while (p < end) {
        const char *start;
        const char *q;
        size_t len;
        char keybuf[128];
        size_t copylen;
        if (*p != '"') {
            p++;
            continue;
        }
        start = p + 1;
        q = start;
        while (q < end && *q != '"') {
            if (*q == '\\' && q + 1 < end) q++;
            q++;
        }
        if (q >= end) return;
        len = (size_t)(q - start);
        p = q + 1;
        skip_ws(&p, end);
        if (p >= end || *p != ':') continue; /* a value, not a key */
        p++;
        if (is_known_key(start, len)) continue;
        copylen = len < sizeof(keybuf) - 1 ? len : sizeof(keybuf) - 1;
        memcpy(keybuf, start, copylen);
        keybuf[copylen] = '\0';
        log_warn("MAIN", "CONFIG", "unknown config key ignored: %s", keybuf);
    }
}

bool relay_config_load(const char *path, relay_config_t *config, char *err,
                       size_t errsz) {
    char *doc = NULL;
    size_t len = 0;
    const char *end;
    const char *limits_b, *limits_e, *nip42_b, *nip42_e, *hr_b, *hr_e;
    bool has_limits, has_nip42, has_hr;
    int tmp;
    if (!path || !config || !err || errsz == 0) return false;

    doc = read_entire_file(path, &len);
    if (!doc) {
        snprintf(err, errsz, "cannot read %s", path);
        return false;
    }
    end = doc + len;

    /* Top-level scalars (unique file-wide). */
    if (!apply_string(doc, end, "database", config->database_path,
                      sizeof(config->database_path), err, errsz)) goto fail;
    if (!apply_int(doc, end, "port", &config->port, err, errsz)) goto fail;
    if (!apply_string(doc, end, "service_url", config->service_url,
                      sizeof(config->service_url), err, errsz)) goto fail;
    if (!apply_int(doc, end, "verbosity", &config->verbosity, err,
                   errsz)) goto fail;

    /* limits.* scope. */
    has_limits = find_object_span(doc, end, "limits", &limits_b, &limits_e);
    if (has_limits) {
        if (!apply_int(limits_b, limits_e, "max_subscriptions_per_connection",
                       &config->max_subscriptions_per_connection, err,
                       errsz)) goto fail;
        if (!apply_int(limits_b, limits_e, "max_filters_per_subscription",
                       &config->max_filters_per_subscription, err,
                       errsz)) goto fail;
        if (!apply_int(limits_b, limits_e, "max_subscription_id_length",
                       &config->max_subscription_id_length, err,
                       errsz)) goto fail;
        if (!apply_int(limits_b, limits_e, "max_query_limit",
                       &config->max_query_limit, err, errsz)) goto fail;
        if (!apply_int(limits_b, limits_e, "max_event_content_length",
                       &config->max_event_content_length, err,
                       errsz)) goto fail;
        if (!apply_int(limits_b, limits_e, "max_event_tags",
                       &config->max_event_tags, err, errsz)) goto fail;
        if (!apply_int(limits_b, limits_e, "max_ws_message_length",
                       &config->max_ws_message_length, err, errsz)) goto fail;
        if (!apply_int(limits_b, limits_e, "min_pow_difficulty",
                       &config->min_pow_difficulty, err, errsz)) goto fail;
        if (!apply_int(limits_b, limits_e, "created_at_lower_limit", &tmp,
                       err, errsz)) goto fail;
        else if (find_key(limits_b, limits_e, "created_at_lower_limit")) {
            config->created_at_lower_limit = (time_t)tmp;
        }
        if (!apply_int(limits_b, limits_e, "created_at_upper_limit", &tmp,
                       err, errsz)) goto fail;
        else if (find_key(limits_b, limits_e, "created_at_upper_limit")) {
            config->created_at_upper_limit = (time_t)tmp;
        }
    }

    /* nip42.* scope ("enabled" disambiguated by span). */
    has_nip42 = find_object_span(doc, end, "nip42", &nip42_b, &nip42_e);
    if (has_nip42) {
        if (!apply_bool(nip42_b, nip42_e, "enabled", &config->nip42_enabled,
                        err, errsz)) goto fail;
        if (!apply_bool(nip42_b, nip42_e, "auth_required_for_write",
                        &config->nip42_auth_required_for_write, err,
                        errsz)) goto fail;
    }

    /* hot_reload.* scope. */
    has_hr = find_object_span(doc, end, "hot_reload", &hr_b, &hr_e);
    if (has_hr) {
        if (!apply_bool(hr_b, hr_e, "enabled", &config->hot_reload_enabled,
                        err, errsz)) goto fail;
        if (!apply_string(hr_b, hr_e, "module_path",
                          config->hot_reload_module_path,
                          sizeof(config->hot_reload_module_path), err,
                          errsz)) goto fail;
    }

    warn_unknown_keys(doc, end);
    free(doc);
    return true;

fail:
    free(doc);
    return false;
}

bool relay_config_write_defaults(const char *path) {
    FILE *f;
    if (!path) return false;
    if (file_exists(path)) return false; /* never overwrite */
    f = fopen(path, "w");
    if (!f) return false;
    fprintf(f,
            "{\n"
            "  \"database\": \"./nostrogotho.sqlite\",\n"
            "  \"port\": 7447,\n"
            "  \"service_url\": \"wss://relay.example.com\",\n"
            "  \"verbosity\": 0,\n"
            "  \"limits\": {\n"
            "    \"max_subscriptions_per_connection\": 50,\n"
            "    \"max_filters_per_subscription\": 10,\n"
            "    \"max_subscription_id_length\": 100,\n"
            "    \"max_query_limit\": 500,\n"
            "    \"max_event_content_length\": 65536,\n"
            "    \"max_event_tags\": 100,\n"
            "    \"max_ws_message_length\": 5242880,\n"
            "    \"min_pow_difficulty\": 0,\n"
            "    \"created_at_lower_limit\": 0,\n"
            "    \"created_at_upper_limit\": 900\n"
            "  },\n"
            "  \"nip42\": {\n"
            "    \"enabled\": true,\n"
            "    \"auth_required_for_write\": false\n"
            "  },\n"
            "  \"hot_reload\": {\n"
            "    \"enabled\": false,\n"
#ifdef _WIN32
            "    \"module_path\": \"build/nostrogotho.dll\"\n"
#else
            "    \"module_path\": \"build/nostrogotho.so\"\n"
#endif
            "  }\n"
            "}\n");
    if (fclose(f) != 0) return false;
    return file_exists(path);
}
