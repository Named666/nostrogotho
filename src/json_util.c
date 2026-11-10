#include <limits.h>
#include "json_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#include "json_lite.h"
#include "relay_conn.h"
#include "platform/ng_alloc.h"
#include "platform/ng_platform.h"
#include <pthread.h>

/* ============================================================================
 * JSON Parsing Utilities
 * ============================================================================ */

/* Skip whitespace in JSON string */
static const char *skip_whitespace(const char *p) {
    while (p && *p && isspace((unsigned char)*p)) p++;
    return p;
}

static bool skip_json_string(const char **p) {
    const char *cursor = *p;
    if (!cursor || *cursor != '"') return false;
    cursor++;

    while (*cursor) {
        if ((unsigned char)*cursor < 0x20) return false;
        if (*cursor == '"') {
            *p = cursor + 1;
            return true;
        }
        if (*cursor == '\\') {
            cursor++;
            if (!*cursor || !strchr("\"\\/bfnrtu", *cursor)) return false;
        }
        cursor++;
    }
    return false;
}

static bool skip_json_value(const char **p) {
    const char *cursor = skip_whitespace(*p);
    if (!cursor || !*cursor) return false;

    if (*cursor == '"') {
        if (!skip_json_string(&cursor)) return false;
    } else if (*cursor == '[' || *cursor == '{') {
        const char open = *cursor++;
        const char close = open == '[' ? ']' : '}';
        bool needs_value = false;
        cursor = skip_whitespace(cursor);
        while (*cursor && *cursor != close) {
            if (needs_value) {
                if (*cursor != ',') return false;
                cursor = skip_whitespace(cursor + 1);
                if (*cursor == close) return false;
            }
            if (open == '{') {
                if (*cursor != '"' || !skip_json_string(&cursor)) return false;
                cursor = skip_whitespace(cursor);
                if (*cursor != ':') return false;
                cursor++;
            }
            if (!skip_json_value(&cursor)) return false;
            cursor = skip_whitespace(cursor);
            needs_value = true;
        }
        if (*cursor != close) return false;
        cursor++;
    } else if (strncmp(cursor, "true", 4) == 0) {
        cursor += 4;
    } else if (strncmp(cursor, "false", 5) == 0) {
        cursor += 5;
    } else if (strncmp(cursor, "null", 4) == 0) {
        cursor += 4;
    } else {
        char *end;
        (void)strtod(cursor, &end);
        if (end == cursor) return false;
        cursor = end;
    }

    *p = cursor;
    return true;
}

static char *copy_json_value(const char *start, const char *end) {
    size_t length = (size_t)(end - start);
    char *copy = (char *) ng_malloc_add(length, 1);
    if (!copy) return NULL;
    memcpy(copy, start, length);
    copy[length] = '\0';
    return copy;
}

/* Parse a JSON string value (assumes current position is after opening quote) */
static char *parse_json_string(const char **p) {
    const char *start = *p;
    size_t len = 0;
    bool escape = false;
    
    /* Find string end, accounting for escapes */
    while (start[len] && (escape || start[len] != '"')) {
        if (escape) {
            escape = false;
        } else if (start[len] == '\\') {
            escape = true;
        }
        len++;
    }
    
    if (!start[len]) {
        return NULL;  /* Unterminated string */
    }
    
    /* Unescape string */
    char *result = (char *) ng_malloc_add(len, 1);
    if (!result) return NULL;
    
    size_t out_idx = 0;
    size_t in_idx = 0;
    
    while (in_idx < len) {
        if (start[in_idx] == '\\' && in_idx + 1 < len) {
            in_idx++;
            char c = start[in_idx];
            switch (c) {
                case '"':  result[out_idx++] = '"'; break;
                case '\\': result[out_idx++] = '\\'; break;
                case '/':  result[out_idx++] = '/'; break;
                case 'b':  result[out_idx++] = '\b'; break;
                case 'f':  result[out_idx++] = '\f'; break;
                case 'n':  result[out_idx++] = '\n'; break;
                case 'r':  result[out_idx++] = '\r'; break;
                case 't':  result[out_idx++] = '\t'; break;
                default:   result[out_idx++] = c; break;
            }
        } else {
            result[out_idx++] = start[in_idx];
        }
        in_idx++;
    }
    result[out_idx] = '\0';
    
    *p = start + len + 1;  /* Skip closing quote */
    return result;
}

/* Parse a JSON number */
static bool parse_json_number(const char **p, long long *out) {
    char *end;
    *out = strtoll(*p, &end, 10);
    if (end == *p) {
        return false;
    }
    *p = end;
    return true;
}

/* Parse a JSON value from current position */
static json_type_t parse_json_value(const char **p, json_value_t *value) {
    *p = skip_whitespace(*p);
    
    if (!*p || !**p) {
        value->type = JSON_TYPE_NULL;
        return JSON_TYPE_NULL;
    }
    
    char c = **p;
    
    if (c == '"') {
        (*p)++;  /* Skip opening quote */
        value->value.string_val = parse_json_string(p);
        if (!value->value.string_val) {
            value->type = JSON_TYPE_NULL;
            return JSON_TYPE_NULL;
        }
        value->type = JSON_TYPE_STRING;
        return JSON_TYPE_STRING;
    }
    
    if (c == '[' || c == '{') {
        const char *start = *p;
        if (!skip_json_value(p)) {
            value->type = JSON_TYPE_NULL;
            return JSON_TYPE_NULL;
        }
        value->value.string_val = copy_json_value(start, *p);
        if (!value->value.string_val) {
            value->type = JSON_TYPE_NULL;
            return JSON_TYPE_NULL;
        }
        value->type = c == '[' ? JSON_TYPE_ARRAY : JSON_TYPE_OBJECT;
        return value->type;
    }
    
    if (c == 't' && strncmp(*p, "true", 4) == 0) {
        *p += 4;
        value->value.bool_val = true;
        value->type = JSON_TYPE_BOOL;
        return JSON_TYPE_BOOL;
    }
    
    if (c == 'f' && strncmp(*p, "false", 5) == 0) {
        *p += 5;
        value->value.bool_val = false;
        value->type = JSON_TYPE_BOOL;
        return JSON_TYPE_BOOL;
    }
    
    if (c == 'n' && strncmp(*p, "null", 4) == 0) {
        *p += 4;
        value->type = JSON_TYPE_NULL;
        return JSON_TYPE_NULL;
    }
    
    if (isdigit(c) || c == '-') {
        if (parse_json_number(p, &value->value.number_val)) {
            value->type = JSON_TYPE_NUMBER;
            return JSON_TYPE_NUMBER;
        }
    }
    
    value->type = JSON_TYPE_NULL;
    return JSON_TYPE_NULL;
}

/* ============================================================================
 * JSON Array Parser Implementation
 * ============================================================================ */

size_t json_array_parse(const char *json_str, json_value_t *values, size_t max_values) {
    if (!json_str || !values || max_values == 0) {
        return 0;
    }
    
    const char *p = skip_whitespace(json_str);
    
    if (!p || *p != '[') {
        return 0;  /* Not an array */
    }
    
    p++;  /* Skip opening bracket */
    size_t count = 0;
    
    while (count < max_values) {
        p = skip_whitespace(p);
        
        if (!p || !*p) {
            return 0;  /* Unterminated array */
        }
        
        if (*p == ']') {
            return count;  /* End of array */
        }
        
        if (count > 0) {
            /* Expect comma separator */
            if (*p != ',') {
                return 0;  /* Expected comma */
            }
            p++;
        }
        
        p = skip_whitespace(p);
        
        if (!p || !*p) {
            return 0;  /* Unterminated array */
        }
        
        if (*p == ']') {
            /* Trailing comma edge case */
            return count;
        }
        
        if (parse_json_value(&p, &values[count]) == JSON_TYPE_NULL &&
            strncmp(skip_whitespace(p), "null", 4) != 0) {
            json_array_free(values, count);
            return 0;
        }
        count++;
    }
    
    return count;
}

void json_array_free(json_value_t *values, size_t count) {
    for (size_t i = 0; i < count; i++) {
           if ((values[i].type == JSON_TYPE_STRING ||
               values[i].type == JSON_TYPE_ARRAY ||
               values[i].type == JSON_TYPE_OBJECT) && values[i].value.string_val) {
            free(values[i].value.string_val);
            values[i].value.string_val = NULL;
        }
    }
}

const char *json_array_get_string(const json_value_t *values, size_t count, size_t index) {
    if (index >= count) {
        return NULL;
    }
    if (values[index].type != JSON_TYPE_STRING) {
        return NULL;
    }
    return values[index].value.string_val;
}

bool json_array_get_number(const json_value_t *values, size_t count, size_t index, long long *out) {
    if (index >= count) {
        return false;
    }
    if (values[index].type != JSON_TYPE_NUMBER) {
        return false;
    }
    *out = values[index].value.number_val;
    return true;
}

/* ============================================================================
 * JSON Builder Implementation
 * ============================================================================ */

/* Make room for `needed` more bytes plus the closing ']' and NUL that
 * json_builder_finish() appends. Errors are sticky: once a reservation
 * fails every later append is a no-op and finish() returns NULL. */
static bool json_builder_reserve(json_builder_t *b, size_t needed) {
    size_t want;
    if (b->status != NG_OK) return false;
    if (!ng_size_add3(b->pos, needed, 2, &want) || want > JSON_BUILDER_MAX) {
        b->status = NG_E_TOOBIG;
        return false;
    }
    if (want <= b->cap) return true;
    size_t cap = ng_grow_cap(b->cap, want, JSON_BUILDER_INLINE);
    if (cap > JSON_BUILDER_MAX) cap = JSON_BUILDER_MAX;
    char *nb;
    if (b->buf == b->inline_buf) {
        nb = (char *) malloc(cap);
        if (nb) memcpy(nb, b->buf, b->pos);
    } else {
        nb = (char *) realloc(b->buf, cap);
    }
    if (!nb) { b->status = NG_E_NOMEM; return false; }
    b->buf = nb;
    b->cap = cap;
    return true;
}

static void json_builder_raw(json_builder_t *b, const char *s, size_t n) {
    if (!json_builder_reserve(b, n)) return;
    memcpy(b->buf + b->pos, s, n);
    b->pos += n;
}

static void json_builder_byte(json_builder_t *b, char c) {
    if (!json_builder_reserve(b, 1)) return;
    b->buf[b->pos++] = c;
}

void json_builder_start(json_builder_t *builder) {
    builder->buf = builder->inline_buf;
    builder->cap = sizeof(builder->inline_buf);
    builder->status = NG_OK;
    builder->buf[0] = '[';
    builder->pos = 1;
}

void json_builder_reset(json_builder_t *builder) {
    if (!builder->buf) { json_builder_start(builder); return; }
    if (builder->buf != builder->inline_buf && builder->cap > JSON_BUILDER_KEEP) {
        free(builder->buf);
        json_builder_start(builder);
        return;
    }
    builder->status = NG_OK;
    builder->buf[0] = '[';
    builder->pos = 1;
}

void json_builder_free(json_builder_t *builder) {
    if (builder->buf && builder->buf != builder->inline_buf) free(builder->buf);
    builder->buf = NULL;
    builder->cap = builder->pos = 0;
}

static NG_THREAD_LOCAL json_builder_t scratch[JSON_SCRATCH_SLOTS];
static NG_THREAD_LOCAL bool scratch_registered;
static pthread_key_t scratch_key;
static pthread_once_t scratch_once = PTHREAD_ONCE_INIT;
static bool scratch_key_ok;

static void scratch_release(void *unused) {
    (void) unused;
    for (int i = 0; i < JSON_SCRATCH_SLOTS; i++) json_builder_free(&scratch[i]);
}

static void scratch_key_init(void) {
    scratch_key_ok = pthread_key_create(&scratch_key, scratch_release) == 0;
}

json_builder_t *json_builder_scratch(json_scratch_t slot) {
    if (!scratch_registered) {
        scratch_registered = true;
        /* The key's value is only a non-NULL marker so its destructor runs
         * (in this thread, while its TLS is still valid) at thread exit. */
        pthread_once(&scratch_once, scratch_key_init);
        if (scratch_key_ok) (void) pthread_setspecific(scratch_key, &scratch[0]);
    }
    json_builder_reset(&scratch[slot]);
    return &scratch[slot];
}

ng_status_t json_builder_status(const json_builder_t *builder) {
    return builder->status;
}

static void json_builder_add_comma(json_builder_t *builder) {
    if (builder->pos == 0) return;
    char last = builder->buf[builder->pos - 1];
    if (builder->pos > 1 && last != '[' && last != '{' && last != ':')
        json_builder_byte(builder, ',');
}

void json_builder_append_null(json_builder_t *builder) {
    json_builder_add_comma(builder);
    json_builder_raw(builder, "null", 4);
}

void json_builder_append_bool(json_builder_t *builder, bool value) {
    json_builder_add_comma(builder);
    if (value) json_builder_raw(builder, "true", 4);
    else json_builder_raw(builder, "false", 5);
}

static void json_builder_number(json_builder_t *builder, long long value) {
    char num[24];
    int n = snprintf(num, sizeof(num), "%lld", value);
    if (n > 0 && (size_t) n < sizeof(num)) json_builder_raw(builder, num, (size_t) n);
}

void json_builder_append_number(json_builder_t *builder, long long value) {
    json_builder_add_comma(builder);
    json_builder_number(builder, value);
}

/* escaped_length - Number of bytes json_builder_escape_string writes for s */
static size_t escaped_length(const char *s) {
    size_t n = 0;
    for (; s && *s; s++) {
        unsigned char c = (unsigned char) *s;
        if (c == '"' || c == '\\' || c == '\b' || c == '\f' ||
            c == '\n' || c == '\r' || c == '\t') {
            n += 2;
        } else if (c < 0x20) {
            n += 6;
        } else {
            n += 1;
        }
    }
    return n;
}

/* json_builder_escape_string - Append a JSON-escaped string value
 *
 * Escapes everything the JSON spec requires: `"`, `\` and every control
 * character below 0x20 (\b \f \n \r \t as short escapes, the rest as \u00XX).
 * Bytes >= 0x20 (including UTF-8 sequences and 0x7f) pass through.
 * Sizes the output exactly first (one reservation, plain memcpy when nothing
 * needs escaping), then writes without per-byte bound checks.
 */
static void json_builder_escape_string(json_builder_t *builder, const char *value) {
    static const char hex[] = "0123456789abcdef";
    size_t out = escaped_length(value);
    if (!json_builder_reserve(builder, out)) return;
    char *w = builder->buf + builder->pos;
    builder->pos += out;
    if (out == strlen(value)) { memcpy(w, value, out); return; }
    for (; *value; value++) {
        unsigned char c = (unsigned char) *value;
        if (c == '"' || c == '\\') { *w++ = '\\'; *w++ = (char) c; }
        else if (c >= 0x20) *w++ = (char) c;
        else if (c == '\b') { *w++ = '\\'; *w++ = 'b'; }
        else if (c == '\f') { *w++ = '\\'; *w++ = 'f'; }
        else if (c == '\n') { *w++ = '\\'; *w++ = 'n'; }
        else if (c == '\r') { *w++ = '\\'; *w++ = 'r'; }
        else if (c == '\t') { *w++ = '\\'; *w++ = 't'; }
        else { memcpy(w, "\\u00", 4); w[4] = hex[c >> 4]; w[5] = hex[c & 15]; w += 6; }
    }
}

static void json_builder_quoted(json_builder_t *builder, const char *value) {
    json_builder_byte(builder, '"');
    json_builder_escape_string(builder, value ? value : "");
    json_builder_byte(builder, '"');
}

/* "key": -- keys are compile-time literals; escaped anyway for safety. */
static void json_builder_key(json_builder_t *builder, const char *key) {
    json_builder_add_comma(builder);
    json_builder_quoted(builder, key);
    json_builder_byte(builder, ':');
}

void json_builder_append_string(json_builder_t *builder, const char *value) {
    json_builder_add_comma(builder);
    json_builder_quoted(builder, value);
}

void json_builder_start_array(json_builder_t *builder) {
    json_builder_add_comma(builder);
    json_builder_byte(builder, '[');
}

void json_builder_end_array(json_builder_t *builder) {
    json_builder_byte(builder, ']');
}

void json_builder_start_object(json_builder_t *builder) {
    json_builder_add_comma(builder);
    json_builder_byte(builder, '{');
}

void json_builder_object_key_string(json_builder_t *builder, const char *key, const char *value) {
    json_builder_key(builder, key);
    json_builder_quoted(builder, value);
}

void json_builder_object_key_number(json_builder_t *builder, const char *key, long long value) {
    json_builder_key(builder, key);
    json_builder_number(builder, value);
}

void json_builder_object_key_bool(json_builder_t *builder, const char *key, bool value) {
    json_builder_key(builder, key);
    if (value) json_builder_raw(builder, "true", 4);
    else json_builder_raw(builder, "false", 5);
}

void json_builder_object_start_nested(json_builder_t *builder, const char *key) {
    json_builder_key(builder, key);
    json_builder_byte(builder, '{');
}

void json_builder_end_object(json_builder_t *builder) {
    json_builder_byte(builder, '}');
}

const char *json_builder_finish(json_builder_t *builder) {
    if (builder->status != NG_OK) return NULL;
    /* Every reservation kept 2 spare bytes, so this cannot fail. */
    builder->buf[builder->pos++] = ']';
    builder->buf[builder->pos] = '\0';
    return builder->buf;
}

size_t json_builder_length(const json_builder_t *builder) {
    return builder->pos;
}

/* ============================================================================
 * Filter and Event Parsing
 * ============================================================================ */

static char *json_raw_string(jstr_t value) {
    char *wrapped;
    json_value_t parsed[1] = {{0}};
    size_t length = value.len;
    char *result = NULL;

    if (!value.buf || length > MAX_JSON_STRING_VALUE) return NULL;
    wrapped = (char *) ng_malloc_add(length, 3);
    if (!wrapped) return NULL;
    wrapped[0] = '[';
    memcpy(wrapped + 1, value.buf, length);
    wrapped[length + 1] = ']';
    wrapped[length + 2] = '\0';
    if (json_array_parse(wrapped, parsed, 1) == 1 &&
        parsed[0].type == JSON_TYPE_STRING) {
        result = parsed[0].value.string_val;
        parsed[0].value.string_val = NULL;
    }
    json_array_free(parsed, 1);
    free(wrapped);
    return result;
}

/* is_hex_64 - Check that a string is exactly 64 lowercase hex characters
 *
 * NIP-01 requires the values in the `ids`, `authors`, `#e` and `#p` filter
 * lists to be exact 64-character lowercase hex strings. This rejects short
 * prefixes (which would otherwise match via prefix comparison) and any
 * non-hex or uppercase characters.
 */
static bool is_hex_64(const char *s) {
    if (!s) return false;
    for (size_t i = 0; i < 64; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return s[64] == '\0';
}

/* is_lower_hex - Check that a string is exactly `len` lowercase hex characters
 *
 * Defense-in-depth at the json_parse_event trust boundary: NIP-01 requires
 * `id`/`pubkey` to be 64-char and `sig` to be 128-char lowercase hex. Even
 * though downstream hex_to_bytes/strcmp fail safely on malformed input,
 * validate here so malformed events are rejected at parse time.
 */
static bool is_lower_hex(const char *s, size_t len) {
    if (!s) return false;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

/* append_string - Append `value` to a growable array of owned strings.
 *
 * `capacity` is in/out: the caller passes the current allocation size and it
 * is updated here after every growth. The previous version passed it by
 * value and recomputed it from a constant, so the array could never grow
 * beyond 32 slots while callers allowed up to 256 entries — a heap buffer
 * overflow reachable from a single REQ filter with >32 ids/authors.
 */
static bool append_string(char ***items, size_t *count, size_t *capacity, const char *value) {
    if (*count >= *capacity) {
        size_t new_capacity = *capacity == 0 ? 16 : *capacity * 2;
        char **resized = (char **) ng_realloc_array(*items, new_capacity, sizeof(**items));
        if (!resized) return false;
        *items = resized;
        *capacity = new_capacity;
    }
    (*items)[*count] = string_dup(value);
    if (!(*items)[*count]) return false;
    (*count)++;
    return true;
}

static bool parse_string_array(jstr_t raw, char ***items, size_t *count,
                               size_t max_items, bool require_hex64) {
    jstr_t key, value;
    size_t offset = 0;
    size_t alloc_size = 16;
    *items = (char **) calloc(alloc_size, sizeof(**items));
    if (!*items) return false;

    while ((offset = jl_next(raw, offset, &key, &value)) != 0) {
        char *string;
        if (*count >= max_items || key.buf != NULL) {
            /* Free previously allocated strings on error */
            for (size_t i = 0; i < *count; i++) free((*items)[i]);
            free(*items);
            *items = NULL;
            *count = 0;
            return false;
        }
        string = json_raw_string(value);
        if (!string || (require_hex64 && !is_hex_64(string))) {
            free(string);
            /* Free previously allocated strings on error */
            for (size_t i = 0; i < *count; i++) free((*items)[i]);
            free(*items);
            *items = NULL;
            *count = 0;
            return false;
        }
        if (!append_string(items, count, &alloc_size, string)) {
            free(string);
            /* Free previously allocated strings on error */
            for (size_t i = 0; i < *count; i++) free((*items)[i]);
            free(*items);
            *items = NULL;
            *count = 0;
            return false;
        }
        free(string);
    }
    return true;
}

static bool append_filter_tag(filter_t *filter, const char *name,
                              jstr_t raw) {
    jstr_t key, value;
    tag_t *tag;
    tag_t *resized;
    size_t offset = 0;

    if (filter->tags_count >= MAX_TAG_ELEMENTS || name[0] == '\0') return false;
    tag = tag_alloc(MAX_TAG_ELEMENTS);
    if (!tag) return false;
    tag->elements[tag->count++] = string_dup(name);
    if (!tag->elements[0]) {
        tag_free(tag);
        return false;
    }
    /* NIP-01: values in #e and #p filters must be exact 64-char lowercase hex */
    bool require_hex64 = (strcmp(name, "e") == 0 || strcmp(name, "p") == 0);
    while ((offset = jl_next(raw, offset, &key, &value)) != 0) {
        char *string;
        if (key.buf != NULL || tag->count >= tag->capacity) {
            tag_free(tag);
            return false;
        }
        string = json_raw_string(value);
        if (!string || (require_hex64 && !is_hex_64(string))) {
            free(string);
            tag_free(tag);
            return false;
        }
        tag->elements[tag->count++] = string;
    }
    if (tag->count < 2) {
        tag_free(tag);
        return false;
    }
    resized = (tag_t *) ng_realloc_array(filter->tags, filter->tags_count + 1, sizeof(*resized));
    if (!resized) {
        tag_free(tag);
        return false;
    }
    filter->tags = resized;
    filter->tags[filter->tags_count++] = *tag;
    free(tag);
    return true;
}

static bool validate_event_tags(jstr_t tags) {
    jstr_t key, tag;
    size_t tag_offset = 0;
    size_t tag_count = 0;
    if (!tags.buf || tags.len < 2 || tags.buf[0] != '[') return false;
    while ((tag_offset = jl_next(tags, tag_offset, &key, &tag)) != 0) {
        jstr_t element_key, element;
        size_t element_offset = 0;
        size_t element_count = 0;
        if (key.buf != NULL || ++tag_count > 100 || tag.len < 2 || tag.buf[0] != '[') return false;
        /* Per-tag element cap must match parse_tags_json() in crypto.c: its
         * scanner aborts (returning NULL) beyond MAX_TAG_ELEMENTS elements,
         * which used to silently skip delegation-tag verification while the
         * json_lite-based tag lookups still honored the tag. Keep both
         * parsers in lockstep so anything accepted here is fully scanned. */
        while ((element_offset = jl_next(tag, element_offset, &element_key, &element)) != 0) {
            char *string;
            if (element_key.buf != NULL || ++element_count > MAX_TAG_ELEMENTS) return false;
            string = json_raw_string(element);
            if (!string || strlen(string) > MAX_TAG_SIZE) {
                free(string);
                return false;
            }
            free(string);
        }
    }
    return true;
}

bool json_parse_filter(const char *json_str, filter_t *filter) {
    jstr_t object, key, value;
    size_t offset = 0;
    if (!json_str || !filter) return false;

    *filter = (filter_t) {0};
    filter->limit = 500;
    object = jl_str(json_str);
    if (object.len < 2 || object.buf[0] != '{') return false;

    bool ok = true;
    while (ok && (offset = jl_next(object, offset, &key, &value)) != 0) {
        char *field = json_raw_string(key);
        ok = field != NULL;
        if (!ok) break;
        if (strcmp(field, "ids") == 0) {
            ok = parse_string_array(value, &filter->ids, &filter->ids_count, 256, true);
        } else if (strcmp(field, "authors") == 0) {
            ok = parse_string_array(value, &filter->authors, &filter->authors_count, 256, true);
        } else if (strcmp(field, "kinds") == 0) {
            jstr_t array_key, array_value;
            size_t array_offset = 0;
            while (ok && (array_offset = jl_next(value, array_offset,
                                                       &array_key, &array_value)) != 0) {
                char *number_text, *end = NULL;
                long kind;
                int *resized;
                if (array_key.buf != NULL || filter->kinds_count >= 256) { ok = false; break; }
                number_text = copy_json_value(array_value.buf, array_value.buf + array_value.len);
                if (!number_text) { ok = false; break; }
                kind = strtol(number_text, &end, 10);
                if (*end != '\0' || kind < INT_MIN || kind > INT_MAX) { free(number_text); ok = false; break; }
                free(number_text);
                resized = (int *) ng_realloc_array(filter->kinds, filter->kinds_count + 1, sizeof(*resized));
                if (!resized) { ok = false; break; }
                filter->kinds = resized;
                filter->kinds[filter->kinds_count++] = (int) kind;
            }
        } else if (field[0] == '#' && field[1] != '\0') {
            ok = append_filter_tag(filter, field + 1, value);
        } else if (strcmp(field, "since") == 0 || strcmp(field, "until") == 0 ||
                   strcmp(field, "limit") == 0) {
            char *number_text = copy_json_value(value.buf, value.buf + value.len);
            char *end = NULL;
            long long number;
            if (!number_text) { free(field); break; }
            number = strtoll(number_text, &end, 10);
            ok = *end == '\0';
            if (ok && strcmp(field, "since") == 0) filter->since = (time_t) number;
            if (ok && strcmp(field, "until") == 0) filter->until = (time_t) number;
            if (ok && strcmp(field, "limit") == 0 && number >= 0) filter->limit = number > 500 ? 500 : (int) number;
            else if (strcmp(field, "limit") == 0 && (!ok || number < 0)) ok = false;
            free(number_text);
        } else if (strcmp(field, "search") == 0) {
            filter->search = json_raw_string(value);
            ok = filter->search != NULL;
        }
        free(field);
        if (!ok) break;
    }
    return ok;
}

bool json_parse_event(const char *json_str, event_t *event) {
    jstr_t json;
    jstr_t tags;
    char *id, *pubkey, *content, *sig;
    double created_at, kind;
    if (!json_str || !event) return false;
    memset(event, 0, sizeof(*event));
    json = jl_str(json_str);
    id = jl_get_str(json, "$.id");
    pubkey = jl_get_str(json, "$.pubkey");
    content = jl_get_str(json, "$.content");
    sig = jl_get_str(json, "$.sig");
    tags = jl_get_tok(json, "$.tags");
    if (!id || !pubkey || !content || !sig || !tags.buf ||
        strlen(id) != MAX_ID_SIZE || strlen(pubkey) != MAX_PUBKEY_SIZE ||
        strlen(sig) != MAX_SIG_SIZE || tags.len > MAX_TAGS_SIZE ||
        !is_lower_hex(id, MAX_ID_SIZE) || !is_lower_hex(pubkey, MAX_PUBKEY_SIZE) ||
        !is_lower_hex(sig, MAX_SIG_SIZE) ||
        strlen(content) > MAX_CONTENT_SIZE || !jl_get_num(json, "$.created_at", &created_at) ||
        !jl_get_num(json, "$.kind", &kind) || created_at != (double)(time_t)created_at || kind != (int) kind ||
        !validate_event_tags(tags)) {
        free(id); free(pubkey); free(content); free(sig);
        return false;
    }
    strcpy(event->id, id);
    strcpy(event->pubkey, pubkey);
    strcpy(event->sig, sig);
    event->created_at = (time_t) created_at;
    event->kind = (int) kind;
    event->content = content;
    event->content_len = strlen(content);
    event->tags_json = copy_json_value(tags.buf, tags.buf + tags.len);
    event->tags_json_len = tags.len;
    free(id); free(pubkey); free(sig);
    if (!event->tags_json) {
        event_release(event);
        return false;
    }
    return true;
}

size_t json_serialized_event_size(const event_t *event) {
    if (!event) return 0;
    /* Mirror json_serialize_event() segment by segment:
     *   {"id":"<id>","pubkey":"<pubkey>","created_at":N,"kind":N,
     *    "tags":<tags>,"content":"<content>","sig":"<sig>"}
     * Each segment is: comma + '"<key>":' + quotes + value length. */
    char num[32];
    int written;

    size_t n = 1; /* '{' */
    n += 5 + 1 + escaped_length(event->id) + 1;           /* "id": */
    n += 1 + 9 + 1 + escaped_length(event->pubkey) + 1;   /* "pubkey": */
    written = snprintf(num, sizeof(num), "%lld", (long long) event->created_at);
    n += 1 + 13 + (size_t) (written > 0 ? written : 20);  /* "created_at": */
    written = snprintf(num, sizeof(num), "%d", event->kind);
    n += 1 + 7 + (size_t) (written > 0 ? written : 11);   /* "kind": */
    n += 1 + 7 + (event->tags_json ? event->tags_json_len : 4); /* "tags": or null */
    n += 1 + 10 + 1 + escaped_length(event->content ? event->content : "") + 1;
    n += 1 + 6 + 1 + escaped_length(event->sig) + 1;      /* "sig": */
    n += 1; /* '}' */
    return n;
}

void json_serialize_event(const event_t *event, json_builder_t *builder) {
    if (!event || !builder) return;
    
    json_builder_start_object(builder);
    json_builder_object_key_string(builder, "id", event->id);
    json_builder_object_key_string(builder, "pubkey", event->pubkey);
    json_builder_object_key_number(builder, "created_at", event->created_at);
    json_builder_object_key_number(builder, "kind", event->kind);
    json_builder_key(builder, "tags");
    if (event->tags_json) json_builder_raw(builder, event->tags_json, event->tags_json_len);
    else json_builder_raw(builder, "null", 4);
    json_builder_object_key_string(builder, "content", event->content ? event->content : "");
    json_builder_object_key_string(builder, "sig", event->sig);
    json_builder_end_object(builder);
}
