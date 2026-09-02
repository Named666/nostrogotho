#include "json_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <mongoose.h>

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
    char *copy = (char *)malloc(length + 1);
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
    char *result = (char *)malloc(len + 1);
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

void json_builder_start(json_builder_t *builder) {
    memset(builder, 0, sizeof(*builder));
    builder->buffer[0] = '[';
    builder->pos = 1;
}

static bool json_builder_ensure_space(json_builder_t *builder, size_t needed) {
    return builder->pos + needed < sizeof(builder->buffer);
}

static void json_builder_add_comma(json_builder_t *builder) {
    if (builder->pos > 1 && builder->buffer[builder->pos - 1] != '[' && 
        builder->buffer[builder->pos - 1] != '{' && builder->buffer[builder->pos - 1] != ':') {
        if (json_builder_ensure_space(builder, 1)) {
            builder->buffer[builder->pos++] = ',';
        }
    }
}

void json_builder_append_null(json_builder_t *builder) {
    json_builder_add_comma(builder);
    if (json_builder_ensure_space(builder, 4)) {
        memcpy(&builder->buffer[builder->pos], "null", 4);
        builder->pos += 4;
    }
}

void json_builder_append_bool(json_builder_t *builder, bool value) {
    json_builder_add_comma(builder);
    if (value) {
        if (json_builder_ensure_space(builder, 4)) {
            memcpy(&builder->buffer[builder->pos], "true", 4);
            builder->pos += 4;
        }
    } else {
        if (json_builder_ensure_space(builder, 5)) {
            memcpy(&builder->buffer[builder->pos], "false", 5);
            builder->pos += 5;
        }
    }
}

void json_builder_append_number(json_builder_t *builder, long long value) {
    json_builder_add_comma(builder);
    if (json_builder_ensure_space(builder, 32)) {
        int written = snprintf(&builder->buffer[builder->pos], 32, "%lld", value);
        if (written > 0) {
            builder->pos += written;
        }
    }
}

void json_builder_append_string(json_builder_t *builder, const char *value) {
    json_builder_add_comma(builder);
    
    if (!json_builder_ensure_space(builder, 2)) return;
    builder->buffer[builder->pos++] = '"';
    
    for (size_t i = 0; value[i]; i++) {
        unsigned char c = (unsigned char)value[i];
        
        if (c == '"' || c == '\\' || c == '/') {
            if (!json_builder_ensure_space(builder, 2)) return;
            builder->buffer[builder->pos++] = '\\';
            builder->buffer[builder->pos++] = c;
        } else if (c == '\b') {
            if (!json_builder_ensure_space(builder, 2)) return;
            builder->buffer[builder->pos++] = '\\';
            builder->buffer[builder->pos++] = 'b';
        } else if (c == '\f') {
            if (!json_builder_ensure_space(builder, 2)) return;
            builder->buffer[builder->pos++] = '\\';
            builder->buffer[builder->pos++] = 'f';
        } else if (c == '\n') {
            if (!json_builder_ensure_space(builder, 2)) return;
            builder->buffer[builder->pos++] = '\\';
            builder->buffer[builder->pos++] = 'n';
        } else if (c == '\r') {
            if (!json_builder_ensure_space(builder, 2)) return;
            builder->buffer[builder->pos++] = '\\';
            builder->buffer[builder->pos++] = 'r';
        } else if (c == '\t') {
            if (!json_builder_ensure_space(builder, 2)) return;
            builder->buffer[builder->pos++] = '\\';
            builder->buffer[builder->pos++] = 't';
        } else if (c < 0x20) {
            if (!json_builder_ensure_space(builder, 6)) return;
            builder->pos += snprintf(&builder->buffer[builder->pos], 6, "\\u%04x", c);
        } else {
            if (!json_builder_ensure_space(builder, 1)) return;
            builder->buffer[builder->pos++] = c;
        }
    }
    
    if (json_builder_ensure_space(builder, 1)) {
        builder->buffer[builder->pos++] = '"';
    }
}

void json_builder_start_array(json_builder_t *builder) {
    json_builder_add_comma(builder);
    if (json_builder_ensure_space(builder, 1)) {
        builder->buffer[builder->pos++] = '[';
    }
}

void json_builder_end_array(json_builder_t *builder) {
    if (json_builder_ensure_space(builder, 1)) {
        builder->buffer[builder->pos++] = ']';
    }
}

void json_builder_start_object(json_builder_t *builder) {
    json_builder_add_comma(builder);
    if (json_builder_ensure_space(builder, 1)) {
        builder->buffer[builder->pos++] = '{';
    }
}

void json_builder_object_key_string(json_builder_t *builder, const char *key, const char *value) {
    json_builder_add_comma(builder);
    if (!json_builder_ensure_space(builder, 4)) return;
    
    builder->buffer[builder->pos++] = '"';
    builder->pos += snprintf(&builder->buffer[builder->pos], 128, "%s\":", key);
    
    /* Append string value with escaping */
    if (!json_builder_ensure_space(builder, 2)) return;
    builder->buffer[builder->pos++] = '"';
    
    for (size_t i = 0; value && value[i]; i++) {
        unsigned char c = (unsigned char)value[i];
        if (c == '"' || c == '\\') {
            if (!json_builder_ensure_space(builder, 2)) return;
            builder->buffer[builder->pos++] = '\\';
            builder->buffer[builder->pos++] = c;
        } else if (c == '\n') {
            if (!json_builder_ensure_space(builder, 2)) return;
            builder->buffer[builder->pos++] = '\\';
            builder->buffer[builder->pos++] = 'n';
        } else if (c < 0x20) {
            if (!json_builder_ensure_space(builder, 6)) return;
            builder->pos += snprintf(&builder->buffer[builder->pos], 6, "\\u%04x", c);
        } else {
            if (!json_builder_ensure_space(builder, 1)) return;
            builder->buffer[builder->pos++] = c;
        }
    }
    
    if (json_builder_ensure_space(builder, 1)) {
        builder->buffer[builder->pos++] = '"';
    }
}

void json_builder_object_key_number(json_builder_t *builder, const char *key, long long value) {
    json_builder_add_comma(builder);
    if (json_builder_ensure_space(builder, 128)) {
        builder->pos += snprintf(&builder->buffer[builder->pos], 128, "\"%s\":%lld", key, value);
    }
}

void json_builder_object_key_bool(json_builder_t *builder, const char *key, bool value) {
    json_builder_add_comma(builder);
    if (json_builder_ensure_space(builder, 128)) {
        builder->pos += snprintf(&builder->buffer[builder->pos], 128, "\"%s\":%s", 
                                 key, value ? "true" : "false");
    }
}

void json_builder_object_start_nested(json_builder_t *builder, const char *key) {
    json_builder_add_comma(builder);
    if (json_builder_ensure_space(builder, 128)) {
        builder->pos += snprintf(&builder->buffer[builder->pos], 128, "\"%s\":{", key);
    }
}

void json_builder_end_object(json_builder_t *builder) {
    if (json_builder_ensure_space(builder, 1)) {
        builder->buffer[builder->pos++] = '}';
    }
}

const char *json_builder_finish(json_builder_t *builder) {
    if (json_builder_ensure_space(builder, 1)) {
        builder->buffer[builder->pos++] = ']';
        builder->buffer[builder->pos] = '\0';
    }
    return builder->buffer;
}

/* ============================================================================
 * Filter and Event Parsing
 * ============================================================================ */

static char *json_raw_string(struct mg_str value) {
    char *wrapped;
    json_value_t parsed[1] = {{0}};
    size_t length = value.len;
    char *result = NULL;

    if (!value.buf || length > MAX_JSON_STRING_VALUE) return NULL;
    wrapped = (char *) malloc(length + 3);
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

static bool append_string(char ***items, size_t *count, const char *value) {
    char **resized = (char **) realloc(*items, (*count + 1) * sizeof(**items));
    if (!resized) return false;
    resized[*count] = string_dup(value);
    if (!resized[*count]) return false;
    *items = resized;
    (*count)++;
    return true;
}

static bool parse_string_array(struct mg_str raw, char ***items, size_t *count,
                               size_t max_items) {
    struct mg_str key, value;
    size_t offset = 0;
    while ((offset = mg_json_next(raw, offset, &key, &value)) != 0) {
        char *string;
        if (*count >= max_items || key.buf != NULL) return false;
        string = json_raw_string(value);
        if (!string || !append_string(items, count, string)) {
            free(string);
            return false;
        }
        free(string);
    }
    return true;
}

static bool append_filter_tag(filter_t *filter, const char *name,
                              struct mg_str raw) {
    struct mg_str key, value;
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
    while ((offset = mg_json_next(raw, offset, &key, &value)) != 0) {
        char *string;
        if (key.buf != NULL || tag->count >= tag->capacity) {
            tag_free(tag);
            return false;
        }
        string = json_raw_string(value);
        if (!string) {
            tag_free(tag);
            return false;
        }
        tag->elements[tag->count++] = string;
    }
    if (tag->count < 2) {
        tag_free(tag);
        return false;
    }
    resized = (tag_t *) realloc(filter->tags,
                                 (filter->tags_count + 1) * sizeof(*resized));
    if (!resized) {
        tag_free(tag);
        return false;
    }
    filter->tags = resized;
    filter->tags[filter->tags_count++] = *tag;
    free(tag);
    return true;
}

static bool validate_event_tags(struct mg_str tags) {
    struct mg_str key, tag;
    size_t tag_offset = 0;
    size_t tag_count = 0;
    if (!tags.buf || tags.len < 2 || tags.buf[0] != '[') return false;
    while ((tag_offset = mg_json_next(tags, tag_offset, &key, &tag)) != 0) {
        struct mg_str element_key, element;
        size_t element_offset = 0;
        if (key.buf != NULL || ++tag_count > 100 || tag.len < 2 || tag.buf[0] != '[') return false;
        while ((element_offset = mg_json_next(tag, element_offset, &element_key, &element)) != 0) {
            char *string;
            if (element_key.buf != NULL) return false;
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
    struct mg_str object, key, value;
    size_t offset = 0;
    if (!json_str || !filter) return false;

    *filter = (filter_t) {0};
    filter->limit = 500;
    object = mg_str(json_str);
    if (object.len < 2 || object.buf[0] != '{') return false;

    while ((offset = mg_json_next(object, offset, &key, &value)) != 0) {
        char *field = json_raw_string(key);
        bool ok = field != NULL;
        if (!ok) break;
        if (strcmp(field, "ids") == 0) {
            ok = parse_string_array(value, &filter->ids, &filter->ids_count, 256);
        } else if (strcmp(field, "authors") == 0) {
            ok = parse_string_array(value, &filter->authors, &filter->authors_count, 256);
        } else if (strcmp(field, "kinds") == 0) {
            struct mg_str array_key, array_value;
            size_t array_offset = 0;
            while (ok && (array_offset = mg_json_next(value, array_offset,
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
                resized = (int *) realloc(filter->kinds,
                                          (filter->kinds_count + 1) * sizeof(*resized));
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
    if (!offset && object.len != 2) return false;
    if (offset == 0 && object.len == 2) return true;
    if (offset == 0) return false;
    return true;
}

bool json_parse_event(const char *json_str, event_t *event) {
    struct mg_str json;
    struct mg_str tags;
    char *id, *pubkey, *content, *sig;
    double created_at, kind;
    if (!json_str || !event) return false;
    memset(event, 0, sizeof(*event));
    json = mg_str(json_str);
    id = mg_json_get_str(json, "$.id");
    pubkey = mg_json_get_str(json, "$.pubkey");
    content = mg_json_get_str(json, "$.content");
    sig = mg_json_get_str(json, "$.sig");
    tags = mg_json_get_tok(json, "$.tags");
    if (!id || !pubkey || !content || !sig || !tags.buf ||
        strlen(id) != MAX_ID_SIZE || strlen(pubkey) != MAX_PUBKEY_SIZE ||
        strlen(sig) != MAX_SIG_SIZE || tags.len > MAX_TAGS_SIZE ||
        strlen(content) > MAX_CONTENT_SIZE || !mg_json_get_num(json, "$.created_at", &created_at) ||
        !mg_json_get_num(json, "$.kind", &kind) || created_at != (time_t) created_at || kind != (int) kind ||
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
        event_free(event);
        return false;
    }
    return true;
}

void json_serialize_event(const event_t *event, json_builder_t *builder) {
    if (!event || !builder) return;
    
    json_builder_start_object(builder);
    json_builder_object_key_string(builder, "id", event->id);
    json_builder_object_key_string(builder, "pubkey", event->pubkey);
    json_builder_object_key_number(builder, "created_at", event->created_at);
    json_builder_object_key_number(builder, "kind", event->kind);
    json_builder_add_comma(builder);
    if (json_builder_ensure_space(builder, 7)) {
        memcpy(&builder->buffer[builder->pos], "\"tags\":", 7);
        builder->pos += 7;
    }
    if (event->tags_json && json_builder_ensure_space(builder, event->tags_json_len)) {
        memcpy(&builder->buffer[builder->pos], event->tags_json, event->tags_json_len);
        builder->pos += event->tags_json_len;
    } else {
        json_builder_append_null(builder);
    }
    json_builder_object_key_string(builder, "content", event->content ? event->content : "");
    json_builder_object_key_string(builder, "sig", event->sig);
    json_builder_end_object(builder);
}
