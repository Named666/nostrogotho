#include "tag_iter.h"
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Tag Iterator Implementation
 * ============================================================================ */

char *tag_iter_element(tag_iter_t *it, size_t index) {
    char path[32];
    int32_t written = snprintf(path, sizeof(path), "$[%llu]", (unsigned long long)index);
    if (written <= 0 || (size_t)written >= sizeof(path)) {
        return NULL;
    }
    return mg_json_get_str(it->tags, path);
}

bool tag_iter_next(tag_iter_t *it, struct mg_str *out_key, struct mg_str *out_tag) {
    size_t next = mg_json_next(it->tags, it->offset, out_key, out_tag);
    if (next == 0) {
        return false;
    }
    it->offset = next;
    return true;
}

/* ============================================================================
 * Tag Matching Predicates
 * ============================================================================ */

bool tag_predicate_match_name(const event_t *event, void *userdata) {
    const tag_match_name_t *match = (const tag_match_name_t *)userdata;
    tag_iter_t it;
    tag_iter_init(&it, event);
    
    struct mg_str key, tag;
    while (tag_iter_next(&it, &key, &tag)) {
        char *name = tag_iter_element(&it, 0);
        if (name && strcmp(name, match->name) == 0) {
            free(name);
            return true;
        }
        free(name);
    }
    return false;
}

bool tag_predicate_match_name_value(const event_t *event, void *userdata) {
    const tag_match_name_value_t *match = (const tag_match_name_value_t *)userdata;
    tag_iter_t it;
    tag_iter_init(&it, event);
    
    struct mg_str key, tag;
    while (tag_iter_next(&it, &key, &tag)) {
        char *name = tag_iter_element(&it, 0);
        if (name && strcmp(name, match->name) == 0) {
            char *value = tag_iter_element(&it, 1);
            bool result = value && strcmp(value, match->value) == 0;
            free(value);
            free(name);
            return result;
        }
        free(name);
    }
    return false;
}

bool tag_predicate_match_name_value_opt(const event_t *event, void *userdata) {
    const tag_match_name_value_opt_t *match = (const tag_match_name_value_opt_t *)userdata;
    tag_iter_t it;
    tag_iter_init(&it, event);
    
    struct mg_str key, tag;
    while (tag_iter_next(&it, &key, &tag)) {
        char *name = tag_iter_element(&it, 0);
        if (name && strcmp(name, match->name) == 0) {
            char *value = tag_iter_element(&it, 1);
            bool result = strcmp(value ? value : "", match->value) == 0;
            free(value);
            free(name);
            return result;
        }
        free(name);
    }
    return match->empty_value_when_missing && match->value[0] == '\0';
}

bool tag_predicate_match_d_tag(const event_t *event, void *userdata) {
    const char *identifier = (const char *)userdata;
    tag_iter_t it;
    tag_iter_init(&it, event);
    
    struct mg_str key, tag;
    bool found_d = false;
    while (tag_iter_next(&it, &key, &tag)) {
        char *name = tag_iter_element(&it, 0);
        if (name && strcmp(name, "d") == 0) {
            found_d = true;
            char *value = tag_iter_element(&it, 1);
            bool matched = strcmp(value ? value : "", identifier) == 0;
            free(value);
            free(name);
            return matched;
        }
        free(name);
    }
    return !found_d && identifier[0] == '\0';
}

bool tag_predicate_match_k_tag(const event_t *event, void *userdata) {
    int *target_kind = (int *)userdata;
    tag_iter_t it;
    tag_iter_init(&it, event);
    
    struct mg_str key, tag;
    bool has_k = false;
    while (tag_iter_next(&it, &key, &tag)) {
        char *name = tag_iter_element(&it, 0);
        if (name && strcmp(name, "k") == 0) {
            has_k = true;
            char *value = tag_iter_element(&it, 1);
            if (value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end && *end == '\0' && parsed == *target_kind) {
                    free(value);
                    free(name);
                    return true;
                }
                free(value);
            }
        }
        free(name);
    }
    return !has_k;
}

/* ============================================================================
 * High-Level Tag Operations
 * ============================================================================ */

char *tag_find_value(const event_t *event, const char *name) {
    if (!event || !name || !event->tags_json) return NULL;
    
    tag_iter_t it;
    tag_iter_init(&it, event);
    
    struct mg_str key, tag;
    while (tag_iter_next(&it, &key, &tag)) {
        char *tag_name = tag_iter_element(&it, 0);
        if (tag_name && strcmp(tag_name, name) == 0) {
            char *tag_value = tag_iter_element(&it, 1);
            free(tag_name);
            return tag_value;
        }
        free(tag_name);
    }
    return NULL;
}

char **tag_find_all_values(const event_t *event, const char *name, size_t *out_count) {
    if (!event || !name || !event->tags_json || !out_count) return NULL;
    
    *out_count = 0;
    size_t capacity = 4;
    char **values = calloc(capacity, sizeof(*values));
    if (!values) return NULL;
    
    tag_iter_t it;
    tag_iter_init(&it, event);
    
    struct mg_str key, tag;
    while (tag_iter_next(&it, &key, &tag)) {
        char *tag_name = tag_iter_element(&it, 0);
        if (tag_name && strcmp(tag_name, name) == 0) {
            char *tag_value = tag_iter_element(&it, 1);
            if (tag_value) {
                if (*out_count >= capacity) {
                    capacity *= 2;
                    char **new_values = realloc(values, capacity * sizeof(*values));
                    if (!new_values) {
                        free(tag_name);
                        tag_free_values(values, *out_count);
                        return NULL;
                    }
                    values = new_values;
                }
                values[(*out_count)++] = tag_value;
            }
        }
        free(tag_name);
    }
    
    return values;
}

size_t tag_count(const event_t *event, const char *name) {
    if (!event || !name || !event->tags_json) return 0;
    
    size_t count = 0;
    tag_iter_t it;
    tag_iter_init(&it, event);
    
    struct mg_str key, tag;
    while (tag_iter_next(&it, &key, &tag)) {
        char *tag_name = tag_iter_element(&it, 0);
        if (tag_name && strcmp(tag_name, name) == 0) {
            count++;
        }
        free(tag_name);
    }
    return count;
}

bool tag_has(const event_t *event, const char *name, const char *value) {
    if (!event || !name || !event->tags_json) return false;
    
    tag_iter_t it;
    tag_iter_init(&it, event);
    
    struct mg_str key, tag;
    while (tag_iter_next(&it, &key, &tag)) {
        char *tag_name = tag_iter_element(&it, 0);
        if (tag_name && strcmp(tag_name, name) == 0) {
            bool found = !value || tag_predicate_match_name_value(event, &(tag_match_name_value_t){name, value});
            free(tag_name);
            return found;
        }
        free(tag_name);
    }
    return false;
}

char **tag_find(const event_t *event, const char *name, size_t *out_count) {
    if (!event || !name || !event->tags_json) return NULL;
    
    tag_iter_t it;
    tag_iter_init(&it, event);
    
    struct mg_str key, tag;
    while (tag_iter_next(&it, &key, &tag)) {
        char *tag_name = tag_iter_element(&it, 0);
        if (tag_name && strcmp(tag_name, name) == 0) {
            size_t elem_count = 0;
            struct mg_str element_key, element;
            tag_iter_t elem_it;
            tag_iter_init_tag(&elem_it, tag);
            
            while (tag_iter_next(&elem_it, &element_key, &element)) {
                elem_count++;
            }
            
            char **elements = calloc(elem_count + 1, sizeof(*elements));
            if (!elements) {
                free(tag_name);
                return NULL;
            }
            
            tag_iter_init_tag(&elem_it, tag);
            size_t idx = 0;
            bool ok = true;
            while (tag_iter_next(&elem_it, &element_key, &element)) {
                char *elem = tag_iter_element(&elem_it, idx);
                if (!elem) {
                    ok = false;
                    break;
                }
                elements[idx++] = elem;
            }
            
            free(tag_name);
            
            if (!ok) {
                for (size_t i = 0; i < idx; i++) free(elements[i]);
                free(elements);
                return NULL;
            }
            
            if (out_count) *out_count = elem_count;
            return elements;
        }
        free(tag_name);
    }
    return NULL;
}

void tag_free_elements(char **elements) {
    if (!elements) return;
    for (size_t i = 0; elements[i]; i++) {
        free(elements[i]);
    }
    free(elements);
}

void tag_free_values(char **values, size_t count) {
    if (!values) return;
    for (size_t i = 0; i < count; i++) {
        free(values[i]);
    }
    free(values);
}