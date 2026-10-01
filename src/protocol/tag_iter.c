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
 * Tag Matching Predicates (used by storage layer for delete_matching)
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