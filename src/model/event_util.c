#include "event_util.h"
#include "tag_iter.h"
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * EVENT_UTIL.C - Generic Event/Tag Utilities Implementation
 * ============================================================================
 * 
 * These functions now delegate to the shared tag_iter utilities to eliminate
 * duplicated mg_json_next loops. The API is kept for backward compatibility.
 * ============================================================================ */

/* Extract a tag element by index from a JSON tag array */
char *event_tag_element(const char *tag_json, size_t index) {
    if (!tag_json) return NULL;
    tag_iter_t it;
    tag_iter_init_json(&it, tag_json);
    return tag_iter_element(&it, index);
}

/* Extract the index-th element of a bounded tag slice as yielded by
 * mg_json_next (not NUL-terminated). Heap-allocated, NULL on failure. */
char *event_tag_element_slice(struct mg_str tag, size_t index) {
    tag_iter_t it;
    tag_iter_init_tag(&it, tag);
    return tag_iter_element(&it, index);
}

bool event_has_tag(const event_t *event, const char *name, const char *value) {
    if (!event || !name || !event->tags_json) return false;
    return tag_has(event, name, value);
}

bool event_has_relay_tag(const event_t *event, const char *relay) {
    if (!event || !relay || !event->tags_json) return false;
    
    size_t relay_length = strlen(relay);
    while (relay_length && relay[relay_length - 1] == '/') relay_length--;
    
    tag_iter_t it;
    tag_iter_init(&it, event);
    
    struct mg_str key, tag;
    while (tag_iter_next(&it, &key, &tag)) {
        char *name = tag_iter_element(&it, 0);
        char *value = tag_iter_element(&it, 1);
        size_t value_length = value ? strlen(value) : 0;
        while (value_length && value[value_length - 1] == '/') value_length--;
        bool found = name && value && strcmp(name, "relay") == 0 && 
                     value_length == relay_length && memcmp(value, relay, relay_length) == 0;
        free(name);
        free(value);
        if (found) return true;
    }
    return false;
}

char *event_get_tag_value(const event_t *event, const char *name) {
    if (!event || !name || !event->tags_json) return NULL;
    return tag_find_value(event, name);
}

char **event_get_tag_values(const event_t *event, const char *name, size_t *count) {
    if (!event || !name || !event->tags_json || !count) return NULL;
    return tag_find_all_values(event, name, count);
}

size_t event_get_tag_count(const event_t *event, const char *name) {
    if (!event || !name || !event->tags_json) return 0;
    return tag_count(event, name);
}

void event_free_tag_values(char **values, size_t count) {
    tag_free_values(values, count);
}

/* Find a tag by name and return all its elements as an array of strings.
 * Returns malloc'd array of element pointers with NULL sentinel.
 * Caller must free with event_free_tag(). */
char **event_find_tag(const event_t *event, const char *name, size_t *count) {
    if (!event || !name || !event->tags_json) return NULL;
    return tag_find(event, name, count);
}

/* Free an array of tag elements returned by event_find_tag */
void event_free_tag(char **elements) {
    tag_free_elements(elements);
}