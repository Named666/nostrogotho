#include "event_util.h"
#include "json_util.h"
#include <mongoose.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * EVENT_UTIL.C - Generic Event/Tag Utilities Implementation
 * ============================================================================ */

/**
 * \brief           Get the `index`-th element of a tag JSON array
 * \param[in]       tag_json: Tag JSON text
 * \param[in]       index: Element index
 * \return          Heap-allocated string, `NULL` on failure
 */
char*
event_tag_element(const char *tag_json, size_t index) {
    char path[32];
    int32_t written = 0;
    struct mg_str tag;
    if (tag_json == NULL) {
        return NULL;
    }
    written = snprintf(path, sizeof(path), "$[%llu]", (unsigned long long)index);
    if (written <= 0 || (size_t)written >= sizeof(path)) {
        return NULL;
    }
    tag = mg_str(tag_json);
    return mg_json_get_str(tag, path);
}

char*
event_tag_element_slice(struct mg_str tag, size_t index) {
    char path[32];
    int32_t written = 0;
    written = snprintf(path, sizeof(path), "$[%llu]", (unsigned long long)index);
    if (written <= 0 || (size_t)written >= sizeof(path)) {
        return NULL;
    }
    return mg_json_get_str(tag, path);
}

bool event_has_tag(const event_t *event, const char *name, const char *value) {
    if (!event || !name || !event->tags_json) return false;
    
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *tag_name = event_tag_element(tag.buf, 0);
        char *tag_value = event_tag_element(tag.buf, 1);
        bool found = tag_name && strcmp(tag_name, name) == 0 && 
                     (!value || (tag_value && strcmp(tag_value, value) == 0));
        free(tag_name);
        free(tag_value);
        if (found) return true;
    }
    return false;
}

bool event_has_relay_tag(const event_t *event, const char *relay) {
    if (!event || !relay || !event->tags_json) return false;
    
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    size_t relay_length = strlen(relay);
    while (relay_length && relay[relay_length - 1] == '/') relay_length--;
    
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = event_tag_element(tag.buf, 0);
        char *value = event_tag_element(tag.buf, 1);
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
    
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *tag_name = event_tag_element(tag.buf, 0);
        if (tag_name && strcmp(tag_name, name) == 0) {
            char *tag_value = event_tag_element(tag.buf, 1);
            free(tag_name);
            return tag_value;
        }
        free(tag_name);
    }
    return NULL;
}

char **event_get_tag_values(const event_t *event, const char *name, size_t *count) {
    if (!event || !name || !event->tags_json || !count) return NULL;
    
    *count = 0;
    size_t capacity = 4;
    char **values = calloc(capacity, sizeof(*values));
    if (!values) return NULL;
    
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *tag_name = event_tag_element(tag.buf, 0);
        if (tag_name && strcmp(tag_name, name) == 0) {
            char *tag_value = event_tag_element(tag.buf, 1);
            if (tag_value) {
                if (*count >= capacity) {
                    capacity *= 2;
                    char **new_values = realloc(values, capacity * sizeof(*values));
                    if (!new_values) {
                        free(tag_name);
                        event_free_tag_values(values, *count);
                        return NULL;
                    }
                    values = new_values;
                }
                values[(*count)++] = tag_value;
            }
        }
        free(tag_name);
    }
    
    return values;
}

size_t event_get_tag_count(const event_t *event, const char *name) {
    if (!event || !name || !event->tags_json) return 0;
    
    size_t count = 0;
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *tag_name = event_tag_element(tag.buf, 0);
        if (tag_name && strcmp(tag_name, name) == 0) {
            count++;
        }
        free(tag_name);
    }
    return count;
}

void event_free_tag_values(char **values, size_t count) {
    if (!values) return;
    for (size_t i = 0; i < count; i++) {
        free(values[i]);
    }
    free(values);
}

/* Find a tag by name and return all its elements as an array of strings.
 * Returns malloc'd array of element pointers with NULL sentinel.
 * Caller must free with event_free_tag(). */
char **event_find_tag(const event_t *event, const char *name, size_t *count) {
    if (!event || !name || !event->tags_json) return NULL;
    
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *tag_name = event_tag_element_slice(tag, 0);
        if (tag_name && strcmp(tag_name, name) == 0) {
            /* Count elements in this tag */
            size_t elem_count = 0;
            struct mg_str element_key, element;
            size_t element_offset = 0;
            while ((element_offset = mg_json_next(tag, element_offset, &element_key, &element)) != 0) {
                elem_count++;
            }
            
            /* Allocate array for elements + NULL sentinel */
            char **elements = calloc(elem_count + 1, sizeof(*elements));
            if (!elements) {
                free(tag_name);
                return NULL;
            }
            
            /* Extract all elements */
            element_offset = 0;
            size_t idx = 0;
            bool ok = true;
            while ((element_offset = mg_json_next(tag, element_offset, &element_key, &element)) != 0) {
                char *elem = event_tag_element_slice(tag, idx);
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
            
            if (count) *count = elem_count;
            return elements;
        }
        free(tag_name);
    }
    return NULL;
}

/* Free an array of tag elements returned by event_find_tag */
void event_free_tag(char **elements) {
    if (!elements) return;
    for (size_t i = 0; elements[i]; i++) {
        free(elements[i]);
    }
    free(elements);
}