#include "event_tags.h"
#include "tag_iter.h"
#include <stdlib.h>
#include <string.h>

/* strndup replacement for Windows */
static char *my_strndup(const char *s, size_t n) {
    char *p = malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

/* ============================================================================
 * Internal: Build values array from a tag (mg_str)
 * Returns malloc'd NULL-terminated array of tag[1..] values.
 * Caller frees with event_tag_free().
 * ============================================================================ */
static char **build_values_array(struct mg_str tag) {
    size_t elem_count = 0;
    tag_iter_t elem_it;
    tag_iter_init_tag(&elem_it, tag);

    struct mg_str ek, elem;
    while (tag_iter_next(&elem_it, &ek, &elem)) elem_count++;

    if (elem_count <= 1) return NULL; // No values (only name)

    char **values = calloc(elem_count, sizeof(char *)); // elem_count-1 values + NULL
    if (!values) return NULL;

    tag_iter_init_tag(&elem_it, tag);
    size_t idx = 0;
    while (tag_iter_next(&elem_it, &ek, &elem)) {
        if (idx == 0) { idx++; continue; } // Skip name (tag[0])
        values[idx - 1] = elem.len > 0 ? my_strndup(elem.buf, elem.len) : strdup("");
        idx++;
    }
    return values;
}

/* ============================================================================
 * Iteration
 * ============================================================================ */
void event_tags_foreach(const event_t *event, event_tag_iter_cb cb, void *ctx) {
    if (!event || !event->tags_json || !cb) return;

    tag_iter_t it;
    tag_iter_init(&it, event);

    struct mg_str key, tag;
    while (tag_iter_next(&it, &key, &tag)) {
        char *name = tag_iter_element(&it, 0);
        if (!name) continue;

        char **values = build_values_array(tag);
        size_t count = values ? 0 : 0;
        if (values) {
            while (values[count]) count++;
        }

        if (!cb(name, values, count, ctx)) {
            free(name);
            if (values) event_tag_free(values);
            break;
        }

        free(name);
        if (values) event_tag_free(values);
    }
}

/* ============================================================================
 * Lookup by Name
 * ============================================================================ */
char **event_tag_get(const event_t *event, const char *name) {
    if (!event || !name || !event->tags_json) return NULL;

    tag_iter_t it;
    tag_iter_init(&it, event);

    struct mg_str key, tag;
    while (tag_iter_next(&it, &key, &tag)) {
        char *n = tag_iter_element(&it, 0);
        if (!n) continue;

        if (strcmp(n, name) == 0) {
            char **values = build_values_array(tag);
            free(n);
            return values;
        }
        free(n);
    }
    return NULL;
}

char ***event_tag_get_all(const event_t *event, const char *name, size_t *out_count) {
    if (!event || !name || !event->tags_json || !out_count) return NULL;

    tag_iter_t it;
    tag_iter_init(&it, event);

    size_t capacity = 4;
    size_t count = 0;
    char ***results = calloc(capacity + 1, sizeof(char **));
    if (!results) { *out_count = 0; return NULL; }

    struct mg_str key, tag;
    while (tag_iter_next(&it, &key, &tag)) {
        char *n = tag_iter_element(&it, 0);
        if (!n) continue;

        if (strcmp(n, name) == 0) {
            char **values = build_values_array(tag);
            if (values) {
                if (count >= capacity) {
                    capacity *= 2;
                    char ***grown = realloc(results, (capacity + 1) * sizeof(char **));
                    if (!grown) { free(n); event_tag_free_all(results, count); *out_count = 0; return NULL; }
                    results = grown;
                }
                results[count++] = values;
            }
        }
        free(n);
    }

    *out_count = count;
    return results;
}

/* ============================================================================
 * First Value
 * ============================================================================ */
char *event_tag_value(const event_t *event, const char *name) {
    if (!event || !name || !event->tags_json) return NULL;

    tag_iter_t it;
    tag_iter_init(&it, event);

    struct mg_str key, tag;
    while (tag_iter_next(&it, &key, &tag)) {
        char *n = tag_iter_element(&it, 0);
        if (!n) continue;

        if (strcmp(n, name) == 0) {
            char *v = tag_iter_element(&it, 1);
            free(n);
            return v; // Already strdup'd by tag_iter_element
        }
        free(n);
    }
    return NULL;
}

/* ============================================================================
 * Existence / Counting
 * ============================================================================ */
bool event_tag_has(const event_t *event, const char *name) {
    return event_tag_value(event, name) != NULL;
}

bool event_tag_has_value(const event_t *event, const char *name, const char *value) {
    if (!event || !name || !value || !event->tags_json) return false;

    tag_iter_t it;
    tag_iter_init(&it, event);

    struct mg_str key, tag;
    while (tag_iter_next(&it, &key, &tag)) {
        char *n = tag_iter_element(&it, 0);
        if (!n) continue;

        if (strcmp(n, name) == 0) {
            char *v = tag_iter_element(&it, 1);
            bool match = v && strcmp(v, value) == 0;
            free(n);
            free(v);
            if (match) return true;
        }
        free(n);
    }
    return false;
}

size_t event_tag_count(const event_t *event, const char *name) {
    if (!event || !name || !event->tags_json) return 0;

    size_t count = 0;
    tag_iter_t it;
    tag_iter_init(&it, event);

    struct mg_str key, tag;
    while (tag_iter_next(&it, &key, &tag)) {
        char *n = tag_iter_element(&it, 0);
        if (n && strcmp(n, name) == 0) count++;
        free(n);
    }
    return count;
}

/* ============================================================================
 * Free Helpers
 * ============================================================================ */
void event_tag_free(char **values) {
    if (!values) return;
    for (size_t i = 0; values[i]; i++) free(values[i]);
    free(values);
}

void event_tag_free_all(char ***values, size_t count) {
    if (!values) return;
    for (size_t i = 0; i < count; i++) event_tag_free(values[i]);
    free(values);
}