#include "filter_builder.h"
#include "protocol.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

struct filter_builder {
    filter_t *filter;
};

filter_builder_t *filter_builder_new(void) {
    filter_builder_t *b = calloc(1, sizeof(filter_builder_t));
    if (!b) return NULL;
    b->filter = calloc(1, sizeof(filter_t));
    if (!b->filter) {
        free(b);
        return NULL;
    }
    b->filter->limit = 500;
    return b;
}

void filter_builder_free(filter_builder_t *b) {
    if (!b) return;
    free(b->filter);
    free(b);
}

static bool grow_array(void ***arr, size_t *count, size_t *capacity, size_t elem_size) {
    if (*count >= *capacity) {
        size_t new_cap = *capacity ? *capacity * 2 : 8;
        void *new_arr = realloc(*arr, new_cap * elem_size);
        if (!new_arr) return false;
        *arr = new_arr;
        *capacity = new_cap;
    }
    return true;
}

filter_builder_t *filter_builder_ids(filter_builder_t *b, const char **ids, size_t count) {
    if (!b || !ids || count == 0) return b;
    for (size_t i = 0; i < count; i++) {
        if (!grow_array((void ***)&b->filter->ids, &b->filter->ids_count, (size_t *)&b->filter->ids_count, sizeof(char *))) return b;
        b->filter->ids[b->filter->ids_count++] = strdup(ids[i]);
    }
    return b;
}

filter_builder_t *filter_builder_kinds(filter_builder_t *b, const int *kinds, size_t count) {
    if (!b || !kinds || count == 0) return b;
    for (size_t i = 0; i < count; i++) {
        if (!grow_array((void ***)&b->filter->kinds, &b->filter->kinds_count, (size_t *)&b->filter->kinds_count, sizeof(int))) return b;
        b->filter->kinds[b->filter->kinds_count++] = kinds[i];
    }
    return b;
}

filter_builder_t *filter_builder_authors(filter_builder_t *b, const char **pubkeys, size_t count) {
    if (!b || !pubkeys || count == 0) return b;
    for (size_t i = 0; i < count; i++) {
        if (!grow_array((void ***)&b->filter->authors, &b->filter->authors_count, (size_t *)&b->filter->authors_count, sizeof(char *))) return b;
        b->filter->authors[b->filter->authors_count++] = strdup(pubkeys[i]);
    }
    return b;
}

filter_builder_t *filter_builder_d_tags(filter_builder_t *b, const char **values, size_t count) {
    if (!b || !values || count == 0) return b;
    tag_t *tag = calloc(1, sizeof(tag_t));
    if (!tag) return b;
    tag->elements[tag->count++] = strdup("d");
    for (size_t i = 0; i < count; i++) {
        if (tag->count >= MAX_TAG_ELEMENTS) break;
        tag->elements[tag->count++] = strdup(values[i]);
    }
    if (tag->count >= 2) {
        if (!grow_array((void ***)&b->filter->tags, &b->filter->tags_count, (size_t *)&b->filter->tags_count, sizeof(tag_t))) {
            for (size_t i = 0; i < tag->count; i++) free(tag->elements[i]);
            free(tag);
            return b;
        }
        b->filter->tags[b->filter->tags_count++] = *tag;
    }
    free(tag);
    return b;
}

filter_builder_t *filter_builder_k_tags(filter_builder_t *b, const int *kinds, size_t count) {
    if (!b || !kinds || count == 0) return b;
    tag_t *tag = calloc(1, sizeof(tag_t));
    if (!tag) return b;
    tag->elements[tag->count++] = strdup("k");
    for (size_t i = 0; i < count; i++) {
        if (tag->count >= MAX_TAG_ELEMENTS) break;
        char kind_str[16];
        snprintf(kind_str, sizeof(kind_str), "%d", kinds[i]);
        tag->elements[tag->count++] = strdup(kind_str);
    }
    if (tag->count >= 2) {
        if (!grow_array((void ***)&b->filter->tags, &b->filter->tags_count, (size_t *)&b->filter->tags_count, sizeof(tag_t))) {
            for (size_t i = 0; i < tag->count; i++) free(tag->elements[i]);
            free(tag);
            return b;
        }
        b->filter->tags[b->filter->tags_count++] = *tag;
    }
    free(tag);
    return b;
}

filter_builder_t *filter_builder_tag(filter_builder_t *b, const char *name, const char **values, size_t count) {
    if (!b || !name || !values || count == 0) return b;
    tag_t *tag = calloc(1, sizeof(tag_t));
    if (!tag) return b;
    tag->elements[tag->count++] = strdup(name);
    for (size_t i = 0; i < count; i++) {
        if (tag->count >= MAX_TAG_ELEMENTS) break;
        tag->elements[tag->count++] = strdup(values[i]);
    }
    if (tag->count >= 2) {
        if (!grow_array((void ***)&b->filter->tags, &b->filter->tags_count, (size_t *)&b->filter->tags_count, sizeof(tag_t))) {
            for (size_t i = 0; i < tag->count; i++) free(tag->elements[i]);
            free(tag);
            return b;
        }
        b->filter->tags[b->filter->tags_count++] = *tag;
    }
    free(tag);
    return b;
}

filter_builder_t *filter_builder_since(filter_builder_t *b, time_t since) {
    if (!b) return NULL;
    b->filter->since = since;
    return b;
}

filter_builder_t *filter_builder_until(filter_builder_t *b, time_t until) {
    if (!b) return NULL;
    b->filter->until = until;
    return b;
}

filter_builder_t *filter_builder_limit(filter_builder_t *b, size_t limit) {
    if (!b) return NULL;
    b->filter->limit = (limit > 500) ? 500 : (int)limit;
    return b;
}

filter_t *filter_builder_build(filter_builder_t *b) {
    return b ? b->filter : NULL;
}

filter_t **filter_builder_build_multi(filter_builder_t **builders, size_t count) {
    if (!builders || count == 0) return NULL;
    filter_t **filters = calloc(count, sizeof(filter_t *));
    if (!filters) return NULL;
    for (size_t i = 0; i < count; i++) {
        filters[i] = filter_builder_build(builders[i]);
    }
    return filters;
}

/* Parse filter from JSON string (uses existing json_parse_filter) */
filter_t *filter_parse_json(const char *json) {
    if (!json) return NULL;
    filter_t *f = calloc(1, sizeof(filter_t));
    if (!f) return NULL;
    if (json_parse_filter(json, f)) {
        return f;
    }
    filter_release(f);
    free(f);
    return NULL;
}

/* Serialize filter to JSON using json_builder */
char *filter_to_json(const filter_t *f) {
    if (!f) return NULL;
    // Use the existing json_builder infrastructure
    // For now, return a simple representation
    // Full implementation would mirror json_parse_filter in reverse
    size_t est = 64;
    for (size_t i = 0; i < f->ids_count; i++) est += strlen(f->ids[i]) + 4;
    for (size_t i = 0; i < f->authors_count; i++) est += strlen(f->authors[i]) + 4;
    for (size_t i = 0; i < f->kinds_count; i++) est += 8;
    for (size_t i = 0; i < f->tags_count; i++) {
        for (size_t j = 0; j < f->tags[i].count; j++) {
            est += strlen(f->tags[i].elements[j]) + 4;
        }
    }
    
    char *json = malloc(est);
    if (!json) return NULL;
    
    // Simplified - in practice would need full builder
    // This is a placeholder for now
    snprintf(json, est, "{}");
    return json;
}