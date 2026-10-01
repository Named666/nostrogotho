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
    /* Build detaches ownership, so only free the struct here.
     * Filters still owned by the builder (never built) are released. */
    if (b->filter) {
        filter_release(b->filter);
        free(b->filter);
    }
    free(b);
}

/* filter_t has no capacity fields, so grow by one element per append.
 * Returns false on allocation failure. */
static bool append_string_copy(char ***arr, size_t *count, const char *s) {
    char **grown;
    char *copy;
    if (!arr || !count || !s) return false;
    copy = strdup(s);
    if (!copy) return false;
    grown = (char **)realloc(*arr, (*count + 1) * sizeof(char *));
    if (!grown) {
        free(copy);
        return false;
    }
    *arr = grown;
    (*arr)[*count] = copy;
    (*count)++;
    return true;
}

static bool append_kind_copy(int **arr, size_t *count, int kind) {
    int *grown;
    if (!arr || !count) return false;
    grown = (int *)realloc(*arr, (*count + 1) * sizeof(int));
    if (!grown) return false;
    *arr = grown;
    (*arr)[*count] = kind;
    (*count)++;
    return true;
}

static bool append_tag_copy(tag_t **arr, size_t *count, const tag_t *tag) {
    tag_t *grown;
    if (!arr || !count || !tag) return false;
    grown = (tag_t *)realloc(*arr, (*count + 1) * sizeof(tag_t));
    if (!grown) return false;
    *arr = grown;
    (*arr)[*count] = *tag;
    (*count)++;
    return true;
}

/* Allocate a tag with room for (1 + nvalues) elements, capped. */
static tag_t *make_tag(const char *name, const char **values, size_t count) {
    tag_t *tag;
    size_t n;
    if (!name || !values || count == 0) return NULL;
    n = count + 1;
    if (n > MAX_TAG_ELEMENTS) n = MAX_TAG_ELEMENTS;
    tag = (tag_t *)calloc(1, sizeof(tag_t));
    if (!tag) return NULL;
    tag->elements = (char **)calloc(n, sizeof(char *));
    if (!tag->elements) {
        free(tag);
        return NULL;
    }
    tag->capacity = n;
    tag->elements[tag->count++] = strdup(name);
    if (!tag->elements[0]) {
        free(tag->elements);
        free(tag);
        return NULL;
    }
    for (size_t i = 0; i < count && tag->count < n; i++) {
        tag->elements[tag->count] = strdup(values[i]);
        if (!tag->elements[tag->count]) {
            for (size_t k = 0; k < tag->count; k++) free(tag->elements[k]);
            free(tag->elements);
            free(tag);
            return NULL;
        }
        tag->count++;
    }
    if (tag->count < 2) {
        for (size_t k = 0; k < tag->count; k++) free(tag->elements[k]);
        free(tag->elements);
        free(tag);
        return NULL;
    }
    return tag;
}

filter_builder_t *filter_builder_ids(filter_builder_t *b, const char **ids, size_t count) {
    if (!b || !ids || count == 0) return b;
    for (size_t i = 0; i < count; i++) {
        if (!ids[i]) continue;
        if (!append_string_copy(&b->filter->ids, &b->filter->ids_count, ids[i])) return b;
    }
    return b;
}

filter_builder_t *filter_builder_kinds(filter_builder_t *b, const int *kinds, size_t count) {
    if (!b || !kinds || count == 0) return b;
    for (size_t i = 0; i < count; i++) {
        if (!append_kind_copy(&b->filter->kinds, &b->filter->kinds_count, kinds[i])) return b;
    }
    return b;
}

filter_builder_t *filter_builder_authors(filter_builder_t *b, const char **pubkeys, size_t count) {
    if (!b || !pubkeys || count == 0) return b;
    for (size_t i = 0; i < count; i++) {
        if (!pubkeys[i]) continue;
        if (!append_string_copy(&b->filter->authors, &b->filter->authors_count, pubkeys[i])) return b;
    }
    return b;
}

filter_builder_t *filter_builder_d_tags(filter_builder_t *b, const char **values, size_t count) {
    tag_t *tag;
    if (!b || !values || count == 0) return b;
    tag = make_tag("d", values, count);
    if (!tag) return b;
    if (!append_tag_copy(&b->filter->tags, &b->filter->tags_count, tag)) {
        for (size_t i = 0; i < tag->count; i++) free(tag->elements[i]);
        free(tag->elements);
        free(tag);
        return b;
    }
    free(tag);
    return b;
}

filter_builder_t *filter_builder_k_tags(filter_builder_t *b, const int *kinds, size_t count) {
    tag_t *tag;
    char **strs = NULL;
    char buf[16];
    if (!b || !kinds || count == 0) return b;
    strs = (char **)calloc(count, sizeof(char *));
    if (!strs) return b;
    for (size_t i = 0; i < count; i++) {
        snprintf(buf, sizeof(buf), "%d", kinds[i]);
        strs[i] = buf;
    }
    /* make_tag strdups each value, so stack buffers are safe. */
    tag = make_tag("k", (const char **)strs, count);
    free(strs);
    if (!tag) return b;
    if (!append_tag_copy(&b->filter->tags, &b->filter->tags_count, tag)) {
        for (size_t i = 0; i < tag->count; i++) free(tag->elements[i]);
        free(tag->elements);
        free(tag);
        return b;
    }
    free(tag);
    return b;
}

filter_builder_t *filter_builder_tag(filter_builder_t *b, const char *name, const char **values, size_t count) {
    tag_t *tag;
    if (!b || !name || !values || count == 0) return b;
    tag = make_tag(name, values, count);
    if (!tag) return b;
    if (!append_tag_copy(&b->filter->tags, &b->filter->tags_count, tag)) {
        for (size_t i = 0; i < tag->count; i++) free(tag->elements[i]);
        free(tag->elements);
        free(tag);
        return b;
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
    filter_t *f;
    if (!b) return NULL;
    /* Detach so filter_builder_free() will not release the built filter. */
    f = b->filter;
    b->filter = NULL;
    return f;
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
