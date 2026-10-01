#ifndef TAG_ITER_H_
#define TAG_ITER_H_

#include <stdbool.h>
#include <stddef.h>
#include <mongoose.h>
#include "nostrogotho.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Tag Iterator - Low-level mg_json_next wrapper
 * ============================================================================
 * Internal implementation. Use event_tags.h API for higher-level operations. */

typedef struct {
    struct mg_str tags;
    size_t offset;
} tag_iter_t;

static inline void tag_iter_init(tag_iter_t *it, const event_t *event) {
    it->tags = mg_str(event->tags_json ? event->tags_json : "[]");
    it->offset = 0;
}

static inline void tag_iter_init_json(tag_iter_t *it, const char *tags_json) {
    it->tags = mg_str(tags_json ? tags_json : "[]");
    it->offset = 0;
}

static inline void tag_iter_init_tag(tag_iter_t *it, struct mg_str tag) {
    it->tags = tag;
    it->offset = 0;
}

/* Tag predicate userdata structs (used by tag_predicate_* in tag_iter.c) */
typedef struct { const char *name; } tag_match_name_t;
typedef struct { const char *name; const char *value; } tag_match_name_value_t;
typedef struct { const char *name; const char *value; bool empty_value_when_missing; } tag_match_name_value_opt_t;

/* Get element at index from current tag array */
char *tag_iter_element(tag_iter_t *it, size_t index);

/* Advance to next tag */
bool tag_iter_next(tag_iter_t *it, struct mg_str *out_key, struct mg_str *out_tag);

/* Storage predicates (called with event_t*) */
bool tag_predicate_match_name(const event_t *event, void *userdata);
bool tag_predicate_match_name_value(const event_t *event, void *userdata);
bool tag_predicate_match_name_value_opt(const event_t *event, void *userdata);
bool tag_predicate_match_d_tag(const event_t *event, void *userdata);
bool tag_predicate_match_k_tag(const event_t *event, void *userdata);

#ifdef __cplusplus
}
#endif

#endif /* TAG_ITER_H_ */