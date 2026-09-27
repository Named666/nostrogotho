#ifndef TAG_ITER_H_
#define TAG_ITER_H_

#include <stdbool.h>
#include <stddef.h>
#include <mongoose.h>
#include "nostrogotho.h"

/* ============================================================================
 * Tag Iterator - Unified tag traversal and matching utilities
 * ============================================================================
 * 
 * Eliminates duplicated mg_json_next loops across NIP implementations and
 * event_util.c. Provides a clean, reusable API for iterating and matching
 * tags within event JSON.
 * ============================================================================ */

/* Opaque tag iterator state */
typedef struct {
    struct mg_str tags;
    size_t offset;
} tag_iter_t;

/* Initialize iterator over an event's tags JSON */
static inline void tag_iter_init(tag_iter_t *it, const event_t *event) {
    it->tags = mg_str(event->tags_json ? event->tags_json : "[]");
    it->offset = 0;
}

/* Initialize iterator over a raw tags JSON string */
static inline void tag_iter_init_json(tag_iter_t *it, const char *tags_json) {
    it->tags = mg_str(tags_json ? tags_json : "[]");
    it->offset = 0;
}

/* Initialize iterator over a single tag array (mg_str from mg_json_next) */
static inline void tag_iter_init_tag(tag_iter_t *it, struct mg_str tag) {
    it->tags = tag;
    it->offset = 0;
}

/* Get the next tag element (by index) from the current tag array.
 * Returns malloc'd string, NULL on failure or index out of bounds.
 * Caller must free result. */
char *tag_iter_element(tag_iter_t *it, size_t index);

/* Advance to next tag in the tags array.
 * Returns true and sets out_key/out_tag on success, false when done. */
bool tag_iter_next(tag_iter_t *it, struct mg_str *out_key, struct mg_str *out_tag);

/* ============================================================================
 * Tag Matching Predicates
 * ============================================================================
 * 
 * Standard predicates for common tag matching patterns.
 * All return true on match, false otherwise.
 * ============================================================================ */

/* Userdata for tag name matching */
typedef struct {
    const char *name;
} tag_match_name_t;

/* Userdata for tag name + value matching */
typedef struct {
    const char *name;
    const char *value;
} tag_match_name_value_t;

/* Userdata for tag name + value matching (empty value when missing) */
typedef struct {
    const char *name;
    const char *value;
    bool empty_value_when_missing;
} tag_match_name_value_opt_t;

/* Match tag by name only (first element == name) */
bool tag_predicate_match_name(const event_t *event, void *userdata);

/* Match tag by name and value (first element == name, second == value) */
bool tag_predicate_match_name_value(const event_t *event, void *userdata);

/* Match tag by name and value, treating missing value as empty string */
bool tag_predicate_match_name_value_opt(const event_t *event, void *userdata);

/* Match "d" tag for NIP-33 addressable events */
bool tag_predicate_match_d_tag(const event_t *event, void *userdata);

/* Match "k" tag for NIP-09 kind filtering */
bool tag_predicate_match_k_tag(const event_t *event, void *userdata);

/* ============================================================================
 * High-Level Tag Operations
 * ============================================================================
 * 
 * Convenience functions that use the iterator internally.
 * ============================================================================ */

/* Find first tag value by name. Returns malloc'd string or NULL.
 * Caller must free result. */
char *tag_find_value(const event_t *event, const char *name);

/* Find all tag values by name. Returns malloc'd array of strings
 * with count in *out_count. Caller must free array and each string. */
char **tag_find_all_values(const event_t *event, const char *name, size_t *out_count);

/* Count tags with given name */
size_t tag_count(const event_t *event, const char *name);

/* Check if event has tag with name (and optional value) */
bool tag_has(const event_t *event, const char *name, const char *value);

/* Find complete tag by name (all elements). Returns malloc'd array
 * of elements with NULL sentinel. Caller must free with tag_free_elements. */
char **tag_find(const event_t *event, const char *name, size_t *out_count);

/* Free array returned by tag_find */
void tag_free_elements(char **elements);

/* Free array returned by tag_find_all_values */
void tag_free_values(char **values, size_t count);

#endif /* TAG_ITER_H_ */