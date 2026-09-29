#ifndef FILTER_BUILDER_H
#define FILTER_BUILDER_H

#include <stddef.h>
#include <time.h>
#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct filter_builder filter_builder_t;

/* Create new filter builder. Returns malloc'd struct, caller frees with filter_builder_free(). */
filter_builder_t *filter_builder_new(void);

/* Add event IDs filter (NIP-01) */
filter_builder_t *filter_builder_ids(filter_builder_t *b, const char **ids, size_t count);

/* Add kinds filter */
filter_builder_t *filter_builder_kinds(filter_builder_t *b, const int *kinds, size_t count);

/* Add authors filter (pubkeys) */
filter_builder_t *filter_builder_authors(filter_builder_t *b, const char **pubkeys, size_t count);

/* Add #d tag filter (NIP-33 addressable events) */
filter_builder_t *filter_builder_d_tags(filter_builder_t *b, const char **values, size_t count);

/* Add #k tag filter (NIP-09 kind references) */
filter_builder_t *filter_builder_k_tags(filter_builder_t *b, const int *kinds, size_t count);

/* Add generic tag filter (#name = value) */
filter_builder_t *filter_builder_tag(filter_builder_t *b, const char *name, const char **values, size_t count);

/* Set since timestamp (events after this time) */
filter_builder_t *filter_builder_since(filter_builder_t *b, time_t since);

/* Set until timestamp (events before this time) */
filter_builder_t *filter_builder_until(filter_builder_t *b, time_t until);

/* Set limit */
filter_builder_t *filter_builder_limit(filter_builder_t *b, size_t limit);

/* Build the filter_t struct (heap-allocated, caller frees with filter_release()) */
filter_t *filter_builder_build(filter_builder_t *b);

/* Free the builder (does not free the built filter) */
void filter_builder_free(filter_builder_t *b);

/* Build multiple filters (for REQ with multiple filters) */
filter_t **filter_builder_build_multi(filter_builder_t **builders, size_t count);

/* Convenience: parse filter from JSON (for incoming REQ) */
filter_t *filter_parse_json(const char *json);

/* Debug: print filter to string (heap-allocated, caller frees) */
char *filter_to_json(const filter_t *f);

#ifdef __cplusplus
}
#endif

#endif