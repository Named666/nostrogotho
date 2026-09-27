#ifndef EVENT_UTIL_H_
#define EVENT_UTIL_H_

#include <stdbool.h>
#include <stddef.h>
#include <mongoose.h>
#include "nostrogotho.h"

/* ============================================================================
 * EVENT_UTIL.H - Generic Event/Tag Utilities
 * 
 * Model layer utilities for event and tag operations.
 * These are generic operations not specific to any NIP.
 * ============================================================================ */

/* Extract a tag element by index from a JSON tag array */
char *event_tag_element(const char *tag_json, size_t index);

/* Extract the index-th element of a bounded tag slice as yielded by
 * mg_json_next (not NUL-terminated). Heap-allocated, NULL on failure. */
char *event_tag_element_slice(struct mg_str tag, size_t index);

/* Check if an event has a tag with the given name and optional value */
bool event_has_tag(const event_t *event, const char *name, const char *value);

/* Check if an event has a relay tag matching the given relay URL */
bool event_has_relay_tag(const event_t *event, const char *relay);

/* Get the value of the first tag with the given name */
char *event_get_tag_value(const event_t *event, const char *name);

/* Get all values for tags with the given name */
char **event_get_tag_values(const event_t *event, const char *name, size_t *count);

/* Count tags with the given name */
size_t event_get_tag_count(const event_t *event, const char *name);

/* Free an array of tag values */
void event_free_tag_values(char **values, size_t count);

#endif /* EVENT_UTIL_H_ */