#ifndef EVENT_TAGS_H
#define EVENT_TAGS_H

#include <stdbool.h>
#include <stddef.h>
#include "nostrogotho.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Event Tag Helpers - Generic, Future-Proof API
 * ============================================================================
 * 
 * Events are the primary object. Tags are JSON arrays of strings inside events.
 * Every tag: ["name", "value1", "value2", ...]
 * 
 * This API makes NO assumptions about tag structure. NIPs decide which tags
 * to parse and how to interpret their values.
 * 
 * All functions return malloc'd memory. Free with corresponding free function.
 * ============================================================================ */

/* ---- Core: Iteration ---- */

/* Iterate all tags in event. Callback receives (name, values_array, count).
 * values_array = tag[1..] (NULL-terminated).
 * Return false to stop iteration. */
typedef bool (*event_tag_iter_cb)(const char *name, char **values, size_t count, void *ctx);

void event_tags_foreach(const event_t *event, event_tag_iter_cb cb, void *ctx);

/* ---- Core: Lookup by Name ---- */

/* Get FIRST tag matching name. Returns malloc'd NULL-terminated array of values (tag[1..]).
 * Example: ["e", "id", "relay", "reply"] -> ["id", "relay", "reply", NULL]
 * Free with event_tag_free(). */
char **event_tag_get(const event_t *event, const char *name);

/* Get ALL tags matching name. Returns malloc'd array of value-arrays (NULL-terminated outer).
 * Example: multiple ["p", "pk1"], ["p", "pk2"] -> [ ["pk1", NULL], ["pk2", NULL], NULL ]
 * Free with event_tag_free_all(). */
char ***event_tag_get_all(const event_t *event, const char *name, size_t *out_count);

/* ---- Core: First Value (Most Common) ---- */

/* Get first value (tag[1]) for a tag name. Returns strdup'd string or NULL.
 * Free with free(). */
char *event_tag_value(const event_t *event, const char *name);

/* ---- Existence / Counting ---- */

bool event_tag_has(const event_t *event, const char *name);
bool event_tag_has_value(const event_t *event, const char *name, const char *value);
size_t event_tag_count(const event_t *event, const char *name);

/* ---- Free Helpers ---- */

void event_tag_free(char **values);              // for event_tag_get()
void event_tag_free_all(char ***values, size_t count); // for event_tag_get_all()

#ifdef __cplusplus
}
#endif

#endif