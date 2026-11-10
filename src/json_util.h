#ifndef JSON_UTIL_H_
#define JSON_UTIL_H_

#include <stddef.h>
#include <stdbool.h>
#include "nostrogotho.h"
#include "ng_status.h"

/* ============================================================================
 * JSON Utilities for Nostr Protocol
 * 
 * Simple JSON parsing and generation for Nostr protocol messages.
 * Supports:
 *   - Parsing incoming JSON arrays (REQ, EVENT, etc.)
 *   - Generating outgoing JSON arrays (EVENT, OK, CLOSED, etc.)
 *   - Proper escaping of strings in JSON context
 * 
 * Not a general-purpose JSON library; designed specifically for Nostr.
 *
 * Contract: no globals; every function is thread-safe on distinct objects.
 * Ownership: parse results (json_value_t arrays, filters, events) own their
 * heap strings; release them with the matching *_free function.
 * Builder: growable. Starts in a small inline buffer and moves to the heap
 * as needed, up to the hard cap JSON_BUILDER_MAX. Sizes are checked; the
 * first failure (NG_E_TOOBIG past the cap, NG_E_NOMEM) is sticky, later
 * appends are no-ops and json_builder_finish returns NULL. Callers must
 * json_builder_free() a started builder (thread-local builders reused via
 * json_builder_reset() keep their heap buffer up to JSON_BUILDER_KEEP).
 * A started builder points into itself: it must not be copied or moved.
 * Errors: parsers return false / 0 and leave outputs freeable.
 * ============================================================================ */

/* Maximum number of elements in a top-level JSON array */
#define MAX_JSON_ARRAY_ELEMENTS 128

/* Maximum length for a single JSON string value */
#define MAX_JSON_STRING_VALUE 65536

/* json_builder_t sizing: inline bytes, the hard output cap (any message the
 * relay builds, including an ["EVENT", sub, {...}] at the largest
 * configurable max_event_size, 4 MiB, see ng_config.h), and the heap buffer
 * size a reused (thread-local) builder may keep between messages. */
#define JSON_BUILDER_INLINE 512
#define JSON_BUILDER_MAX    (8u * 1024u * 1024u)
#define JSON_BUILDER_KEEP   (128u * 1024u)

/* ============================================================================
 * JSON Value Types
 * ============================================================================ */

typedef enum {
    JSON_TYPE_NULL,
    JSON_TYPE_BOOL,
    JSON_TYPE_NUMBER,
    JSON_TYPE_STRING,
    JSON_TYPE_ARRAY,
    JSON_TYPE_OBJECT,
} json_type_t;

/* Represents a single JSON value in an array */
typedef struct {
    json_type_t type;
    union {
        bool bool_val;
        long long number_val;
        /* For strings, arrays and objects this is malloc'd JSON text. */
        char *string_val;
    } value;
} json_value_t;

/* ============================================================================
 * JSON Array Parser
 * 
 * Parse incoming Nostr protocol messages which are always JSON arrays.
 * Example: ["REQ", "sub-123", {"kinds": [1, 2, 3]}]
 * ============================================================================ */

/* Parse a JSON array from a string
 * 
 * Args:
 *   json_str - Input JSON string
 *   values - Output array for parsed values (caller allocated)
 *   max_values - Size of values array
 * 
 * Returns: Number of values parsed (0-max_values), or 0 on error
 * 
 * Note: Caller must call json_array_free() to clean up string values
 */
size_t json_array_parse(const char *json_str, json_value_t *values, size_t max_values);

/* Free all string values in a parsed JSON array
 * 
 * Args:
 *   values - Array of parsed JSON values
 *   count - Number of values in array
 */
void json_array_free(json_value_t *values, size_t count);

/* Get string value from parsed JSON array
 * 
 * Args:
 *   values - Array of parsed JSON values
 *   count - Number of values in array
 *   index - Index to access
 * 
 * Returns: String value or NULL if index out of range or not a string
 */
const char *json_array_get_string(const json_value_t *values, size_t count, size_t index);

/* Get number value from parsed JSON array
 * 
 * Args:
 *   values - Array of parsed JSON values
 *   count - Number of values in array
 *   index - Index to access
 *   out - Output pointer for value
 * 
 * Returns: true if value exists and is a number, false otherwise
 */
bool json_array_get_number(const json_value_t *values, size_t count, size_t index, long long *out);

/* ============================================================================
 * JSON Array Builder
 * 
 * Build outgoing Nostr protocol messages as JSON arrays.
 * Example: ["EVENT", "sub-123", {"id": "...", "pubkey": "...", ...}]
 * ============================================================================ */

/* An in-progress JSON array being built */
typedef struct {
    char *buf;            /* inline_buf or heap; NULL before start / after free */
    size_t pos;           /* bytes written (excluding the closing "]\0") */
    size_t cap;
    ng_status_t status;   /* NG_OK, or the first error (sticky) */
    char inline_buf[JSON_BUILDER_INLINE];
} json_builder_t;

/* Start building a new JSON array
 * 
 * Args: builder - Uninitialized builder structure
 */
void json_builder_start(json_builder_t *builder);

/* Append a null value
 * 
 * Args: builder - Builder being constructed
 */
void json_builder_append_null(json_builder_t *builder);

/* Append a boolean value
 * 
 * Args:
 *   builder - Builder being constructed
 *   value - Boolean value to append
 */
void json_builder_append_bool(json_builder_t *builder, bool value);

/* Append a number value
 * 
 * Args:
 *   builder - Builder being constructed
 *   value - Number to append
 */
void json_builder_append_number(json_builder_t *builder, long long value);

/* Append a string value (properly escaped for JSON)
 * 
 * Args:
 *   builder - Builder being constructed
 *   value - String to append (must not be NULL)
 * 
 * Escapes: ", \, /, \b, \f, \n, \r, \t, and control characters
 */
void json_builder_append_string(json_builder_t *builder, const char *value);

/* Start a nested array
 * 
 * Args: builder - Builder being constructed
 */
void json_builder_start_array(json_builder_t *builder);

/* End a nested array
 * 
 * Args: builder - Builder being constructed
 */
void json_builder_end_array(json_builder_t *builder);

/* Start a nested object
 * 
 * Args: builder - Builder being constructed
 */
void json_builder_start_object(json_builder_t *builder);

/* Add an object key-value pair (key must be ASCII identifier)
 * 
 * Args:
 *   builder - Builder being constructed
 *   key - Object key (must be valid identifier)
 *   value - Value to set (properly escaped)
 */
void json_builder_object_key_string(json_builder_t *builder, const char *key, const char *value);

/* Add an object key-number pair
 * 
 * Args:
 *   builder - Builder being constructed
 *   key - Object key
 *   value - Number value
 */
void json_builder_object_key_number(json_builder_t *builder, const char *key, long long value);

/* Add an object key-boolean pair
 * 
 * Args:
 *   builder - Builder being constructed
 *   key - Object key
 *   value - Boolean value
 */
void json_builder_object_key_bool(json_builder_t *builder, const char *key, bool value);

/* Start a nested object as a value (for key-object pairs)
 * 
 * Args:
 *   builder - Builder being constructed
 *   key - Object key
 */
void json_builder_object_start_nested(json_builder_t *builder, const char *key);

/* End nested object
 * 
 * Args: builder - Builder being constructed
 */
void json_builder_end_object(json_builder_t *builder);

/* "key": inside an object; the next append is its value. */
void json_builder_object_key(json_builder_t *builder, const char *key);

/* Finish building and get the result
 * 
 * Args: builder - Completed builder
 * 
 * Returns: Pointer to built JSON string (valid until next builder operation),
 *          or NULL if any append failed (see json_builder_status)
 */
const char *json_builder_finish(json_builder_t *builder);

/* Start a builder that may already hold a heap buffer (or is zero
 * initialized, e.g. static NG_THREAD_LOCAL); keeps up to JSON_BUILDER_KEEP. */
void json_builder_reset(json_builder_t *builder);

/* Release the heap buffer (if any). Safe on a zeroed or freed builder. */
void json_builder_free(json_builder_t *builder);

/* Per-thread scratch builders for hot paths (one per slot, so two users
 * that may interleave on one thread never share). The returned builder is
 * already reset; its heap buffer (<= JSON_BUILDER_KEEP) is reused across
 * calls and released when the thread exits. Never free it. */
typedef enum { JSON_SCRATCH_BCAST, JSON_SCRATCH_QUERY, JSON_SCRATCH_SLOTS } json_scratch_t;
json_builder_t *json_builder_scratch(json_scratch_t slot);

/* NG_OK, NG_E_TOOBIG (past JSON_BUILDER_MAX) or NG_E_NOMEM. */
ng_status_t json_builder_status(const json_builder_t *builder);

/* strlen of the finished string (valid after a successful finish). */
size_t json_builder_length(const json_builder_t *builder);

/* ============================================================================
 * Filter Parsing
 * 
 * Parse filter objects from incoming REQ/COUNT messages.
 * A filter is a JSON object with constraints on events.
 * ============================================================================ */

/* Parse a single filter object from JSON
 * 
 * Args:
 *   json_str - JSON object string (e.g., from array element)
 *   filter - Output filter structure to populate
 * 
 * Returns: true on success, false on parse error or memory allocation failure
 * 
 * Note: This populates the filter structure; caller is responsible for
 *       freeing via filter_free()
 */
bool json_parse_filter(const char *json_str, filter_t *filter);
/* As json_parse_filter; on failure *why (if why) is a static NIP-01
 * machine-readable reason ("invalid: ..." or "error: ..."). */
bool json_parse_filter_why(const char *json_str, filter_t *filter, const char **why);

/* Parse event object from JSON
 * 
 * Args:
 *   json_str - JSON object string
 *   event - Output event structure to populate
 * 
 * Returns: true on success, false on parse error
 * 
 * Note: This populates the event structure; caller is responsible for
 *       freeing via event_free()
 */
bool json_parse_event(const char *json_str, event_t *event);
/* As json_parse_event; on failure *why (if why) is a static NIP-01 reason. */
bool json_parse_event_why(const char *json_str, event_t *event, const char **why);
/* The event's "id" when it is 64 lowercase hex (to address an OK false to
 * an event that failed to parse). */
bool json_event_id_hint(const char *json_str, char out[MAX_ID_SIZE + 1]);

/* ============================================================================
 * Event Serialization
 * 
 * Convert event_t structures to JSON for transmission.
 * ============================================================================ */

/* Serialize an event to JSON
 *
 * Args:
 *   event - Event to serialize
 *   builder - JSON builder to append to
 */
void json_serialize_event(const event_t *event, json_builder_t *builder);

/* Exact size in bytes json_serialize_event() writes for this event
 * (excluding the enclosing ["EVENT", sub, ...] wrapper).
 *
 * Callers can use this to reject, before storing or broadcasting, any event
 * whose serialization exceeds the max_event_size limit (ng_limits).
 */
size_t json_serialized_event_size(const event_t *event);

/* Number of tags in event->tags_json (0 when there are none). */
size_t json_event_tag_count(const event_t *event);

#endif /* JSON_UTIL_H_ */
