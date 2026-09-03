#ifndef JSON_UTIL_H_
#define JSON_UTIL_H_

#include <stddef.h>
#include <stdbool.h>
#include "nostrogotho.h"

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
 * ============================================================================ */

/* Maximum number of elements in a top-level JSON array */
#define MAX_JSON_ARRAY_ELEMENTS 128

/* Maximum length for a single JSON string value */
#define MAX_JSON_STRING_VALUE 65536

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
    char buffer[65536];
    size_t pos;
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

/* Finish building and get the result
 * 
 * Args: builder - Completed builder
 * 
 * Returns: Pointer to built JSON string (valid until next builder operation)
 */
const char *json_builder_finish(json_builder_t *builder);

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

#endif /* JSON_UTIL_H_ */
