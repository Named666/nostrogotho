#ifndef CAGLIOSTR_H_
#define CAGLIOSTR_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

/* ============================================================================
 * CAGLIOSTR - C99 Nostr Relay Server
 * 
 * Core data structures and memory management utilities for Nostr events,
 * filters, and tags. All structures using malloc'd memory require explicit
 * cleanup via their corresponding free functions.
 * ============================================================================ */

/* Maximum sizes for string fields - must fit in stack-allocated arrays */
#define MAX_ID_SIZE 64          /* Event ID (SHA256 hex) */
#define MAX_PUBKEY_SIZE 64      /* Public key (hex) */
#define MAX_SIG_SIZE 128        /* Schnorr signature (hex) */
#define MAX_CONTENT_SIZE 65536  /* Event content payload */
#define MAX_TAGS_SIZE 65536     /* Full tags JSON size */
#define MAX_TAG_ELEMENTS 256    /* Maximum elements in a single tag */
#define MAX_TAG_SIZE 512        /* Maximum size of a tag element */

/* ============================================================================
 * event_t - Represents a single Nostr event
 * 
 * A Nostr event is the fundamental data structure containing a message,
 * metadata, and cryptographic proof of authenticity.
 * 
 * Fields:
 *   id[MAX_ID_SIZE+1]      - SHA256 hash of event data (hex string, null-terminated)
 *   pubkey[MAX_PUBKEY_SIZE+1] - Author's public key (hex string, null-terminated)
 *   created_at             - Unix timestamp when event was created
 *   kind                   - Event type code (0-based integer)
 *   tags_json              - Tags as JSON array string (malloc'd, may be NULL)
 *   tags_json_len          - Length of tags JSON (excluding null terminator)
 *   content                - Event content/message (malloc'd, may be NULL)
 *   content_len            - Length of content (excluding null terminator)
 *   sig[MAX_SIG_SIZE+1]    - Schnorr signature proof (hex string, null-terminated)
 * 
 * Memory management:
 *   - tags_json and content are dynamically allocated and must be freed
 *   - Use event_alloc() and event_free() for proper lifecycle management
 *   - Fixed fields (id, pubkey, sig) are stack-allocated (bounded)
 * ============================================================================ */
typedef struct {
    char id[MAX_ID_SIZE + 1];
    char pubkey[MAX_PUBKEY_SIZE + 1];
    time_t created_at;
    int kind;
    char *tags_json;
    size_t tags_json_len;
    char *content;
    size_t content_len;
    char sig[MAX_SIG_SIZE + 1];
} event_t;

/* ============================================================================
 * tag_t - Represents a single Nostr tag
 * 
 * Tags are arrays of strings attached to events. A tag is typically:
 *   ["tag_name", "value1", "value2", ...]
 * 
 * Fields:
 *   elements  - Array of string pointers (malloc'd elements array)
 *   count     - Number of elements currently in the tag (0 to MAX_TAG_ELEMENTS)
 * 
 * Memory management:
 *   - Both the elements array and each element string are malloc'd
 *   - Use tag_alloc() and tag_free() for proper lifecycle management
 *   - tag_alloc(n) allocates capacity for n elements but count starts at 0
 * ============================================================================ */
typedef struct {
    char **elements;
    size_t count;
    size_t capacity;
} tag_t;

/* ============================================================================
 * filter_t - Represents a Nostr subscription filter (NIP-01)
 * 
 * Filters specify which events a client wants to receive. Multiple filters
 * in a subscription are OR'd together (send if ANY filter matches).
 * Within a filter, all criteria are AND'd (event must match ALL).
 * 
 * Fields:
 *   ids, ids_count         - Event IDs to match (can be full or prefixes)
 *   authors, authors_count - Author pubkeys to match (can be full or prefixes)
 *   kinds, kinds_count     - Event kinds to match
 *   tags, tags_count       - Tag filters (e.g., tag name "e" with values)
 *   since                  - Minimum created_at (0 = no limit)
 *   until                  - Maximum created_at (0 = no limit)
 *   limit                  - Maximum number of events to return (default 500)
 *   search                 - Full-text search in content (optional)
 * 
 * Memory management:
 *   - All pointer arrays and strings are malloc'd
 *   - Use filter_alloc() and filter_free() for proper lifecycle management
 * ============================================================================ */
typedef struct {
    char **ids;
    size_t ids_count;
    
    char **authors;
    size_t authors_count;
    
    int *kinds;
    size_t kinds_count;
    
    tag_t *tags;
    size_t tags_count;
    
    time_t since;
    time_t until;
    int limit;
    
    char *search;
} filter_t;

/* ============================================================================
 * tags_array_t - Collection of tags for easier bulk manipulation
 * 
 * A helper structure for storing and iterating over multiple tags,
 * typically used when parsing tags from an event's JSON.
 * 
 * Fields:
 *   tags  - Array of tag_t structures (malloc'd array)
 *   count - Number of tags currently in array (0 to MAX_TAG_ELEMENTS)
 * 
 * Memory management:
 *   - Both array and contained tags are malloc'd
 *   - Use tags_array_alloc() and tags_array_free()
 * ============================================================================ */
typedef struct {
    tag_t *tags;
    size_t count;
} tags_array_t;

/* ============================================================================
 * Memory Management Functions
 * ============================================================================ */

/* event_alloc - Allocate and zero-initialize an event structure
 * Returns: pointer to new event, or NULL on allocation failure
 * Caller: must call event_free() to release */
event_t *event_alloc(void);

/* event_free - Free an event and its dynamically allocated fields
 * Args: ev - pointer to event (NULL-safe)
 * Note: Frees tags_json and content if allocated */
void event_free(event_t *ev);

/* filter_alloc - Allocate and zero-initialize a filter structure
 * Returns: pointer to new filter, or NULL on allocation failure
 * Caller: must call filter_free() to release */
filter_t *filter_alloc(void);

/* filter_free - Free a filter and all its dynamically allocated fields
 * Args: f - pointer to filter (NULL-safe)
 * Note: Recursively frees all string arrays and tag arrays */
void filter_free(filter_t *f);

/* tag_alloc - Allocate a tag structure with capacity for element_count strings
 * Args: element_count - maximum elements this tag can hold
 * Returns: pointer to new tag with count=0, or NULL on failure
 * Note: Allocates the elements array but leaves count at 0 */
tag_t *tag_alloc(size_t element_count);

/* tag_free - Free a tag and all its element strings
 * Args: tag - pointer to tag (NULL-safe)
 * Note: Frees both the elements array and each element string */
void tag_free(tag_t *tag);

/* tags_array_alloc - Allocate a tags array structure with capacity for tag_count tags
 * Args: tag_count - maximum tags this array can hold
 * Returns: pointer to new tags array with count=0, or NULL on failure */
tags_array_t *tags_array_alloc(size_t tag_count);

/* tags_array_free - Free a tags array and all its contained tags
 * Args: tags - pointer to tags array (NULL-safe)
 * Note: Recursively frees all tag structures in the array */
void tags_array_free(tags_array_t *tags);

/* ============================================================================
 * String Utility Functions
 * ============================================================================ */

/* string_dup - Duplicate a null-terminated string
 * Args: str - string to duplicate (NULL-safe)
 * Returns: malloc'd copy of string, or NULL if str is NULL or allocation fails
 * Caller: must call string_free() to release */
char *string_dup(const char *str);

/* string_free - Free a duplicated string
 * Args: str - pointer to malloc'd string (NULL-safe) */
void string_free(char *str);

#endif /* CAGLIOSTR_H_ */
