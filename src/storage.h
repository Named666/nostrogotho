#ifndef STORAGE_H_
#define STORAGE_H_

#include "nostrogotho.h"
#include <stdbool.h>

/* ============================================================================
 * STORAGE.H - Event Storage Backend Interface
 * 
 * Defines the abstract storage interface that can be implemented by
 * different backends (SQLite3, PostgreSQL, etc.). Events are stored
 * persistently and queried via filters.
 * 
 * All storage operations are synchronous and NOT thread-safe. A mutex
 * should be used at the application level if concurrent access is needed.
 * ============================================================================ */

/* ============================================================================
 * Result Types
 * ============================================================================ */

/* storage_result_t - Typed result for storage operations
 * 
 * Distinguishes between different failure modes so callers can handle
 * each appropriately. In particular, duplicate vs failure must be
 * distinguishable because the current helper interprets any false result
 * as a duplicate, which is unsafe if the storage backend can fail for
 * another reason.
 */
typedef enum {
    STORAGE_OK = 0,           /* Operation succeeded */
    STORAGE_DUPLICATE,        /* Event already exists (unique constraint) */
    STORAGE_NOT_FOUND,        /* Event not found */
    STORAGE_ERROR,            /* Database/storage error */
    STORAGE_INVALID_ARGUMENT  /* Invalid input parameters */
} storage_result_t;

/* storage_insert_result_t - Result of insert operation with detail */
typedef struct {
    storage_result_t result;
    char error_message[256];
} storage_insert_result_t;

/* storage_delete_result_t - Result of delete operation with count */
typedef struct {
    storage_result_t result;
    int deleted_count;
    char error_message[256];
} storage_delete_result_t;

/* ============================================================================
 * Callback Types
 * ============================================================================ */

/* send_records_callback_t - Callback for sending records to client
 * 
 * Called by send_records() for each event matching a filter.
 * Also called once for COUNT responses.
 * 
 * Args: json_event - JSON-formatted event string (EVENT or COUNT response)
 *                    Format: ["EVENT", subscription_id, event] or
 *                            ["COUNT", subscription_id, {count: N}]
 *       userdata - opaque context passed to send_records
 * 
 * Note: json_event is valid only for the duration of the callback
 */
typedef void (*send_records_callback_t)(const char *json_event, void *userdata);

/* Optional column-level narrowing for generic event walks. Tag interpretation
 * is deliberately left to the caller's synchronous predicate callback. */
typedef struct {
    const char *id;
    const char *after_id;
    const char *pubkey;
    bool has_kind;
    int kind;
    bool has_created_at_before;
    time_t created_at_before;
    bool has_created_at_at_or_before;
    time_t created_at_at_or_before;
    bool has_created_at_after;
    time_t created_at_after;
    bool has_excluded_kind;
    int excluded_kind;
    size_t limit; /* Maximum rows examined; zero uses the backend default. */
} storage_event_scope_t;

/* Called synchronously with a borrowed event view. Return true to select the
 * event for deletion. The callback is never retained by storage. */
typedef bool (*storage_event_predicate_t)(const event_t *event, void *userdata);

/* Generic opaque tag-index extension. A NIP may provide (tag name, tag value)
 * pairs at insertion and query time; storage performs no interpretation. */
typedef struct {
    char *tag_name;
    char *tag_value;
    size_t filter_index;
} storage_tag_match_t;

/* ============================================================================
 * Storage Context Structure
 * ============================================================================ */

/* storage_context_t - Abstract storage backend interface
 * 
 * Function pointers to storage operations. Allows switching between
 * SQLite3, PostgreSQL, or other backends without changing application code.
 * 
 * All function pointers must be initialized by the backend (e.g.,
 * storage_context_init_sqlite3). Application uses the public interface
 * through these pointers.
 * 
 * Requirements:
 *   - init() must be called first, before any other operations
 *   - Exactly one backend must be selected and initialized
 *   - deinit() must be called at shutdown
 * 
 * Thread safety: NOT thread-safe; caller must synchronize
 */
typedef struct {
    /* Initialization and cleanup */
    
    /* init - Initialize storage backend
     * Args: dsn - connection string (varies by backend)
     *             SQLite: "file:nostrogotho.sqlite" or ":memory:"
     *             PostgreSQL: "postgresql://user:pass@host/db"
     * Returns: true on success, false on connection failure
     * Must be called exactly once before other operations
     */
    bool (*init)(const char *dsn);
    
    /* deinit - Cleanup storage backend
     * Closes connections and releases resources
     * Safe to call even if init() failed
     */
    void (*deinit)(void);
    
    /* ====================================================================
     * Event Query Operations
     * ==================================================================== */
    
    /* get_event_by_id - Retrieve a single event by ID
     * Args: id - event ID (hex string)
     * Returns: malloc'd event_t on success, NULL if not found
     *          caller must call event_free() to release
     */
    event_t *(*get_event_by_id)(const char *id);
    
    /* insert_record - Store a new event
     * Args: ev - event to store (must be valid, call check_event() first)
     *        indexed_tags - optional tag index entries
     *        indexed_tags_count - number of tag index entries
     * Returns: storage_insert_result_t with result and error details
     * Note: May enforce uniqueness on event ID
     */
    storage_insert_result_t (*insert_record)(const event_t *ev,
                                             const storage_tag_match_t *indexed_tags,
                                             size_t indexed_tags_count);
    
    /* ====================================================================
     * Event Deletion Operations
     * ==================================================================== */
    
    /* delete_record_by_id_and_pubkey - Delete a specific event (NIP-09)
     * Args: id - event ID, pubkey - author pubkey
     * Returns: storage_delete_result_t with result and deleted count
     * Used for NIP-09 deletion events
     */
    storage_delete_result_t (*delete_record_by_id_and_pubkey)(const char *id, const char *pubkey);
    
    /* delete_record_by_kind_and_pubkey - Delete replaceable events (NIP-09, NIP-16)
     * Args:
     *   kind - event kind (0, 3, or 10000-20000 range)
     *   pubkey - author pubkey
     *   created_at - delete events with created_at < this timestamp
     * Returns: storage_delete_result_t with result and deleted count
     * Used for replaceable events where newer overwrites older
     */
    storage_delete_result_t (*delete_record_by_kind_and_pubkey)(int kind, const char *pubkey, time_t created_at);
    
    /* delete_matching - Delete events narrowed by generic columns and
     * selected by a caller-supplied synchronous predicate. The callback may
     * inspect tags but must not retain the borrowed event pointers. `deleted`
     * receives the number of deleted rows when non-NULL. Returns false on
     * database/allocation failure. Storage invokes the callback in bounded
     * batches and never stores it. */
    bool (*delete_matching)(const storage_event_scope_t *scope,
                            storage_event_predicate_t predicate,
                            void *userdata, size_t *deleted,
                            char *next_id, size_t next_id_size, bool *more);

    /* Generic indexed tag-value lookup; NIP code chooses the tag semantics.
     * Returns caller-owned event ID strings and an allocated array. */
    bool (*find_ids_by_tag)(const char *tag_name, const char *tag_value,
                            char ***ids, size_t *count);
    void (*free_id_list)(char **ids, size_t count);
    
    /* ====================================================================
     * Event Query and Streaming
     * ==================================================================== */
    
/* send_records - Query and stream events matching filters (NIP-01, NIP-67)
 * 
 * Searches database for events matching filter criteria and calls
 * the sender callback for each matching event. Also supports COUNT queries.
 * 
 * Args:
 *   sender - callback function called for each result
 *   sub - subscription ID (included in response)
 *   filters - array of filter structures
 *   filters_count - number of filters in array
 *   do_count - if true, count matching events instead of streaming.
 *              When counting, the sender is NOT invoked; the total is
 *              returned via out_count (NIP-45) and the caller builds the
 *              COUNT response.
 *   has_more - if not NULL, set to true if more events exist beyond limit
 *   out_count - when do_count is true, receives the aggregated count.
 *               May be NULL when do_count is false.
 *   userdata - opaque context passed to sender callback
 * 
 * Returns: true on success, false on database error
 * 
 * Behavior:
 *   - Multiple filters are OR'd (send if ANY filter matches)
 *   - Within a filter, criteria are AND'd
 *   - If do_count is true, reports the count via out_count instead of
 *     emitting a COUNT response (NIP-45)
 *   - Fetches limit+1 events to determine has_more flag (NIP-67)
 */
    bool (*send_records)(send_records_callback_t sender, const char *sub,
                         const filter_t *filters, size_t filters_count,
                         bool do_count, bool *has_more, int *out_count,
                         const storage_tag_match_t *indexed_tags,
                         size_t indexed_tags_count,
                         void *userdata);
    /* Return a module-owned array of generic tag index keys extracted from an
     * event, for use in the next insert_record call. Caller releases it with
     * free_tag_matches(). Storage stores only the supplied opaque pairs. */
} storage_context_t;

/* ============================================================================
 * Backend Initialization
 * ============================================================================ */

/* storage_context_init_sqlite3 - Initialize SQLite3 storage backend
 * 
 * Fills in storage_context_t function pointers to use SQLite3.
 * Supports both file and in-memory (:memory:) databases.
 * Uses WAL mode for better concurrency and crash safety.
 * 
 * Args: ctx - storage context to initialize (must not be NULL)
 * 
 * Usage:
 *   storage_context_t ctx = {0};
 *   storage_context_init_sqlite3(&ctx);
 *   ctx.init("file:nostrogotho.sqlite");
 */
void storage_context_init_sqlite3(storage_context_t *ctx);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/* escape_like - Escape special characters for SQL LIKE clause
 * 
 * Escapes characters that have special meaning in LIKE patterns: %, _, \
 * Output uses backslash escaping (requires ESCAPE '\' in SQL query).
 * 
 * Args:
 *   str - string to escape (NULL-safe)
 *   len - length of string
 * 
 * Returns: malloc'd escaped string, or NULL if str is NULL or malloc fails
 * 
 * Caller responsibility: Must free result with free()
 * 
 * Example: "a_b%c" with backslash escape -> "a\_b\%c"
 */
char *escape_like(const char *str, size_t len);

#endif /* STORAGE_H_ */
