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
 * 
 * OWNERSHIP MODEL:
 * - storage_find_events() TRANSFERS ownership of returned events to CALLER
 *   (caller MUST call event_free() on each event, then free() the array)
 * - storage_insert_record() BORROWS event - does NOT take ownership
 *   (storage copies data if needed)
 * - storage_get_event_by_id() TRANSFERS ownership to CALLER
 * - storage_delete_events() BORROWS scope - does NOT take ownership
 * - storage_count_events() BORROWS scope - does NOT take ownership
 * - storage_find_ids_by_tags() TRANSFERS ownership of ID list to CALLER
 *   (caller MUST call storage_free_id_list())
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

/* Optional column-level narrowing for generic event walks. Tag interpretation
 * is deliberately left to the caller's synchronous predicate callback. */
typedef struct {
    /* Exact ID match (single) */
    const char *id;
    const char *after_id;

    /* Multiple ID match (IN query) */
    const char **ids;
    size_t ids_count;

    /* Exact author match (single) */
    const char *pubkey;

    /* Multiple author match (IN query) */
    const char **pubkeys;
    size_t pubkeys_count;

    /* Kind filter (single) */
    bool has_kind;
    int kind;

    /* Multiple kind filter (IN query) */
    int *kinds;
    size_t kinds_count;

    /* Timestamp range (strict upper bound, <) */
    bool has_created_at_before;
    time_t created_at_before;

    /* Timestamp range (inclusive upper bound, <=) */
    bool has_created_at_at_or_before;
    time_t created_at_at_or_before;

    /* Timestamp range (strict lower bound, >) */
    bool has_created_at_after;
    time_t created_at_after;

    /* Timestamp range (inclusive lower bound, >=) */
    bool has_created_at_at_or_after;
    time_t created_at_at_or_after;

    /* Excluded kind (NIP-62) */
    bool has_excluded_kind;
    int excluded_kind;

    /* Multiple excluded kinds */
    int *excluded_kinds;
    size_t excluded_kinds_count;

    /* Tag filter: match events having ALL of these tag name/value pairs (AND) */
    const char **tag_names;
    const char **tag_values;
    size_t tag_count;

    /* Result limit (0 = backend default) */
    size_t limit;

    /* Offset for pagination (0 = no offset) */
    size_t offset;
} storage_event_scope_t;

/* Legacy storage_event_predicate_t (delete_matching callback) deleted with
 * the predicate delete path. Tag policy lives in NIP code via
 * event_tag_has_value(), not in storage callbacks. */

/* Generic opaque tag-index extension. A NIP may provide (tag name, tag value)
 * pairs at insertion and query time; storage performs no interpretation. */
typedef struct {
    char *tag_name;
    char *tag_value;
    size_t filter_index;
} storage_tag_match_t;

/* Forward declaration for transaction API used in storage_context_t */
typedef struct storage_transaction_t storage_transaction_t;

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
     *          CALLER OWNS returned event - must call event_free() to release
     * OWNERSHIP: TRANSFERS ownership to caller
     */
    event_t *(*get_event_by_id)(const char *id);
    
    /* insert_record - Store a new event
     * Args: ev - event to store (must be valid, call check_event() first)
     *        indexed_tags - optional tag index entries
     *        indexed_tags_count - number of tag index entries
     * Returns: storage_insert_result_t with result and error details
     * Note: May enforce uniqueness on event ID
     * OWNERSHIP: BORROWS event - does NOT take ownership
     */
    storage_insert_result_t (*insert_record)(const event_t *ev,  /* BORROWED */
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
    
    /* Legacy delete_matching (bounded scan + caller predicate) deleted.
     * Use delete_events with the same scope as find. Legacy
     * find_ids_by_tag (single pair) deleted; use find_ids_by_tags. */
    
    /* ====================================================================
     * Event Query and Streaming
     * ==================================================================== */
    
/* Return a module-owned array of generic tag index keys extracted from an
     * event, for use in the next insert_record call. Caller releases it with
     * free_tag_matches(). Storage stores only the supplied opaque pairs. */

    /* ====================================================================
     * New Unified Storage API (per NOSTR_EVENT_STORAGE_SPEC.md)
     * ==================================================================== */

    /* find_events - Find events matching scope
     * Args: scope - selection scope, out_events - receives CALLER-OWNED array,
     *       out_count - receives number of returned events
     * Returns: true on success, false on database error
     * OWNERSHIP: TRANSFERS ownership of returned events to CALLER
     */
    bool (*find_events)(const storage_event_scope_t *scope,  /* BORROWED */
                        event_t ***out_events, size_t *out_count);

    /* count_events - Count events matching scope
     * Args: scope - selection scope, out_count - receives total matching count
     * Returns: true on success, false on database error
     * OWNERSHIP: BORROWS scope - does NOT take ownership
     */
    bool (*count_events)(const storage_event_scope_t *scope,  /* BORROWED */
                         size_t *out_count);

    /* delete_events - Delete events matching scope
     * Args: scope - selection scope, out_deleted - receives number of deleted rows
     * Returns: true on success, false on database error
     * OWNERSHIP: BORROWS scope - does NOT take ownership
     */
    bool (*delete_events)(const storage_event_scope_t *scope,  /* BORROWED */
                          size_t *out_deleted);

    /* Transaction API */
    storage_transaction_t *(*transaction_begin)(void);
    bool (*transaction_commit)(storage_transaction_t *tx);
    void (*transaction_rollback)(storage_transaction_t *tx);

    bool (*delete_events_tx)(const storage_event_scope_t *scope,  /* BORROWED */
                             storage_transaction_t *tx, size_t *out_deleted);
    bool (*find_events_tx)(const storage_event_scope_t *scope,  /* BORROWED */
                           storage_transaction_t *tx,
                           event_t ***out_events, size_t *out_count);  /* TRANSFERS ownership to caller */

    /* Replaceable event upsert (atomic delete-older-then-insert)
     * OWNERSHIP: BORROWS event - does NOT take ownership */
    storage_insert_result_t (*upsert_replaceable)(const event_t *ev,  /* BORROWED */
                                                  const storage_tag_match_t *indexed_tags,
                                                  size_t indexed_tags_count);

    /* Addressable event upsert (atomic delete-older-then-insert)
     * OWNERSHIP: BORROWS event - does NOT take ownership */
    storage_insert_result_t (*upsert_addressable)(const event_t *ev,  /* BORROWED */
                                                  const char *d_tag_value,
                                                  const storage_tag_match_t *indexed_tags,
                                                  size_t indexed_tags_count);

    /* Compound tag index lookup (AND across names, OR within values)
     * OWNERSHIP: TRANSFERS ownership of ID list to CALLER
     * Caller MUST call free_id_list() */
    bool (*find_ids_by_tags)(const char *const *tag_names,
                             const char *const *tag_values,
                             size_t tag_count,
                             char ***ids_out, size_t *count_out);

    /* Free ID list from find_ids_by_tags
     * OWNERSHIP: Caller owns the ID list, this frees it */
    void (*free_id_list)(char **ids, size_t count);
} storage_context_t;

/* ============================================================================
 * New Unified Storage API (per NOSTR_EVENT_STORAGE_SPEC.md)
 * ============================================================================ */

/* storage_count_result_t - Result of count operation */
typedef struct {
    storage_result_t result;
    size_t count;
    char error_message[256];
} storage_count_result_t;

/* storage_find_events - Find events matching scope
 *
 * Args:
 *   scope - selection scope (NULL = no filter, subject to backend safety) - BORROWED
 *   out_events - receives CALLER-OWNED array of CALLER-OWNED event_t*
 *   out_count - receives number of returned events
 *
 * Returns: true on success (including zero matches), false on database error
 *
 * Contract:
 *   - Zero matches = success with count 0
 *   - Ordering: ORDER BY created_at DESC, id DESC
 *   - limit == 0 means no limit
 *   - offset skips first N matching events
 *   - OWNERSHIP: TRANSFERS ownership of returned events to CALLER
 *   - Caller MUST: event_free() each event, then free() the array
 */
bool storage_find_events(const storage_event_scope_t *scope,  /* BORROWED */
                         event_t ***out_events, size_t *out_count);

/* storage_count_events - Count events matching scope
 *
 * Args:
 *   scope - selection scope (same semantics as storage_find_events) - BORROWED
 *   out_count - receives total matching count
 *
 * Returns: true on success (including zero matches), false on database error
 *
 * Contract:
 *   - Same scope semantics as storage_find_events
 *   - Returns total matching count without materializing events
 *   - Zero matches = success with *out_count == 0
 *   - Ignores limit and offset
 *   - OWNERSHIP: BORROWS scope - does NOT take ownership
 */
bool storage_count_events(const storage_event_scope_t *scope,  /* BORROWED */
                          size_t *out_count);

/* storage_delete_events - Delete events matching scope
 *
 * Args:
 *   scope - selection scope (same semantics as storage_find_events) - BORROWED
 *   out_deleted - receives number of deleted rows (may be NULL)
 *
 * Returns: true on success (including zero matches), false on database error
 *
 * Contract:
 *   - Same scope semantics as storage_find_events
 *   - Zero matches = success with *out_deleted == 0
 *   - Atomic from storage call perspective
 *   - limit controls maximum deleted rows (symmetry with find)
 *   - offset skips first N matching events before deleting
 *   - OWNERSHIP: BORROWS scope - does NOT take ownership
 */
bool storage_delete_events(const storage_event_scope_t *scope,  /* BORROWED */
                           size_t *out_deleted);

/* Transaction API */
storage_transaction_t *storage_transaction_begin(void);
bool storage_transaction_commit(storage_transaction_t *tx);
void storage_transaction_rollback(storage_transaction_t *tx);

bool storage_delete_events_tx(const storage_event_scope_t *scope,  /* BORROWED */
                              storage_transaction_t *tx, size_t *out_deleted);
bool storage_find_events_tx(const storage_event_scope_t *scope,  /* BORROWED */
                            storage_transaction_t *tx,
                            event_t ***out_events, size_t *out_count);  /* TRANSFERS ownership to caller */

/* Replaceable event upsert (atomic delete-older-then-insert)
 * OWNERSHIP: BORROWS event - does NOT take ownership */
storage_insert_result_t storage_upsert_replaceable(const event_t *ev,  /* BORROWED */
                                                    const storage_tag_match_t *indexed_tags,
                                                    size_t indexed_tags_count);

/* Addressable event upsert (atomic delete-older-then-insert)
 * OWNERSHIP: BORROWS event - does NOT take ownership */
storage_insert_result_t storage_upsert_addressable(const event_t *ev,  /* BORROWED */
                                                     const char *d_tag_value,
                                                     const storage_tag_match_t *indexed_tags,
                                                     size_t indexed_tags_count);

/* Compound tag index lookup (AND of multiple tag name/value pairs)
 * OWNERSHIP: TRANSFERS ownership of ID list to CALLER
 * Caller MUST call storage_free_id_list() */
bool storage_find_ids_by_tags(const char *const *tag_names,
                              const char *const *tag_values,
                              size_t tag_count,
                              char ***ids_out, size_t *count_out);

/* Free ID list from storage_find_ids_by_tag or storage_find_ids_by_tags
 * OWNERSHIP: Caller owns the ID list, this frees it */
void storage_free_id_list(char **ids, size_t count);

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
