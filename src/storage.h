#ifndef STORAGE_H_
#define STORAGE_H_

#include "nostrogotho.h"
#include "ng_status.h"
#include <stdbool.h>
#include <stdint.h>

/* ============================================================================
 * STORAGE.H - Event Storage Backend Interface
 * 
 * Defines the abstract storage interface that can be implemented by
 * different backends (SQLite3, PostgreSQL, etc.). Events are stored
 * persistently and queried via filters.
 * 
 * Threading contract (SQLite backend):
 *   - Connections are per thread (thread-local). A thread calls
 *     thread_open(readonly) once before any other operation and
 *     thread_close() before it exits. Calls on a thread without its own
 *     connection fail (false / NULL / -1).
 *   - Exactly ONE thread (the writer) opens read-write and is the only
 *     caller of the write functions and begin/commit/rollback_batch.
 *     Workers open read-only WAL connections for queries; the checkpointer
 *     opens its own and only calls checkpoint().
 *   - init/deinit and storage_set_sync_full run single-threaded at
 *     startup/shutdown.
 * Ownership: records handed to callbacks are borrowed for the duration of
 * the callback; functions returning allocated objects say so below.
 * Errors: bool false / NULL / negative int; details go to stderr.
 * ============================================================================ */

/* ============================================================================
 * Result and Callback Types
 * ============================================================================ */

/* Outcome of insert_event. */
typedef enum {
    STORAGE_PUT_INSERTED,    /* stored */
    STORAGE_PUT_DUPLICATE,   /* id already stored (UNIQUE index is authoritative) */
    STORAGE_PUT_TOMBSTONED,  /* a NIP-09 tombstone from the same author blocks it */
    STORAGE_PUT_VANISHED,    /* NIP-62: the author vanished at or after created_at */
    STORAGE_PUT_FAILED       /* database error (details on stderr) */
} storage_put_t;

/* Outcome of replaceable_admit. */
typedef enum {
    STORAGE_ADMIT_NEWEST,    /* newest version: older ones were deleted, store it */
    STORAGE_ADMIT_STALE,     /* a newer (or tie-winning) version is stored; drop it */
    STORAGE_ADMIT_FAILED     /* database error or OOM */
} storage_admit_t;

/* send_records_callback_t - Callback for sending records to client
 * 
 * Called by send_records() for each event matching a filter.
 * Also called once for COUNT responses.
 * 
 * Args: json_event - JSON-formatted event string (EVENT or COUNT response)
 *                    Format: ["EVENT", subscription_id, event] or
 *                            ["COUNT", subscription_id, {count: N}]
 * 
 *              NULL when the row could not be rendered (builder OOM / size
 *              cap); the callback should tell the client (NOTICE).
 * 
 * Note: json_event and event are valid only for the duration of the callback
 */
typedef void (*send_records_callback_t)(const char *json_event, const event_t *event);

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
     * Returns: true if inserted, false if duplicate or error
     * Note: May enforce uniqueness on event ID
     */
    bool (*insert_record)(const event_t *ev);

    /* insert_event - insert with a precise outcome (writer thread only).
     * See storage_put_t. */
    storage_put_t (*insert_event)(const event_t *ev);

    /* replaceable_admit - NIP-01 replaceable / addressable admission.
     * dtag is NULL for replaceable kinds, the "d" value ("" if absent) for
     * addressable ones. If a stored version for the same key is newer (or
     * same created_at and lower id), returns STORAGE_ADMIT_STALE and deletes
     * nothing. Otherwise deletes every stored version for the key and
     * returns STORAGE_ADMIT_NEWEST. STORAGE_ADMIT_FAILED on error.
     * Writer thread only; runs inside the batch transaction so two versions
     * in one batch resolve in order and only the winner survives. */
    storage_admit_t (*replaceable_admit)(const event_t *ev, const char *dtag);

    /* add_tombstone - remember that `pubkey` deleted event `id` (NIP-09), so
     * the event can never be re-inserted by that author. */
    bool (*add_tombstone)(const char *id, const char *pubkey);
    
    /* ====================================================================
     * Event Deletion Operations
     * All deletion functions return true on success (false = database error
     * or OOM) and store the number of rows deleted in *deleted when it is
     * not NULL (*deleted is untouched on failure).
     * ==================================================================== */
    
    /* delete_record_by_id_and_pubkey - Delete a specific event (NIP-09)
     * Args: id - event ID, pubkey - author pubkey
     * Used for NIP-09 deletion events
     */
    bool (*delete_record_by_id_and_pubkey)(const char *id, const char *pubkey, size_t *deleted);
    
    /* delete_record_by_kind_and_pubkey - Delete replaceable events (NIP-09, NIP-16)
     * Args:
     *   kind - event kind (0, 3, or 10000-20000 range)
     *   pubkey - author pubkey
     *   created_at - delete events with created_at < this timestamp
     * Used for replaceable events where newer overwrites older
     */
    bool (*delete_record_by_kind_and_pubkey)(int kind, const char *pubkey, time_t created_at,
                                             size_t *deleted);
    
    /* delete_record_by_kind_and_pubkey_and_dtag - Delete addressable events (NIP-09, NIP-33)
     * Args:
     *   kind - addressable event kind (30000-40000 range)
     *   pubkey - author pubkey
     *   tag - tag to match (usually ["d", "identifier"])
     *   created_at - delete events with created_at < this timestamp
     * Used for parameterized replaceable events
     */
    bool (*delete_record_by_kind_and_pubkey_and_dtag)(int kind, const char *pubkey,
                                                      const tag_t *tag, time_t created_at,
                                                      size_t *deleted);
    
    /* delete_record_by_id_and_kind_and_ptag - Delete gift-wrap events (NIP-09, NIP-17)
     * Args:
     *   id - event ID to match
     *   kind - event kind (1059, 21059 for gift wraps)
     *   tag - p-tag to match (usually ["p", pubkey])
     * Used for gift wrap deletion (only sender/recipient can delete)
     */
    bool (*delete_record_by_id_and_kind_and_ptag)(const char *id, int kind,
                                                  const tag_t *tag, size_t *deleted);
    
    /* delete_all_events_by_pubkey - Delete all events by author up to a time
     * Args:
     *   pubkey - author pubkey
     *   created_at - delete events with created_at <= this timestamp
     *   exclude_kind - if non-zero, events of this kind are kept (0 = delete all)
     * Generic primitive; the NIP-62 plugin passes its own kind to keep the
     * vanish request itself from being deleted.
     */
    bool (*delete_all_events_by_pubkey)(const char *pubkey, time_t created_at,
                                        int exclude_kind, size_t *deleted);

    /* vanish - NIP-62 Request to Vanish (writer thread only, inside the
     * batch transaction so it commits atomically with the request).
     * Records (pubkey, until) durably in the `vanished` table (until only
     * ever grows), deletes the author's events with created_at <= until
     * except kind 62 requests, and every kind 1059 gift wrap p-tagging the
     * pubkey. From then on insert_event answers STORAGE_PUT_VANISHED for
     * any non-62 event by that author with created_at <= until, across
     * restarts. forget (may be NULL) is called with each deleted id before
     * the delete, so the caller can drop it from its dedupe set. */
    bool (*vanish)(const char *pubkey, time_t until, void (*forget)(const char *hex_id),
                   size_t *deleted);
    
    /* purge_expired - Delete NIP-40 expired events (background GC)
     * 
     * Deletes every stored event whose ["expiration", "<timestamp>"] tag has
     * a timestamp <= now. Intended to be driven by a periodic background task
     * (the server event loop) so that already-accepted events don't linger in
     * the database forever.
     * 
     * Args: now - reference timestamp (time(NULL)); events expiring on or
     *             before this instant are removed.
     * Returns: true on success (*deleted = rows removed), false on error.
     *          The pointer may be NULL if the backend has no expiration GC.
     * Writer thread only (plugin timers run there).
     */
    bool (*purge_expired)(time_t now, size_t *deleted);
    
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
     *   out_count - when do_count is true, receives the aggregated count.
     *               May be NULL when do_count is false.
     * 
     * Returns: NG_OK; NG_E_TOOBIG when the request exceeds the complexity
     * limits (ng_limits, SQ_MAX_*); NG_E_IO on a database error. Rows of
     * earlier filters may already have been streamed on failure.
     * 
     * Behavior:
     *   - Multiple filters are OR'd (send if ANY filter matches)
     *   - Within a filter, criteria are AND'd
     *   - If do_count is true, reports the count via out_count instead of
     *     emitting a COUNT response (NIP-45)
     */
    ng_status_t (*send_records)(send_records_callback_t sender, const char *sub,
                        const filter_t *filters, size_t filters_count,
                        bool do_count, int *out_count);

    /* NIP-45 HyperLogLog COUNT of one filter: *out_count events and the
     * 256 registers over their pubkeys with the given offset (8..23).
     * NG_OK / NG_E_TOOBIG / NG_E_IO like send_records. */
    ng_status_t (*count_hll)(const filter_t *filter, int offset,
                             int *out_count, uint8_t hll[256]);

    /* Multi-threaded backends: per-thread connection management and write
     * batching (BEGIN IMMEDIATE ... COMMIT). Only the single writer thread
     * calls the write functions / begin_batch / commit_batch. */
    bool (*thread_open)(bool readonly);
    void (*thread_close)(void);
    bool (*begin_batch)(void);
    bool (*commit_batch)(void);
    bool (*rollback_batch)(void);   /* after a failed commit */
    /* Checkpointer thread: PASSIVE WAL checkpoint on this thread's own
     * connection (never blocks the writer). false on error. */
    bool (*checkpoint)(void);
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
/* Writer durability: true = PRAGMA synchronous=FULL (default), false =
 * NORMAL. Startup only: call before init() and before any thread runs. */
void storage_set_sync_full(bool full);

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
