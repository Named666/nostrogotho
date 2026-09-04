#include "storage.h"
#include "json_util.h"
#include "nips/nip40.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ============================================================================
 * SQLite3 Storage Backend
 * 
 * Implements Nostr event storage using SQLite3 with:
 * - WAL mode for concurrency and crash safety
 * - Optimized indexes for common queries (created_at, pubkey, kind, tags)
 * - PRAGMA configurations for performance
 * - Support for full-text search via LIKE clause
 * 
 * Thread safety: NOT thread-safe; mutex required at application level
 * ============================================================================ */

/* Global SQLite3 connection (single instance) */
static sqlite3 *db_conn = NULL;

/* Parameter types for bound SQL statements */
#define PARAM_TYPE_NUMBER 0
#define PARAM_TYPE_STRING 1

/* Parameter structure for flexible SQL binding */
typedef struct {
    int type;
    union {
        int number;
        char *string;
    } value;
} param_t;

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/* escape_like - Escape SQL LIKE special characters
 * 
 * Escapes characters that have meaning in SQL LIKE patterns:
 * - '%' matches any sequence
 * - '_' matches single character
 * - '\' is escape character
 * 
 * Caller adds ESCAPE '\' to SQL to use this output.
 * 
 * Args:
 *   str - input string (NULL-safe)
 *   len - length of input string
 * 
 * Returns: malloc'd escaped string, or NULL on malloc failure or if str is NULL
 * 
 * Example:
 *   Input: "hello%world"
 *   Output: "hello\%world" (with backslash escaping)
 */
char *escape_like(const char *str, size_t len) {
    if (!str) return NULL;
    
    /* Cap reasonable length to prevent allocation attacks */
    if (len > 1024 * 1024) return NULL;  /* 1MB max */
    
    /* Count how many characters need escaping */
    size_t count = 0;
    for (size_t i = 0; i < len; i++) {
        if (str[i] == '%' || str[i] == '_' || str[i] == '\\') {
            count++;
        }
    }
    
    char *escaped = (char *)malloc(len + count + 1);
    if (!escaped) return NULL;
    
    size_t out_idx = 0;
    for (size_t i = 0; i < len; i++) {
        if (str[i] == '%' || str[i] == '_' || str[i] == '\\') {
            escaped[out_idx++] = '\\';
        }
        escaped[out_idx++] = str[i];
    }
    escaped[out_idx] = '\0';
    
    return escaped;
}

/* is_expired - Check if event has expired
 * 
 * Searches an event's tags for ["expiration", "<timestamp>"] tag.
 * Returns true if found and current time is past expiration.
 * 
 * Args: tags - parsed tags array (NULL-safe)
 * Returns: true if expired, false otherwise
 * 
 * NIP-40: Expiration represents absolute Unix timestamp in seconds
 */
bool is_expired(const tags_array_t *tags) {
    if (!tags) return false;
    
    time_t now = time(NULL);
    
    for (size_t i = 0; i < tags->count; i++) {
        tag_t *tag = &tags->tags[i];
        
        if (tag->count >= 2 && strcmp(tag->elements[0], "expiration") == 0) {
            time_t expiration = (time_t)strtol(tag->elements[1], NULL, 10);
            if (expiration <= now) {
                return true;
            }
        }
    }
    
    return false;
}

/* ============================================================================
 * Core Storage Operations
 * ============================================================================ */

/* get_event_by_id - Retrieve a single event by ID from database
 * 
 * Performs a SELECT query to find an event by its ID.
 * Reconstructs the event_t structure from database columns.
 * 
 * Args: id - event ID to search (hex string, NULL-safe)
 * 
 * Returns: malloc'd event_t on success, NULL if:
 *   - id is NULL or db_conn is NULL
 *   - Event not found
 *   - Database error
 * 
 * Caller responsibility: Must call event_free() to release returned event
 * 
 * Database columns retrieved: id, pubkey, created_at, kind, tags, content, sig
 */
static event_t *get_event_by_id(const char *id) {
    if (!db_conn || !id) return NULL;
    
    const char *sql = "SELECT id, pubkey, created_at, kind, tags, content, sig FROM event WHERE id = ?";
    sqlite3_stmt *stmt = NULL;
    
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
        return NULL;
    }
    
    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT);
    
    event_t *ev = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        ev = event_alloc();
        if (ev) {
            strncpy(ev->id, (const char *)sqlite3_column_text(stmt, 0), MAX_ID_SIZE);
            ev->id[MAX_ID_SIZE] = '\0';
            strncpy(ev->pubkey, (const char *)sqlite3_column_text(stmt, 1), MAX_PUBKEY_SIZE);
            ev->pubkey[MAX_PUBKEY_SIZE] = '\0';
            ev->created_at = (time_t)sqlite3_column_int(stmt, 2);
            ev->kind = sqlite3_column_int(stmt, 3);
            
            const char *tags_json = (const char *)sqlite3_column_text(stmt, 4);
            if (tags_json) {
                ev->tags_json_len = strlen(tags_json);
                ev->tags_json = (char *)malloc(ev->tags_json_len + 1);
                if (ev->tags_json) {
                    strcpy(ev->tags_json, tags_json);
                } else {
                    sqlite3_finalize(stmt);
                    free(ev);
                    return NULL;
                }
            }
            
            const char *content = (const char *)sqlite3_column_text(stmt, 5);
            if (content) {
                ev->content_len = strlen(content);
                ev->content = (char *)malloc(ev->content_len + 1);
                if (!ev->content) {
                    free(ev->tags_json);
                    sqlite3_finalize(stmt);
                    free(ev);
                    return NULL;
                }
                strcpy(ev->content, content);
            }
            
            strncpy(ev->sig, (const char *)sqlite3_column_text(stmt, 6), MAX_SIG_SIZE);
            ev->sig[MAX_SIG_SIZE] = '\0';
        }
    }
    
    sqlite3_finalize(stmt);
    return ev;
}

/* insert_record - Store a new event in database
 * 
 * Inserts an event into the database. Event should be validated
 * with check_event() before insertion.
 * 
 * Args: ev - event to insert (must not be NULL)
 * 
 * Returns: true on success, false if:
 *   - ev is NULL or db_conn is NULL
 *   - Database error (e.g., unique constraint violation)
 *   - Prepared statement fails
 * 
 * Database columns: id, pubkey, created_at, kind, tags, content, sig
 * Indexes enforce: UNIQUE on id
 * 
 * Note: Does NOT duplicate-check before insert (relies on DB unique constraint)
 */
static bool insert_record(const event_t *ev) {
    if (!db_conn || !ev) return false;
    
    const char *sql = "INSERT INTO event (id, pubkey, created_at, kind, tags, content, sig) VALUES (?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, ev->id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ev->pubkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, (int)ev->created_at);
    sqlite3_bind_int(stmt, 4, ev->kind);
    sqlite3_bind_text(stmt, 5, ev->tags_json ? ev->tags_json : "[]", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, ev->content ? ev->content : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, ev->sig, -1, SQLITE_TRANSIENT);
    
    bool result = (sqlite3_step(stmt) == SQLITE_DONE);
    if (!result) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
    }
    
    sqlite3_finalize(stmt);
    return result;
}

/* Delete record by ID and pubkey */
static int delete_record_by_id_and_pubkey(const char *id, const char *pubkey) {
    if (!db_conn || !id || !pubkey) return -1;
    
    const char *sql = "DELETE FROM event WHERE id = ? AND pubkey = ?";
    sqlite3_stmt *stmt = NULL;
    
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, pubkey, -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
        sqlite3_finalize(stmt);
        return -1;
    }
    
    sqlite3_finalize(stmt);
    return sqlite3_changes(db_conn);
}

/* Delete record by kind and pubkey */
static int delete_record_by_kind_and_pubkey(int kind, const char *pubkey, time_t created_at) {
    if (!db_conn || !pubkey) return -1;
    
    const char *sql = "DELETE FROM event WHERE kind = ? AND pubkey = ? AND created_at < ?";
    sqlite3_stmt *stmt = NULL;
    
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
        return -1;
    }
    
    sqlite3_bind_int(stmt, 1, kind);
    sqlite3_bind_text(stmt, 2, pubkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, (int)created_at);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
        sqlite3_finalize(stmt);
        return -1;
    }
    
    sqlite3_finalize(stmt);
    return sqlite3_changes(db_conn);
}

/* Delete record by kind, pubkey, and delegation tag */
static int delete_record_by_kind_and_pubkey_and_dtag(int kind, const char *pubkey,
                                                     const tag_t *tag, time_t created_at) {
    if (!db_conn || !pubkey || !tag) return -1;
    
    /* First, find matching events */
    const char *sql = "SELECT id FROM event WHERE kind = ? AND pubkey = ? AND tags LIKE ? ESCAPE '\\' AND created_at < ?";
    sqlite3_stmt *stmt = NULL;
    
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
        return -1;
    }
    
    /* Build tag search pattern: the exact JSON element ["name","value"]
     * (comma only between elements — a trailing comma would never match). */
    char tag_pattern[1100] = {0};
    if (tag->count > 0) {
        size_t pos = 0;
        bool ok = true;
        tag_pattern[pos++] = '[';
        for (size_t i = 0; ok && i < tag->count && i < 2; i++) {
            int written;
            if (!tag->elements[i]) { ok = false; break; }
            if (i > 0) tag_pattern[pos++] = ',';
            written = snprintf(tag_pattern + pos, sizeof(tag_pattern) - pos,
                               "\"%s\"", tag->elements[i]);
            if (written < 0 || (size_t) written >= sizeof(tag_pattern) - pos) {
                ok = false;
                break;
            }
            pos += (size_t) written;
        }
        if (!ok || pos + 2 > sizeof(tag_pattern)) {
            sqlite3_finalize(stmt);
            return -1;
        }
        tag_pattern[pos++] = ']';
        tag_pattern[pos] = '\0';
    }
    
    char *escaped = escape_like(tag_pattern, strlen(tag_pattern));
    if (!escaped) {
        sqlite3_finalize(stmt);
        return -1;
    }
    
    char pattern[1024];
    snprintf(pattern, sizeof(pattern), "%%%s%%", escaped);
    free(escaped);
    
    sqlite3_bind_int(stmt, 1, kind);
    sqlite3_bind_text(stmt, 2, pubkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, pattern, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, (int)created_at);
    
    size_t ids_count = 0;
    char **ids = NULL;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(stmt, 0);
        char **new_ids = (char **)realloc(ids, (ids_count + 1) * sizeof(char *));
        if (!new_ids) {
            sqlite3_finalize(stmt);
            for (size_t i = 0; i < ids_count; i++) free(ids[i]);
            free(ids);
            return -1;
        }
        ids = new_ids;
        ids[ids_count++] = string_dup(id);
    }
    
    sqlite3_finalize(stmt);
    
    if (ids_count == 0) {
        return 0;
    }
    
    /* Delete the found events */
    char delete_sql[1024] = "DELETE FROM event WHERE id IN (";
    for (size_t i = 0; i < ids_count; i++) {
        strcat(delete_sql, "?");
        if (i < ids_count - 1) strcat(delete_sql, ",");
    }
    strcat(delete_sql, ")");
    
    stmt = NULL;
    if (sqlite3_prepare_v2(db_conn, delete_sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
        for (size_t i = 0; i < ids_count; i++) free(ids[i]);
        free(ids);
        return -1;
    }
    
    for (size_t i = 0; i < ids_count; i++) {
        sqlite3_bind_text(stmt, i + 1, ids[i], -1, SQLITE_TRANSIENT);
    }
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
        sqlite3_finalize(stmt);
        for (size_t i = 0; i < ids_count; i++) free(ids[i]);
        free(ids);
        return -1;
    }
    
    sqlite3_finalize(stmt);
    
    int changes = sqlite3_changes(db_conn);
    for (size_t i = 0; i < ids_count; i++) free(ids[i]);
    free(ids);
    
    return changes;
}

/* Delete record by ID, kind, and p-tag */
static int delete_record_by_id_and_kind_and_ptag(const char *id, int kind,
                                                 const tag_t *tag) {
    if (!db_conn || !id || !tag) return -1;
    
    /* Similar to above but for p-tag */
    const char *sql = "SELECT id FROM event WHERE id = ? AND kind = ? AND tags LIKE ? ESCAPE '\\'";
    sqlite3_stmt *stmt = NULL;
    
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
        return -1;
    }
    
    char tag_pattern[512] = "";
    if (tag->count >= 2 && tag->elements[1]) {
        strcat(tag_pattern, "[\"p\",\"");
        strcat(tag_pattern, tag->elements[1]);
        strcat(tag_pattern, "\"]");
    }
    
    char *escaped = escape_like(tag_pattern, strlen(tag_pattern));
    if (!escaped) {
        sqlite3_finalize(stmt);
        return -1;
    }
    
    char pattern[1024];
    snprintf(pattern, sizeof(pattern), "%%%s%%", escaped);
    free(escaped);
    
    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, kind);
    sqlite3_bind_text(stmt, 3, pattern, -1, SQLITE_TRANSIENT);
    
    size_t ids_count = 0;
    char **ids = NULL;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *found_id = (const char *)sqlite3_column_text(stmt, 0);
        char **new_ids = (char **)realloc(ids, (ids_count + 1) * sizeof(char *));
        if (!new_ids) {
            sqlite3_finalize(stmt);
            for (size_t i = 0; i < ids_count; i++) free(ids[i]);
            free(ids);
            return -1;
        }
        ids = new_ids;
        ids[ids_count++] = string_dup(found_id);
    }
    
    sqlite3_finalize(stmt);
    
    if (ids_count == 0) {
        return 0;
    }
    
    /* Delete the found events */
    char delete_sql[1024] = "DELETE FROM event WHERE id IN (";
    for (size_t i = 0; i < ids_count; i++) {
        strcat(delete_sql, "?");
        if (i < ids_count - 1) strcat(delete_sql, ",");
    }
    strcat(delete_sql, ")");
    
    stmt = NULL;
    if (sqlite3_prepare_v2(db_conn, delete_sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
        for (size_t i = 0; i < ids_count; i++) free(ids[i]);
        free(ids);
        return -1;
    }
    
    for (size_t i = 0; i < ids_count; i++) {
        sqlite3_bind_text(stmt, i + 1, ids[i], -1, SQLITE_TRANSIENT);
    }
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
        sqlite3_finalize(stmt);
        for (size_t i = 0; i < ids_count; i++) free(ids[i]);
        free(ids);
        return -1;
    }
    
    sqlite3_finalize(stmt);
    
    int changes = sqlite3_changes(db_conn);
    for (size_t i = 0; i < ids_count; i++) free(ids[i]);
    free(ids);
    
    return changes;
}

/* Delete all events by pubkey */
static int delete_all_events_by_pubkey(const char *pubkey, time_t created_at) {
    if (!db_conn || !pubkey) return -1;
    
    const char *sql = "DELETE FROM event WHERE pubkey = ? AND created_at <= ? AND kind != 62";
    sqlite3_stmt *stmt = NULL;
    
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, pubkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, (int)created_at);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
        sqlite3_finalize(stmt);
        return -1;
    }
    
    sqlite3_finalize(stmt);
    return sqlite3_changes(db_conn);
}

/* ============================================================================
 * Event Query and Streaming
 * ============================================================================ */

/* purge_expired_sqlite3 - Garbage-collect NIP-40 expired events (background)
 *
 * Deletes every stored row whose `tags` column carries an
 * ["expiration","<timestamp>"] tag with a timestamp <= now. Expired events
 * are never served (matches_filter() in server.c drops them) and never
 * accepted on publication (nip01_process_event), but without this sweep the
 * rows would accumulate indefinitely in the database.
 *
 * The bundled SQLite build has no JSON1 functions, so we can't use
 * json_extract(). Instead we narrow the candidate set cheaply in SQL with a
 * LIKE on the tags column and a created_at bound, then load each candidate
 * with get_event_by_id() and confirm expiry via nip40_event_is_expired().
 * Re-checking in C keeps the decision exact (a bare JSON substring could
 * otherwise match inside content or another tag's element, and a LIKE on
 * created_at alone is only a heuristic, not proof the row has expired).
 *
 * Args: now - reference timestamp (time(NULL)) used as the expiry threshold.
 *
 * Returns: number of rows deleted, or -1 if the database is unusable.
 */
static int purge_expired_sqlite3(time_t now) {
    if (!db_conn) return -1;

    sqlite3_stmt *select;
    const char *find_sql =
        "SELECT id FROM event WHERE tags LIKE '%\"expiration\"%' AND created_at <= ?";
    int deleted = 0;

    if (sqlite3_prepare_v2(db_conn, find_sql, -1, &select, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
        return -1;
    }
    sqlite3_bind_int(select, 1, (int) now);

    int rc;
    int iterations = 0;
    const int MAX_PURGE_ITERATIONS = 10000;
    while ((rc = sqlite3_step(select)) == SQLITE_ROW && iterations < MAX_PURGE_ITERATIONS) {
        const char *id = (const char *) sqlite3_column_text(select, 0);
        /* get_event_by_id() prepares its own statement, so the candidate
         * step is safe to interleave with it here. */
        event_t *ev = get_event_by_id(id);
        if (ev) {
            if (nip40_event_is_expired(ev)) {
                if (delete_record_by_id_and_pubkey(ev->id, ev->pubkey) > 0) deleted++;
            }
            event_free(ev);
        }
        iterations++;
    }
    if (iterations >= MAX_PURGE_ITERATIONS) {
        fprintf(stderr, "Purge hit iteration limit (%d), some events may remain expired\n", MAX_PURGE_ITERATIONS);
    }
    sqlite3_finalize(select);
    return deleted;
}

/* conditions_append - strcat with overflow guard for the fixed WHERE buffer */
static bool conditions_append(char *conditions, size_t size, const char *text) {
    if (strlen(conditions) + strlen(text) + 1 > size) return false;
    strcat(conditions, text);
    return true;
}

/* append_tag_like_condition - Add one exact tag-element match to a WHERE
 *
 * Emits "tags LIKE ? ESCAPE '\'" once per JSON spacing variant so that an
 * exact ["name","value"] element inside the stored tags JSON is matched
 * whether the publishing client sent compact or spaced JSON. The name and
 * value are LIKE-escaped; both bind parameters are string_dup'd, matching
 * the ownership convention of the delegation patterns above. Returns false
 * when the conditions buffer or the parameter table would overflow, in
 * which case the caller fails the whole query.
 */
static bool append_tag_like_condition(char *conditions, size_t conditions_size,
                                      param_t *params, size_t *param_count,
                                      const char *name, const char *value) {
    static const char *const formats[] = {
        "%%[\"%s\",\"%s\"]%%",   /* compact:  ...%["p","<hex>"]%...  */
        "%%[\"%s\", \"%s\"]%%",  /* spaced:   ...%["p", "<hex>"]%... */
    };
    char *name_escaped = escape_like(name, strlen(name));
    char *value_escaped = escape_like(value, strlen(value));
    bool ok = name_escaped != NULL && value_escaped != NULL;

    for (size_t i = 0; ok && i < sizeof(formats) / sizeof(formats[0]); i++) {
        size_t length = strlen(formats[i]) + strlen(name_escaped) +
                        strlen(value_escaped) + 2;
        char *pattern = (char *) malloc(length);
        if (!pattern) { ok = false; break; }
        snprintf(pattern, length, formats[i], name_escaped, value_escaped);
        if (i > 0 && !conditions_append(conditions, conditions_size, " OR ")) {
            free(pattern);
            ok = false;
            break;
        }
        if (*param_count >= 256 ||
            strlen(conditions) + 32 >= conditions_size) {
            free(pattern);
            ok = false;
            break;
        }
        if (!conditions_append(conditions, conditions_size,
                               "tags LIKE ? ESCAPE '\\'")) {
            free(pattern);
            ok = false;
            break;
        }
        params[*param_count].type = PARAM_TYPE_STRING;
        params[*param_count].value.string = string_dup(pattern);
        (*param_count)++;
        free(pattern);
    }

    free(name_escaped);
    free(value_escaped);
    return ok;
}

/* send_records - Query database and stream matching events (NIP-01, NIP-67)
 * 
 * Primary query interface. Searches for events matching filter criteria and
 * calls sender() callback for each result. Also supports COUNT queries.
 * 
 * Algorithm:
 *   1. For each filter (OR'd together):
 *      a. Build WHERE clause from filter criteria (AND'd)
 *      b. Bind parameters for ids, authors, kinds, since, until, search
 *      c. Execute query with ORDER BY created_at DESC
 *      d. Fetch results and send via callback
 *      e. Track if more events exist beyond limit (NIP-67)
 *   2. If do_count, aggregate counts and send COUNT response
 *   3. Skip expired events before sending
 * 
 * Args:
 *   sender - callback called for each event result
 *   sub - subscription ID (included in response)
 *   filters - array of filter structures
 *   filters_count - number of filters
 *   do_count - if true, count events instead of streaming
 *   has_more - if not NULL, set to true if more events exist
 * 
 * Returns: true on success, false on database error
 * 
 * Features:
 *   - Fetches limit+1 events to determine has_more (NIP-67)
 *   - Filters can contain:
 *     - ids: event IDs (full or prefix match)
 *     - authors: pubkeys (full or prefix match)
 *     - kinds: event kinds
 *     - since: minimum created_at
 *     - until: maximum created_at
 *     - search: full-text search in content (LIKE with escaping)
 *   - Skips expired events
 *   - Generates JSON responses: ["EVENT", sub, event] or ["COUNT", sub, {count}]
 * 
 * Thread safety: NOT thread-safe; requires external synchronization
 * 
 * LIMITATIONS:
 *   - conditions buffer: 2048 bytes (limits very large filters)
 *   - sql buffer: 4096 bytes (limits very large queries)
 *   - param array: 256 parameters (limits filter complexity)
 *   TODO: Replace fixed buffers with dynamic allocation for arbitrary filter sizes
 */
static bool send_records(send_records_callback_t sender, const char *sub,
                        const filter_t *filters, size_t filters_count,
                        bool do_count, bool *has_more, int *out_count) {
    if (!db_conn || !sender) return false;
    if (has_more) *has_more = false;
    if (do_count && out_count) *out_count = 0;
    
    /* Validate input sizes to prevent buffer overflows */
    if (filters_count > 256) {
        fprintf(stderr, "Error: too many filters (%zu > 256)\n", filters_count);
        return false;
    }
    
    int total_count = 0;
    
    for (size_t f = 0; f < filters_count; f++) {
        const filter_t *filter = &filters[f];
        
        /* Validate filter array sizes to prevent buffer overflows */
        if (filter->ids_count > 256 || filter->authors_count > 256 || 
            filter->kinds_count > 256 || filter->tags_count > 256) {
            fprintf(stderr, "Error: filter arrays too large\n");
            return false;
        }
        
        /* Build SQL query */
        char sql[4096] = "";
        if (do_count) {
            strcpy(sql, "SELECT COUNT(id) FROM event");
        } else {
            strcpy(sql, "SELECT id, pubkey, created_at, kind, tags, content, sig FROM event");
        }
        
        int limit = 500;
        if (filter->limit > 0 && filter->limit < limit) {
            limit = filter->limit;
        }
        
        param_t params[256];
        size_t param_count = 0;
        char conditions[2048] = "";
        
        /* Build WHERE clause */
        bool first = true;
        
        if (filter->ids_count > 0) {
            if (!first) strcat(conditions, " AND ");
            first = false;
            
            if (filter->ids_count == 1) {
                strcat(conditions, "id = ?");
                params[param_count].type = PARAM_TYPE_STRING;
                params[param_count].value.string = filter->ids[0];
                param_count++;
            } else {
                strcat(conditions, "id IN (");
                for (size_t i = 0; i < filter->ids_count; i++) {
                    strcat(conditions, "?");
                    if (i < filter->ids_count - 1) strcat(conditions, ",");
                    params[param_count].type = PARAM_TYPE_STRING;
                    params[param_count].value.string = filter->ids[i];
                    param_count++;
                }
                strcat(conditions, ")");
            }
        }
        
        if (filter->authors_count > 0) {
            if (!first) strcat(conditions, " AND ");
            first = false;

            /* NIP-26: relays should answer {authors: [A]} by matching both
             * the event pubkey and the delegation tag's [1] value (delegator).
             * SQL tags are stored as JSON text; delegation[1] is matched with
             * LIKE on a bounded pattern built from the author hex (safe: hex
             * only, fixed 64 chars). */
            strcat(conditions, "(pubkey IN (");
            for (size_t i = 0; i < filter->authors_count; i++) {
                strcat(conditions, "?");
                if (i < filter->authors_count - 1) strcat(conditions, ",");
                params[param_count].type = PARAM_TYPE_STRING;
                params[param_count].value.string = filter->authors[i];
                param_count++;
            }
            strcat(conditions, ") OR ");
            /* One LIKE per author: ["delegation","<pubkey> — the leading
             * quote on the value prevents matching a longer pubkey prefix.
             * Author values are validated 64-char lowercase hex, so the
             * pattern is injection-safe. Cap the expansion to keep the
             * conditions buffer bounded. */
            size_t delegation_authors = filter->authors_count;
            if (delegation_authors > 32) delegation_authors = 32;
            for (size_t i = 0; i < delegation_authors; i++) {
                char pattern[160];
                snprintf(pattern, sizeof(pattern),
                         "%%[\"delegation\",\"%s\",%%", filter->authors[i]);
                strcat(conditions, "tags LIKE ?");
                if (i < delegation_authors - 1) strcat(conditions, " OR ");
                params[param_count].type = PARAM_TYPE_STRING;
                params[param_count].value.string = string_dup(pattern);
                param_count++;
            }
            strcat(conditions, ")");
        }
        
        if (filter->kinds_count > 0) {
            if (!first) strcat(conditions, " AND ");
            first = false;
            
            if (filter->kinds_count == 1) {
                strcat(conditions, "kind = ?");
                params[param_count].type = PARAM_TYPE_NUMBER;
                params[param_count].value.number = filter->kinds[0];
                param_count++;
            } else {
                strcat(conditions, "kind IN (");
                for (size_t i = 0; i < filter->kinds_count; i++) {
                    strcat(conditions, "?");
                    if (i < filter->kinds_count - 1) strcat(conditions, ",");
                    params[param_count].type = PARAM_TYPE_NUMBER;
                    params[param_count].value.number = filter->kinds[i];
                    param_count++;
                }
                strcat(conditions, ")");
            }
        }
        
        if (filter->since > 0) {
            if (!first) strcat(conditions, " AND ");
            first = false;
            
            char since_str[32];
            snprintf(since_str, sizeof(since_str), "created_at >= %lld",
                     (long long) filter->since);
            strcat(conditions, since_str);
        }
        
        if (filter->until > 0) {
            if (!first) strcat(conditions, " AND ");
            first = false;
            
            char until_str[32];
            snprintf(until_str, sizeof(until_str), "created_at <= %lld",
                     (long long) filter->until);
            strcat(conditions, until_str);
        }
        
        if (filter->tags_count > 0) {
            bool tags_ok = true;
            if (!first) strcat(conditions, " AND ");
            first = false;
            
            if (!conditions_append(conditions, sizeof(conditions), "(")) tags_ok = false;
            for (size_t t = 0; tags_ok && t < filter->tags_count; t++) {
                const tag_t *tag = &filter->tags[t];
                if (t > 0 && !conditions_append(conditions, sizeof(conditions), " AND ")) { tags_ok = false; break; }
                if (!conditions_append(conditions, sizeof(conditions), "(")) { tags_ok = false; break; }
                for (size_t v = 1; v < tag->count; v++) {
                    if (v > 1 && !conditions_append(conditions, sizeof(conditions), " OR ")) { tags_ok = false; break; }
                    if (!append_tag_like_condition(conditions, sizeof(conditions),
                                                   params, &param_count,
                                                   tag->elements[0], tag->elements[v])) {
                        tags_ok = false;
                        break;
                    }
                }
                if (tags_ok && !conditions_append(conditions, sizeof(conditions), ")")) tags_ok = false;
            }
            if (tags_ok) {
                if (!conditions_append(conditions, sizeof(conditions), ")")) tags_ok = false;
            }
            if (!tags_ok) {
                fprintf(stderr, "Error: tag filter conditions too large\n");
                return false;
            }
        }
        
        if (filter->search && strlen(filter->search) > 0) {
            if (!first) strcat(conditions, " AND ");
            first = false;
            
            strcat(conditions, "content LIKE ? ESCAPE '\\'");
            params[param_count].type = PARAM_TYPE_STRING;
            char *escaped = escape_like(filter->search, strlen(filter->search));
            char pattern[512];
            snprintf(pattern, sizeof(pattern), "%%%s%%", escaped ? escaped : filter->search);
            params[param_count].value.string = string_dup(pattern);
            if (escaped) free(escaped);
            param_count++;
        }
        
        if (strlen(conditions) > 0) {
            strcat(sql, " WHERE ");
            strcat(sql, conditions);
        }
        
        if (!do_count) {
            strcat(sql, " ORDER BY created_at DESC LIMIT ?");
            params[param_count].type = PARAM_TYPE_NUMBER;
            params[param_count].value.number = limit + 1;  /* Fetch one extra */
            param_count++;
        }
        
        /* Execute query */
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
            return false;
        }
        
        /* Bind parameters */
        for (size_t i = 0; i < param_count; i++) {
            if (params[i].type == PARAM_TYPE_NUMBER) {
                sqlite3_bind_int(stmt, i + 1, params[i].value.number);
            } else {
                sqlite3_bind_text(stmt, i + 1, params[i].value.string, -1, SQLITE_TRANSIENT);
            }
        }
        
        if (do_count) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                total_count += sqlite3_column_int(stmt, 0);
            }
            sqlite3_finalize(stmt);
        } else {
            int fetched = 0;
            
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                fetched++;
                
                if (fetched > limit) {
                    if (has_more) *has_more = true;
                    break;
                }
                
                event_t event = {0};
                json_builder_t builder;
                snprintf(event.id, sizeof(event.id), "%s", (const char *) sqlite3_column_text(stmt, 0));
                snprintf(event.pubkey, sizeof(event.pubkey), "%s", (const char *) sqlite3_column_text(stmt, 1));
                event.created_at = (time_t) sqlite3_column_int64(stmt, 2);
                event.kind = sqlite3_column_int(stmt, 3);
                event.tags_json = (char *) sqlite3_column_text(stmt, 4);
                event.tags_json_len = event.tags_json ? strlen(event.tags_json) : 0;
                event.content = (char *) sqlite3_column_text(stmt, 5);
                snprintf(event.sig, sizeof(event.sig), "%s", (const char *) sqlite3_column_text(stmt, 6));
                json_builder_start(&builder);
                json_builder_append_string(&builder, "EVENT");
                json_builder_append_string(&builder, sub);
                json_serialize_event(&event, &builder);
                sender(json_builder_finish(&builder));
            }
            
            sqlite3_finalize(stmt);
        }
    }
    
    if (do_count) {
        /* NIP-45: report the aggregated count to the caller, which builds
         * the ["COUNT", sub, {"count": N}] response via nip45. */
        if (out_count) *out_count = total_count;
    }
    
    return true;
}

/* ============================================================================
 * Database Initialization and Management
 * ============================================================================ */

/* storage_init_sqlite3 - Initialize SQLite3 database connection
 * 
 * Opens a SQLite3 database (file or in-memory) and initializes schema.
 * Sets up tables and indexes for Nostr event storage.
 * 
 * Args: dsn - data source name / connection string
 *             Examples:
 *             - "file:nostrogotho.sqlite" -> file database
 *             - "file:nostrogotho.sqlite?mode=memory&cache=shared" -> memory
 *             - ":memory:" -> transient in-memory database
 * 
 * Returns: true on success, false if:
 *   - Database open fails
 *   - Schema creation fails
 *   - Connection already exists (closes first and reconnects)
 * 
 * Database Configuration:
 *   - SQLite3 URI mode for flexible connection strings
 *   - NOMUTEX flag (caller handles synchronization)
 *   - WAL mode for better concurrency and crash safety
 *   - 5 second busy timeout
 *   - NORMAL synchronous mode (balance speed/safety)
 *   - 256MB cache for performance
 * 
 * Indexes Created:
 *   - ididx: unique on event.id (primary key)
 *   - pubkeyprefix: on event.pubkey
 *   - timeidx: on event.created_at DESC
 *   - kindidx: on event.kind
 *   - kindtimeidx: composite on (kind, created_at DESC)
 * 
 * Thread safety: NOT thread-safe; must be called during init
 */
static bool storage_init_sqlite3(const char *dsn) {
    if (db_conn) {
        sqlite3_close_v2(db_conn);
    }
    
    int ret = sqlite3_open_v2(dsn, &db_conn,
                         SQLITE_OPEN_URI | SQLITE_OPEN_READWRITE |
                         SQLITE_OPEN_CREATE,
                         NULL);
    
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Unable to connect to database: %s\n", sqlite3_errmsg(db_conn));
        return false;
    }
    
    /* Create tables and indexes */
    const char *schema_sql = 
        "CREATE TABLE IF NOT EXISTS event ("
        "    id TEXT NOT NULL,"
        "    pubkey TEXT NOT NULL,"
        "    created_at INTEGER NOT NULL,"
        "    kind INTEGER NOT NULL,"
        "    tags TEXT NOT NULL,"
        "    content TEXT NOT NULL,"
        "    sig TEXT NOT NULL"
        ");"
        "CREATE UNIQUE INDEX IF NOT EXISTS ididx ON event(id);"
        "CREATE INDEX IF NOT EXISTS pubkeyprefix ON event(pubkey);"
        "CREATE INDEX IF NOT EXISTS timeidx ON event(created_at DESC);"
        "CREATE INDEX IF NOT EXISTS kindidx ON event(kind);"
        "CREATE INDEX IF NOT EXISTS kindtimeidx ON event(kind,created_at DESC);"
        "PRAGMA journal_mode = WAL;"
        "PRAGMA busy_timeout = 5000;"
        "PRAGMA synchronous = NORMAL;"
        "PRAGMA cache_size = -262144;"
        "PRAGMA foreign_keys = true;"
        "PRAGMA temp_store = memory;";
    
    char *errmsg = NULL;
    if (sqlite3_exec(db_conn, schema_sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close_v2(db_conn);
        db_conn = NULL;
        return false;
    }
    
    return true;
}

/* storage_deinit_sqlite3 - Close database connection
 * 
 * Cleanly shuts down the SQLite3 connection.
 * Safe to call even if init() failed.
 * 
 * Thread safety: NOT thread-safe; must be called during shutdown
 */
static void storage_deinit_sqlite3(void) {
    if (db_conn) {
        sqlite3_close_v2(db_conn);
        db_conn = NULL;
    }
}

/* ============================================================================
 * Backend Interface Initialization
 * ============================================================================ */

/* storage_context_init_sqlite3 - Set up SQLite3 backend function pointers
 * 
 * Fills in a storage_context_t structure with SQLite3 implementations.
 * After calling this, the context is ready to use:
 * 
 *   storage_context_t ctx = {0};
 *   storage_context_init_sqlite3(&ctx);
 *   ctx.init("file:nostrogotho.sqlite");  // opens database
 *   // ... use ctx.get_event_by_id(), ctx.insert_record(), etc.
 *   ctx.deinit();  // closes database
 * 
 * Args: ctx - storage context structure (must not be NULL)
 * 
 * Sets function pointers for:
 *   - init, deinit: database lifecycle
 *   - get_event_by_id: retrieve single event
 *   - insert_record: store new event
 *   - delete_*: remove events (various criteria)
 *   - send_records: query and stream events
 */
void storage_context_init_sqlite3(storage_context_t *ctx) {
    if (!ctx) return;
    
    ctx->init = storage_init_sqlite3;
    ctx->deinit = storage_deinit_sqlite3;
    ctx->get_event_by_id = get_event_by_id;
    ctx->insert_record = insert_record;
    ctx->delete_record_by_id_and_pubkey = delete_record_by_id_and_pubkey;
    ctx->delete_record_by_kind_and_pubkey = delete_record_by_kind_and_pubkey;
    ctx->delete_record_by_kind_and_pubkey_and_dtag = delete_record_by_kind_and_pubkey_and_dtag;
    ctx->delete_record_by_id_and_kind_and_ptag = delete_record_by_id_and_kind_and_ptag;
    ctx->delete_all_events_by_pubkey = delete_all_events_by_pubkey;
    ctx->send_records = send_records;
    ctx->purge_expired = purge_expired_sqlite3;
}
