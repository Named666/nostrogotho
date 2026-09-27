#include "storage.h"
#include "json_util.h"
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

/* Parameter types for bound SQL statements.
 * PARAM_TYPE_OWNED_STRING marks heap-allocated (string_dup'd) values that
 * must be released by params_release(); PARAM_TYPE_STRING values are
 * borrowed (e.g. they point into a filter_t) and are never freed here. */
#define PARAM_TYPE_NUMBER 0
#define PARAM_TYPE_STRING 1
#define PARAM_TYPE_OWNED_STRING 2

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

/* params_release - Free heap-owned bind parameters
 *
 * send_records() mixes borrowed strings (pointing into filter_t arrays) with
 * heap-owned patterns built for LIKE/search conditions. Only OWNED_STRING
 * entries are freed; calling this after each query keeps a REQ storm from
 * leaking memory per filter iteration.
 */
static void params_release(param_t *params, size_t param_count) {
    for (size_t i = 0; i < param_count; i++) {
        if (params[i].type == PARAM_TYPE_OWNED_STRING) {
            free(params[i].value.string);
            params[i].value.string = NULL;
        }
    }
}

/* Generic tag index maintenance. The backend stores opaque tag key/value
 * pairs; interpretation of those pairs belongs to NIP-level query code. */
static bool index_event_tag(const char *event_id, const char *tag_name,
                            const char *tag_value) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT OR IGNORE INTO event_tag_index (event_id, tag_name, tag_value) VALUES (?, ?, ?)";
    if (!db_conn || !event_id || !tag_name || !tag_value) return false;
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, event_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, tag_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, tag_value, -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

static bool find_ids_by_tag_sqlite3(const char *tag_name, const char *tag_value,
                                    char ***ids_out, size_t *count_out);
static void free_id_list_sqlite3(char **ids, size_t count);

static void index_legacy_delegations(void) {
    sqlite3_stmt *scan = NULL;
    if (!db_conn) return;
    sqlite3_exec(db_conn, "CREATE TABLE IF NOT EXISTS delegation ("
                 "event_id TEXT NOT NULL REFERENCES event(id) ON DELETE CASCADE,"
                 "delegator TEXT NOT NULL, PRIMARY KEY (event_id, delegator))",
                 NULL, NULL, NULL);
    if (sqlite3_prepare_v2(db_conn,
                           "SELECT event_id, delegator FROM delegation",
                           -1, &scan, NULL) != SQLITE_OK) return;
    while (sqlite3_step(scan) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(scan, 0);
        const char *value = (const char *)sqlite3_column_text(scan, 1);
        if (id && value) index_event_tag(id, "delegation", value);
    }
    sqlite3_finalize(scan);
}

static bool find_ids_by_tag_sqlite3(const char *tag_name, const char *tag_value,
                                    char ***ids_out, size_t *count_out) {
    sqlite3_stmt *stmt = NULL;
    char **ids = NULL;
    size_t count = 0;
    const char *sql = "SELECT event_id FROM event_tag_index WHERE tag_name = ? AND tag_value = ? ORDER BY event_id";
    if (!db_conn || !tag_name || !tag_value || !ids_out || !count_out) return false;
    *ids_out = NULL;
    *count_out = 0;
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, tag_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, tag_value, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(stmt, 0);
        char **grown;
        if (!id) continue;
        grown = (char **)realloc(ids, (count + 1) * sizeof(*ids));
        if (!grown) {
            sqlite3_finalize(stmt);
            for (size_t i = 0; i < count; i++) free(ids[i]);
            free(ids);
            return false;
        }
        ids = grown;
        ids[count] = string_dup(id);
        if (!ids[count]) {
            sqlite3_finalize(stmt);
            for (size_t i = 0; i < count; i++) free(ids[i]);
            free(ids);
            return false;
        }
        count++;
    }
    sqlite3_finalize(stmt);
    *ids_out = ids;
    *count_out = count;
    return true;
}

static void free_id_list_sqlite3(char **ids, size_t count) {
    for (size_t i = 0; i < count; i++) free(ids[i]);
    free(ids);
}

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
        const char *col_id = (const char *)sqlite3_column_text(stmt, 0);
        const char *col_pubkey = (const char *)sqlite3_column_text(stmt, 1);
        const char *col_sig = (const char *)sqlite3_column_text(stmt, 6);
        ev = event_alloc();
        if (ev) {
            /* Column text can be NULL on a corrupt/attacker-controlled DB.
             * Treat NULL as empty so we never dereference NULL. */
            snprintf(ev->id, sizeof(ev->id), "%s", col_id != NULL ? col_id : "");
            snprintf(ev->pubkey, sizeof(ev->pubkey), "%s", col_pubkey != NULL ? col_pubkey : "");
            ev->created_at = (time_t)sqlite3_column_int64(stmt, 2);
            ev->kind = sqlite3_column_int(stmt, 3);

            const char *tags_json = (const char *)sqlite3_column_text(stmt, 4);
            if (tags_json) {
                ev->tags_json_len = strlen(tags_json);
                ev->tags_json = (char *)malloc(ev->tags_json_len + 1);
                if (ev->tags_json) {
                    memcpy(ev->tags_json, tags_json, ev->tags_json_len + 1);
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
                    ev->tags_json = NULL;
                    sqlite3_finalize(stmt);
                    free(ev);
                    return NULL;
                }
                memcpy(ev->content, content, ev->content_len + 1);
            }

            snprintf(ev->sig, sizeof(ev->sig), "%s", col_sig != NULL ? col_sig : "");
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
 * Returns: storage_insert_result_t with result and error details
 * 
 * Database columns: id, pubkey, created_at, kind, tags, content, sig
 * Indexes enforce: UNIQUE on id
 * 
 * Note: Does NOT duplicate-check before insert (relies on DB unique constraint)
 */
static storage_insert_result_t insert_record(const event_t *ev,
                                             const storage_tag_match_t *indexed_tags,
                                             size_t indexed_tags_count) {
    storage_insert_result_t result = {0};
    result.result = STORAGE_ERROR;
    snprintf(result.error_message, sizeof(result.error_message), "not implemented");
    
    if (!db_conn || !ev) return result;
    
    const char *sql = "INSERT INTO event (id, pubkey, created_at, kind, tags, content, sig) VALUES (?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
        snprintf(result.error_message, sizeof(result.error_message), "SQL error: %s", sqlite3_errmsg(db_conn));
        return result;
    }
    
    sqlite3_bind_text(stmt, 1, ev->id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ev->pubkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)ev->created_at);
    sqlite3_bind_int(stmt, 4, ev->kind);
    sqlite3_bind_text(stmt, 5, ev->tags_json ? ev->tags_json : "[]", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, ev->content ? ev->content : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, ev->sig, -1, SQLITE_TRANSIENT);
    
    int step_result = sqlite3_step(stmt);
    if (step_result == SQLITE_DONE) {
        result.result = STORAGE_OK;
    } else if (step_result == SQLITE_CONSTRAINT) {
        result.result = STORAGE_DUPLICATE;
        snprintf(result.error_message, sizeof(result.error_message), "duplicate event id");
    } else {
        result.result = STORAGE_ERROR;
        snprintf(result.error_message, sizeof(result.error_message), "SQL error: %s", sqlite3_errmsg(db_conn));
    }
    
    sqlite3_finalize(stmt);

    /* Index generic tag key/value pairs only after the event row exists so
     * the foreign key is satisfied. */
    if (result.result == STORAGE_OK) {
        for (size_t i = 0; i < indexed_tags_count; i++) {
            if (!index_event_tag(ev->id, indexed_tags[i].tag_name,
                                 indexed_tags[i].tag_value)) {
                fprintf(stderr, "Warning: could not index tag for event %s\n", ev->id);
            }
        }
    }
    return result;
}

/* Delete record by ID and pubkey */
static void free_event_tag_indexes(const char *event_id);

static storage_delete_result_t delete_record_by_id_and_pubkey(const char *id, const char *pubkey) {
    storage_delete_result_t result = {0};
    if (!db_conn || !id) {
        result.result = STORAGE_INVALID_ARGUMENT;
        snprintf(result.error_message, sizeof(result.error_message), "invalid arguments");
        return result;
    }
    
    const char *sql = pubkey
        ? "DELETE FROM event WHERE id = ? AND pubkey = ?"
        : "DELETE FROM event WHERE id = ?";
    sqlite3_stmt *stmt = NULL;
    
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        result.result = STORAGE_ERROR;
        snprintf(result.error_message, sizeof(result.error_message), "SQL error: %s", sqlite3_errmsg(db_conn));
        return result;
    }
    
    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT);
    if (pubkey) sqlite3_bind_text(stmt, 2, pubkey, -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        result.result = STORAGE_ERROR;
        snprintf(result.error_message, sizeof(result.error_message), "SQL error: %s", sqlite3_errmsg(db_conn));
        sqlite3_finalize(stmt);
        return result;
    }
    
    sqlite3_finalize(stmt);
    int changes = sqlite3_changes(db_conn);
    if (changes > 0) free_event_tag_indexes(id);
    
    result.result = STORAGE_OK;
    result.deleted_count = changes;
    return result;
}

static void free_event_tag_indexes(const char *event_id) {
    sqlite3_stmt *stmt = NULL;
    if (!db_conn || !event_id) return;
    if (sqlite3_prepare_v2(db_conn,
                           "DELETE FROM event_tag_index WHERE event_id = ?",
                           -1, &stmt, NULL) != SQLITE_OK) return;
    sqlite3_bind_text(stmt, 1, event_id, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

/* Delete record by kind and pubkey */
static storage_delete_result_t delete_record_by_kind_and_pubkey(int kind, const char *pubkey, time_t created_at) {
    storage_delete_result_t result = {0};
    if (!db_conn || !pubkey) {
        result.result = STORAGE_INVALID_ARGUMENT;
        snprintf(result.error_message, sizeof(result.error_message), "invalid arguments");
        return result;
    }
    
    const char *sql = "SELECT id FROM event WHERE kind = ? AND pubkey = ? AND created_at < ?";
    sqlite3_stmt *stmt = NULL;
    
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        result.result = STORAGE_ERROR;
        snprintf(result.error_message, sizeof(result.error_message), "SQL error: %s", sqlite3_errmsg(db_conn));
        return result;
    }
    
    sqlite3_bind_int(stmt, 1, kind);
    sqlite3_bind_text(stmt, 2, pubkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)created_at);
    
    char **ids = NULL;
    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *event_id = (const char *)sqlite3_column_text(stmt, 0);
        char **grown;
        if (!event_id) continue;
        grown = (char **)realloc(ids, (count + 1) * sizeof(*ids));
        if (!grown) {
            for (size_t i = 0; i < count; i++) free(ids[i]);
            free(ids);
            sqlite3_finalize(stmt);
            result.result = STORAGE_ERROR;
            snprintf(result.error_message, sizeof(result.error_message), "out of memory");
            return result;
        }
        ids = grown;
        ids[count] = string_dup(event_id);
        if (!ids[count]) {
            for (size_t i = 0; i < count; i++) free(ids[i]);
            free(ids);
            sqlite3_finalize(stmt);
            result.result = STORAGE_ERROR;
            snprintf(result.error_message, sizeof(result.error_message), "out of memory");
            return result;
        }
        count++;
    }
    sqlite3_finalize(stmt);
    int deleted = 0;
    for (size_t i = 0; i < count; i++) {
        storage_delete_result_t del_result = delete_record_by_id_and_pubkey(ids[i], pubkey);
        if (del_result.result != STORAGE_OK) {
            result.result = del_result.result;
            snprintf(result.error_message, sizeof(result.error_message), "%s", del_result.error_message);
            for (size_t j = i; j < count; j++) free(ids[j]);
            free(ids);
            return result;
        }
        deleted += del_result.deleted_count;
        free(ids[i]);
    }
    free(ids);
    result.result = STORAGE_OK;
    result.deleted_count = deleted;
    return result;
}

static bool conditions_append(char *conditions, size_t size, const char *text);

static bool event_matches_scope(const event_t *event,
                                const storage_event_scope_t *scope) {
    if (!scope) return true;
    if (scope->id && strcmp(event->id, scope->id) != 0) return false;
    if (scope->after_id && strcmp(event->id, scope->after_id) <= 0) return false;
    if (scope->pubkey && strcmp(event->pubkey, scope->pubkey) != 0) return false;
    if (scope->has_kind && event->kind != scope->kind) return false;
    if (scope->has_created_at_before &&
        event->created_at >= scope->created_at_before) return false;
    if (scope->has_created_at_at_or_before &&
        event->created_at > scope->created_at_at_or_before) return false;
    if (scope->has_created_at_after &&
        event->created_at <= scope->created_at_after) return false;
    if (scope->has_excluded_kind && event->kind == scope->excluded_kind) return false;
    return true;
}

/* Generic bounded selector/deleter. Tag policy is supplied by the caller;
 * SQLite only narrows by ordinary event columns and deletes selected IDs. */
static bool delete_matching_sqlite3(const storage_event_scope_t *scope,
                                    storage_event_predicate_t predicate,
                                    void *userdata, size_t *deleted_out,
                                    char *next_id, size_t next_id_size,
                                    bool *more) {
    enum { STORAGE_SCAN_BATCH = 256 };
    char sql[512];
    char conditions[384] = "";
    char last_id[MAX_ID_SIZE + 1] = "";
    size_t page_limit = scope && scope->limit ? scope->limit : STORAGE_SCAN_BATCH;
    size_t deleted = 0;
    bool ok = true;

    if (!db_conn) return false;
    if (deleted_out) *deleted_out = 0;
    if (next_id && next_id_size) next_id[0] = '\0';
    if (more) *more = false;
    if (page_limit > STORAGE_SCAN_BATCH) page_limit = STORAGE_SCAN_BATCH;

    /* Build a bounded, parameterized keyset query. Since event IDs are
     * unique and immutable, each batch can be finalized before deletions. */
    if ((scope && scope->id && !conditions_append(conditions, sizeof(conditions), "id = ? AND ")) ||
        (scope && scope->after_id && !conditions_append(conditions, sizeof(conditions), "id > ? AND ")) ||
        (scope && scope->pubkey && !conditions_append(conditions, sizeof(conditions), "pubkey = ? AND ")) ||
        (scope && scope->has_kind && !conditions_append(conditions, sizeof(conditions), "kind = ? AND ")) ||
        (scope && scope->has_created_at_before && !conditions_append(conditions, sizeof(conditions), "created_at < ? AND ")) ||
        (scope && scope->has_created_at_at_or_before && !conditions_append(conditions, sizeof(conditions), "created_at <= ? AND ")) ||
        (scope && scope->has_created_at_after && !conditions_append(conditions, sizeof(conditions), "created_at > ? AND ")) ||
        (scope && scope->has_excluded_kind && !conditions_append(conditions, sizeof(conditions), "kind != ? AND "))) {
        return false;
    }
    if (conditions[0]) conditions[strlen(conditions) - 5] = '\0';
    snprintf(sql, sizeof(sql), "SELECT id,pubkey,created_at,kind,tags,content,sig FROM event WHERE %s ORDER BY id LIMIT %lu",
             conditions[0] ? conditions : "1", (unsigned long)page_limit);

    {
        sqlite3_stmt *stmt = NULL;
        char *ids[STORAGE_SCAN_BATCH] = {0};
        char *pubkeys[STORAGE_SCAN_BATCH] = {0};
        size_t ids_count = 0;
        size_t scanned = 0;
        int bind = 1, rc;

        if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
            return false;
        }
        if (scope && scope->id) sqlite3_bind_text(stmt, bind++, scope->id, -1, SQLITE_TRANSIENT);
        if (scope && scope->after_id) sqlite3_bind_text(stmt, bind++, scope->after_id, -1, SQLITE_TRANSIENT);
        if (scope && scope->pubkey) sqlite3_bind_text(stmt, bind++, scope->pubkey, -1, SQLITE_TRANSIENT);
        if (scope && scope->has_kind) sqlite3_bind_int(stmt, bind++, scope->kind);
        if (scope && scope->has_created_at_before) sqlite3_bind_int64(stmt, bind++, (sqlite3_int64)scope->created_at_before);
        if (scope && scope->has_created_at_at_or_before) sqlite3_bind_int64(stmt, bind++, (sqlite3_int64)scope->created_at_at_or_before);
        if (scope && scope->has_created_at_after) sqlite3_bind_int64(stmt, bind++, (sqlite3_int64)scope->created_at_after);
        if (scope && scope->has_excluded_kind) sqlite3_bind_int(stmt, bind++, scope->excluded_kind);
        while (scanned < page_limit && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            event_t event = {0};
            const unsigned char *id = sqlite3_column_text(stmt, 0);
            const unsigned char *pubkey = sqlite3_column_text(stmt, 1);
            const unsigned char *sig = sqlite3_column_text(stmt, 6);
            if (!id || !pubkey || !sig) { ok = false; break; }
            snprintf(event.id, sizeof(event.id), "%s", (const char *)id);
            snprintf(event.pubkey, sizeof(event.pubkey), "%s", (const char *)pubkey);
            event.created_at = (time_t)sqlite3_column_int64(stmt, 2);
            event.kind = sqlite3_column_int(stmt, 3);
            event.tags_json = (char *)sqlite3_column_text(stmt, 4);
            event.tags_json_len = event.tags_json ? strlen(event.tags_json) : 0;
            event.content = (char *)sqlite3_column_text(stmt, 5);
            event.content_len = event.content ? strlen(event.content) : 0;
            snprintf(event.sig, sizeof(event.sig), "%s", (const char *)sig);
            if (event_matches_scope(&event, scope) && (!predicate || predicate(&event, userdata))) {
                ids[ids_count] = string_dup(event.id);
                pubkeys[ids_count] = string_dup(event.pubkey);
                if (!ids[ids_count] || !pubkeys[ids_count]) { ok = false; break; }
                ids_count++;
            }
            snprintf(last_id, sizeof(last_id), "%s", event.id);
            scanned++;
        }
        if (ok && scanned == page_limit) {
            rc = sqlite3_step(stmt);
            if (rc == SQLITE_ROW) *more = true;
            else if (rc != SQLITE_DONE) ok = false;
        } else if (ok && rc != SQLITE_DONE) {
            ok = false;
        }
        sqlite3_finalize(stmt);
        if (ok) {
            for (size_t i = 0; i < ids_count; i++) {
                storage_delete_result_t result = delete_record_by_id_and_pubkey(ids[i], pubkeys[i]);
                if (result.result != STORAGE_OK) ok = false;
                else deleted += (size_t)result.deleted_count;
                free(ids[i]);
                free(pubkeys[i]);
            }
            for (size_t i = ids_count; i < STORAGE_SCAN_BATCH; i++) {
                free(ids[i]);
                free(pubkeys[i]);
            }
        } else {
            for (size_t i = 0; i < STORAGE_SCAN_BATCH; i++) {
                free(ids[i]);
                free(pubkeys[i]);
            }
        }
        if (next_id && next_id_size) snprintf(next_id, next_id_size, "%s", last_id);
    }
    if (deleted_out) *deleted_out = deleted;
    return ok;
}

/* ============================================================================
 * Event Query and Streaming
 * ============================================================================ */

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
 * value are LIKE-escaped; both bind parameters are heap-owned
 * (PARAM_TYPE_OWNED_STRING) and are released by params_release(). Returns
 * false when the conditions buffer or the parameter table would overflow,
 * in which case the caller fails the whole query.
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
        params[*param_count].type = PARAM_TYPE_OWNED_STRING;
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
                         bool do_count, bool *has_more, int *out_count,
                         const storage_tag_match_t *indexed_tags,
                         size_t indexed_tags_count,
                         void *userdata) {
    if (!db_conn || !sender) return false;
    if (has_more) *has_more = false;
    if (do_count && out_count) *out_count = 0;
    
    /* Validate input sizes to prevent buffer overflows */
    if (filters_count > 256) {
        fprintf(stderr, "Error: too many filters (%zu > 256)\n", filters_count);
        return false;
    }
    
    /* Complexity guard: bound the total query cost of a single REQ/COUNT.
     * Each filter compiles to one SQL statement whose cost scales with its
     * author/id/tag list length; thousands of authors across many filters
     * would otherwise let one client monopolize the storage thread. The
     * per-filter caps (256) still apply; this caps the aggregate. */
    size_t total_authors = 0;
    for (size_t f = 0; f < filters_count; f++) {
        total_authors += filters[f].authors_count;
    }
    if (total_authors > 1024) {
        fprintf(stderr, "Error: REQ too complex (%zu total authors across %zu filters)\n",
                total_authors, filters_count);
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

        /* Build WHERE clause. Every write to `conditions` and `params` below
         * is bounds-checked: the per-field caps (<=256 each) multiply across
         * fields and both buffers are shared, so each append must fail
         * safely instead of assuming the caps guarantee enough room. */
        bool first = true;

        if (filter->ids_count > 0) {
            bool ids_ok = true;
            if (!first) ids_ok = conditions_append(conditions, sizeof(conditions), " AND ");
            first = false;

            if (filter->ids_count == 1) {
                if (!conditions_append(conditions, sizeof(conditions), "id = ?")) ids_ok = false;
                if (param_count >= 256) ids_ok = false;
                if (ids_ok) {
                    params[param_count].type = PARAM_TYPE_STRING;
                    params[param_count].value.string = filter->ids[0];
                    param_count++;
                }
            } else {
                if (!conditions_append(conditions, sizeof(conditions), "id IN (")) ids_ok = false;
                for (size_t i = 0; ids_ok && i < filter->ids_count; i++) {
                    if (!conditions_append(conditions, sizeof(conditions),
                                           i < filter->ids_count - 1 ? "?," : "?")) {
                        ids_ok = false;
                        break;
                    }
                    if (param_count >= 256) { ids_ok = false; break; }
                    params[param_count].type = PARAM_TYPE_STRING;
                    params[param_count].value.string = filter->ids[i];
                    param_count++;
                }
                if (ids_ok &&
                    !conditions_append(conditions, sizeof(conditions), ")")) ids_ok = false;
            }
            if (!ids_ok) {
                fprintf(stderr, "Error: ids filter too large for query buffers\n");
                params_release(params, param_count);
                return false;
            }
        }

        if (filter->authors_count > 0) {
            bool authors_ok = true;
            if (!first) authors_ok = conditions_append(conditions, sizeof(conditions), " AND ");
            first = false;

            /* The caller supplies author values; the generic tag index
             * contributes additional event IDs when a NIP module has inserted
             * policy-specific tag criteria into this filter adapter. */
            if (!authors_ok ||
                !conditions_append(conditions, sizeof(conditions), "(pubkey IN (")) authors_ok = false;
            for (size_t i = 0; authors_ok && i < filter->authors_count; i++) {
                if (!conditions_append(conditions, sizeof(conditions),
                                       i < filter->authors_count - 1 ? "?," : "?")) {
                    authors_ok = false;
                    break;
                }
                if (param_count >= 256) { authors_ok = false; break; }
                params[param_count].type = PARAM_TYPE_STRING;
                params[param_count].value.string = filter->authors[i];
                param_count++;
            }
            bool delegated_group_open = false;
            for (size_t i = 0; authors_ok && i < indexed_tags_count; i++) {
                if (indexed_tags[i].filter_index != f) continue;
                if (!delegated_group_open) {
                    if (!conditions_append(conditions, sizeof(conditions), ") OR (")) {
                        authors_ok = false;
                        break;
                    }
                    delegated_group_open = true;
                } else if (!conditions_append(conditions, sizeof(conditions), " OR ")) {
                    authors_ok = false;
                    break;
                }
                if (!conditions_append(conditions, sizeof(conditions),
                                       "id IN (SELECT event_id FROM event_tag_index WHERE tag_name = ? AND tag_value = ?)")) {
                    authors_ok = false;
                    break;
                }
                if (param_count + 2 > 256) { authors_ok = false; break; }
                params[param_count].type = PARAM_TYPE_STRING;
                params[param_count++].value.string = (char *)indexed_tags[i].tag_name;
                params[param_count].type = PARAM_TYPE_STRING;
                params[param_count++].value.string = (char *)indexed_tags[i].tag_value;
            }
            if (authors_ok && delegated_group_open &&
                !conditions_append(conditions, sizeof(conditions), ")")) authors_ok = false;
            if (authors_ok && !conditions_append(conditions, sizeof(conditions), ")")) authors_ok = false;
            if (!authors_ok) {
                fprintf(stderr, "Error: authors filter too large for query buffers\n");
                params_release(params, param_count);
                return false;
            }
        }
        
        if (filter->kinds_count > 0) {
            bool kinds_ok = true;
            if (!first) kinds_ok = conditions_append(conditions, sizeof(conditions), " AND ");
            first = false;

            if (filter->kinds_count == 1) {
                if (!conditions_append(conditions, sizeof(conditions), "kind = ?")) kinds_ok = false;
                if (param_count >= 256) kinds_ok = false;
                if (kinds_ok) {
                    params[param_count].type = PARAM_TYPE_NUMBER;
                    params[param_count].value.number = filter->kinds[0];
                    param_count++;
                }
            } else {
                if (!conditions_append(conditions, sizeof(conditions), "kind IN (")) kinds_ok = false;
                for (size_t i = 0; kinds_ok && i < filter->kinds_count; i++) {
                    if (!conditions_append(conditions, sizeof(conditions),
                                           i < filter->kinds_count - 1 ? "?," : "?")) {
                        kinds_ok = false;
                        break;
                    }
                    if (param_count >= 256) { kinds_ok = false; break; }
                    params[param_count].type = PARAM_TYPE_NUMBER;
                    params[param_count].value.number = filter->kinds[i];
                    param_count++;
                }
                if (kinds_ok &&
                    !conditions_append(conditions, sizeof(conditions), ")")) kinds_ok = false;
            }
            if (!kinds_ok) {
                fprintf(stderr, "Error: kinds filter too large for query buffers\n");
                params_release(params, param_count);
                return false;
            }
        }
        
        if (filter->since > 0) {
            char since_str[32];
            snprintf(since_str, sizeof(since_str), "created_at >= %lld",
                     (long long) filter->since);
            if ((!first && !conditions_append(conditions, sizeof(conditions), " AND ")) ||
                !conditions_append(conditions, sizeof(conditions), since_str)) {
                fprintf(stderr, "Error: since filter too large for query buffers\n");
                params_release(params, param_count);
                return false;
            }
            first = false;
        }
        
        if (filter->until > 0) {
            char until_str[32];
            snprintf(until_str, sizeof(until_str), "created_at <= %lld",
                     (long long) filter->until);
            if ((!first && !conditions_append(conditions, sizeof(conditions), " AND ")) ||
                !conditions_append(conditions, sizeof(conditions), until_str)) {
                fprintf(stderr, "Error: until filter too large for query buffers\n");
                params_release(params, param_count);
                return false;
            }
            first = false;
        }
        
        if (filter->tags_count > 0) {
            bool tags_ok = true;
            if (!first && !conditions_append(conditions, sizeof(conditions), " AND ")) tags_ok = false;
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
                params_release(params, param_count);
                return false;
            }
        }
        
        if (filter->search && strlen(filter->search) > 0) {
            if (param_count >= 256) {
                fprintf(stderr, "Error: too many query parameters for search filter\n");
                params_release(params, param_count);
                return false;
            }
            if (!first && !conditions_append(conditions, sizeof(conditions), " AND ")) {
                fprintf(stderr, "Error: search filter too large for query buffers\n");
                params_release(params, param_count);
                return false;
            }
            if (!conditions_append(conditions, sizeof(conditions),
                                   "content LIKE ? ESCAPE '\\'")) {
                fprintf(stderr, "Error: search filter too large for query buffers\n");
                params_release(params, param_count);
                return false;
            }
            first = false;

            params[param_count].type = PARAM_TYPE_OWNED_STRING;
            char *escaped = escape_like(filter->search, strlen(filter->search));
            char pattern[512];
            snprintf(pattern, sizeof(pattern), "%%%s%%", escaped ? escaped : filter->search);
            params[param_count].value.string = string_dup(pattern);
            if (escaped) free(escaped);
            param_count++;
        }
        
        if (strlen(conditions) > 0) {
            if (snprintf(sql + strlen(sql), sizeof(sql) - strlen(sql),
                         " WHERE %s", conditions) >= (int) sizeof(sql)) {
                fprintf(stderr, "Error: query too large for SQL buffer\n");
                params_release(params, param_count);
                return false;
            }
        }
        
        if (!do_count) {
            if (param_count >= 256) {
                fprintf(stderr, "Error: too many query parameters\n");
                params_release(params, param_count);
                return false;
            }
            if (snprintf(sql + strlen(sql), sizeof(sql) - strlen(sql),
                         " ORDER BY created_at DESC LIMIT ?") >= (int) sizeof(sql)) {
                fprintf(stderr, "Error: query too large for SQL buffer\n");
                params_release(params, param_count);
                return false;
            }
            params[param_count].type = PARAM_TYPE_NUMBER;
            params[param_count].value.number = limit + 1;  /* Fetch one extra */
            param_count++;
        }
        
        /* Execute query */
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db_conn));
            params_release(params, param_count);
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
        /* Bind copies the text (SQLITE_TRANSIENT), so owned patterns can be
         * released immediately after binding. */
        params_release(params, param_count);
        
        if (do_count) {
            if (sqlite3_step(stmt) == SQLITE_ROW) total_count += sqlite3_column_int(stmt, 0);
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
                const char *col_id = (const char *)sqlite3_column_text(stmt, 0);
                const char *col_pubkey = (const char *)sqlite3_column_text(stmt, 1);
                const char *col_sig = (const char *)sqlite3_column_text(stmt, 6);
                /* Skip corrupt rows instead of dereferencing NULL text. */
                if (col_id == NULL || col_pubkey == NULL || col_sig == NULL) {
                    continue;
                }
                snprintf(event.id, sizeof(event.id), "%s", col_id);
                snprintf(event.pubkey, sizeof(event.pubkey), "%s", col_pubkey);
                event.created_at = (time_t) sqlite3_column_int64(stmt, 2);
                event.kind = sqlite3_column_int(stmt, 3);
                event.tags_json = (char *) sqlite3_column_text(stmt, 4);
                event.tags_json_len = event.tags_json ? strlen(event.tags_json) : 0;
                event.content = (char *) sqlite3_column_text(stmt, 5);
                event.content_len = event.content ? strlen(event.content) : 0;
                snprintf(event.sig, sizeof(event.sig), "%s", col_sig);
                json_builder_start(&builder);
                json_builder_append_string(&builder, "EVENT");
                json_builder_append_string(&builder, sub);
                json_serialize_event(&event, &builder);
                sender(json_builder_finish(&builder), userdata);
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
 * Generic tag index:
 *   - event_tag_index(event_id, tag_name, tag_value) stores opaque tag
 *     values with event/tag and tag/value indexes for NIP-defined queries.
 * Page size:
 *   - PRAGMA page_size = 1048576 (~1MB) set before any table exists; larger
 *     pages reduce B-tree depth and I/O for big events (content + tags JSON
 *     can be tens of KB each). Existing databases keep their page size,
 *     which SQLite fixes at first table creation.
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
    
    /* Page size must be set before the first table is created (it is baked
     * into the database file on creation). 1MB is the SQLite maximum and
     * suits large Nostr payloads; existing databases keep their page size. */
    const char *pragmas_sql =
        "PRAGMA page_size = 1048576;"
        "PRAGMA journal_mode = WAL;"
        "PRAGMA synchronous = NORMAL;"
        "PRAGMA busy_timeout = 5000;"
        "PRAGMA cache_size = -262144;"
        "PRAGMA foreign_keys = true;"
        "PRAGMA temp_store = memory;";

    char *errmsg = NULL;
    if (sqlite3_exec(db_conn, pragmas_sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close_v2(db_conn);
        db_conn = NULL;
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
        "CREATE TABLE IF NOT EXISTS event_tag_index ("
        "    event_id TEXT NOT NULL REFERENCES event(id) ON DELETE CASCADE,"
        "    tag_name TEXT NOT NULL,"
        "    tag_value TEXT NOT NULL,"
        "    PRIMARY KEY (event_id, tag_name, tag_value)"
        ");"
        "CREATE INDEX IF NOT EXISTS event_tag_index_lookup "
        "    ON event_tag_index(tag_name, tag_value, event_id);";
    
    errmsg = NULL;
    if (sqlite3_exec(db_conn, schema_sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close_v2(db_conn);
        db_conn = NULL;
        return false;
    }

    index_legacy_delegations();
    if (!db_conn) return false;
    
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
 *   ctx.init("file:nostrogotho.sqlite");  -- opens database --
 *   ctx.deinit();  -- closes database --
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
    ctx->delete_matching = delete_matching_sqlite3;
    ctx->find_ids_by_tag = find_ids_by_tag_sqlite3;
    ctx->free_id_list = free_id_list_sqlite3;
    ctx->send_records = send_records;
}
