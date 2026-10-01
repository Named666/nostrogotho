#include "storage.h"
#include "json_util.h"
#include "log.h"
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

/* Parameter types for bound SQL statements. All values are borrowed
 * (e.g. they point into a filter_t) and are never freed here. The legacy
 * heap-owned LIKE-pattern path (params_release/PARAM_TYPE_OWNED_STRING)
 * was deleted with the old filter path. */
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

/* append_condition - Helper to append a condition to the WHERE clause buffer
 * Returns false on buffer overflow */
static bool append_condition(char *conditions, size_t conditions_size,
                             const char *condition, bool *first) {
    if (*first) {
        if (strlen(conditions) + strlen(condition) + 1 >= conditions_size) return false;
        strcpy(conditions, condition);
        *first = false;
    } else {
        const char *and_cond = " AND ";
        if (strlen(conditions) + strlen(and_cond) + strlen(condition) + 1 >= conditions_size) return false;
        strcat(conditions, and_cond);
        strcat(conditions, condition);
    }
    return true;
}

/* build_where_clause - Build WHERE clause from storage_event_scope_t
 *
 * Translates scope fields into SQL WHERE conditions with bound parameters.
 * All string values are bound as parameters - never interpolated.
 *
 * Args:
 *   scope - selection scope (may be NULL)
 *   conditions - output buffer for WHERE clause (without "WHERE " prefix)
 *   conditions_size - size of conditions buffer
 *   params - parameter array for bound values
 *   param_count - in/out parameter count
 *   max_params - maximum parameters allowed
 *
 * Returns: true on success, false on buffer/parameter overflow or error
 */
static bool build_where_clause(const storage_event_scope_t *scope,
                               char *conditions, size_t conditions_size,
                               param_t *params, size_t *param_count,
                               size_t max_params) {
    if (!scope) return true;
    bool first = true;
    conditions[0] = '\0';

    /* id = ? */
    if (scope->id) {
        if (*param_count >= max_params) return false;
        if (!append_condition(conditions, conditions_size, "id = ?", &first)) return false;
        params[*param_count].type = PARAM_TYPE_STRING;
        params[*param_count].value.string = (char *)scope->id;
        (*param_count)++;
    }

    /* ids IN (?,?,...) */
    if (scope->ids && scope->ids_count > 0) {
        if (*param_count + scope->ids_count > max_params) return false;
        char *in_clause = (char *)malloc(64 + scope->ids_count * 4);
        if (!in_clause) return false;
        strcpy(in_clause, "id IN (");
        for (size_t i = 0; i < scope->ids_count; i++) {
            if (i > 0) strcat(in_clause, ",");
            strcat(in_clause, "?");
        }
        strcat(in_clause, ")");
        if (!append_condition(conditions, conditions_size, in_clause, &first)) {
            free(in_clause);
            return false;
        }
        free(in_clause);
        for (size_t i = 0; i < scope->ids_count; i++) {
            params[*param_count].type = PARAM_TYPE_STRING;
            params[*param_count].value.string = (char *)scope->ids[i];
            (*param_count)++;
        }
    }

    /* pubkey = ? */
    if (scope->pubkey) {
        if (*param_count >= max_params) return false;
        if (!append_condition(conditions, conditions_size, "pubkey = ?", &first)) return false;
        params[*param_count].type = PARAM_TYPE_STRING;
        params[*param_count].value.string = (char *)scope->pubkey;
        (*param_count)++;
    }

    /* pubkeys IN (?,?,...) */
    if (scope->pubkeys && scope->pubkeys_count > 0) {
        if (*param_count + scope->pubkeys_count > max_params) return false;
        char *in_clause = (char *)malloc(64 + scope->pubkeys_count * 4);
        if (!in_clause) return false;
        strcpy(in_clause, "pubkey IN (");
        for (size_t i = 0; i < scope->pubkeys_count; i++) {
            if (i > 0) strcat(in_clause, ",");
            strcat(in_clause, "?");
        }
        strcat(in_clause, ")");
        if (!append_condition(conditions, conditions_size, in_clause, &first)) {
            free(in_clause);
            return false;
        }
        free(in_clause);
        for (size_t i = 0; i < scope->pubkeys_count; i++) {
            params[*param_count].type = PARAM_TYPE_STRING;
            params[*param_count].value.string = (char *)scope->pubkeys[i];
            (*param_count)++;
        }
    }

    /* kind = ? */
    if (scope->has_kind) {
        if (*param_count >= max_params) return false;
        if (!append_condition(conditions, conditions_size, "kind = ?", &first)) return false;
        params[*param_count].type = PARAM_TYPE_NUMBER;
        params[*param_count].value.number = scope->kind;
        (*param_count)++;
    }

    /* kinds IN (?,?,...) */
    if (scope->kinds && scope->kinds_count > 0) {
        if (*param_count + scope->kinds_count > max_params) return false;
        char *in_clause = (char *)malloc(64 + scope->kinds_count * 4);
        if (!in_clause) return false;
        strcpy(in_clause, "kind IN (");
        for (size_t i = 0; i < scope->kinds_count; i++) {
            if (i > 0) strcat(in_clause, ",");
            strcat(in_clause, "?");
        }
        strcat(in_clause, ")");
        if (!append_condition(conditions, conditions_size, in_clause, &first)) {
            free(in_clause);
            return false;
        }
        free(in_clause);
        for (size_t i = 0; i < scope->kinds_count; i++) {
            params[*param_count].type = PARAM_TYPE_NUMBER;
            params[*param_count].value.number = scope->kinds[i];
            (*param_count)++;
        }
    }

    /* created_at < ? */
    if (scope->has_created_at_before) {
        if (*param_count >= max_params) return false;
        if (!append_condition(conditions, conditions_size, "created_at < ?", &first)) return false;
        params[*param_count].type = PARAM_TYPE_NUMBER;
        params[*param_count].value.number = (int)scope->created_at_before;
        (*param_count)++;
    }

    /* created_at <= ? */
    if (scope->has_created_at_at_or_before) {
        if (*param_count >= max_params) return false;
        if (!append_condition(conditions, conditions_size, "created_at <= ?", &first)) return false;
        params[*param_count].type = PARAM_TYPE_NUMBER;
        params[*param_count].value.number = (int)scope->created_at_at_or_before;
        (*param_count)++;
    }

    /* created_at > ? */
    if (scope->has_created_at_after) {
        if (*param_count >= max_params) return false;
        if (!append_condition(conditions, conditions_size, "created_at > ?", &first)) return false;
        params[*param_count].type = PARAM_TYPE_NUMBER;
        params[*param_count].value.number = (int)scope->created_at_after;
        (*param_count)++;
    }

    /* created_at >= ? */
    if (scope->has_created_at_at_or_after) {
        if (*param_count >= max_params) return false;
        if (!append_condition(conditions, conditions_size, "created_at >= ?", &first)) return false;
        params[*param_count].type = PARAM_TYPE_NUMBER;
        params[*param_count].value.number = (int)scope->created_at_at_or_after;
        (*param_count)++;
    }

    /* kind != ? */
    if (scope->has_excluded_kind) {
        if (*param_count >= max_params) return false;
        if (!append_condition(conditions, conditions_size, "kind != ?", &first)) return false;
        params[*param_count].type = PARAM_TYPE_NUMBER;
        params[*param_count].value.number = scope->excluded_kind;
        (*param_count)++;
    }

    /* kind NOT IN (?,?,...) */
    if (scope->excluded_kinds && scope->excluded_kinds_count > 0) {
        if (*param_count + scope->excluded_kinds_count > max_params) return false;
        char *in_clause = (char *)malloc(64 + scope->excluded_kinds_count * 4);
        if (!in_clause) return false;
        strcpy(in_clause, "kind NOT IN (");
        for (size_t i = 0; i < scope->excluded_kinds_count; i++) {
            if (i > 0) strcat(in_clause, ",");
            strcat(in_clause, "?");
        }
        strcat(in_clause, ")");
        if (!append_condition(conditions, conditions_size, in_clause, &first)) {
            free(in_clause);
            return false;
        }
        free(in_clause);
        for (size_t i = 0; i < scope->excluded_kinds_count; i++) {
            params[*param_count].type = PARAM_TYPE_NUMBER;
            params[*param_count].value.number = scope->excluded_kinds[i];
            (*param_count)++;
        }
    }

    /* Compound tag filter: AND across distinct tag names, OR within
     * values of the same name (NIP-01: within a filter, tag values for one
     * name are OR'd, different names are AND'd). The scope carries a flat
     * (name, value) list from filter_to_scope; group by name so each
     * distinct name emits a single EXISTS ... IN (...) clause. The old code
     * emitted one EXISTS per pair ANDed together, requiring multi-value
     * filters like {"#p": ["a","b"]} to match BOTH. */
    if (scope->tag_names && scope->tag_values && scope->tag_count > 0) {
        for (size_t i = 0; i < scope->tag_count; i++) {
            const char *name = scope->tag_names[i];
            if (!name) return false;
            /* Skip names already emitted (grouped globally, order-independent). */
            bool seen = false;
            for (size_t s = 0; s < i; s++) {
                if (scope->tag_names[s] && strcmp(scope->tag_names[s], name) == 0) {
                    seen = true;
                    break;
                }
            }
            if (seen) continue;
            /* Count values for this name. */
            size_t nvalues = 0;
            for (size_t k = i; k < scope->tag_count; k++) {
                if (scope->tag_names[k] && strcmp(scope->tag_names[k], name) == 0) nvalues++;
            }
            if (nvalues == 0) continue;
            if (*param_count + 1 + nvalues > max_params) return false;
            /* Build: EXISTS (SELECT 1 FROM event_tag_index
             *         WHERE event_id=event.id AND tag_name=? AND tag_value IN (?,?,...)) */
            char subquery[1024];
            int written = snprintf(subquery, sizeof(subquery),
                     "EXISTS (SELECT 1 FROM event_tag_index WHERE event_id=event.id AND tag_name=? AND tag_value IN (");
            if (written < 0 || (size_t)written >= sizeof(subquery)) return false;
            for (size_t k = 0; k < nvalues; k++) {
                if (k > 0) {
                    if (strlen(subquery) + 1 >= sizeof(subquery)) return false;
                    strcat(subquery, ",");
                }
                if (strlen(subquery) + 1 >= sizeof(subquery)) return false;
                strcat(subquery, "?");
            }
            if (strlen(subquery) + 2 >= sizeof(subquery)) return false;
            strcat(subquery, "))");
            if (!append_condition(conditions, conditions_size, subquery, &first)) return false;
            params[*param_count].type = PARAM_TYPE_STRING;
            params[*param_count].value.string = (char *)name;
            (*param_count)++;
            for (size_t k = i; k < scope->tag_count; k++) {
                if (scope->tag_names[k] && strcmp(scope->tag_names[k], name) == 0) {
                    params[*param_count].type = PARAM_TYPE_STRING;
                    params[*param_count].value.string = (char *)scope->tag_values[k];
                    (*param_count)++;
                }
            }
        }
    }

    return true;
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

/* Legacy single-tag lookup (find_ids_by_tag_sqlite3/free_id_list_sqlite3)
 * deleted: compound storage_find_ids_by_tags below is the single tag-index
 * path, and history queries go through build_where_clause. */

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

/* escape_like kept as a public utility (tests cover it); the legacy
 * tags-LIKE filter path that used it was deleted. */

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
        log_storage_error("GET_EVENT", "SQL error: %s", sqlite3_errmsg(db_conn));
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
        log_storage_error("INSERT", "SQL error: %s", sqlite3_errmsg(db_conn));
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
                log_storage_warn("INDEX_TAG", "could not index tag for event %s", ev->id);
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
        ids[count] = malloc(strlen(event_id) + 1);
        if (!ids[count]) {
            for (size_t i = 0; i < count; i++) free(ids[i]);
            free(ids);
            sqlite3_finalize(stmt);
            result.result = STORAGE_ERROR;
            snprintf(result.error_message, sizeof(result.error_message), "out of memory");
            return result;
        }
        strcpy(ids[count], event_id);
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

/* Legacy delete_matching/event_matches_scope/conditions_append/tags-LIKE
 * path deleted. Bounded deletes go through storage_delete_events (same
 * WHERE builder as find); tag predicates live in NIP code with
 * event_tag_has_value(), not in storage callbacks. */

/* ============================================================================
 * New Unified Storage API (per NOSTR_EVENT_STORAGE_SPEC.md)
 * ============================================================================ */

/* Helper: Materialize events from a prepared statement into caller-owned array */
static event_t **materialize_events(sqlite3_stmt *stmt, size_t *out_count) {
    if (!stmt || !out_count) return NULL;
    *out_count = 0;
    
    /* We'll just collect in a dynamic array */
    size_t capacity = 16;
    event_t **events = (event_t **)malloc(capacity * sizeof(event_t *));
    if (!events) return NULL;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*out_count >= capacity) {
            capacity *= 2;
            event_t **grown = (event_t **)realloc(events, capacity * sizeof(event_t *));
            if (!grown) {
                for (size_t i = 0; i < *out_count; i++) {
                    if (events[i]) event_free(events[i]);
                }
                free(events);
                return NULL;
            }
            events = grown;
        }
        
        const char *col_id = (const char *)sqlite3_column_text(stmt, 0);
        const char *col_pubkey = (const char *)sqlite3_column_text(stmt, 1);
        const char *col_sig = (const char *)sqlite3_column_text(stmt, 6);
        
        if (col_id == NULL || col_pubkey == NULL || col_sig == NULL) {
            continue;  /* Skip corrupt rows */
        }
        
        event_t *ev = event_alloc();
        if (!ev) {
            for (size_t i = 0; i < *out_count; i++) {
                if (events[i]) event_free(events[i]);
            }
            free(events);
            return NULL;
        }
        
        snprintf(ev->id, sizeof(ev->id), "%s", col_id);
        snprintf(ev->pubkey, sizeof(ev->pubkey), "%s", col_pubkey);
        ev->created_at = (time_t)sqlite3_column_int64(stmt, 2);
        ev->kind = sqlite3_column_int(stmt, 3);
        
        const char *tags_json = (const char *)sqlite3_column_text(stmt, 4);
        if (tags_json) {
            ev->tags_json_len = strlen(tags_json);
            ev->tags_json = (char *)malloc(ev->tags_json_len + 1);
            if (!ev->tags_json) {
                event_free(ev);
                for (size_t i = 0; i < *out_count; i++) {
                    if (events[i]) event_free(events[i]);
                }
                free(events);
                return NULL;
            }
            memcpy(ev->tags_json, tags_json, ev->tags_json_len + 1);
        }
        
        const char *content = (const char *)sqlite3_column_text(stmt, 5);
        if (content) {
            ev->content_len = strlen(content);
            ev->content = (char *)malloc(ev->content_len + 1);
            if (!ev->content) {
                event_free(ev);
                for (size_t i = 0; i < *out_count; i++) {
                    if (events[i]) event_free(events[i]);
                }
                free(events);
                return NULL;
            }
            memcpy(ev->content, content, ev->content_len + 1);
        }
        
        snprintf(ev->sig, sizeof(ev->sig), "%s", col_sig);
        events[*out_count] = ev;
        (*out_count)++;
    }
    
    return events;
}

/* storage_find_events - Find events matching scope */
bool storage_find_events(const storage_event_scope_t *scope,
                         event_t ***out_events, size_t *out_count) {
    if (!db_conn || !out_events || !out_count) return false;
    
    char conditions[2048];
    param_t params[256];
    size_t param_count = 0;
    
    if (!build_where_clause(scope, conditions, sizeof(conditions), params, &param_count, 256)) {
        return false;
    }
    
    char sql[4096];
    if (conditions[0]) {
        snprintf(sql, sizeof(sql),
                 "SELECT id, pubkey, created_at, kind, tags, content, sig FROM event WHERE %s ORDER BY created_at DESC, id DESC",
                 conditions);
    } else {
        snprintf(sql, sizeof(sql),
                 "SELECT id, pubkey, created_at, kind, tags, content, sig FROM event ORDER BY created_at DESC, id DESC");
    }
    
    /* Add LIMIT if specified */
    if (scope && scope->limit > 0) {
        char limit_clause[64];
        snprintf(limit_clause, sizeof(limit_clause), " LIMIT %zu", scope->limit);
        if (strlen(sql) + strlen(limit_clause) + 1 < sizeof(sql)) {
            strcat(sql, limit_clause);
        }
    }
    
    /* Add OFFSET if specified */
    if (scope && scope->offset > 0) {
        char offset_clause[64];
        snprintf(offset_clause, sizeof(offset_clause), " OFFSET %zu", scope->offset);
        if (strlen(sql) + strlen(offset_clause) + 1 < sizeof(sql)) {
            strcat(sql, offset_clause);
        }
    }
    
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        log_storage_error("STORAGE", "SQL error: %s", sqlite3_errmsg(db_conn));
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
    
    event_t **events = materialize_events(stmt, out_count);
    sqlite3_finalize(stmt);
    
    *out_events = events;
    return events != NULL;
}

/* storage_count_events - Count events matching scope */
bool storage_count_events(const storage_event_scope_t *scope,
                          size_t *out_count) {
    if (!db_conn || !out_count) return false;
    
    char conditions[2048];
    param_t params[256];
    size_t param_count = 0;
    
    if (!build_where_clause(scope, conditions, sizeof(conditions), params, &param_count, 256)) {
        return false;
    }
    
    char sql[4096];
    if (conditions[0]) {
        snprintf(sql, sizeof(sql),
                 "SELECT COUNT(id) FROM event WHERE %s", conditions);
    } else {
        snprintf(sql, sizeof(sql),
                 "SELECT COUNT(id) FROM event");
    }
    
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        log_storage_error("STORAGE", "SQL error: %s", sqlite3_errmsg(db_conn));
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
    
    bool ok = true;
    *out_count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *out_count = (size_t)sqlite3_column_int64(stmt, 0);
    } else {
        ok = false;
    }
    
    sqlite3_finalize(stmt);
    return ok;
}

/* storage_delete_events - Delete events matching scope */
bool storage_delete_events(const storage_event_scope_t *scope,
                           size_t *out_deleted) {
    if (!db_conn || !out_deleted) return false;
    
    char conditions[2048];
    param_t params[256];
    size_t param_count = 0;
    
    if (!build_where_clause(scope, conditions, sizeof(conditions), params, &param_count, 256)) {
        return false;
    }
    
    char sql[4096];
    if (conditions[0]) {
        snprintf(sql, sizeof(sql),
                 "DELETE FROM event WHERE %s", conditions);
    } else {
        /* Safety: require explicit scope for DELETE to prevent accidental full table delete */
        log_storage_error("DELETE_EVENTS", "DELETE without scope not allowed");
        return false;
    }
    
    /* Add LIMIT if specified (symmetry with find) */
    if (scope && scope->limit > 0) {
        char limit_clause[64];
        snprintf(limit_clause, sizeof(limit_clause), " LIMIT %zu", scope->limit);
        if (strlen(sql) + strlen(limit_clause) + 1 < sizeof(sql)) {
            strcat(sql, limit_clause);
        }
    }
    
    /* Add OFFSET if specified */
    if (scope && scope->offset > 0) {
        char offset_clause[64];
        snprintf(offset_clause, sizeof(offset_clause), " OFFSET %zu", scope->offset);
        if (strlen(sql) + strlen(offset_clause) + 1 < sizeof(sql)) {
            strcat(sql, offset_clause);
        }
    }
    
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        log_storage_error("STORAGE", "SQL error: %s", sqlite3_errmsg(db_conn));
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
    
    bool ok = false;
    int deleted = 0;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        ok = true;
        deleted = sqlite3_changes(db_conn);
    } else {
        log_storage_error("DELETE_EVENTS", "SQL error during DELETE: %s", sqlite3_errmsg(db_conn));
    }
    
    sqlite3_finalize(stmt);
    *out_deleted = (size_t)deleted;
    return ok;
}

/* ============================================================================
 * Transaction API
 * ============================================================================ */

struct storage_transaction_t {
    sqlite3 *db;
    bool active;
};

storage_transaction_t *storage_transaction_begin(void) {
    if (!db_conn) return NULL;
    
    storage_transaction_t *tx = (storage_transaction_t *)malloc(sizeof(storage_transaction_t));
    if (!tx) return NULL;
    
    tx->db = db_conn;
    tx->active = false;
    
    if (sqlite3_exec(db_conn, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK) {
        tx->active = true;
        return tx;
    }
    
    free(tx);
    return NULL;
}

bool storage_transaction_commit(storage_transaction_t *tx) {
    if (!tx || !tx->active || tx->db != db_conn) return false;
    
    bool ok = (sqlite3_exec(db_conn, "COMMIT", NULL, NULL, NULL) == SQLITE_OK);
    tx->active = false;
    free(tx);
    return ok;
}

void storage_transaction_rollback(storage_transaction_t *tx) {
    if (!tx || tx->db != db_conn) return;
    
    if (tx->active) {
        sqlite3_exec(db_conn, "ROLLBACK", NULL, NULL, NULL);
    }
    free(tx);
}

/* Helper: execute SQL with bound params in a transaction */
static bool execute_sql_tx(storage_transaction_t *tx, const char *sql,
                           param_t *params, size_t param_count, int *out_changes) {
    if (!tx || !tx->active || tx->db != db_conn) return false;
    
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        log_storage_error("STORAGE", "SQL error: %s", sqlite3_errmsg(db_conn));
        return false;
    }
    
    for (size_t i = 0; i < param_count; i++) {
        if (params[i].type == PARAM_TYPE_NUMBER) {
            sqlite3_bind_int(stmt, i + 1, params[i].value.number);
        } else {
            sqlite3_bind_text(stmt, i + 1, params[i].value.string, -1, SQLITE_TRANSIENT);
        }
    }
    
    bool ok = false;
    int changes = 0;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        ok = true;
        changes = sqlite3_changes(db_conn);
    } else {
        log_storage_error("STORAGE", "SQL error: %s", sqlite3_errmsg(db_conn));
    }
    
    sqlite3_finalize(stmt);
    if (out_changes) *out_changes = changes;
    return ok;
}

bool storage_find_events_tx(const storage_event_scope_t *scope,
                            storage_transaction_t *tx,
                            event_t ***out_events, size_t *out_count) {
    (void)tx; /* Transaction context; storage uses global db_conn with explicit BEGIN/COMMIT */
    if (!db_conn || !out_events || !out_count) return false;
    
    char conditions[2048];
    param_t params[256];
    size_t param_count = 0;
    
    if (!build_where_clause(scope, conditions, sizeof(conditions), params, &param_count, 256)) {
        return false;
    }
    
    char sql[4096];
    if (conditions[0]) {
        snprintf(sql, sizeof(sql),
                 "SELECT id, pubkey, created_at, kind, tags, content, sig FROM event WHERE %s ORDER BY created_at DESC, id DESC",
                 conditions);
    } else {
        snprintf(sql, sizeof(sql),
                 "SELECT id, pubkey, created_at, kind, tags, content, sig FROM event ORDER BY created_at DESC, id DESC");
    }
    
    if (scope && scope->limit > 0) {
        char limit_clause[64];
        snprintf(limit_clause, sizeof(limit_clause), " LIMIT %zu", scope->limit);
        if (strlen(sql) + strlen(limit_clause) + 1 < sizeof(sql)) {
            strcat(sql, limit_clause);
        }
    }
    
    if (scope && scope->offset > 0) {
        char offset_clause[64];
        snprintf(offset_clause, sizeof(offset_clause), " OFFSET %zu", scope->offset);
        if (strlen(sql) + strlen(offset_clause) + 1 < sizeof(sql)) {
            strcat(sql, offset_clause);
        }
    }
    
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        log_storage_error("STORAGE", "SQL error: %s", sqlite3_errmsg(db_conn));
        return false;
    }
    
    for (size_t i = 0; i < param_count; i++) {
        if (params[i].type == PARAM_TYPE_NUMBER) {
            sqlite3_bind_int(stmt, i + 1, params[i].value.number);
        } else {
            sqlite3_bind_text(stmt, i + 1, params[i].value.string, -1, SQLITE_TRANSIENT);
        }
    }
    
    event_t **events = materialize_events(stmt, out_count);
    sqlite3_finalize(stmt);
    
    *out_events = events;
    return events != NULL;
}

bool storage_delete_events_tx(const storage_event_scope_t *scope,
                              storage_transaction_t *tx,
                              size_t *out_deleted) {
    if (!db_conn || !tx || !tx->active || tx->db != db_conn || !out_deleted) return false;
    
    char conditions[2048];
    param_t params[256];
    size_t param_count = 0;
    
    if (!build_where_clause(scope, conditions, sizeof(conditions), params, &param_count, 256)) {
        return false;
    }
    
    char sql[4096];
    if (conditions[0]) {
        snprintf(sql, sizeof(sql),
                 "DELETE FROM event WHERE %s", conditions);
    } else {
        log_storage_error("DELETE_MATCHING", "DELETE without scope not allowed");
        return false;
    }
    
    if (scope && scope->limit > 0) {
        char limit_clause[64];
        snprintf(limit_clause, sizeof(limit_clause), " LIMIT %zu", scope->limit);
        if (strlen(sql) + strlen(limit_clause) + 1 < sizeof(sql)) {
            strcat(sql, limit_clause);
        }
    }
    
    if (scope && scope->offset > 0) {
        char offset_clause[64];
        snprintf(offset_clause, sizeof(offset_clause), " OFFSET %zu", scope->offset);
        if (strlen(sql) + strlen(offset_clause) + 1 < sizeof(sql)) {
            strcat(sql, offset_clause);
        }
    }
    
    int deleted = 0;
    bool ok = execute_sql_tx(tx, sql, params, param_count, &deleted);
    *out_deleted = (size_t)deleted;
    return ok;
}

/* ============================================================================
 * Atomic Upserts
 * ============================================================================ */

/* Helper: Delete older replaceable events (same pubkey, kind, created_at < new) */
static bool delete_older_replaceable(const char *pubkey, int kind, time_t created_at) {
    char sql[512];
    snprintf(sql, sizeof(sql),
             "DELETE FROM event WHERE pubkey = ? AND kind = ? AND created_at < ?");
    
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        log_storage_error("STORAGE", "SQL error: %s", sqlite3_errmsg(db_conn));
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, pubkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, kind);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)created_at);
    
    bool ok = false;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        ok = true;
    } else {
        log_storage_error("STORAGE", "SQL error: %s", sqlite3_errmsg(db_conn));
    }
    
    sqlite3_finalize(stmt);
    return ok;
}

/* Helper: Delete older addressable events (same pubkey, kind, d tag, created_at < new) */
static bool delete_older_addressable(const char *pubkey, int kind, const char *d_value, time_t created_at) {
    char sql[512];
    snprintf(sql, sizeof(sql),
             "DELETE FROM event WHERE pubkey = ? AND kind = ? AND "
             "id IN (SELECT event_id FROM event_tag_index WHERE tag_name = 'd' AND tag_value = ?) "
             "AND created_at < ?");
    
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        log_storage_error("STORAGE", "SQL error: %s", sqlite3_errmsg(db_conn));
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, pubkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, kind);
    sqlite3_bind_text(stmt, 3, d_value, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)created_at);
    
    bool ok = false;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        ok = true;
    } else {
        log_storage_error("STORAGE", "SQL error: %s", sqlite3_errmsg(db_conn));
    }
    
    sqlite3_finalize(stmt);
    return ok;
}

/* Helper: Check if exact duplicate event exists */
static bool event_exists(const char *id) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT 1 FROM event WHERE id = ?";
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT);
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return exists;
}

/* storage_upsert_replaceable - Atomic upsert for replaceable events */
storage_insert_result_t storage_upsert_replaceable(const event_t *ev,
                                                    const storage_tag_match_t *indexed_tags,
                                                    size_t indexed_tags_count) {
    storage_insert_result_t result = {0};
    result.result = STORAGE_ERROR;
    snprintf(result.error_message, sizeof(result.error_message), "not implemented");
    
    if (!db_conn || !ev) {
        result.result = STORAGE_INVALID_ARGUMENT;
        snprintf(result.error_message, sizeof(result.error_message), "invalid arguments");
        return result;
    }
    
    /* Check for exact duplicate */
    if (event_exists(ev->id)) {
        result.result = STORAGE_DUPLICATE;
        snprintf(result.error_message, sizeof(result.error_message), "duplicate event id");
        return result;
    }
    
    /* Begin transaction */
    if (sqlite3_exec(db_conn, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(result.error_message, sizeof(result.error_message), "transaction begin failed: %s", sqlite3_errmsg(db_conn));
        return result;
    }
    
    /* Delete older events with same pubkey + kind + created_at < ev->created_at */
    if (!delete_older_replaceable(ev->pubkey, ev->kind, ev->created_at)) {
        sqlite3_exec(db_conn, "ROLLBACK", NULL, NULL, NULL);
        snprintf(result.error_message, sizeof(result.error_message), "failed to delete older events");
        return result;
    }
    
    /* Insert the new event */
    const char *sql = "INSERT INTO event (id, pubkey, created_at, kind, tags, content, sig) VALUES (?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_exec(db_conn, "ROLLBACK", NULL, NULL, NULL);
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
    
    bool ok = false;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        ok = true;
    } else if (sqlite3_errcode(db_conn) == SQLITE_CONSTRAINT) {
        result.result = STORAGE_DUPLICATE;
        snprintf(result.error_message, sizeof(result.error_message), "duplicate event id");
    } else {
        snprintf(result.error_message, sizeof(result.error_message), "SQL error: %s", sqlite3_errmsg(db_conn));
    }
    
    sqlite3_finalize(stmt);
    
    if (!ok) {
        sqlite3_exec(db_conn, "ROLLBACK", NULL, NULL, NULL);
        return result;
    }
    
    /* Index tags */
    for (size_t i = 0; i < indexed_tags_count; i++) {
        if (!index_event_tag(ev->id, indexed_tags[i].tag_name, indexed_tags[i].tag_value)) {
            log_storage_warn("INDEX_TAG", "could not index tag for event %s", ev->id);
        }
    }
    
    if (sqlite3_exec(db_conn, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(result.error_message, sizeof(result.error_message), "transaction commit failed: %s", sqlite3_errmsg(db_conn));
        return result;
    }
    
    result.result = STORAGE_OK;
    return result;
}

/* storage_upsert_addressable - Atomic upsert for addressable events */
storage_insert_result_t storage_upsert_addressable(const event_t *ev,
                                                    const char *d_tag_value,
                                                    const storage_tag_match_t *indexed_tags,
                                                    size_t indexed_tags_count) {
    storage_insert_result_t result = {0};
    result.result = STORAGE_ERROR;
    snprintf(result.error_message, sizeof(result.error_message), "not implemented");
    
    if (!db_conn || !ev || !d_tag_value) {
        result.result = STORAGE_INVALID_ARGUMENT;
        snprintf(result.error_message, sizeof(result.error_message), "invalid arguments");
        return result;
    }
    
    /* Check for exact duplicate */
    if (event_exists(ev->id)) {
        result.result = STORAGE_DUPLICATE;
        snprintf(result.error_message, sizeof(result.error_message), "duplicate event id");
        return result;
    }
    
    /* Begin transaction */
    if (sqlite3_exec(db_conn, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(result.error_message, sizeof(result.error_message), "transaction begin failed: %s", sqlite3_errmsg(db_conn));
        return result;
    }
    
    /* Delete older events with same pubkey + kind + d tag + created_at < ev->created_at */
    if (!delete_older_addressable(ev->pubkey, ev->kind, d_tag_value, ev->created_at)) {
        sqlite3_exec(db_conn, "ROLLBACK", NULL, NULL, NULL);
        snprintf(result.error_message, sizeof(result.error_message), "failed to delete older events");
        return result;
    }
    
    /* Insert the new event */
    const char *sql = "INSERT INTO event (id, pubkey, created_at, kind, tags, content, sig) VALUES (?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_exec(db_conn, "ROLLBACK", NULL, NULL, NULL);
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
    
    bool ok = false;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        ok = true;
    } else if (sqlite3_errcode(db_conn) == SQLITE_CONSTRAINT) {
        result.result = STORAGE_DUPLICATE;
        snprintf(result.error_message, sizeof(result.error_message), "duplicate event id");
    } else {
        snprintf(result.error_message, sizeof(result.error_message), "SQL error: %s", sqlite3_errmsg(db_conn));
    }
    
    sqlite3_finalize(stmt);
    
    if (!ok) {
        sqlite3_exec(db_conn, "ROLLBACK", NULL, NULL, NULL);
        return result;
    }
    
    /* Index tags */
    for (size_t i = 0; i < indexed_tags_count; i++) {
        if (!index_event_tag(ev->id, indexed_tags[i].tag_name, indexed_tags[i].tag_value)) {
            log_storage_warn("INDEX_TAG", "could not index tag for event %s", ev->id);
        }
    }
    
    if (sqlite3_exec(db_conn, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(result.error_message, sizeof(result.error_message), "transaction commit failed: %s", sqlite3_errmsg(db_conn));
        return result;
    }
    
    result.result = STORAGE_OK;
    return result;
}

/* ============================================================================
 * Compound Tag Index Lookup
 * ============================================================================ */

bool storage_find_ids_by_tags(const char *const *tag_names,
                              const char *const *tag_values,
                              size_t tag_count,
                              char ***ids_out, size_t *count_out) {
    if (!db_conn || !tag_names || !tag_values || tag_count == 0 || !ids_out || !count_out) {
        return false;
    }

    /* Group by distinct tag name: AND across names, OR (IN) within values
     * of the same name. The old query ANDed every pair, so a multi-value
     * filter for one name could never match. */
    const char *distinct[64];
    size_t distinct_count = 0;
    for (size_t i = 0; i < tag_count && distinct_count < 64; i++) {
        if (!tag_names[i]) return false;
        bool seen = false;
        for (size_t s = 0; s < distinct_count; s++) {
            if (strcmp(distinct[s], tag_names[i]) == 0) { seen = true; break; }
        }
        if (!seen) distinct[distinct_count++] = tag_names[i];
    }
    if (distinct_count == 0) return false;

    char sql[4096];
    sql[0] = '\0';
    int bind_index = 1;
    /* Bind order must follow SQL construction: for each distinct name,
     * name first, then its values. Collect binds in order. */
    const char *bind_names[256];
    const char *bind_values[256];
    size_t nbind = 0;
    for (size_t d = 0; d < distinct_count; d++) {
        size_t nvalues = 0;
        for (size_t i = 0; i < tag_count; i++) {
            if (strcmp(tag_names[i], distinct[d]) == 0) nvalues++;
        }
        char clause[1024];
        if (d == 0) {
            snprintf(clause, sizeof(clause),
                     "SELECT event_id FROM event_tag_index WHERE tag_name = ? AND tag_value IN (");
        } else {
            snprintf(clause, sizeof(clause),
                     " AND event_id IN (SELECT event_id FROM event_tag_index WHERE tag_name = ? AND tag_value IN (");
        }
        for (size_t k = 0; k < nvalues; k++) {
            if (k > 0) strcat(clause, ",");
            strcat(clause, "?");
        }
        strcat(clause, ")");
        if (d > 0) strcat(clause, ")");
        if (strlen(sql) + strlen(clause) + 16 >= sizeof(sql)) return false;
        strcat(sql, clause);
        bind_names[nbind] = distinct[d];
        bind_values[nbind] = NULL;
        nbind++;
        for (size_t i = 0; i < tag_count; i++) {
            if (strcmp(tag_names[i], distinct[d]) == 0) {
                bind_names[nbind] = NULL;
                bind_values[nbind] = tag_values[i];
                nbind++;
            }
        }
    }
    if (strlen(sql) + 16 >= sizeof(sql)) return false;
    strcat(sql, " ORDER BY event_id");

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        log_storage_error("STORAGE", "SQL error: %s", sqlite3_errmsg(db_conn));
        return false;
    }

    for (size_t b = 0; b < nbind; b++) {
        const char *v = bind_names[b] ? bind_names[b] : bind_values[b];
        sqlite3_bind_text(stmt, (int)(bind_index++), v, -1, SQLITE_TRANSIENT);
    }
    
    char **ids = (char **)malloc(16 * sizeof(char *));
    size_t count = 0;
    size_t capacity = 16;
    if (!ids) {
        sqlite3_finalize(stmt);
        return false;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(stmt, 0);
        if (!id) continue;
        
        if (count >= capacity) {
            capacity *= 2;
            char **grown = (char **)realloc(ids, capacity * sizeof(char *));
            if (!grown) {
                for (size_t j = 0; j < count; j++) free(ids[j]);
                free(ids);
                sqlite3_finalize(stmt);
                return false;
            }
            ids = grown;
        }
        
        ids[count] = malloc(strlen(id) + 1);
        if (!ids[count]) {
            for (size_t j = 0; j < count; j++) free(ids[j]);
            free(ids);
            sqlite3_finalize(stmt);
            return false;
        }
        strcpy(ids[count], id);
        count++;
    }
    
    sqlite3_finalize(stmt);
    *ids_out = ids;
    *count_out = count;
    return true;
}

/* storage_free_id_list - Free ID list returned by storage_find_ids_by_tag or storage_find_ids_by_tags */
void storage_free_id_list(char **ids, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(ids[i]);
    }
    free(ids);
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
        log_storage_error("INIT", "Unable to connect to database: %s", sqlite3_errmsg(db_conn));
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
        log_storage_error("INIT", "SQL error: %s", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close_v2(db_conn);
        db_conn = NULL;
        return false;
    }

    /* Create tables and indexes */
    const char *schema_sql = 
        "CREATE TABLE IF NOT EXISTS event ("
        "    id TEXT PRIMARY KEY,"
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
        log_storage_error("INIT", "SQL error: %s", errmsg);
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
 *   - find_events, count_events, delete_events: unified query API
 *   - transaction_*: transaction management
 *   - upsert_replaceable, upsert_addressable: atomic upserts
 *   - find_ids_by_tags, free_id_list: compound tag index lookup
 */
void storage_context_init_sqlite3(storage_context_t *ctx) {
    if (!ctx) return;
    
    ctx->init = storage_init_sqlite3;
    ctx->deinit = storage_deinit_sqlite3;
    ctx->get_event_by_id = get_event_by_id;
    ctx->insert_record = insert_record;
    ctx->delete_record_by_id_and_pubkey = delete_record_by_id_and_pubkey;
    ctx->delete_record_by_kind_and_pubkey = delete_record_by_kind_and_pubkey;
    /* Legacy delete_matching/find_ids_by_tag removed: unified find/delete API only. */
    /* New unified storage API */
    ctx->find_events = storage_find_events;
    ctx->count_events = storage_count_events;
    ctx->delete_events = storage_delete_events;
    ctx->transaction_begin = storage_transaction_begin;
    ctx->transaction_commit = storage_transaction_commit;
    ctx->transaction_rollback = storage_transaction_rollback;
    ctx->delete_events_tx = storage_delete_events_tx;
    ctx->find_events_tx = storage_find_events_tx;
    ctx->upsert_replaceable = storage_upsert_replaceable;
    ctx->upsert_addressable = storage_upsert_addressable;
    ctx->find_ids_by_tags = storage_find_ids_by_tags;
    ctx->free_id_list = storage_free_id_list;
}
