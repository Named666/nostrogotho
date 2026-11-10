/* storage_read - SQLite read path (see storage_internal.h). Runs on worker
 * threads, each with its own read-only WAL connection. */
#include "storage_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json_util.h"
#include "storage_query.h"

/* get_event_by_id - Retrieve a single event by ID from database
 * 
 * Performs a SELECT query to find an event by its ID.
 * Reconstructs the event_t structure from database columns.
 * 
 * Args: id - event ID to search (hex string, NULL-safe)
 * 
 * Returns: malloc'd event_t on success, NULL if:
 *   - id is NULL or ngdb_conn is NULL
 *   - Event not found
 *   - Database error
 * 
 * Caller responsibility: Must call event_free() to release returned event
 * 
 * Database columns retrieved: id, pubkey, created_at, kind, tags, content, sig
 */
event_t *ngdb_get_event_by_id(const char *id) {
    if (!ngdb_conn || !id) return NULL;
    
    const char *sql = "SELECT lower(hex(id)), lower(hex(pubkey)), created_at, kind, tags, content, lower(hex(sig)) FROM event WHERE id = unhex(?)";
    sqlite3_stmt *stmt = NULL;
    
    if (sqlite3_prepare_v2(ngdb_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
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
            ev->created_at = (time_t) sqlite3_column_int64(stmt, 2);
            ev->kind = sqlite3_column_int(stmt, 3);
            
            const char *tags_json = (const char *)sqlite3_column_text(stmt, 4);
            if (tags_json) {
                ev->tags_json_len = strlen(tags_json);
                ev->tags_json = (char *) ng_malloc_add(ev->tags_json_len, 1);
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
                ev->content = (char *) ng_malloc_add(ev->content_len, 1);
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

/* Per-REQ complexity policy (on top of the per-filter caps of the parser):
 * the total author count bounds the work one REQ/COUNT can put on a
 * worker's connection; each filter compiles to one statement. */
#define SR_MAX_FILTERS       256
#define SR_MAX_FILTER_ITEMS  256
#define SR_MAX_TOTAL_AUTHORS 1024
#define SR_MAX_LIMIT         500

/* Stream one compiled query's rows to sender as ["EVENT", sub, {...}]. */
static bool stream_rows(sqlite3_stmt *stmt, send_records_callback_t sender, const char *sub, int limit) {
    int rc, fetched = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (++fetched > limit) return true;
        event_t event = {0};
        snprintf(event.id, sizeof(event.id), "%s", (const char *) sqlite3_column_text(stmt, 0));
        snprintf(event.pubkey, sizeof(event.pubkey), "%s", (const char *) sqlite3_column_text(stmt, 1));
        event.created_at = (time_t) sqlite3_column_int64(stmt, 2);
        event.kind = sqlite3_column_int(stmt, 3);
        event.tags_json = (char *) sqlite3_column_text(stmt, 4);
        event.tags_json_len = event.tags_json ? strlen(event.tags_json) : 0;
        event.content = (char *) sqlite3_column_text(stmt, 5);
        snprintf(event.sig, sizeof(event.sig), "%s", (const char *) sqlite3_column_text(stmt, 6));
        json_builder_t *builder = json_builder_scratch(JSON_SCRATCH_QUERY);
        json_builder_append_string(builder, "EVENT");
        json_builder_append_string(builder, sub);
        json_serialize_event(&event, builder);
        sender(json_builder_finish(builder), &event);   /* NULL = could not render */
    }
    if (rc != SQLITE_DONE) { fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn)); return false; }
    return true;
}

/* send_records - Query and stream events matching filters (NIP-01, NIP-45)
 *
 * Filters are OR'd: each compiles (storage_query) to one statement with its
 * criteria AND'd, ORDER BY created_at DESC LIMIT min(limit, 500). Rows are
 * passed to sender as ["EVENT", sub, {...}]; with do_count the per-filter
 * COUNT(id) results are summed into *out_count instead.
 *
 * Returns false (after streaming any earlier filters' rows) when the REQ
 * exceeds the complexity policy, a filter cannot be compiled (size caps,
 * OOM) or SQLite fails; details go to stderr.
 */
bool ngdb_send_records(send_records_callback_t sender, const char *sub,
                       const filter_t *filters, size_t filters_count,
                       bool do_count, int *out_count) {
    if (!ngdb_conn || !sender) return false;
    if (do_count && out_count) *out_count = 0;
    if (filters_count > SR_MAX_FILTERS) {
        fprintf(stderr, "Error: too many filters (%zu > %d)\n", filters_count, SR_MAX_FILTERS);
        return false;
    }
    size_t total_authors = 0;
    for (size_t f = 0; f < filters_count; f++) total_authors += filters[f].authors_count;
    if (total_authors > SR_MAX_TOTAL_AUTHORS) {
        fprintf(stderr, "Error: REQ too complex (%zu total authors across %zu filters)\n",
                total_authors, filters_count);
        return false;
    }

    int total_count = 0;
    for (size_t f = 0; f < filters_count; f++) {
        const filter_t *filter = &filters[f];
        if (filter->ids_count > SR_MAX_FILTER_ITEMS || filter->authors_count > SR_MAX_FILTER_ITEMS ||
            filter->kinds_count > SR_MAX_FILTER_ITEMS || filter->tags_count > SR_MAX_FILTER_ITEMS) {
            fprintf(stderr, "Error: filter arrays too large\n");
            return false;
        }
        int limit = filter->limit > 0 && filter->limit < SR_MAX_LIMIT ? filter->limit : SR_MAX_LIMIT;

        sq_query_t q = {0};
        ng_status_t st = sq_build(&q, filter, do_count, limit);
        if (st != NG_OK) {
            fprintf(stderr, "Error: filter not compiled: %s\n", ng_status_str(st));
            sq_free(&q);
            return false;
        }
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(ngdb_conn, q.sql, (int) q.len, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
            sq_free(&q);
            return false;
        }
        for (size_t i = 0; i < q.n; i++) {             /* n <= SQ_MAX_PARAMS */
            int idx = (int) i + 1;
            if (q.params[i].type == SQ_INT) sqlite3_bind_int64(stmt, idx, q.params[i].num);
            else sqlite3_bind_text(stmt, idx, q.params[i].text, -1, SQLITE_TRANSIENT);
        }
        sq_free(&q);                                   /* bind copied the text */

        bool ok;
        if (do_count) {
            int rc = sqlite3_step(stmt);
            ok = rc == SQLITE_ROW;
            if (ok) total_count += sqlite3_column_int(stmt, 0);
            else fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
        } else {
            ok = stream_rows(stmt, sender, sub, limit);
        }
        sqlite3_finalize(stmt);
        if (!ok) return false;
    }
    if (do_count && out_count) *out_count = total_count;
    return true;
}
