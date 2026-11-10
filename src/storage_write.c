/* storage_write - SQLite write path (see storage_internal.h). Runs on the
 * single writer thread, inside its batch transaction. */
#include "storage_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json_lite.h"
#include "nips/nip40.h"
#include "nips/nip_event.h"

/* store_delegations - Index an event's NIP-26 delegation tags
 *
 * Scans the event's tags JSON for ["delegation", "<delegator>", ...] tags
 * and records (event_id, delegator) pairs in the normalized `delegation`
 * table. This replaces LIKE '%...%' scans over the tags column with an
 * indexed lookup: {authors: [A]} filters resolve delegators via
 * delegation(delegator) in O(log n) instead of a full table scan, which
 * matters at scale (users following/being followed by thousands of keys).
 *
 * Called only after the event row was inserted successfully; failures are
 * logged but never fail the publication (a missing delegation row only
 * makes that one delegated event unqueryable by delegator).
 */
static void store_delegations(const event_t *ev) {
    if (!ngdb_conn || !ev || !ev->tags_json || !ev->tags_json[0]) return;

    static const char *insert_sql =
        "INSERT OR IGNORE INTO delegation (event_id, delegator) VALUES (unhex(?), unhex(?))";

    jstr_t key, t, tags_str = jl_str(ev->tags_json);
    size_t offset = 0;
    bool found_any = false;
    sqlite3_stmt *stmt = NULL;

    while ((offset = jl_next(tags_str, offset, &key, &t)) != 0) {
        char *name = nip_tag_element(t, 0);
        if (!name || strcmp(name, "delegation") != 0) { free(name); continue; }
        free(name);

        char *delegator = nip_tag_element(t, 1);
        if (!delegator) continue;

        if (!stmt) {
            if (sqlite3_prepare_v2(ngdb_conn, insert_sql, -1, &stmt, NULL) != SQLITE_OK) {
                fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
                free(delegator);
                return;
            }
        }
        sqlite3_bind_text(stmt, 1, ev->id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, delegator, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(ngdb_conn) > 0) {
            found_any = true;
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        free(delegator);
    }

    if (stmt) sqlite3_finalize(stmt);
    (void) found_any;
}

/* ngdb_insert_record - Store a new event in database
 * 
 * Inserts an event into the database. Event should be validated
 * with check_event() before insertion.
 * 
 * Args: ev - event to insert (must not be NULL)
 * 
 * Returns: true on success, false if:
 *   - ev is NULL or ngdb_conn is NULL
 *   - Database error (e.g., unique constraint violation)
 *   - Prepared statement fails
 * 
 * Database columns: id, pubkey, created_at, kind, tags, content, sig
 * Indexes enforce: UNIQUE on id
 * 
 * Note: Does NOT duplicate-check before insert (relies on DB unique constraint)
 */
storage_put_t ngdb_insert_event(const event_t *ev) {
    if (!ngdb_conn || !ev) return STORAGE_PUT_FAILED;

    /* NIP-09: an author's deletion request permanently blocks the id. */
    sqlite3_stmt *t = ngdb_ps(PS_TOMB_CHECK);
    if (!t) return STORAGE_PUT_FAILED;
    sqlite3_bind_text(t, 1, ev->id, -1, SQLITE_STATIC);
    sqlite3_bind_text(t, 2, ev->pubkey, -1, SQLITE_STATIC);
    int rc = sqlite3_step(t);
    sqlite3_reset(t);
    if (rc == SQLITE_ROW) return STORAGE_PUT_TOMBSTONED;
    if (rc != SQLITE_DONE) return STORAGE_PUT_FAILED;

    sqlite3_stmt *stmt = ngdb_ps(PS_INSERT);
    if (!stmt) return STORAGE_PUT_FAILED;
    sqlite3_bind_text(stmt, 1, ev->id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, ev->pubkey, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64) ev->created_at);
    sqlite3_bind_int(stmt, 4, ev->kind);
    sqlite3_bind_text(stmt, 5, ev->tags_json ? ev->tags_json : "[]", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, ev->content ? ev->content : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, ev->sig, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(ngdb_conn);
    sqlite3_reset(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
        return STORAGE_PUT_FAILED;
    }
    if (changes == 0) return STORAGE_PUT_DUPLICATE;   /* ON CONFLICT(id) DO NOTHING */
    /* Index delegation tags only after the event row exists (FK). */
    store_delegations(ev);
    return STORAGE_PUT_INSERTED;
}

bool ngdb_insert_record(const event_t *ev) { return ngdb_insert_event(ev) == STORAGE_PUT_INSERTED; }

bool ngdb_add_tombstone(const char *id, const char *pubkey) {
    sqlite3_stmt *t = ngdb_ps(PS_TOMB_ADD);
    if (!t || !id || !pubkey) return false;
    sqlite3_bind_text(t, 1, id, -1, SQLITE_STATIC);
    sqlite3_bind_text(t, 2, pubkey, -1, SQLITE_STATIC);
    int rc = sqlite3_step(t);
    sqlite3_reset(t);
    return rc == SQLITE_DONE;
}

/* d-tag value of a tags JSON array ("" when absent), compared to want. */
static bool tags_d_equals(const char *tags_json, const char *want) {
    bool match = want[0] == '\0';
    if (!tags_json) return match;
    jstr_t key, t, tags_str = jl_str(tags_json);
    size_t offset = 0;
    while ((offset = jl_next(tags_str, offset, &key, &t)) != 0) {
        char *name = nip_tag_element(t, 0);
        bool is_d = name && strcmp(name, "d") == 0;
        free(name);
        if (!is_d) continue;
        char *v = nip_tag_element(t, 1);
        match = strcmp(v ? v : "", want) == 0;
        free(v);
        break;
    }
    return match;
}

storage_admit_t ngdb_replaceable_admit(const event_t *ev, const char *dtag) {
    sqlite3_stmt *sel = ngdb_ps(PS_REPL_SEL);
    if (!sel || !ev) return STORAGE_ADMIT_FAILED;
    sqlite3_bind_text(sel, 1, ev->pubkey, -1, SQLITE_STATIC);
    sqlite3_bind_int(sel, 2, ev->kind);
    char (*victims)[MAX_ID_SIZE + 1] = NULL;
    size_t nv = 0, cap = 0;
    int rc;
    storage_admit_t verdict = STORAGE_ADMIT_NEWEST;
    while ((rc = sqlite3_step(sel)) == SQLITE_ROW) {
        const char *id = (const char *) sqlite3_column_text(sel, 0);
        sqlite3_int64 at = sqlite3_column_int64(sel, 1);
        if (!id) continue;
        if (dtag && !tags_d_equals((const char *) sqlite3_column_text(sel, 2), dtag)) continue;
        int idcmp = strcmp(id, ev->id);
        if (idcmp == 0) { verdict = STORAGE_ADMIT_STALE; break; }                      /* exact duplicate */
        /* NIP-01: newest created_at wins; on a tie the lowest id wins. */
        if (at > (sqlite3_int64) ev->created_at ||
            (at == (sqlite3_int64) ev->created_at && idcmp < 0)) { verdict = STORAGE_ADMIT_STALE; break; }
        if (nv == cap) {
            size_t nc = cap ? cap * 2 : 4;
            void *p = ng_realloc_array(victims, nc, sizeof(*victims));
            if (!p) { verdict = STORAGE_ADMIT_FAILED; break; }
            victims = p; cap = nc;
        }
        snprintf(victims[nv++], MAX_ID_SIZE + 1, "%s", id);
    }
    if (verdict == STORAGE_ADMIT_NEWEST && rc != SQLITE_DONE) verdict = STORAGE_ADMIT_FAILED;
    sqlite3_reset(sel);
    if (verdict == STORAGE_ADMIT_NEWEST) {
        sqlite3_stmt *del = ngdb_ps(PS_DEL_ID);
        for (size_t i = 0; del && i < nv; i++) {
            sqlite3_bind_text(del, 1, victims[i], -1, SQLITE_STATIC);
            if (sqlite3_step(del) != SQLITE_DONE) verdict = STORAGE_ADMIT_FAILED;
            sqlite3_reset(del);
        }
        if (!del && nv) verdict = STORAGE_ADMIT_FAILED;
    }
    free(victims);
    return verdict;
}

/* Run a prepared DELETE to completion and finalize it. true on success,
 * *deleted (if not NULL) = rows changed. */
static bool run_delete(sqlite3_stmt *stmt, size_t *deleted) {
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    if (!ok) fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
    else if (deleted) *deleted = (size_t) sqlite3_changes(ngdb_conn);
    sqlite3_finalize(stmt);
    return ok;
}

static bool prepare(const char *sql, sqlite3_stmt **stmt) {
    *stmt = NULL;
    if (sqlite3_prepare_v2(ngdb_conn, sql, -1, stmt, NULL) == SQLITE_OK) return true;
    fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
    return false;
}

/* Delete record by ID and pubkey */
bool ngdb_delete_record_by_id_and_pubkey(const char *id, const char *pubkey, size_t *deleted) {
    sqlite3_stmt *stmt;
    if (!ngdb_conn || !id || !pubkey) return false;
    if (!prepare("DELETE FROM event WHERE id = unhex(?) AND pubkey = unhex(?)", &stmt)) return false;
    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, pubkey, -1, SQLITE_TRANSIENT);
    return run_delete(stmt, deleted);
}

/* Delete record by kind and pubkey */
bool ngdb_delete_record_by_kind_and_pubkey(int kind, const char *pubkey, time_t created_at,
                                             size_t *deleted) {
    sqlite3_stmt *stmt;
    if (!ngdb_conn || !pubkey) return false;
    if (!prepare("DELETE FROM event WHERE kind = ? AND pubkey = unhex(?) AND created_at < ?", &stmt)) return false;
    sqlite3_bind_int(stmt, 1, kind);
    sqlite3_bind_text(stmt, 2, pubkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64) created_at);
    return run_delete(stmt, deleted);
}

/* Growable list of owned hex id strings (NIP-09 delete candidates). */
static bool ids_push(char ***ids, size_t *n, const char *id) {
    char **nv = (char **) ng_realloc_array(*ids, *n + 1, sizeof(char *));
    if (!nv) return false;
    *ids = nv;
    if (!(nv[*n] = string_dup(id))) return false;
    (*n)++;
    return true;
}
static void ids_free(char **ids, size_t n) {
    for (size_t i = 0; i < n; i++) free(ids[i]);
    free(ids);
}

/* DELETE every id in ids with one statement; consumes ids. false on SQL
 * error, OOM, or more ids than SQLite accepts as bound parameters. */
static bool delete_ids(char **ids, size_t n, size_t *deleted) {
    if (!n) { free(ids); if (deleted) *deleted = 0; return true; }
    static const char head[] = "DELETE FROM event WHERE id IN (";
    static const char item[] = "unhex(?),";
    size_t len;
    if (!ng_size_flex(sizeof(head) + 1, n, sizeof(item) - 1, &len)) { ids_free(ids, n); return false; }
    char *sql = (char *) malloc(len), *w = sql;
    if (!sql) { ids_free(ids, n); return false; }
    memcpy(w, head, sizeof(head) - 1); w += sizeof(head) - 1;
    for (size_t i = 0; i < n; i++) { memcpy(w, item, sizeof(item) - 1); w += sizeof(item) - 1; }
    w[-1] = ')'; *w = '\0';                 /* replaces the last ',' */
    sqlite3_stmt *stmt;
    bool ok = prepare(sql, &stmt);
    if (ok) {
        for (size_t i = 0; i < n; i++) sqlite3_bind_text(stmt, (int) i + 1, ids[i], -1, SQLITE_TRANSIENT);
        ok = run_delete(stmt, deleted);
    }
    free(sql);
    ids_free(ids, n);
    return ok;
}

/* Delete record by kind, pubkey, and delegation tag */
bool ngdb_delete_record_by_kind_and_pubkey_and_dtag(int kind, const char *pubkey,
                                                      const tag_t *tag, time_t created_at,
                                                      size_t *deleted) {
    sqlite3_stmt *stmt;
    if (!ngdb_conn || !pubkey || !tag) return false;
    /* Candidates by kind, pubkey and created_at; the exact "d" value is then
     * checked by JSON iteration (an event without a "d" tag has d=""). */
    if (!prepare("SELECT lower(hex(id)), tags FROM event WHERE kind = ? AND pubkey = unhex(?) AND created_at < ?", &stmt))
        return false;
    sqlite3_bind_int(stmt, 1, kind);
    sqlite3_bind_text(stmt, 2, pubkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64) created_at);

    const char *target_d = (tag->count >= 2 && tag->elements[1]) ? tag->elements[1] : "";
    size_t ids_count = 0;
    char **ids = NULL;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *id = (const char *) sqlite3_column_text(stmt, 0);
        const char *tags_json = (const char *) sqlite3_column_text(stmt, 1);
        if (!id || !tags_json) continue;
        if (!tags_d_equals(tags_json, target_d)) continue;
        if (!ids_push(&ids, &ids_count, id)) { sqlite3_finalize(stmt); ids_free(ids, ids_count); return false; }
    }
    if (rc != SQLITE_DONE) fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) { ids_free(ids, ids_count); return false; }
    return delete_ids(ids, ids_count, deleted);
}

/* Delete record by ID, kind, and p-tag */
bool ngdb_delete_record_by_id_and_kind_and_ptag(const char *id, int kind,
                                                  const tag_t *tag, size_t *deleted) {
    sqlite3_stmt *stmt;
    if (!ngdb_conn || !id || !tag) return false;
    if (!prepare("SELECT lower(hex(id)), tags FROM event WHERE id = unhex(?) AND kind = ?", &stmt)) return false;
    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, kind);

    const char *target_p = (tag->count >= 2 && tag->elements[1]) ? tag->elements[1] : NULL;
    size_t ids_count = 0;
    char **ids = NULL;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *found_id = (const char *) sqlite3_column_text(stmt, 0);
        const char *tags_json = (const char *) sqlite3_column_text(stmt, 1);
        if (!found_id || !tags_json || !target_p) continue;
        event_t ev_temp = {0};                     /* exact "p" tag match via JSON iteration */
        ev_temp.tags_json = (char *) tags_json;
        if (!nip_event_has_tag(&ev_temp, "p", target_p)) continue;
        if (!ids_push(&ids, &ids_count, found_id)) { sqlite3_finalize(stmt); ids_free(ids, ids_count); return false; }
    }
    if (rc != SQLITE_DONE) fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) { ids_free(ids, ids_count); return false; }
    return delete_ids(ids, ids_count, deleted);
}

/* Delete all events by pubkey up to a timestamp, optionally excluding one
 * kind. Generic storage primitive — the caller (e.g. the NIP-62 plugin)
 * decides which kind, if any, must survive. */
bool ngdb_delete_all_events_by_pubkey(const char *pubkey, time_t created_at,
                                        int exclude_kind, size_t *deleted) {
    sqlite3_stmt *stmt;
    if (!ngdb_conn || !pubkey) return false;
    if (!prepare(exclude_kind
                 ? "DELETE FROM event WHERE pubkey = unhex(?) AND created_at <= ? AND kind != ?"
                 : "DELETE FROM event WHERE pubkey = unhex(?) AND created_at <= ?", &stmt)) return false;
    sqlite3_bind_text(stmt, 1, pubkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64) created_at);
    if (exclude_kind) sqlite3_bind_int(stmt, 3, exclude_kind);
    return run_delete(stmt, deleted);
}


/* ngdb_purge_expired - Garbage-collect NIP-40 expired events (background)
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
 * with ngdb_get_event_by_id() and confirm expiry via nip40_event_is_expired().
 * Re-checking in C keeps the decision exact (a bare JSON substring could
 * otherwise match inside content or another tag's element, and a LIKE on
 * created_at alone is only a heuristic, not proof the row has expired).
 *
 * Args: now - reference timestamp (time(NULL)) used as the expiry threshold.
 *
 * Returns: false on a database error (rows already purged stay purged and
 * are counted in *deleted).
 */
bool ngdb_purge_expired(time_t now, size_t *deleted) {
    sqlite3_stmt *select;
    if (!ngdb_conn) return false;
    if (!prepare("SELECT lower(hex(id)) FROM event WHERE tags LIKE '%\"expiration\"%' AND created_at <= ?", &select))
        return false;
    sqlite3_bind_int64(select, 1, (sqlite3_int64) now);

    size_t n = 0;
    bool ok = true;
    int rc, iterations = 0;
    const int MAX_PURGE_ITERATIONS = 10000;
    while (iterations < MAX_PURGE_ITERATIONS && (rc = sqlite3_step(select)) == SQLITE_ROW) {
        const char *id = (const char *) sqlite3_column_text(select, 0);
        /* ngdb_get_event_by_id() prepares its own statement, so the candidate
         * step is safe to interleave with it here. */
        event_t *ev = id ? ngdb_get_event_by_id(id) : NULL;
        if (ev) {
            size_t d = 0;
            if (nip40_event_is_expired(ev)) {
                if (ngdb_delete_record_by_id_and_pubkey(ev->id, ev->pubkey, &d)) n += d;
                else ok = false;
            }
            event_free(ev);
        }
        iterations++;
    }
    if (iterations >= MAX_PURGE_ITERATIONS)
        fprintf(stderr, "Purge hit iteration limit (%d), some events may remain expired\n", MAX_PURGE_ITERATIONS);
    else if (rc != SQLITE_DONE) { fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn)); ok = false; }
    sqlite3_finalize(select);
    if (deleted) *deleted = n;
    return ok;
}
