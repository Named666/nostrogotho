/* storage_write - SQLite write path (see storage_internal.h). Runs on the
 * single writer thread, inside its batch transaction. */
#include "storage_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json_lite.h"
#include "storage_query.h"
#include "nips/nip40.h"
#include "nips/nip_event.h"

/* Bind one tag value: 64-char lowercase hex as a 32-byte blob (the form the
 * query side and the delete trigger use), anything else as text. */
static void bind_tag_value(sqlite3_stmt *st, int idx, const char *v, size_t len) {
    if (sq_is_hex64(v, len)) {
        unsigned char raw[32];
        for (size_t i = 0; i < 32; i++) {
            unsigned hi = (unsigned) (v[2 * i] <= '9' ? v[2 * i] - '0' : v[2 * i] - 'a' + 10);
            unsigned lo = (unsigned) (v[2 * i + 1] <= '9' ? v[2 * i + 1] - '0' : v[2 * i + 1] - 'a' + 10);
            raw[i] = (unsigned char) ((hi << 4) | lo);
        }
        sqlite3_bind_blob(st, idx, raw, 32, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_text(st, idx, v, (int) len, SQLITE_TRANSIENT);
    }
}

/* store_tags - NIP-01 tag index rows for a just-inserted event (seq): one
 * per tag whose name is an indexed letter (tag_index_letters) and whose
 * first value is a string, up to tag_index_max_per_event; past that the
 * event is listed in tag_overflow and queries check its tags JSON.
 * Exact duplicates collapse on the primary key. Values containing NUL are
 * skipped (they cannot round-trip through the C string API).
 *
 * Rows are collected first (writer-thread scratch, reused across events,
 * so no allocation per event once warm), then inserted TAG_CHUNK rows per
 * statement step, which halves the per-row VDBE cost of one INSERT per row.
 * false on a database error or OOM: the caller undoes the insert so a batch
 * never commits an event the index does not know. */
typedef struct { char name; size_t off, len; } tag_row_t;
static NG_THREAD_LOCAL tag_row_t *tr_rows;
static NG_THREAD_LOCAL size_t tr_cap;
static NG_THREAD_LOCAL char *tr_buf;
static NG_THREAD_LOCAL size_t tr_buf_cap;

static bool tag_rows_reserve(size_t rows, size_t bytes) {
    if (rows > tr_cap) {
        size_t cap = ng_grow_cap(tr_cap, rows, 64);
        tag_row_t *p = (tag_row_t *) ng_realloc_array(tr_rows, cap, sizeof(*p));
        if (!p) return false;
        tr_rows = p; tr_cap = cap;
    }
    if (bytes > tr_buf_cap) {
        size_t cap = ng_grow_cap(tr_buf_cap, bytes, 4096);
        char *p = (char *) realloc(tr_buf, cap);
        if (!p) return false;
        tr_buf = p; tr_buf_cap = cap;
    }
    return true;
}

/* Writer-thread cache: -1 unknown, 0 the vanished table is empty, 1 not.
 * Only the writer inserts into `vanished`, so once 1 it stays 1. A rolled
 * back vanish leaves it 1, which only costs an extra point lookup. */
static NG_THREAD_LOCAL int vanished_state = -1;

/* NIP-50 bulk feed. seq is INTEGER PRIMARY KEY (max + 1 on insert), and
 * every DELETE on event flushes first, so the rows inserted since the last
 * flush are exactly seq >= fts_pending: one INSERT ... SELECT feeds them.
 * 0 = nothing pending. */
static NG_THREAD_LOCAL sqlite3_int64 fts_pending;

void ngdb_fts_reset(void) { fts_pending = 0; }

bool ngdb_fts_flush(void) {
    if (!fts_pending) return true;
    sqlite3_int64 from = fts_pending;
    fts_pending = 0;
    if (!ngdb_search_enabled()) return true;
    sqlite3_stmt *st = ngdb_ps(PS_FTS_FEED);
    if (!st) return false;
    sqlite3_bind_int64(st, 1, from);
    int rc = sqlite3_step(st);
    sqlite3_reset(st);
    if (rc != SQLITE_DONE) { fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn)); return false; }
    return true;
}

void ngdb_write_scratch_free(void) {
    fts_pending = 0;
    vanished_state = -1;
    free(tr_rows); free(tr_buf);
    tr_rows = NULL; tr_buf = NULL; tr_cap = tr_buf_cap = 0;
}

static void bind_tag_row(sqlite3_stmt *st, int base, const tag_row_t *r, const event_t *ev,
                         sqlite3_int64 seq) {
    sqlite3_bind_text(st, base + 1, &r->name, 1, SQLITE_STATIC);
    bind_tag_value(st, base + 2, tr_buf + r->off, r->len);
    sqlite3_bind_int64(st, base + 3, (sqlite3_int64) ev->created_at);
    sqlite3_bind_int64(st, base + 4, seq);
    sqlite3_bind_int(st, base + 5, ev->kind);
}

static bool store_tags(const event_t *ev, sqlite3_int64 seq) {
    if (!ev->tags_json || !ev->tags_json[0]) return true;
    jstr_t key, tag, tags = jl_str(ev->tags_json);
    size_t offset = 0, n = 0, used = 0;
    const size_t cap = (size_t) ngdb_tag_cap();
    bool overflow = false;
    /* Unescaped values never exceed the JSON text. */
    size_t json_len = ev->tags_json_len ? ev->tags_json_len : strlen(ev->tags_json);
    if (!tag_rows_reserve(16, json_len + 1)) return false;
    while ((offset = jl_next(tags, offset, &key, &tag)) != 0) {
        jstr_t k2, nm, v;
        size_t to = jl_next(tag, 0, &k2, &nm);
        if (!to || nm.len != 3 || nm.buf[0] != '"') continue;    /* "x": one-letter name */
        char name[2] = { nm.buf[1], '\0' };
        if (!sq_tag_indexed(name)) continue;
        if (jl_next(tag, to, &k2, &v) == 0 || !v.buf || v.buf[0] != '"') continue;
        if (n >= cap) { overflow = true; break; }
        size_t vl;
        if (!jl_unescape(v, tr_buf + used, &vl) || memchr(tr_buf + used, '\0', vl)) continue;
        if (n == tr_cap && !tag_rows_reserve(n + 1, json_len + 1)) return false;
        tr_rows[n].name = name[0]; tr_rows[n].off = used; tr_rows[n].len = vl;
        n++; used += vl;
    }
    size_t i = 0;
    for (; i + TAG_CHUNK <= n; i += TAG_CHUNK) {
        sqlite3_stmt *st = ngdb_ps(PS_TAG_INSERT_CHUNK);
        if (!st) return false;
        for (int r = 0; r < TAG_CHUNK; r++) bind_tag_row(st, r * 5, &tr_rows[i + (size_t) r], ev, seq);
        int rc = sqlite3_step(st);
        sqlite3_reset(st);
        if (rc != SQLITE_DONE) { fprintf(stderr, "SQL error (tag index): %s\n", sqlite3_errmsg(ngdb_conn)); return false; }
    }
    if (overflow) {
        sqlite3_stmt *st = ngdb_ps(PS_TAG_OVERFLOW);
        if (!st) return false;
        sqlite3_bind_int64(st, 1, seq);
        sqlite3_bind_int64(st, 2, (sqlite3_int64) ev->created_at);
        sqlite3_bind_int(st, 3, ev->kind);
        int rc = sqlite3_step(st);
        sqlite3_reset(st);
        if (rc != SQLITE_DONE) { fprintf(stderr, "SQL error (tag overflow): %s\n", sqlite3_errmsg(ngdb_conn)); return false; }
    }
    for (; i < n; i++) {
        sqlite3_stmt *st = ngdb_ps(PS_TAG_INSERT);
        if (!st) return false;
        bind_tag_row(st, 0, &tr_rows[i], ev, seq);
        int rc = sqlite3_step(st);
        sqlite3_reset(st);
        if (rc != SQLITE_DONE) { fprintf(stderr, "SQL error (tag index): %s\n", sqlite3_errmsg(ngdb_conn)); return false; }
    }
    return true;
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
static int vanished_any(void) {
    if (vanished_state >= 0) return vanished_state;
    sqlite3_stmt *s;
    if (sqlite3_prepare_v2(ngdb_conn, "SELECT EXISTS(SELECT 1 FROM vanished)", -1, &s, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(s);
    if (rc == SQLITE_ROW) vanished_state = sqlite3_column_int(s, 0) ? 1 : 0;
    sqlite3_finalize(s);
    return vanished_state;
}

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

    /* NIP-62: a vanished author cannot re-publish what it asked to erase.
     * Skipped (one cached flag) while the table is empty. */
    if (ev->kind != 62) {
        int v = vanished_any();
        if (v < 0) return STORAGE_PUT_FAILED;
        if (v) {
            t = ngdb_ps(PS_VANISH_CHECK);
            if (!t) return STORAGE_PUT_FAILED;
            sqlite3_bind_text(t, 1, ev->pubkey, -1, SQLITE_STATIC);
            sqlite3_bind_int64(t, 2, (sqlite3_int64) ev->created_at);
            rc = sqlite3_step(t);
            sqlite3_reset(t);
            if (rc == SQLITE_ROW) return STORAGE_PUT_VANISHED;
            if (rc != SQLITE_DONE) return STORAGE_PUT_FAILED;
        }
    }

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
    /* The event row exists: index its tags. A
     * failed tag index fails the insert; the writer rolls the batch back. */
    sqlite3_int64 seq = sqlite3_last_insert_rowid(ngdb_conn);
    if (ngdb_search_enabled() && !fts_pending && ev->content && ev->content[0] && ng_search_kind(ev->kind))
        fts_pending = seq;
    if (!store_tags(ev, seq)) {
        /* Undo the row (the delete trigger drops any tag rows written). */
        (void) ngdb_fts_flush();
        sqlite3_stmt *del = ngdb_ps(PS_DEL_ID);
        if (del) {
            sqlite3_bind_text(del, 1, ev->id, -1, SQLITE_STATIC);
            if (sqlite3_step(del) != SQLITE_DONE) fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
            sqlite3_reset(del);
        }
        return STORAGE_PUT_FAILED;
    }
    /* Outside a batch transaction (tests, tools): feed it now. */
    if (fts_pending && sqlite3_get_autocommit(ngdb_conn) && !ngdb_fts_flush()) return STORAGE_PUT_FAILED;
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
    if (verdict == STORAGE_ADMIT_NEWEST && nv && !ngdb_fts_flush()) verdict = STORAGE_ADMIT_FAILED;
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
    if (!ngdb_fts_flush()) { sqlite3_finalize(stmt); return false; }   /* see fts_pending */
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

/* Delete record by kind, pubkey and "d" tag value */
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


/* ngdb_vanish - NIP-62: durable vanish record plus the deletes (see
 * storage.h). Runs inside the writer's batch transaction. */
#define VANISH_AUTHOR "pubkey = unhex(?1) AND created_at <= ?2 AND kind != 62"
#define VANISH_WRAPS "seq IN (SELECT ev FROM tag WHERE name = 'p' AND value = unhex(?1) AND kind = 1059)"

bool ngdb_vanish(const char *pubkey, time_t until, void (*forget)(const char *hex_id),
                 size_t *deleted) {
    sqlite3_stmt *stmt;
    size_t n = 0, m = 0;
    if (!ngdb_conn || !pubkey) return false;
    if (forget) {
        if (!prepare("SELECT lower(hex(id)) FROM event WHERE " VANISH_AUTHOR
                     " UNION ALL SELECT lower(hex(id)) FROM event WHERE " VANISH_WRAPS, &stmt))
            return false;
        sqlite3_bind_text(stmt, 1, pubkey, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64) until);
        int rc;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            const char *id = (const char *) sqlite3_column_text(stmt, 0);
            if (id) forget(id);
        }
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return false;
    }
    if (!prepare("INSERT INTO vanished (pubkey, until) VALUES (unhex(?), ?) "
                 "ON CONFLICT(pubkey) DO UPDATE SET until = max(until, excluded.until)", &stmt))
        return false;
    sqlite3_bind_text(stmt, 1, pubkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64) until);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
        return false;
    }
    vanished_state = 1;
    if (!prepare("DELETE FROM event WHERE " VANISH_AUTHOR, &stmt)) return false;
    sqlite3_bind_text(stmt, 1, pubkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64) until);
    if (!run_delete(stmt, &n)) return false;
    /* "Relays SHOULD delete all NIP-59 Gift Wraps that p-tagged the
     * .pubkey": every one stored now, whatever its (randomised) created_at. */
    if (!prepare("DELETE FROM event WHERE " VANISH_WRAPS, &stmt)) return false;
    sqlite3_bind_text(stmt, 1, pubkey, -1, SQLITE_TRANSIENT);
    if (!run_delete(stmt, &m)) return false;
    if (deleted) *deleted = n + m;
    return true;
}

bool ngdb_delete_by_id(const char *id, size_t *deleted) {
    if (!id || !ngdb_fts_flush()) return false;
    sqlite3_stmt *stmt = ngdb_ps(PS_DEL_ID);
    if (!stmt) return false;
    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    if (deleted) *deleted = rc == SQLITE_DONE ? (size_t) sqlite3_changes(ngdb_conn) : 0;
    sqlite3_reset(stmt);
    return rc == SQLITE_DONE;
}

/* The tag table stores 64-char lowercase hex values as 32-byte blobs. */
static void bind_tag_value_text(sqlite3_stmt *st, int i, const char *v) {
    size_t n = strlen(v);
    bool hex = n == 64;
    for (size_t k = 0; hex && k < n; k++) hex = (v[k] >= '0' && v[k] <= '9') || (v[k] >= 'a' && v[k] <= 'f');
    if (!hex) { sqlite3_bind_text(st, i, v, (int) n, SQLITE_TRANSIENT); return; }
    unsigned char b[32];
    for (size_t k = 0; k < 32; k++) {
        int hi = v[2 * k] <= '9' ? v[2 * k] - '0' : v[2 * k] - 'a' + 10;
        int lo = v[2 * k + 1] <= '9' ? v[2 * k + 1] - '0' : v[2 * k + 1] - 'a' + 10;
        b[k] = (unsigned char) (hi * 16 + lo);
    }
    sqlite3_bind_blob(st, i, b, 32, SQLITE_TRANSIENT);
}

bool ngdb_delete_by_tag(char name, const char *value, void (*forget)(const char *hex_id), size_t *deleted) {
    sqlite3_stmt *stmt;
    char n[2] = { name, '\0' };
    if (!ngdb_conn || !value) return false;
    if (forget) {
        if (!prepare("SELECT lower(hex(e.id)) FROM tag t JOIN event e ON e.seq = t.ev WHERE t.name = ? AND t.value = ?", &stmt))
            return false;
        sqlite3_bind_text(stmt, 1, n, 1, SQLITE_TRANSIENT);
        bind_tag_value_text(stmt, 2, value);
        int rc;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            const char *id = (const char *) sqlite3_column_text(stmt, 0);
            if (id) forget(id);
        }
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return false;
    }
    if (!prepare("DELETE FROM event WHERE seq IN (SELECT ev FROM tag WHERE name = ? AND value = ?)", &stmt))
        return false;
    sqlite3_bind_text(stmt, 1, n, 1, SQLITE_TRANSIENT);
    bind_tag_value_text(stmt, 2, value);
    return run_delete(stmt, deleted);
}

bool ngdb_scan_kinds(const int *kinds, size_t n, void (*cb)(const event_t *ev, void *arg), void *arg) {
    if (!ngdb_conn || !kinds || !n || n > 64 || !cb) return false;
    char sql[1024];
    size_t len = (size_t) snprintf(sql, sizeof sql, "SELECT lower(hex(id)), lower(hex(pubkey)), created_at, kind, tags, "
                                   "content, lower(hex(sig)) FROM event WHERE kind IN (");
    for (size_t i = 0; i < n && len < sizeof sql - 32; i++)
        len += (size_t) snprintf(sql + len, sizeof sql - len, i ? ",%d" : "%d", kinds[i]);
    snprintf(sql + len, sizeof sql - len, ") ORDER BY seq");
    sqlite3_stmt *stmt;
    if (!prepare(sql, &stmt)) return false;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        event_t ev; memset(&ev, 0, sizeof ev);
        snprintf(ev.id, sizeof ev.id, "%s", (const char *) sqlite3_column_text(stmt, 0));
        snprintf(ev.pubkey, sizeof ev.pubkey, "%s", (const char *) sqlite3_column_text(stmt, 1));
        ev.created_at = (time_t) sqlite3_column_int64(stmt, 2);
        ev.kind = sqlite3_column_int(stmt, 3);
        ev.tags_json = (char *) sqlite3_column_text(stmt, 4);
        ev.tags_json_len = ev.tags_json ? (size_t) sqlite3_column_bytes(stmt, 4) : 0;
        ev.content = (char *) sqlite3_column_text(stmt, 5);
        ev.content_len = ev.content ? (size_t) sqlite3_column_bytes(stmt, 5) : 0;
        snprintf(ev.sig, sizeof ev.sig, "%s", (const char *) sqlite3_column_text(stmt, 6));
        cb(&ev, arg);
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
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
