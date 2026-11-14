/* storage_sqlite - SQLite backend lifecycle (see storage_internal.h). */
#include "storage_internal.h"
#include "storage_vfs.h"
#include "platform/ng_atomic.h"
#include "storage_query.h"
#include "memidx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* One SQLite connection per thread. The main/writer thread owns the
 * read-write connection opened by init(); reader threads call
 * thread_open(true) to get their own read-only WAL connection. */
NG_THREAD_LOCAL sqlite3 *ngdb_conn = NULL;

static const char *const ps_sql[PS_COUNT] = {
    /* seq: explicit in tag_index = memory (ngdb_seq_take), NULL = SQLite's max + 1 otherwise. */
    [PS_INSERT] = ("INSERT INTO event (id, pubkey, created_at, kind, tags, content, sig, seq) "
                   "VALUES (unhex(?), unhex(?), ?, ?, ?, ?, unhex(?), ?) ON CONFLICT(id) DO NOTHING"),
    [PS_TOMB_CHECK] = "SELECT 1 FROM deleted_event WHERE id = unhex(?) AND pubkey = unhex(?)",
    [PS_TOMB_ADD] = "INSERT OR IGNORE INTO deleted_event (id, pubkey) VALUES (unhex(?), unhex(?))",
    [PS_REPL_SEL] = "SELECT lower(hex(id)), created_at, tags FROM event WHERE pubkey = unhex(?) AND kind = ?",
    [PS_DEL_ID] = "DELETE FROM event WHERE id = unhex(?)",
    [PS_TAG_OVERFLOW] = "INSERT OR IGNORE INTO tag_overflow (ev, created_at, kind) VALUES (?, ?, ?)",
    [PS_TAG_INSERT] = "INSERT OR IGNORE INTO tag (name, value, created_at, ev, kind) VALUES (?, ?, ?, ?, ?)",
    [PS_TAG_INSERT_CHUNK] = "INSERT OR IGNORE INTO tag (name, value, created_at, ev, kind) VALUES "
                            "(?, ?, ?, ?, ?), (?, ?, ?, ?, ?), (?, ?, ?, ?, ?), (?, ?, ?, ?, ?)",
    [PS_VANISH_CHECK] = "SELECT 1 FROM vanished WHERE pubkey = unhex(?) AND until >= ?",
    [PS_FTS_FEED] = "INSERT INTO event_fts (rowid, content) SELECT seq, content FROM event"
                    " WHERE seq >= ? AND content != '' AND " NG_SEARCH_KIND_SQL("kind"),
};
static NG_THREAD_LOCAL sqlite3_stmt *ps[PS_COUNT];

sqlite3_stmt *ngdb_ps(int which) {
    if (!ngdb_conn) return NULL;
    if (!ps[which] && sqlite3_prepare_v3(ngdb_conn, ps_sql[which], -1, SQLITE_PREPARE_PERSISTENT,
                                         &ps[which], NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
        ps[which] = NULL;
        return NULL;
    }
    sqlite3_reset(ps[which]);
    sqlite3_clear_bindings(ps[which]);
    return ps[which];
}

static void ps_finalize_all(void) {
    for (int i = 0; i < PS_COUNT; i++) { if (ps[i]) sqlite3_finalize(ps[i]); ps[i] = NULL; }
    ngdb_write_scratch_free();
}
static char db_dsn[1024];
static const char *db_sync = "FULL";

void storage_set_sync_full(bool full) { db_sync = full ? "FULL" : "NORMAL"; }
static bool db_search = true;
void storage_set_search(bool on) { db_search = on; }
bool ngdb_search_enabled(void) { return db_search; }
static int db_tag_cap = NG_TAG_CAP_DEFAULT;
static char db_tag_letters[64] = SQ_TAG_LETTERS_DEFAULT;
bool storage_set_tag_index(const char *letters, int max_per_event) {
    if (max_per_event < 1) return false;
    if (letters) {
        if (!sq_set_tag_letters(letters)) return false;      /* validates and normalises */
        snprintf(db_tag_letters, sizeof(db_tag_letters), "%s", sq_tag_letters());
    }
    db_tag_cap = max_per_event;
    return true;
}
int ngdb_tag_cap(void) { return db_tag_cap; }

static bool db_tag_memory = true;
static size_t db_tag_memory_mb;
static int db_tag_snapshot_secs = 300;
bool storage_set_tag_index_mode(bool memory, size_t memory_mb, int snapshot_secs) {
    if (snapshot_secs < 0 || memory_mb > ((size_t) 1 << 24)) return false;
    db_tag_memory = memory;
    db_tag_memory_mb = memory_mb;
    db_tag_snapshot_secs = snapshot_secs;
    return true;
}
/* Whether this database runs the in-memory index (set by init). */
static bool db_mem_on;
bool ngdb_tag_memory(void) { return db_mem_on; }

/* tag_index = memory assigns seqs itself, strictly increasing over the
 * life of the database and never reused: the snapshot's "covered" seq and
 * the tombstone bitmap stay meaningful across deletes, rollbacks and
 * restarts. Initialised by init past MAX(seq) and the snapshot. */
static ng_atomic_ullong db_next_seq;
uint64_t ngdb_seq_take(void) { return ng_atomic_fetch_add_explicit(&db_next_seq, 1, NG_MO_RELAXED); }

/* ---- memory-mode transaction bookkeeping (per read-write connection) ----
 * Deletes reach memidx through a TEMP trigger calling ng_tomb(old.seq) on
 * every read-write connection; the seqs wait here until the delete is
 * known committed (ngdb_mem_settle after an autocommit statement, the
 * batch COMMIT) and are dropped if it rolls back. Inserts are indexed at
 * once (readers recheck every candidate in SQL, so an uncommitted posting
 * only costs a lookup); the first seq of the open transaction is kept so
 * a rollback tombstones its whole seq range. */
static NG_THREAD_LOCAL uint64_t *mt_pending;
static NG_THREAD_LOCAL size_t mt_n, mt_cap;
static NG_THREAD_LOCAL uint64_t mt_first_ins;

static void mt_reset(void) { mt_n = 0; mt_first_ins = 0; }
static void mt_apply(void) {
    for (size_t i = 0; i < mt_n; i++) memidx_tomb_set(mt_pending[i]);
    mt_reset();
}
static void mt_free(void) { free(mt_pending); mt_pending = NULL; mt_cap = 0; mt_reset(); }

void ngdb_mem_inserted(uint64_t seq) {
    if (db_mem_on && !mt_first_ins && ngdb_conn && !sqlite3_get_autocommit(ngdb_conn)) mt_first_ins = seq;
}
void ngdb_mem_settle(void) {
    if (db_mem_on && ngdb_conn && sqlite3_get_autocommit(ngdb_conn)) mt_apply();
}

static void sql_tomb(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
    (void) argc;
    sqlite3_result_null(ctx);
    if (!db_mem_on) return;
    if (mt_n == mt_cap) {
        size_t nc = ng_grow_cap(mt_cap, mt_n + 1, 64);
        uint64_t *p = (uint64_t *) ng_realloc_array(mt_pending, nc, sizeof(*p));
        if (!p) return;                  /* the posting stays: readers' recheck drops it */
        mt_pending = p; mt_cap = nc;
    }
    mt_pending[mt_n++] = (uint64_t) sqlite3_value_int64(argv[0]);
}

/* Any rollback (ROLLBACK, or SQLite's own after an I/O / full-disk error
 * mid-batch): the pending deletes did not happen; the events inserted in
 * the transaction never existed. */
static void mt_rollback_hook(void *arg) {
    (void) arg;
    if (!db_mem_on) return;
    uint64_t next = ng_atomic_load_explicit(&db_next_seq, NG_MO_RELAXED);
    if (mt_first_ins && next > mt_first_ins) memidx_tomb_range(mt_first_ins, next - 1);
    mt_reset();
}

static const char mem_trigger_sql[] =
    "CREATE TEMP TRIGGER IF NOT EXISTS ng_memidx_delete AFTER DELETE ON main.event BEGIN"
    "  SELECT ng_tomb(old.seq);"
    "END;";

/* Register the delete hooks on a read-write connection (memory mode). */
static bool mem_conn_setup(sqlite3 *db) {
    if (!db_mem_on) return true;
    sqlite3_rollback_hook(db, mt_rollback_hook, NULL);
    char *err = NULL;
    if (sqlite3_exec(db, mem_trigger_sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err ? err : sqlite3_errmsg(db));
        sqlite3_free(err);
        return false;
    }
    return true;
}

/* NIP-50 full-text index over content (FTS5, external content =
 * the event table, keyed by seq). Encrypted / AUTH kinds and empty
 * content are not indexed. Inserts are fed in bulk, once per batch
 * (PS_FTS_FEED, storage_write.c), not by a per-row trigger: a per-row
 * FTS5 insert cost ~15-20 us/event on the writer. The delete trigger
 * stays; every DELETE on event first flushes the pending rows, so it
 * never issues an FTS5 'delete' for a row the index lacks. */
static const char search_sql[] =
    "CREATE VIRTUAL TABLE IF NOT EXISTS event_fts USING fts5("
    "    content, content='event', content_rowid='seq',"
    "    tokenize='unicode61 remove_diacritics 2');"
    "DROP TRIGGER IF EXISTS event_fts_insert;"
    "CREATE TRIGGER IF NOT EXISTS event_fts_delete AFTER DELETE ON event"
    "  WHEN old.content != '' AND " NG_SEARCH_KIND_SQL("old.kind") " BEGIN"
    "  INSERT INTO event_fts (event_fts, rowid, content) VALUES ('delete', old.seq, old.content);"
    "END;";

static bool has_table(const char *name) {
    sqlite3_stmt *st = NULL;
    bool yes = false;
    if (sqlite3_prepare_v2(ngdb_conn, "SELECT 1 FROM sqlite_master WHERE name = ?", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
        yes = sqlite3_step(st) == SQLITE_ROW;
    }
    sqlite3_finalize(st);
    return yes;
}

/* Run sql on the init connection; on error report it and close. */
static bool exec_or_close(const char *sql) {
    char *errmsg = NULL;
    if (sqlite3_exec(ngdb_conn, sql, NULL, NULL, &errmsg) == SQLITE_OK) return true;
    fprintf(stderr, "SQL error: %s\n", errmsg ? errmsg : sqlite3_errmsg(ngdb_conn));
    sqlite3_free(errmsg);
    sqlite3_close_v2(ngdb_conn);
    ngdb_conn = NULL;
    return false;
}

/* tag_index = sqlite: the NIP-01 tag index as a table. One row per
 * (single-letter tag name, first value) of each stored event, written by
 * storage_write.c in the writer's batch transaction: name is the letter's
 * code point, value the 8-byte sq_tag_key8 key (collisions are rechecked
 * against the tags JSON by every reader). The key serves #<name> filters
 * newest-first; kind rides along so kinds filters are checked before the
 * join to event.
 *
 * Every delete path (replaceable overwrite, NIP-09, NIP-40, NIP-62) drops
 * the event's tag rows by recomputing their keys from the stored tags JSON
 * (ng_tagkey, registered on every read-write connection): point deletes on
 * the primary key, no second index on ev.
 *
 * tag_overflow lists events with more indexed tags than
 * tag_index_max_per_event: only the first ones are in tag; queries check
 * these events' tags JSON for the rest (storage_query.c). */
static const char tag_table_sql[] =
    "CREATE TABLE IF NOT EXISTS tag ("
    "    name INTEGER NOT NULL, value BLOB NOT NULL, created_at INTEGER NOT NULL,"
    "    ev INTEGER NOT NULL, kind INTEGER NOT NULL,"
    "    PRIMARY KEY (name, value, created_at, ev)"
    ") WITHOUT ROWID;"
    "CREATE TRIGGER IF NOT EXISTS event_tag_delete AFTER DELETE ON event BEGIN"
    "  DELETE FROM tag WHERE (name, value, created_at, ev) IN ("
    "    SELECT unicode(n), ng_tagkey(v), old.created_at, old.seq"
    "    FROM (SELECT json_extract(j.value, '$[0]') AS n, json_extract(j.value, '$[1]') AS v"
    "          FROM json_each(CASE WHEN json_valid(old.tags) THEN old.tags ELSE '[]' END) AS j"
    "          WHERE json_type(j.value, '$[0]') = 'text' AND json_type(j.value, '$[1]') = 'text')"
    "    WHERE n GLOB '[A-Za-z]');"
    "END;"
    "CREATE TABLE IF NOT EXISTS tag_overflow ("
    "    ev INTEGER PRIMARY KEY, created_at INTEGER NOT NULL, kind INTEGER NOT NULL);"
    "CREATE TRIGGER IF NOT EXISTS event_tag_overflow_delete AFTER DELETE ON event BEGIN"
    "  DELETE FROM tag_overflow WHERE ev = old.seq;"
    "END;";
static const char tag_table_drop_sql[] =
    "DROP TRIGGER IF EXISTS event_tag_delete; DROP TRIGGER IF EXISTS event_tag_overflow_delete;"
    "DROP TABLE IF EXISTS tag; DROP TABLE IF EXISTS tag_overflow;";

/* The tag table holds rows for the configured letters and cap only, in
 * the k8 layout. When the settings differ from the ones it was built with
 * (or it predates them, or the k8 key), drop it and rebuild it and
 * tag_overflow from the stored events in one transaction. Same selection
 * as store_tags: string first values, the first `cap` qualifying tags in
 * order. */
static bool tag_index_sync(void) {
    char want[96], have[96] = "";
    snprintf(want, sizeof(want), "k8|%s|%d", sq_tag_letters(), db_tag_cap);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ngdb_conn, "SELECT v FROM meta WHERE k = 'tag_index'", -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
        return false;
    }
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *v = sqlite3_column_text(st, 0);
        if (v) snprintf(have, sizeof(have), "%s", (const char *) v);
    }
    sqlite3_finalize(st);
    if (strcmp(want, have) == 0) return exec_or_close(tag_table_sql);
    /* letters are validated A-Za-z (sq_set_tag_letters): safe to inline. */
    static const char rows[] =
        "SELECT e.seq AS seq, e.created_at AS created_at, e.kind AS kind,"
        "       json_extract(j.value, '$[0]') AS n, json_extract(j.value, '$[1]') AS v,"
        "       row_number() OVER (PARTITION BY e.seq ORDER BY j.key) AS rn"
        " FROM event e, json_each(CASE WHEN json_valid(e.tags) THEN e.tags ELSE '[]' END) j"
        " WHERE json_type(j.value, '$[0]') = 'text' AND json_type(j.value, '$[1]') = 'text'"
        "   AND length(json_extract(j.value, '$[0]')) = 1"
        "   AND instr('%s', json_extract(j.value, '$[0]')) > 0";
    char sel[1024], sql[6144];
    snprintf(sel, sizeof(sel), rows, sq_tag_letters());
    int w = snprintf(sql, sizeof(sql),
        "BEGIN IMMEDIATE;%s%s"
        "INSERT OR IGNORE INTO tag (name, value, created_at, ev, kind)"
        " SELECT unicode(n), ng_tagkey(v), created_at, seq, kind FROM (%s) WHERE rn <= %d;"
        "INSERT INTO tag_overflow (ev, created_at, kind)"
        " SELECT seq, created_at, kind FROM (%s) WHERE rn = %d;"
        "INSERT OR REPLACE INTO meta (k, v) VALUES ('tag_index', '%s');"
        "COMMIT;", tag_table_drop_sql, tag_table_sql, sel, db_tag_cap, sel, db_tag_cap + 1, want);
    if (w < 0 || (size_t) w >= sizeof(sql)) return false;
    bool any = false;
    if (sqlite3_prepare_v2(ngdb_conn, "SELECT 1 FROM event LIMIT 1", -1, &st, NULL) == SQLITE_OK)
        any = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    if (any)
        fprintf(stderr, "storage: rebuilding the tag index (letters %s, max %d per event)...\n",
                sq_tag_letters(), db_tag_cap);
    return exec_or_close(sql);
}

/* ---- tag_index = memory: open memidx, load the snapshot or rebuild ---- */
static char db_snap_path[1100];
static uint64_t db_token;

static bool meta_get(const char *k, char *out, size_t n) {
    sqlite3_stmt *st = NULL;
    out[0] = '\0';
    if (sqlite3_prepare_v2(ngdb_conn, "SELECT v FROM meta WHERE k = ?", -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
        return false;
    }
    sqlite3_bind_text(st, 1, k, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *v = sqlite3_column_text(st, 0);
        if (v) snprintf(out, n, "%s", (const char *) v);
    }
    sqlite3_finalize(st);
    return true;
}

static sqlite3_int64 max_seq(void) {
    sqlite3_stmt *st = NULL;
    sqlite3_int64 m = 0;
    if (sqlite3_prepare_v2(ngdb_conn, "SELECT MAX(seq) FROM event", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) m = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return m;
}

/* Index every stored event with seq > after, in seq order. */
static bool mem_replay(uint64_t after, size_t *n) {
    sqlite3_stmt *st = NULL;
    *n = 0;
    if (sqlite3_prepare_v2(ngdb_conn, "SELECT seq, created_at, kind, tags FROM event WHERE seq > ? ORDER BY seq",
                           -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
        return false;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64) after);
    int rc;
    bool ok = true;
    while (ok && (rc = sqlite3_step(st)) == SQLITE_ROW) {
        sqlite3_int64 seq = sqlite3_column_int64(st, 0), ca = sqlite3_column_int64(st, 1);
        const char *tags = (const char *) sqlite3_column_text(st, 3);
        ok = memidx_add_event(tags, tags ? (size_t) sqlite3_column_bytes(st, 3) : 0, (uint64_t) seq,
                              ca < 0 ? 0u : ca > (sqlite3_int64) UINT32_MAX ? UINT32_MAX : (uint32_t) ca,
                              sqlite3_column_int(st, 2));
        (*n)++;
    }
    sqlite3_finalize(st);
    if (!ok) { fprintf(stderr, "memidx: out of memory building the tag index\n"); return false; }
    if (rc != SQLITE_DONE) { fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn)); return false; }
    return true;
}

static double secs_since(const struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (double) (t1.tv_sec - t0->tv_sec) + (double) (t1.tv_nsec - t0->tv_nsec) / 1e9;
}

/* meta 'tag_index' = "mem|<token>": the database runs the memory index and
 * its snapshot identity. The token is replaced at every startup (after the
 * snapshot was loaded), so a snapshot written by a later run never matches
 * a database restored from an older copy. Switching from sqlite drops the
 * tag tables (rebuilt from the events if switched back). */
static bool mem_index_init(void) {
    char have[96];
    if (!meta_get("tag_index", have, sizeof(have))) return false;
    uint64_t token = strncmp(have, "mem|", 4) == 0 ? strtoull(have + 4, NULL, 16) : 0;
    if (!token && has_table("tag"))
        fprintf(stderr, "storage: tag_index = memory: dropping the SQLite tag table\n");
    const char *fn = sqlite3_db_filename(ngdb_conn, "main");
    db_snap_path[0] = '\0';
    if (fn && fn[0]) snprintf(db_snap_path, sizeof(db_snap_path), "%s-tagidx", fn);

    memidx_config_t c = { db_tag_letters, (size_t) db_tag_cap, db_tag_memory_mb << 20 };
    if (!memidx_open(&c)) { fprintf(stderr, "memidx: cannot open the tag index\n"); return false; }
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    uint64_t covered = 0;
    sqlite3_int64 top = max_seq();
    ng_status_t st = token && db_snap_path[0] ? memidx_snapshot_load(db_snap_path, token, &covered) : NG_E_UNKNOWN;
    if (st == NG_OK && covered > (uint64_t) top) {         /* the database is older than the snapshot */
        memidx_close();
        if (!memidx_open(&c)) return false;
        st = NG_E_INVALID;
        covered = 0;
    }
    if (st == NG_E_INVALID)
        fprintf(stderr, "memidx: snapshot %s unusable (corrupt, another database or other settings): full rebuild\n",
                db_snap_path);
    size_t n = 0;
    if (!mem_replay(covered, &n)) { memidx_close(); return false; }
    memidx_stats_t ms;
    memidx_stats(&ms);
    fprintf(stderr, "memidx: %s%s + %zu events replayed in %.2f s: %zu keys, %zu postings, %.1f MiB\n",
            st == NG_OK ? "snapshot " : "rebuilt", st == NG_OK ? db_snap_path : "", n, secs_since(&t0),
            ms.keys, ms.postings, (double) ms.bytes / 1048576.0);
    memidx_enforce_cap();

    uint64_t next = (uint64_t) top > covered ? (uint64_t) top : covered;
    ng_atomic_store(&db_next_seq, next + 1);
    sqlite3_randomness((int) sizeof(token), &token);
    token |= 1;                                             /* never 0 */
    char sql[512];
    snprintf(sql, sizeof(sql), "BEGIN IMMEDIATE;%sINSERT OR REPLACE INTO meta (k, v) VALUES ('tag_index', 'mem|%016llx');COMMIT;",
             tag_table_drop_sql, (unsigned long long) token);
    if (!exec_or_close(sql)) { memidx_close(); return false; }
    db_token = token;
    db_mem_on = true;
    if (!mem_conn_setup(ngdb_conn)) { db_mem_on = false; memidx_close(); return false; }
    if (db_snap_path[0] && db_tag_snapshot_secs > 0 && !memidx_snapshot_start(db_snap_path, token, db_tag_snapshot_secs))
        fprintf(stderr, "memidx: warning: no background snapshot thread; the index is written at shutdown only\n");
    return true;
}

/* Shutdown (writer stopped): final snapshot, then free the index. */
static void mem_index_close(void) {
    if (!db_mem_on) return;
    memidx_snapshot_stop();
    if (db_snap_path[0]) {
        ng_status_t st = memidx_snapshot_write(db_snap_path, db_token);
        if (st != NG_OK) fprintf(stderr, "memidx: snapshot %s not written: %s\n", db_snap_path, ng_status_str(st));
    }
    memidx_close();
    memidx_thread_done();
    mt_free();
    db_mem_on = false;
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
 *   - FULL synchronous mode (durable commits by default)
 *   - 256MB cache for performance
 * 
 * Indexes Created:
 *   - ididx: unique on event.id
 *   - pubkindtimeidx: (pubkey, kind, created_at DESC)
 *   - timeidx: on event.created_at DESC
 *   - kindtimeidx: composite on (kind, created_at DESC)
 * Page size:
 *   - 2048 for a new database (NG_PAGE_SIZE overrides); existing databases
 *     keep theirs, which SQLite fixes at first table creation.
 * 
 * Thread safety: NOT thread-safe; must be called during init
 */

/* ng_tagkey(text) -> the 8-byte sq_tag_key8 blob, for the tag table's
 * delete trigger and rebuild. Registered on every connection we open. */
static void sql_tagkey(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
    (void) argc;
    const unsigned char *v = sqlite3_value_text(argv[0]);
    if (!v) { sqlite3_result_null(ctx); return; }
    unsigned char k[8];
    sq_tag_key8((const char *) v, (size_t) sqlite3_value_bytes(argv[0]), k);
    sqlite3_result_blob(ctx, k, 8, SQLITE_TRANSIENT);
}
static void register_fns(sqlite3 *db) {
    sqlite3_create_function(db, "ng_tagkey", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sql_tagkey, NULL, NULL);
    sqlite3_create_function(db, "ng_tomb", 1, SQLITE_UTF8 | SQLITE_DIRECTONLY, NULL, sql_tomb, NULL, NULL);
}

static bool storage_init_sqlite3(const char *dsn) {
    snprintf(db_dsn, sizeof(db_dsn), "%s", dsn ? dsn : "");
    if (!ngdb_vfs_register()) fprintf(stderr, "warning: WAL write coalescing unavailable\n");
    mem_index_close();                                     /* re-init without deinit */
    if (ngdb_conn) {
        sqlite3_close_v2(ngdb_conn);
    }
    
    int ret = sqlite3_open_v2(dsn, &ngdb_conn,
                         SQLITE_OPEN_URI | SQLITE_OPEN_READWRITE |
                         SQLITE_OPEN_CREATE,
                         NULL);
    
    if (ret == SQLITE_OK) register_fns(ngdb_conn);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Unable to connect to database: %s\n", sqlite3_errmsg(ngdb_conn));
        return false;
    }
    
    /* Page size must be set before the first table is created (it is baked
     * into the database file on creation); existing databases keep theirs. */
    char page_sql[64];
    {
        /* Only effective for a new database (fixed at first table). Small
         * pages keep the per-event write cost low: each insert dirties a
         * leaf in every index and the whole page is written to the WAL. */
        const char *ps_env = getenv("NG_PAGE_SIZE");
        snprintf(page_sql, sizeof(page_sql), "PRAGMA page_size = %d;", ps_env ? atoi(ps_env) : 2048);
        sqlite3_exec(ngdb_conn, page_sql, NULL, NULL, NULL);
    }
    const char *pragmas_sql =
        "PRAGMA journal_mode = WAL;"
        "PRAGMA synchronous = FULL;"
        "PRAGMA busy_timeout = 5000;"
        "PRAGMA cache_size = -262144;"
        "PRAGMA foreign_keys = true;"
        "PRAGMA temp_store = memory;";

    char *errmsg = NULL;
    if (sqlite3_exec(ngdb_conn, pragmas_sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close_v2(ngdb_conn);
        ngdb_conn = NULL;
        return false;
    }

    /* Create tables and indexes */
    const char *schema_sql = 
        "CREATE TABLE IF NOT EXISTS event ("
        /* seq aliases the rowid: the tag index refers to events by it.
         * ids, pubkeys and sigs are stored binary (32/32/64 bytes); SQL
         * converts at the boundary with unhex(?) / lower(hex(col)). */
        "    seq INTEGER PRIMARY KEY,"
        "    id BLOB NOT NULL CHECK (length(id) = 32),"
        "    pubkey BLOB NOT NULL CHECK (length(pubkey) = 32),"
        "    created_at INTEGER NOT NULL,"
        "    kind INTEGER NOT NULL,"
        "    tags TEXT NOT NULL,"
        "    content TEXT NOT NULL,"
        "    sig BLOB NOT NULL"
        ");"
        "CREATE UNIQUE INDEX IF NOT EXISTS ididx ON event(id);"
        /* (pubkey,kind,created_at) serves authors filters (prefix), the
         * replaceable lookup and the newest-first top-k probes
         * (storage_read.c); it replaces the older (pubkey,kind) index. */
        "CREATE INDEX IF NOT EXISTS pubkindtimeidx ON event(pubkey,kind,created_at DESC);"
        "DROP INDEX IF EXISTS pubkindidx;"
        "CREATE INDEX IF NOT EXISTS timeidx ON event(created_at DESC);"
        "CREATE INDEX IF NOT EXISTS kindtimeidx ON event(kind,created_at DESC);"
        /* Settings the stored indexes were built with (tag_index). */
        "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL) WITHOUT ROWID;"
        /* NIP-09 tombstones: (id, deleting author). */
        "CREATE TABLE IF NOT EXISTS deleted_event ("
        "    id BLOB NOT NULL, pubkey BLOB NOT NULL, PRIMARY KEY (id, pubkey)"
        ") WITHOUT ROWID;"
        /* NIP-62 vanished pubkeys: events by `pubkey` with created_at <=
         * `until` (other than kind 62 requests) are refused on ingest. */
        "CREATE TABLE IF NOT EXISTS vanished ("
        "    pubkey BLOB PRIMARY KEY CHECK (length(pubkey) = 32), until INTEGER NOT NULL"
        ") WITHOUT ROWID;";
    /* A database from before the search index: index its events once. */
    bool had_events = has_table("event"), had_fts = has_table("event_fts");
    if (has_table("pubkindidx"))
        fprintf(stderr, "storage: rebuilding the author index as (pubkey, kind, created_at)...\n");

    if (!exec_or_close(schema_sql)) return false;
    /* tag_index = memory: the SQL builder sees no indexed letter (its tag
     * conditions are JSON checks); storage_read.c drives tag filters from
     * memidx. tag_index = sqlite: the tag table. */
    sq_set_tag_letters(db_tag_memory ? "" : db_tag_letters);
    if (!db_tag_memory && !tag_index_sync()) return false;
    if (!exec_or_close(db_search ? search_sql :
                       "DROP TRIGGER IF EXISTS event_fts_insert; DROP TRIGGER IF EXISTS event_fts_delete;"
                       "DROP TABLE IF EXISTS event_fts;")) return false;
    if (db_search && had_events && !had_fts) {
        fprintf(stderr, "storage: building the NIP-50 search index for the stored events...\n");
        if (!exec_or_close("INSERT INTO event_fts (rowid, content) SELECT seq, content FROM event"
                           " WHERE content != '' AND " NG_SEARCH_KIND_SQL("kind"))) return false;
    }
    if (db_tag_memory && !mem_index_init()) {
        if (ngdb_conn) { sqlite3_close_v2(ngdb_conn); ngdb_conn = NULL; }
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
    mem_index_close();
    ps_finalize_all();
    if (ngdb_conn) {
        sqlite3_close_v2(ngdb_conn);
        ngdb_conn = NULL;
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
 *   - ngdb_get_event_by_id: retrieve single event
 *   - ngdb_insert_record: store new event
 *   - delete_*: remove events (various criteria)
 *   - ngdb_send_records: query and stream events
 */
/* Open this thread's own connection to the database init() opened.
 * readonly=true is used by REQ reader threads; the single writer thread
 * opens read-write. Schema/migrations are only done by init(). */
static bool storage_thread_open_sqlite3(bool readonly) {
    if (ngdb_conn) return true;
    int flags = SQLITE_OPEN_URI | SQLITE_OPEN_NOMUTEX |
                (readonly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE);
    if (sqlite3_open_v2(db_dsn, &ngdb_conn, flags, NULL) != SQLITE_OK) {
        fprintf(stderr, "thread db open failed: %s\n", sqlite3_errmsg(ngdb_conn));
        sqlite3_close_v2(ngdb_conn); ngdb_conn = NULL;
        return false;
    }
    register_fns(ngdb_conn);
    if (!readonly && !mem_conn_setup(ngdb_conn)) { sqlite3_close_v2(ngdb_conn); ngdb_conn = NULL; return false; }
    sqlite3_exec(ngdb_conn,
                 "PRAGMA busy_timeout = 5000;"
                 "PRAGMA cache_size = -65536;"
                 "PRAGMA temp_store = memory;"
                 "PRAGMA mmap_size = 268435456;"
                 "PRAGMA foreign_keys = true;", NULL, NULL, NULL);
    if (!readonly) {
        /* FULL syncs every committed batch by default. The runtime config
         * can opt into NORMAL (process-crash safe, not power-loss durable). */
        char sql[160];
        snprintf(sql, sizeof(sql),
                 "PRAGMA synchronous = %s; PRAGMA cache_size = -262144;"
                 "PRAGMA wal_autocheckpoint = %d;",
                 db_sync,
                 getenv("NG_WAL_CKPT") ? atoi(getenv("NG_WAL_CKPT")) : 0);
        if (sqlite3_exec(ngdb_conn, sql, NULL, NULL, NULL) != SQLITE_OK) {
            fprintf(stderr, "writer db configuration failed: %s\n", sqlite3_errmsg(ngdb_conn));
            sqlite3_close_v2(ngdb_conn); ngdb_conn = NULL;
            return false;
        }
    }
    return true;
}

static void storage_thread_close_sqlite3(void) {
    ps_finalize_all();
    mt_free();
    memidx_thread_done();
    if (ngdb_conn) { sqlite3_close_v2(ngdb_conn); ngdb_conn = NULL; }
}

static bool storage_exec_sqlite3(const char *sql) {
    char *err = NULL;
    if (!ngdb_conn || sqlite3_exec(ngdb_conn, sql, NULL, NULL, &err) != SQLITE_OK) {
        if (err) { fprintf(stderr, "SQL error: %s\n", err); sqlite3_free(err); }
        return false;
    }
    return true;
}
/* PASSIVE checkpoints never block the writer, but under sustained writes
 * they never let the WAL wrap either (the log only restarts once fully
 * backfilled), so it would grow without bound. When the log passes
 * NG_WAL_RESTART_FRAMES (default 262144 pages = 1 GiB at 4 KiB) we follow a
 * PASSIVE pass (which already backfilled almost everything) with a RESTART
 * checkpoint: it waits for the current batch COMMIT, backfills the few
 * remaining frames and makes the next batch rewrite the WAL from the start.
 * The writer stalls only for that short tail. */
static bool storage_checkpoint_sqlite3(void) {
    int log = 0, done = 0;
    if (!ngdb_conn) return false;
    if (sqlite3_wal_checkpoint_v2(ngdb_conn, NULL, SQLITE_CHECKPOINT_PASSIVE, &log, &done) != SQLITE_OK) return false;
    static int restart_frames;
    if (!restart_frames) {
        const char *v = getenv("NG_WAL_RESTART_FRAMES");
        restart_frames = v && atoi(v) > 0 ? atoi(v) : 262144;
    }
    if (log >= restart_frames)
        sqlite3_wal_checkpoint_v2(ngdb_conn, NULL, SQLITE_CHECKPOINT_RESTART, &log, &done);
    return true;
}
static bool storage_begin_sqlite3(void) {
    ngdb_fts_reset();
    mt_reset();
    return storage_exec_sqlite3("BEGIN IMMEDIATE");
}
/* The batch's pending search rows go in with the batch: a failed feed
 * fails the commit (the writer rolls back and answers error:). Memory
 * mode: the batch's deletes reach the index once committed; then a slice
 * of the dead-posting sweep and the memory cap, off the commit path. */
static bool storage_commit_sqlite3(void) {
    if (!ngdb_fts_flush() || !storage_exec_sqlite3("COMMIT")) return false;
    if (db_mem_on) {
        mt_apply();
        memidx_maintain(65536);
        memidx_enforce_cap();
    }
    return true;
}
static bool storage_rollback_sqlite3(void) {
    ngdb_fts_reset();
    /* COMMIT failed (e.g. SQLITE_BUSY/IOERR/FULL): the transaction may still be
     * open; roll it back so the writer starts the next batch cleanly. */
    if (!ngdb_conn || sqlite3_get_autocommit(ngdb_conn)) return true;
    return storage_exec_sqlite3("ROLLBACK");
}

void storage_context_init_sqlite3(storage_context_t *ctx) {
    if (!ctx) return;
    
    ctx->init = storage_init_sqlite3;
    ctx->deinit = storage_deinit_sqlite3;
    ctx->get_event_by_id = ngdb_get_event_by_id;
    ctx->insert_record = ngdb_insert_record;
    ctx->insert_event = ngdb_insert_event;
    ctx->replaceable_admit = ngdb_replaceable_admit;
    ctx->add_tombstone = ngdb_add_tombstone;
    ctx->delete_record_by_id_and_pubkey = ngdb_delete_record_by_id_and_pubkey;
    ctx->delete_record_by_kind_and_pubkey = ngdb_delete_record_by_kind_and_pubkey;
    ctx->delete_record_by_kind_and_pubkey_and_dtag = ngdb_delete_record_by_kind_and_pubkey_and_dtag;
    ctx->delete_record_by_id_and_kind_and_ptag = ngdb_delete_record_by_id_and_kind_and_ptag;
    ctx->delete_all_events_by_pubkey = ngdb_delete_all_events_by_pubkey;
    ctx->vanish = ngdb_vanish;
    ctx->delete_by_id = ngdb_delete_by_id;
    ctx->delete_by_tag = ngdb_delete_by_tag;
    ctx->scan_kinds = ngdb_scan_kinds;
    ctx->has_id_prefix = ngdb_has_id_prefix;
    ctx->send_records = ngdb_send_records;
    ctx->count_hll = ngdb_count_hll;
    ctx->purge_expired = ngdb_purge_expired;
    ctx->thread_open = storage_thread_open_sqlite3;
    ctx->thread_close = storage_thread_close_sqlite3;
    ctx->begin_batch = storage_begin_sqlite3;
    ctx->commit_batch = storage_commit_sqlite3;
    ctx->rollback_batch = storage_rollback_sqlite3;
    ctx->checkpoint = storage_checkpoint_sqlite3;
}
