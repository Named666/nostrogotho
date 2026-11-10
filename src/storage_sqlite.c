/* storage_sqlite - SQLite backend lifecycle (see storage_internal.h). */
#include "storage_internal.h"
#include "storage_vfs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    [PS_INSERT] = ("INSERT INTO event (id, pubkey, created_at, kind, tags, content, sig) "
                   "VALUES (unhex(?), unhex(?), ?, ?, ?, ?, unhex(?)) ON CONFLICT(id) DO NOTHING"),
    [PS_TOMB_CHECK] = "SELECT 1 FROM deleted_event WHERE id = unhex(?) AND pubkey = unhex(?)",
    [PS_TOMB_ADD] = "INSERT OR IGNORE INTO deleted_event (id, pubkey) VALUES (unhex(?), unhex(?))",
    [PS_REPL_SEL] = "SELECT lower(hex(id)), created_at, tags FROM event WHERE pubkey = unhex(?) AND kind = ?",
    [PS_DEL_ID] = "DELETE FROM event WHERE id = unhex(?)",
    [PS_TAG_INSERT] = "INSERT OR IGNORE INTO tag (name, value, created_at, ev, kind) VALUES (?, ?, ?, ?, ?)",
    [PS_TAG_INSERT_CHUNK] = "INSERT OR IGNORE INTO tag (name, value, created_at, ev, kind) VALUES "
                            "(?, ?, ?, ?, ?), (?, ?, ?, ?, ?), (?, ?, ?, ?, ?), (?, ?, ?, ?, ?)",
    [PS_VANISH_CHECK] = "SELECT 1 FROM vanished WHERE pubkey = unhex(?) AND until >= ?",
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

/* NIP-50 full-text index over content (FTS5, external content =
 * the event table, keyed by seq). Encrypted / AUTH kinds and empty
 * content are not indexed; insert and delete triggers share that
 * WHEN so the index never sees a delete for a row it lacks. */
static const char search_sql[] =
    "CREATE VIRTUAL TABLE IF NOT EXISTS event_fts USING fts5("
    "    content, content='event', content_rowid='seq',"
    "    tokenize='unicode61 remove_diacritics 2');"
    "CREATE TRIGGER IF NOT EXISTS event_fts_insert AFTER INSERT ON event"
    "  WHEN new.content != '' AND " NG_SEARCH_KIND_SQL("new.kind") " BEGIN"
    "  INSERT INTO event_fts (rowid, content) VALUES (new.seq, new.content);"
    "END;"
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
 *   - ididx: unique on event.id (primary key)
 *   - pubkeyprefix: on event.pubkey
 *   - timeidx: on event.created_at DESC
 *   - kindidx: on event.kind
 *   - kindtimeidx: composite on (kind, created_at DESC)
 * Page size:
 *   - PRAGMA page_size = 1048576 (~1MB) set before any table exists; larger
 *     pages reduce B-tree depth and I/O for big events (content + tags JSON
 *     can be tens of KB each). Existing databases keep their page size,
 *     which SQLite fixes at first table creation.
 * 
 * Thread safety: NOT thread-safe; must be called during init
 */
static bool storage_init_sqlite3(const char *dsn) {
    snprintf(db_dsn, sizeof(db_dsn), "%s", dsn ? dsn : "");
    if (!ngdb_vfs_register()) fprintf(stderr, "warning: WAL write coalescing unavailable\n");
    if (ngdb_conn) {
        sqlite3_close_v2(ngdb_conn);
    }
    
    int ret = sqlite3_open_v2(dsn, &ngdb_conn,
                         SQLITE_OPEN_URI | SQLITE_OPEN_READWRITE |
                         SQLITE_OPEN_CREATE,
                         NULL);
    
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Unable to connect to database: %s\n", sqlite3_errmsg(ngdb_conn));
        return false;
    }
    
    /* Page size must be set before the first table is created (it is baked
     * into the database file on creation). 1MB is the SQLite maximum and
     * suits large Nostr payloads; existing databases keep their page size. */
    char page_sql[64];
    {
        /* Only effective for a new database (fixed at first table). Small
         * pages keep the per-event write cost low: each insert dirties a
         * leaf in every index and the whole page is written to the WAL. */
        const char *ps_env = getenv("NG_PAGE_SIZE");
        snprintf(page_sql, sizeof(page_sql), "PRAGMA page_size = %d;", ps_env ? atoi(ps_env) : 4096);
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
        /* (pubkey,kind) serves authors filters (prefix) and the replaceable
         * lookup; kindidx was a redundant prefix of kindtimeidx. */
        "CREATE INDEX IF NOT EXISTS pubkindidx ON event(pubkey,kind);"
        "CREATE INDEX IF NOT EXISTS timeidx ON event(created_at DESC);"
        "CREATE INDEX IF NOT EXISTS kindtimeidx ON event(kind,created_at DESC);"
        /* NIP-01 tag index: one row per (single-letter tag name, first
         * value) of each stored event, written by storage_write.c in the
         * writer's batch transaction. 64-char lowercase hex values (e, p,
         * q, E, P ... ids and pubkeys) are stored as 32-byte blobs. The key
         * serves #<name> filters newest-first; kind rides along so kinds
         * filters are checked before the join to event. */
        "CREATE TABLE IF NOT EXISTS tag ("
        "    name TEXT NOT NULL, value NOT NULL, created_at INTEGER NOT NULL,"
        "    ev INTEGER NOT NULL, kind INTEGER NOT NULL,"
        "    PRIMARY KEY (name, value, created_at, ev)"
        ") WITHOUT ROWID;"
        /* Every delete path (replaceable overwrite, NIP-09, NIP-40, NIP-62)
         * drops the event's tag rows by recomputing their keys from the
         * stored tags JSON: point deletes on the primary key, no second
         * index on ev. Same selection and blob mapping as the insert side. */
        "CREATE TRIGGER IF NOT EXISTS event_tag_delete AFTER DELETE ON event BEGIN"
        "  DELETE FROM tag WHERE (name, value, created_at, ev) IN ("
        "    SELECT n, CASE WHEN length(v) = 64 AND v NOT GLOB '*[^0-9a-f]*' THEN unhex(v) ELSE v END,"
        "           old.created_at, old.seq"
        "    FROM (SELECT json_extract(j.value, '$[0]') AS n, json_extract(j.value, '$[1]') AS v"
        "          FROM json_each(CASE WHEN json_valid(old.tags) THEN old.tags ELSE '[]' END) AS j"
        "          WHERE json_type(j.value, '$[0]') = 'text' AND json_type(j.value, '$[1]') = 'text')"
        "    WHERE n GLOB '[A-Za-z]');"
        "END;"
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

    if (!exec_or_close(schema_sql)) return false;
    if (!exec_or_close(db_search ? search_sql :
                       "DROP TRIGGER IF EXISTS event_fts_insert; DROP TRIGGER IF EXISTS event_fts_delete;"
                       "DROP TABLE IF EXISTS event_fts;")) return false;
    if (db_search && had_events && !had_fts) {
        fprintf(stderr, "storage: building the NIP-50 search index for the stored events...\n");
        if (!exec_or_close("INSERT INTO event_fts (rowid, content) SELECT seq, content FROM event"
                           " WHERE content != '' AND " NG_SEARCH_KIND_SQL("kind"))) return false;
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
static bool storage_begin_sqlite3(void) { return storage_exec_sqlite3("BEGIN IMMEDIATE"); }
static bool storage_commit_sqlite3(void) { return storage_exec_sqlite3("COMMIT"); }
static bool storage_rollback_sqlite3(void) {
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
