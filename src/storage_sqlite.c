/* storage_sqlite - SQLite backend lifecycle (see storage_internal.h). */
#include "storage_internal.h"

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
}
static char db_dsn[1024];
static const char *db_sync = "FULL";

void storage_set_sync_full(bool full) { db_sync = full ? "FULL" : "NORMAL"; }

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
 * Delegation side table (NIP-26):
 *   - delegation(event_id, delegator): PK on (event_id, delegator)
 *   - delegation_delegator_idx: on delegation(delegator) so REQ filters
 *     with {authors: [A]} resolve delegated events via index lookups
 *     instead of full-table LIKE scans over tags JSON.
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
        /* ids, pubkeys and sigs are stored binary (32/32/64 bytes); SQL
         * converts at the boundary with unhex(?) / lower(hex(col)). */
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
        /* NIP-09 tombstones: (id, deleting author). */
        "CREATE TABLE IF NOT EXISTS deleted_event ("
        "    id BLOB NOT NULL, pubkey BLOB NOT NULL, PRIMARY KEY (id, pubkey)"
        ") WITHOUT ROWID;"
        /* NIP-26 delegation side table: one row per (event, delegator).
         * ON DELETE CASCADE keeps it in sync with event deletions because
         * PRAGMA foreign_keys is enabled above. */
        "CREATE TABLE IF NOT EXISTS delegation ("
        "    event_id BLOB NOT NULL REFERENCES event(id) ON DELETE CASCADE,"
        "    delegator BLOB NOT NULL,"
        "    PRIMARY KEY (event_id, delegator)"
        ");"
        "CREATE INDEX IF NOT EXISTS delegation_delegator_idx "
        "    ON delegation(delegator);";
    
    errmsg = NULL;
    if (sqlite3_exec(ngdb_conn, schema_sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close_v2(ngdb_conn);
        ngdb_conn = NULL;
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
    ctx->send_records = ngdb_send_records;
    ctx->purge_expired = ngdb_purge_expired;
    ctx->thread_open = storage_thread_open_sqlite3;
    ctx->thread_close = storage_thread_close_sqlite3;
    ctx->begin_batch = storage_begin_sqlite3;
    ctx->commit_batch = storage_commit_sqlite3;
    ctx->rollback_batch = storage_rollback_sqlite3;
    ctx->checkpoint = storage_checkpoint_sqlite3;
}
