/* storage_internal.h - shared by the SQLite storage backend modules only
 * (not a public API; the relay sees storage_context_t from storage.h).
 *
 *   storage_sqlite.c  lifecycle: open/close, schema, pragmas, per-thread
 *                     connections, prepared statements, batch transactions,
 *                     WAL checkpoint, storage_context_t wiring
 *   storage_write.c   write path (the single writer thread): insert,
 *                     tombstones, replaceable admission, NIP-09/62 deletes,
 *                     NIP-40 purge
 *   storage_query.c   query planner/builder: filter -> SQL + params (pure)
 *   storage_read.c    read path (worker threads): get_event_by_id,
 *                     send_records
 *
 * Every function acts on the calling thread's connection (ngdb_conn).
 */
#ifndef STORAGE_INTERNAL_H_
#define STORAGE_INTERNAL_H_

#include <sqlite3.h>
#include "platform/ng_alloc.h"
#include "platform/ng_platform.h"
#include "storage.h"

/* This thread's SQLite connection (NULL until init / thread_open). */
extern NG_THREAD_LOCAL sqlite3 *ngdb_conn;

/* Per-connection prepared statements for the hot write path, reused across
 * events (reset instead of prepare/finalize per insert). */
enum { PS_INSERT, PS_TOMB_CHECK, PS_TOMB_ADD, PS_REPL_SEL, PS_DEL_ID, PS_TAG_INSERT, PS_TAG_INSERT_CHUNK, PS_VANISH_CHECK, PS_FTS_FEED, PS_COUNT };
/* Tag index rows per multi-row INSERT step (PS_TAG_INSERT_CHUNK). */
#define TAG_CHUNK 4

/* The statement, reset and with bindings cleared; NULL on prepare error. */
sqlite3_stmt *ngdb_ps(int which);

/* storage_write.c */
storage_put_t ngdb_insert_event(const event_t *ev);
bool ngdb_insert_record(const event_t *ev);
bool ngdb_add_tombstone(const char *id, const char *pubkey);
storage_admit_t ngdb_replaceable_admit(const event_t *ev, const char *dtag);
bool ngdb_delete_record_by_id_and_pubkey(const char *id, const char *pubkey, size_t *deleted);
bool ngdb_delete_record_by_kind_and_pubkey(int kind, const char *pubkey, time_t created_at,
                                           size_t *deleted);
bool ngdb_delete_record_by_kind_and_pubkey_and_dtag(int kind, const char *pubkey, const tag_t *tag,
                                                    time_t created_at, size_t *deleted);
bool ngdb_delete_record_by_id_and_kind_and_ptag(const char *id, int kind, const tag_t *tag,
                                                size_t *deleted);
bool ngdb_delete_all_events_by_pubkey(const char *pubkey, time_t created_at, int exclude_kind,
                                      size_t *deleted);
bool ngdb_vanish(const char *pubkey, time_t until, void (*forget)(const char *hex_id),
                 size_t *deleted);
bool ngdb_delete_by_id(const char *id, size_t *deleted);
bool ngdb_delete_by_tag(char name, const char *value, void (*forget)(const char *hex_id), size_t *deleted);
bool ngdb_has_id_prefix(const char *hex8);
bool ngdb_scan_kinds(const int *kinds, size_t n, void (*cb)(const event_t *ev, void *arg), void *arg);
bool ngdb_purge_expired(time_t now, size_t *deleted);
/* Free the writer thread's tag-index scratch (thread close). */
void ngdb_write_scratch_free(void);
/* NIP-50: rows are fed to event_fts in bulk (see storage_write.c). */
bool ngdb_search_enabled(void);
bool ngdb_fts_flush(void);
void ngdb_fts_reset(void);

/* storage_read.c */
event_t *ngdb_get_event_by_id(const char *id);
ng_status_t ngdb_send_records(send_records_callback_t sender, const char *sub,
                       const filter_t *filters, size_t filters_count,
                       bool do_count, int *out_count, bool *out_more);
ng_status_t ngdb_count_hll(const filter_t *filter, int offset, int *out_count, uint8_t hll[256]);

#endif /* STORAGE_INTERNAL_H_ */
