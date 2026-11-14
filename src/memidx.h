/* memidx - the in-memory NIP-01 tag index (tag_index = memory).
 *
 * A derived, lossy-by-design index over the event table: for every stored
 * event, each of its first tag_index_max_per_event tags whose name is an
 * indexed letter and whose first value is a string contributes one posting
 * (created_at, seq, kind) to the key (letter, sq_tag_key8(value)). SQLite
 * stays the only source of truth: every candidate the index returns is
 * re-read by seq with the full filter, the tag JSON recheck included, so
 * key collisions, postings of deleted or rolled-back events and a stale
 * snapshot can cost lookups but never change a result.
 *
 * Layout per key: a frozen, delta-encoded run (blocks of MEMIDX_BLOCK
 * postings with a directory of (offset, last created_at)) plus a small
 * sorted tail of raw postings, merged into the frozen run when it reaches
 * ~2*sqrt(n) entries; a key with one posting stores it inline in its hash
 * slot. Deleted events are a seq bitmap (memidx_tomb_*); their postings are
 * dropped whenever a key is re-encoded and by the memidx_maintain sweep.
 *
 * Threads: one writer (the SQLite writer thread, or the init thread before
 * it starts) calls the mutating functions; any number of readers call
 * memidx_candidates / memidx_estimate / the stats concurrently. The keys
 * are split over MEMIDX_SHARDS hash shards, each with its own rwlock; a
 * reader copies the postings it needs out of one shard at a time.
 *
 * Snapshot: memidx_snapshot_write serialises the index (from any thread,
 * concurrently with the writer) with the highest seq it fully covers; a
 * later memidx_snapshot_load restores it and the caller replays the events
 * after that seq. See memidx_snapshot_start for the background writer.
 */
#ifndef MEMIDX_H_
#define MEMIDX_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ng_status.h"

#define MEMIDX_SHARDS 64
#define MEMIDX_BLOCK 64

/* One candidate event, newest first. */
typedef struct { uint64_t seq; uint32_t ca; uint16_t kind; } memidx_cand_t;

typedef struct {
    const char *letters;        /* indexed letters, validated A-Za-z */
    size_t max_per_event;       /* tag_index_max_per_event (>= 1) */
    size_t mem_cap;             /* tag_index_memory_mb in bytes; 0 = no cap */
} memidx_config_t;

typedef struct {
    size_t keys, postings;      /* live keys / stored postings (dead included until reclaimed) */
    size_t bytes;               /* everything memidx allocated (tables, runs, tails, bitmap) */
    size_t frozen_bytes, tail_bytes, table_bytes, tomb_bytes;
    size_t frozen_postings, tail_postings, inline_postings;
    size_t degraded;            /* letters dropped by the memory cap */
    uint64_t max_seq;           /* highest seq added */
} memidx_stats_t;

/* Lifecycle (single-threaded: before readers / the writer start, after they stop). */
bool memidx_open(const memidx_config_t *cfg);
void memidx_close(void);

/* Letters currently indexed: configured and not degraded by the memory cap.
 * Any thread. */
bool memidx_letter(char c);

/* ---- writer ---- */
/* Index one stored event. false on OOM (the index is then incomplete: the
 * caller fails the insert so the batch rolls back). Same tag selection as
 * the SQLite tag table (store_tags). */
bool memidx_add_event(const char *tags_json, size_t len, uint64_t seq, uint32_t created_at, int kind);
/* Mark seq deleted / mark [from, to] deleted (rolled-back batch). */
void memidx_tomb_set(uint64_t seq);
void memidx_tomb_range(uint64_t from, uint64_t to);
/* Reclaim dead postings: examine up to budget postings of the sweep;
 * a no-op while nothing was deleted since the last full pass. */
void memidx_maintain(size_t budget);
/* Enforce tag_index_memory_mb: while over the cap, drop the least-queried
 * letter (logged); its queries fall back to the JSON scan. */
void memidx_enforce_cap(void);

/* Free the calling thread's scratch (writer / snapshot thread exit). */
void memidx_thread_done(void);

/* ---- readers ---- */
/* Up to max candidates for "tag `letter` has one of values[0..n)", newest
 * first (created_at DESC, seq DESC), each event once, that pass kinds
 * (nk = 0: any), since/until (0 = unbounded) and are not deleted, after
 * skipping the first `skip` such candidates. NG_OK with *got set;
 * NG_E_UNKNOWN if the letter is not (or no longer) indexed (fall back);
 * NG_E_NOMEM; NG_E_TOOBIG if n > 256. */
ng_status_t memidx_candidates(char letter, char *const *values, size_t n, const int *kinds, size_t nk,
                              int64_t since, int64_t until, size_t skip, size_t max,
                              memidx_cand_t *out, size_t *got);
/* Postings stored for these values (dead included): a cost estimate. */
size_t memidx_estimate(char letter, char *const *values, size_t n);
/* Postings and encoded bytes of one key (tests, stats). false if absent. */
bool memidx_key_stats(char letter, const char *value, size_t *postings, size_t *bytes);
void memidx_stats(memidx_stats_t *out);

/* ---- snapshot ---- */
/* Write the index to path (via path.tmp, fsync, rename, fsync dir), tagged
 * with token (the database's identity) and the highest seq it covers.
 * Safe concurrently with the writer and readers. */
ng_status_t memidx_snapshot_write(const char *path, uint64_t token);
/* Load a snapshot into an empty index. NG_OK with *covered = its seq;
 * NG_E_UNKNOWN if missing; NG_E_INVALID if corrupt, of another format,
 * database (token), letters or cap: rebuild instead. Init thread only. */
ng_status_t memidx_snapshot_load(const char *path, uint64_t token, uint64_t *covered);
/* Background snapshots every interval_s seconds (0: none) while the index
 * changed; memidx_snapshot_stop joins the thread. */
bool memidx_snapshot_start(const char *path, uint64_t token, int interval_s);
void memidx_snapshot_stop(void);

#endif /* MEMIDX_H_ */
