/* storage_read - SQLite read path (see storage_internal.h). Runs on worker
 * threads, each with its own read-only WAL connection. */
#include "ng_config.h"
#include "storage_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json_util.h"
#include "memidx.h"
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

/* Per-REQ complexity policy: ng_limits (max_filters, max_filter_items,
 * max_req_authors, max_limit, default_limit), enforced by the protocol
 * layer when the REQ is parsed and re-checked here (defense in depth);
 * each filter compiles to one statement. */

/* Stream one compiled query's rows to sender as ["EVENT", sub, {...}]. */
/* The statement is bound with LIMIT limit+1: a row past the limit only
 * proves there are more (NIP-67) and is not sent. */
static void render_row(sqlite3_stmt *stmt, send_records_callback_t sender, const char *sub) {
    event_t event = {0};
    snprintf(event.id, sizeof(event.id), "%s", (const char *) sqlite3_column_text(stmt, 0));
    snprintf(event.pubkey, sizeof(event.pubkey), "%s", (const char *) sqlite3_column_text(stmt, 1));
    event.created_at = (time_t) sqlite3_column_int64(stmt, 2);
    event.kind = sqlite3_column_int(stmt, 3);
    event.tags_json = (char *) sqlite3_column_text(stmt, 4);
    event.tags_json_len = event.tags_json ? strlen(event.tags_json) : 0;
    event.content = (char *) sqlite3_column_text(stmt, 5);
    event.content_len = event.content ? (size_t) sqlite3_column_bytes(stmt, 5) : 0;
    snprintf(event.sig, sizeof(event.sig), "%s", (const char *) sqlite3_column_text(stmt, 6));
    json_builder_t *builder = json_builder_scratch(JSON_SCRATCH_QUERY);
    json_builder_append_string(builder, "EVENT");
    json_builder_append_string(builder, sub);
    json_serialize_event(&event, builder);
    sender(json_builder_finish(builder), &event);   /* NULL = could not render */
}

static bool stream_rows(sqlite3_stmt *stmt, send_records_callback_t sender, const char *sub, int limit, bool *more) {
    int rc, fetched = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (++fetched > limit) { *more = true; return true; }
        render_row(stmt, sender, sub);
    }
    if (rc != SQLITE_DONE) { fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn)); return false; }
    return true;
}

/* NIP-45 HyperLogLog register update for one 32-byte pubkey. */
static void hll_add(uint8_t hll[256], int offset, const uint8_t *pk) {
    unsigned zeros = 0;
    for (int b = offset + 1; b < 32; b++) {
        if (pk[b] == 0) { zeros += 8; continue; }
        for (int bit = 7; bit >= 0 && !(pk[b] >> bit & 1); bit--) zeros++;
        break;
    }
    uint8_t v = (uint8_t) (zeros + 1);
    if (v > hll[pk[offset]]) hll[pk[offset]] = v;
}

/* ---------------------------------------------- tag_index = memory --- */
/* Above this many postings for the driving tag, a filter that also names
 * authors is cheaper through the (pubkey, kind) index with the JSON tag
 * check than candidate by candidate. */
#define MEM_AUTHORS_MAX_POSTINGS 2000

/* The tag condition memidx drives this filter with (fewest postings), or
 * f->tags_count: the filter takes the SQL path (no indexed letter, ids,
 * search, or authors with a big tag). */
static size_t mem_drive(const filter_t *f) {
    if (!ngdb_tag_memory() || f->search || f->ids_count) return f->tags_count;
    size_t drive = f->tags_count, best = 0;
    for (size_t t = 0; t < f->tags_count; t++) {
        const tag_t *tg = &f->tags[t];
        if (tg->count < 2 || tg->count - 1 > 256 || !tg->elements[0] || !memidx_letter(tg->elements[0][0]) ||
            tg->elements[0][1] != '\0') continue;
        size_t est = memidx_estimate(tg->elements[0][0], tg->elements + 1, tg->count - 1);
        if (drive == f->tags_count || est < best) { drive = t; best = est; }
    }
    if (drive < f->tags_count && f->authors_count && best > MEM_AUTHORS_MAX_POSTINGS) return f->tags_count;
    return drive;
}

typedef struct { uint64_t seq; char id[65]; } mem_grp_t;
static int grp_cmp(const void *a, const void *b) {
    return strcmp(((const mem_grp_t *) a)->id, ((const mem_grp_t *) b)->id);
}

/* One filter driven by memidx. Candidates come newest first (created_at,
 * then seq, DESC; kinds and since/until already applied on the posting),
 * page by page behind a (created_at, seq) cursor so concurrent inserts
 * neither repeat nor skip one. Each is re-read by seq with the whole
 * filter compiled in SQL (sq_set_seq_param): the exact tag JSON match, the
 * other conditions, and the event still existing. SQ_MODE_ROWS streams up
 * to limit rows (NIP-01 ties: equal created_at lowest id first, so rows
 * of one created_at are gathered, sorted by id and re-read to render);
 * SQ_MODE_COUNT counts; SQ_MODE_PUBKEYS feeds hll. */
static ng_status_t mem_filter(const filter_t *f, size_t drive, sq_mode_t mode, int limit,
                              send_records_callback_t sender, const char *sub, bool *more,
                              int *count, uint8_t *hll, int hll_offset) {
    sq_query_t q = {0};
    sq_set_seq_param(true);
    ng_status_t st = sq_build_mode(&q, f, mode == SQ_MODE_ROWS ? SQ_MODE_ROWS : SQ_MODE_PUBKEYS, 1);
    sq_set_seq_param(false);
    if (st != NG_OK) { sq_free(&q); return st; }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(ngdb_conn, q.sql, (int) q.len, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
        sq_free(&q);
        return NG_E_IO;
    }
    for (size_t i = 0; i < q.n; i++) {
        int idx = (int) i + 1;
        if (q.params[i].type == SQ_INT) sqlite3_bind_int64(stmt, idx, q.params[i].num);
        else sqlite3_bind_text(stmt, idx, q.params[i].text, -1, SQLITE_TRANSIENT);
    }
    sq_free(&q);

    const tag_t *tg = &f->tags[drive];
    const char letter = tg->elements[0][0];
    size_t window = mode == SQ_MODE_ROWS ? (size_t) limit * 2 + 16 : 4096;
    memidx_cand_t *c = NULL;
    mem_grp_t *g = NULL;
    size_t gn = 0, gcap = 0;
    uint32_t gca = 0, cur_ca = 0;
    uint64_t cur_seq = 0;
    bool have_cur = false, done = false;
    int sent = 0, n_match = 0;
    st = NG_OK;
    while (!done && st == NG_OK) {
        memidx_cand_t *nc = (memidx_cand_t *) ng_realloc_array(c, window, sizeof(*c));
        if (!nc) { st = NG_E_NOMEM; break; }
        c = nc;
        size_t got = 0;
        int64_t until = f->until > 0 ? (int64_t) f->until : 0;
        if (have_cur && cur_ca > 0 && (until == 0 || (int64_t) cur_ca < until)) until = cur_ca;
        st = memidx_candidates(letter, tg->elements + 1, tg->count - 1, f->kinds, f->kinds_count,
                               f->since > 0 ? (int64_t) f->since : 0, until, 0, window, c, &got);
        if (st != NG_OK) break;                          /* NG_E_UNKNOWN: letter dropped meanwhile */
        bool progressed = false;
        for (size_t i = 0; i < got && !done && st == NG_OK; i++) {
            if (have_cur && (c[i].ca > cur_ca || (c[i].ca == cur_ca && c[i].seq >= cur_seq))) continue;
            progressed = true;
            if (mode == SQ_MODE_ROWS && gn && c[i].ca != gca) {
                /* flush the previous created_at group, lowest id first */
                if (gn > 1) qsort(g, gn, sizeof(*g), grp_cmp);
                for (size_t z = 0; z < gn; z++) {
                    if (sent >= limit) { *more = true; done = true; break; }
                    sqlite3_bind_int64(stmt, 1, (sqlite3_int64) g[z].seq);
                    if (sqlite3_step(stmt) == SQLITE_ROW) { render_row(stmt, sender, sub); sent++; }
                    sqlite3_reset(stmt);
                }
                gn = 0;
                if (done) break;
            }
            sqlite3_bind_int64(stmt, 1, (sqlite3_int64) c[i].seq);
            int rc = sqlite3_step(stmt);
            if (rc == SQLITE_ROW) {
                if (mode == SQ_MODE_ROWS) {
                    if (gn == gcap) {
                        size_t ncap = ng_grow_cap(gcap, gn + 1, 8);
                        mem_grp_t *ng = (mem_grp_t *) ng_realloc_array(g, ncap, sizeof(*g));
                        if (!ng) { st = NG_E_NOMEM; sqlite3_reset(stmt); break; }
                        g = ng; gcap = ncap;
                    }
                    g[gn].seq = c[i].seq;
                    snprintf(g[gn].id, sizeof(g[gn].id), "%s", (const char *) sqlite3_column_text(stmt, 0));
                    gn++;
                    gca = c[i].ca;
                } else {
                    n_match++;
                    const uint8_t *pk = (const uint8_t *) sqlite3_column_blob(stmt, 1);
                    if (hll && pk && sqlite3_column_bytes(stmt, 1) == 32) hll_add(hll, hll_offset, pk);
                }
            } else if (rc != SQLITE_DONE) {
                fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
                st = NG_E_IO;
            }
            sqlite3_reset(stmt);
        }
        if (done || st != NG_OK || got < window) break;
        cur_ca = c[got - 1].ca; cur_seq = c[got - 1].seq; have_cur = true;
        if (!progressed || window < ((size_t) 1 << 16)) window *= 4;   /* a huge created_at tie: widen */
    }
    if (st == NG_OK && mode == SQ_MODE_ROWS && !done && gn) {
        if (gn > 1) qsort(g, gn, sizeof(*g), grp_cmp);
        for (size_t z = 0; z < gn; z++) {
            if (sent >= limit) { *more = true; break; }
            sqlite3_bind_int64(stmt, 1, (sqlite3_int64) g[z].seq);
            if (sqlite3_step(stmt) == SQLITE_ROW) { render_row(stmt, sender, sub); sent++; }
            sqlite3_reset(stmt);
        }
    }
    free(c);
    free(g);
    sqlite3_finalize(stmt);
    if (count) *count = n_match;
    return st;
}

/* Whether any stored event overflowed tag_index_max_per_event (see
 * sq_set_overflow); probed once per query call that has tag conditions. */
static bool tag_overflow_present(void) {
    if (ngdb_tag_memory()) return false;                  /* no tag tables */
    sqlite3_stmt *st = NULL;
    bool yes = false;
    if (sqlite3_prepare_v2(ngdb_conn, "SELECT 1 FROM tag_overflow LIMIT 1", -1, &st, NULL) == SQLITE_OK)
        yes = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return yes;
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
ng_status_t ngdb_send_records(send_records_callback_t sender, const char *sub,
                              const filter_t *filters, size_t filters_count,
                              bool do_count, int *out_count, bool *out_more) {
    if (!ngdb_conn || !sender) return NG_E_INVALID;
    bool more = false;
    if (out_more) *out_more = false;
    if (do_count && out_count) *out_count = 0;
    const size_t max_items = (size_t) ng_limits.max_filter_items;
    if (filters_count > (size_t) ng_limits.max_filters) return NG_E_TOOBIG;
    size_t total_authors = 0;
    for (size_t f = 0; f < filters_count; f++) total_authors += filters[f].authors_count;
    if (total_authors > (size_t) ng_limits.max_req_authors) return NG_E_TOOBIG;

    bool any_tags = false;
    for (size_t f = 0; f < filters_count; f++) any_tags |= filters[f].tags_count > 0;
    sq_set_overflow(any_tags && tag_overflow_present());

    int total_count = 0;
    for (size_t f = 0; f < filters_count; f++) {
        const filter_t *filter = &filters[f];
        if (filter->ids_count > max_items || filter->authors_count > max_items ||
            filter->kinds_count > max_items || filter->tags_count > max_items) return NG_E_TOOBIG;
        /* NIP-01: limit:0 asks for no stored events (live events only);
         * COUNT ignores limit. */
        if (!do_count && filter->limit_set && filter->limit == 0) continue;
        int limit = !filter->limit_set ? ng_limits.default_limit
                  : filter->limit < ng_limits.max_limit ? filter->limit : ng_limits.max_limit;

        size_t drive = mem_drive(filter);
        if (drive < filter->tags_count) {
            int n = 0;
            ng_status_t ms = mem_filter(filter, drive, do_count ? SQ_MODE_COUNT : SQ_MODE_ROWS, limit,
                                        sender, sub, &more, &n, NULL, 0);
            if (ms == NG_OK) { total_count += n; continue; }
            if (ms != NG_E_UNKNOWN) return ms;
            /* the letter was dropped by the memory cap meanwhile: SQL path */
        }
        sq_query_t q = {0};
        ng_status_t st = sq_build(&q, filter, do_count, limit + 1);
        if (st != NG_OK) {
            sq_free(&q);
            return st;                                  /* TOOBIG: over SQ_MAX_* */
        }
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(ngdb_conn, q.sql, (int) q.len, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
            sq_free(&q);
            return NG_E_IO;
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
            ok = stream_rows(stmt, sender, sub, limit, &more);
        }
        sqlite3_finalize(stmt);
        if (!ok) return NG_E_IO;
    }
    if (do_count && out_count) *out_count = total_count;
    if (out_more) *out_more = more;
    return NG_OK;
}

/* NIP-45 HyperLogLog over the pubkeys of the events one filter counts:
 * register = pubkey[offset], value = leading zero bits from byte
 * offset + 1 on, plus one; each register keeps its maximum. */
ng_status_t ngdb_count_hll(const filter_t *filter, int offset, int *out_count, uint8_t hll[256]) {
    if (!ngdb_conn || !filter || offset < 0 || offset > 30 || !out_count || !hll) return NG_E_INVALID;
    const size_t max_items = (size_t) ng_limits.max_filter_items;
    if (filter->ids_count > max_items || filter->authors_count > max_items ||
        filter->kinds_count > max_items || filter->tags_count > max_items) return NG_E_TOOBIG;
    memset(hll, 0, 256);
    *out_count = 0;
    sq_set_overflow(filter->tags_count > 0 && tag_overflow_present());
    size_t drive = mem_drive(filter);
    if (drive < filter->tags_count) {
        int n = 0;
        ng_status_t ms = mem_filter(filter, drive, SQ_MODE_PUBKEYS, 0, NULL, NULL, NULL, &n, hll, offset);
        if (ms == NG_OK) { *out_count = n; return NG_OK; }
        if (ms != NG_E_UNKNOWN) return ms;
        memset(hll, 0, 256);
    }
    sq_query_t q = {0};
    ng_status_t st = sq_build_mode(&q, filter, SQ_MODE_PUBKEYS, 0);
    if (st != NG_OK) { sq_free(&q); return st; }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(ngdb_conn, q.sql, (int) q.len, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn));
        sq_free(&q);
        return NG_E_IO;
    }
    for (size_t i = 0; i < q.n; i++) {
        int idx = (int) i + 1;
        if (q.params[i].type == SQ_INT) sqlite3_bind_int64(stmt, idx, q.params[i].num);
        else sqlite3_bind_text(stmt, idx, q.params[i].text, -1, SQLITE_TRANSIENT);
    }
    sq_free(&q);
    int rc, n = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const uint8_t *pk = (const uint8_t *) sqlite3_column_blob(stmt, 1);
        if (!pk || sqlite3_column_bytes(stmt, 1) != 32) continue;
        n++;
        hll_add(hll, offset, pk);
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) { fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(ngdb_conn)); return NG_E_IO; }
    *out_count = n;
    return NG_OK;
}

/* An event id starting with the 4 bytes of hex8 exists: one index seek on
 * the id range [prefix, prefix + 1). */
bool ngdb_has_id_prefix(const char *hex8) {
    if (!ngdb_conn || !hex8 || strlen(hex8) != 8) return false;
    unsigned char lo[4], hi[4];
    for (int i = 0; i < 4; i++) {
        unsigned v = 0;
        for (int k = 0; k < 2; k++) {
            char c = hex8[i * 2 + k];
            unsigned d = (c >= '0' && c <= '9') ? (unsigned) (c - '0') : (c >= 'a' && c <= 'f') ? (unsigned) (c - 'a' + 10) : 16u;
            if (d > 15) return false;
            v = v * 16 + d;
        }
        lo[i] = hi[i] = (unsigned char) v;
    }
    int i = 3;
    while (i >= 0 && hi[i] == 0xff) hi[i--] = 0;
    bool top = i < 0;                                  /* ffffffff: no upper bound */
    if (!top) hi[i]++;
    sqlite3_stmt *st = NULL;
    const char *sql = top ? "SELECT 1 FROM event WHERE id >= ? LIMIT 1"
                          : "SELECT 1 FROM event WHERE id >= ? AND id < ? LIMIT 1";
    if (sqlite3_prepare_v2(ngdb_conn, sql, -1, &st, NULL) != SQLITE_OK) return false;
    sqlite3_bind_blob(st, 1, lo, 4, SQLITE_TRANSIENT);
    if (!top) sqlite3_bind_blob(st, 2, hi, 4, SQLITE_TRANSIENT);
    bool found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}
