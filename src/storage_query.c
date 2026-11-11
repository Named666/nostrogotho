/* storage_query - see storage_query.h. */
#include "storage_query.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform/ng_alloc.h"
#include "platform/ng_platform.h"
#include "storage.h"

/* escape_like - Escape SQL LIKE special characters ('%', '_', '\') with a
 * backslash; the SQL uses ESCAPE '\'.
 * Returns a malloc'd string, or NULL for NULL input, len > 1 MiB or OOM. */
char *escape_like(const char *str, size_t len) {
    if (!str) return NULL;
    if (len > 1024 * 1024) return NULL;   /* cap: allocation attacks */
    size_t count = 0;
    for (size_t i = 0; i < len; i++)
        if (str[i] == '%' || str[i] == '_' || str[i] == '\\') count++;
    size_t sz;   /* one '\\' per escaped byte + NUL */
    if (!ng_size_add3(len, count, 1, &sz)) return NULL;
    char *escaped = (char *) malloc(sz);
    if (!escaped) return NULL;
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        if (str[i] == '%' || str[i] == '_' || str[i] == '\\') escaped[o++] = '\\';
        escaped[o++] = str[i];
    }
    escaped[o] = '\0';
    return escaped;
}

/* ------------------------------------------------------------ buffers --- */
static bool sq_fail(sq_query_t *q, ng_status_t st) {
    if (q->status == NG_OK) q->status = st;
    return false;
}

static bool sq_sql(sq_query_t *q, const char *s) {
    if (q->status != NG_OK) return false;
    size_t n = strlen(s), want;
    if (!ng_size_add3(q->len, n, 1, &want) || want > SQ_MAX_SQL) return sq_fail(q, NG_E_TOOBIG);
    if (want > q->cap) {
        size_t cap = ng_grow_cap(q->cap, want, 512);
        if (cap > SQ_MAX_SQL) cap = SQ_MAX_SQL;
        char *p = (char *) realloc(q->sql, cap);
        if (!p) return sq_fail(q, NG_E_NOMEM);
        q->sql = p; q->cap = cap;
    }
    memcpy(q->sql + q->len, s, n + 1);
    q->len += n;
    return true;
}

static sq_param_t *sq_param(sq_query_t *q) {
    if (q->status != NG_OK) return NULL;
    if (q->n >= SQ_MAX_PARAMS) { sq_fail(q, NG_E_TOOBIG); return NULL; }
    if (q->n == q->pcap) {
        size_t cap = ng_grow_cap(q->pcap, q->n + 1, 16);
        if (cap > SQ_MAX_PARAMS) cap = SQ_MAX_PARAMS;
        sq_param_t *p = (sq_param_t *) ng_realloc_array(q->params, cap, sizeof(*p));
        if (!p) { sq_fail(q, NG_E_NOMEM); return NULL; }
        q->params = p; q->pcap = cap;
    }
    sq_param_t *p = &q->params[q->n++];
    memset(p, 0, sizeof(*p));
    return p;
}

static void sq_int(sq_query_t *q, long long v) {
    sq_param_t *p = sq_param(q);
    if (p) { p->type = SQ_INT; p->num = v; }
}

static void sq_text(sq_query_t *q, char *borrowed) {
    sq_param_t *p = sq_param(q);
    if (p) { p->type = SQ_TEXT; p->text = borrowed; }
}

static void sq_owned(sq_query_t *q, char *owned) {      /* takes owned (NULL = OOM) */
    if (!owned) { sq_fail(q, NG_E_NOMEM); return; }
    sq_param_t *p = sq_param(q);
    if (!p) { free(owned); return; }
    p->type = SQ_TEXT; p->text = owned; p->owned = true;
}

void sq_free(sq_query_t *q) {
    for (size_t i = 0; i < q->n; i++) if (q->params[i].owned) free(q->params[i].text);
    free(q->params);
    free(q->sql);
    memset(q, 0, sizeof(*q));
}

/* "<item>,<item>,...,<item>" n times; n >= 1. */
static void sq_list(sq_query_t *q, const char *item, size_t n) {
    for (size_t i = 0; i < n; i++) { if (i) sq_sql(q, ","); sq_sql(q, item); }
}

bool sq_tag_name_indexable(const char *name) {
    return name && ((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z')) &&
           name[1] == '\0';
}

/* Letters the tag table indexes (tag_index_letters). Set once at startup
 * before any thread runs; read-only afterwards. */
static bool sq_letters[128] = {
    ['e'] = true, ['p'] = true, ['a'] = true, ['q'] = true,
    ['t'] = true, ['d'] = true, ['h'] = true, ['k'] = true,
};
static char sq_letters_str[64] = SQ_TAG_LETTERS_DEFAULT;

bool sq_set_tag_letters(const char *letters) {
    bool set[128] = { false };
    char out[64];
    size_t n = 0;
    if (!letters) return false;
    if (strcmp(letters, "*") == 0) letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (const char *c = letters; *c; c++) {
        if (*c == ',' || *c == ' ') continue;
        char nm[2] = { *c, '\0' };
        if (!sq_tag_name_indexable(nm)) return false;
        if (!set[(unsigned char) *c]) { set[(unsigned char) *c] = true; out[n++] = *c; }
    }
    out[n] = '\0';
    memcpy(sq_letters, set, sizeof(set));
    memcpy(sq_letters_str, out, n + 1);
    return true;
}

const char *sq_tag_letters(void) { return sq_letters_str; }

bool sq_tag_indexed(const char *name) {
    return sq_tag_name_indexable(name) && sq_letters[(unsigned char) name[0]];
}

static NG_THREAD_LOCAL bool sq_overflow;
void sq_set_overflow(bool on) { sq_overflow = on; }

bool sq_is_hex64(const char *s, size_t len) {
    if (len != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

/* One tag value placeholder: 64-char lowercase hex values are stored as
 * 32-byte blobs in the tag table (storage_write.c), everything else as text. */
static void sq_tag_value(sq_query_t *q, char *value) {
    sq_sql(q, sq_is_hex64(value, strlen(value)) ? "unhex(?)" : "?");
    sq_text(q, value);
}

/* "<alias>.name = ? AND <alias>.value IN (...)" for one tag condition. */
static void sq_tag_match(sq_query_t *q, const char *alias, const tag_t *tag) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%s.name = ? AND %s.value ", alias, alias);
    sq_sql(q, buf);
    sq_text(q, tag->elements[0]);
    if (tag->count == 2) { sq_sql(q, "= "); sq_tag_value(q, tag->elements[1]); return; }
    sq_sql(q, "IN (");
    for (size_t v = 1; v < tag->count; v++) {
        if (v > 1) sq_sql(q, ",");
        sq_tag_value(q, tag->elements[v]);
    }
    sq_sql(q, ")");
}

/* Fallback for a tag condition the index cannot answer (a letter outside
 * tag_index_letters, or an event whose tags passed tag_index_max_per_event):
 * scan the stored tags JSON of `alias`. Exact text match on the first
 * value, as NIP-01 requires; slower than the index (one JSON walk per
 * candidate event). */
static void sq_tag_json(sq_query_t *q, const char *alias, const tag_t *tag) {
    char buf[96];
    snprintf(buf, sizeof(buf), "EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(%s.tags) THEN %s.tags", alias, alias);
    sq_sql(q, buf);
    sq_sql(q, " ELSE '[]' END) j WHERE json_extract(j.value, '$[0]') = ? AND json_extract(j.value, '$[1]') ");
    sq_text(q, tag->elements[0]);
    if (tag->count == 2) { sq_sql(q, "= ?"); sq_text(q, tag->elements[1]); }
    else {
        sq_sql(q, "IN (");
        for (size_t v = 1; v < tag->count; v++) { if (v > 1) sq_sql(q, ","); sq_sql(q, "?"); sq_text(q, tag->elements[v]); }
        sq_sql(q, ")");
    }
    sq_sql(q, ")");
}

/* ----------------------------------------------------------- compiler --- */
/* Plain filters scan `event e` (pubkindidx / kindtimeidx / timeidx). Filters
 * with tag conditions are driven by the tag index: the condition with the
 * fewest values is joined (tag t, ordered by its (name, value, created_at,
 * ev) key), the others are EXISTS point lookups on the same key. kinds and
 * the time window are checked on the tag row itself before the join. */
ng_status_t sq_build(sq_query_t *q, const filter_t *f, bool do_count, int limit) {
    return sq_build_mode(q, f, do_count ? SQ_MODE_COUNT : SQ_MODE_ROWS, limit);
}

ng_status_t sq_build_mode(sq_query_t *q, const filter_t *f, sq_mode_t mode, int limit) {
    bool do_count = mode == SQ_MODE_COUNT;
    q->status = NG_OK;
    size_t drive = f->tags_count;
    for (size_t t = 0; t < f->tags_count; t++) {
        const tag_t *tag = &f->tags[t];
        if (tag->count < 2 || !sq_tag_name_indexable(tag->elements[0])) { sq_fail(q, NG_E_INVALID); return q->status; }
        if (!sq_tag_indexed(tag->elements[0])) continue;   /* JSON fallback below */
        if (drive == f->tags_count || tag->count < f->tags[drive].count) drive = t;
    }
    bool tagged = drive < f->tags_count;
    bool multi = tagged && f->tags[drive].count > 2;   /* one event can match several values */
    const char *tc = tagged ? "t." : "e.";             /* created_at / kind source */
    char buf[96];

    if (do_count) sq_sql(q, multi ? "SELECT COUNT(DISTINCT e.seq) FROM " : "SELECT COUNT(*) FROM ");
    else if (mode == SQ_MODE_PUBKEYS) sq_sql(q, multi ? "SELECT DISTINCT e.seq, e.pubkey FROM " : "SELECT e.seq, e.pubkey FROM ");
    else sq_sql(q, multi ? "SELECT DISTINCT " SQ_EVENT_COLUMNS " FROM " : "SELECT " SQ_EVENT_COLUMNS " FROM ");
    if (tagged && sq_overflow) {
        /* Some events carry more tags than tag_index_max_per_event: their
         * unindexed tags are found by the JSON fallback, merged into the
         * driving rows (same ev, created_at, kind shape as the tag table). */
        sq_sql(q, "(SELECT g.ev, g.created_at, g.kind FROM tag g WHERE ");
        sq_tag_match(q, "g", &f->tags[drive]);
        sq_sql(q, " UNION SELECT o.ev, o.created_at, o.kind FROM tag_overflow o JOIN event y ON y.seq = o.ev WHERE ");
        sq_tag_json(q, "y", &f->tags[drive]);
        sq_sql(q, ") t JOIN event e ON e.seq = t.ev");
    } else {
        sq_sql(q, tagged ? "tag t JOIN event e ON e.seq = t.ev" : "event e");
    }
    /* NIP-50: the FTS5 index drives or joins; ranked by bm25 below. */
    char *fts = f->search && ng_search_has_terms(f->search) ? ng_search_fts_query(f->search) : NULL;
    if (f->search && !fts && ng_search_has_terms(f->search)) sq_fail(q, NG_E_NOMEM);
    if (fts) sq_sql(q, " JOIN event_fts ON event_fts.rowid = e.seq");
    const char *sep = " WHERE ";
#define NEXT() (sq_sql(q, sep), sep = " AND ")

    if (tagged && !sq_overflow) { NEXT(); sq_tag_match(q, "t", &f->tags[drive]); }
    if (f->ids_count > 0) {
        NEXT();
        if (f->ids_count == 1) sq_sql(q, "e.id = unhex(?)");
        else { sq_sql(q, "e.id IN ("); sq_list(q, "unhex(?)", f->ids_count); sq_sql(q, ")"); }
        for (size_t i = 0; i < f->ids_count; i++) sq_text(q, f->ids[i]);
    }
    if (f->authors_count > 0) {
        NEXT();
        if (f->authors_count == 1) sq_sql(q, "e.pubkey = unhex(?)");
        else { sq_sql(q, "e.pubkey IN ("); sq_list(q, "unhex(?)", f->authors_count); sq_sql(q, ")"); }
        for (size_t i = 0; i < f->authors_count; i++) sq_text(q, f->authors[i]);
    }
    if (f->kinds_count > 0) {
        NEXT();
        snprintf(buf, sizeof(buf), f->kinds_count == 1 ? "%skind = ?" : "%skind IN (", tc);
        sq_sql(q, buf);
        if (f->kinds_count > 1) { sq_list(q, "?", f->kinds_count); sq_sql(q, ")"); }
        for (size_t i = 0; i < f->kinds_count; i++) sq_int(q, f->kinds[i]);
    }
    if (f->hide_gift_wraps) {
        snprintf(buf, sizeof(buf), "%skind NOT IN (1059, 21059)", tc);
        NEXT(); sq_sql(q, buf);
    }
    if (f->since > 0) {
        snprintf(buf, sizeof(buf), "%screated_at >= %lld", tc, (long long) f->since);
        NEXT(); sq_sql(q, buf);
    }
    if (f->until > 0) {
        snprintf(buf, sizeof(buf), "%screated_at <= %lld", tc, (long long) f->until);
        NEXT(); sq_sql(q, buf);
    }
    for (size_t t = 0; t < f->tags_count; t++) {        /* AND across tag names */
        if (t == drive) continue;
        NEXT();
        if (!sq_tag_indexed(f->tags[t].elements[0])) { sq_tag_json(q, "e", &f->tags[t]); continue; }
        sq_sql(q, sq_overflow ? "(EXISTS (SELECT 1 FROM tag x WHERE " : "EXISTS (SELECT 1 FROM tag x WHERE ");
        sq_tag_match(q, "x", &f->tags[t]);
        sq_sql(q, " AND x.created_at = e.created_at AND x.ev = e.seq)");
        if (sq_overflow) {
            sq_sql(q, " OR (e.seq IN (SELECT ev FROM tag_overflow) AND ");
            sq_tag_json(q, "e", &f->tags[t]);
            sq_sql(q, "))");
        }
    }
    if (fts) { NEXT(); sq_sql(q, "event_fts MATCH ?"); sq_owned(q, fts); }
#undef NEXT
    if (mode == SQ_MODE_ROWS && fts) {
        /* NIP-50: best match first, the limit applies after ranking. */
        sq_sql(q, " ORDER BY event_fts.rank, e.created_at DESC, e.id ASC LIMIT ?");
        sq_int(q, limit);
    } else if (mode == SQ_MODE_ROWS) {
        /* NIP-01: newest first; equal created_at by lowest id first. */
        sq_sql(q, tagged && !multi ? " ORDER BY t.created_at DESC, e.id ASC LIMIT ?"
                                   : " ORDER BY e.created_at DESC, e.id ASC LIMIT ?");
        sq_int(q, limit);
    }
    return q->status;
}
