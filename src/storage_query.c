/* storage_query - see storage_query.h. */
#include "storage_query.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform/ng_alloc.h"
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

/* "%" + LIKE-escaped pieces + "%" as one owned pattern. */
static char *like_pattern(const char *fmt_a, const char *a, const char *fmt_b, const char *b,
                          const char *fmt_end) {
    char *ea = escape_like(a, strlen(a));
    char *eb = b ? escape_like(b, strlen(b)) : NULL;
    char *out = NULL;
    size_t n;
    if (ea && (eb || !b) &&
        ng_size_add3(strlen(fmt_a) + strlen(fmt_end) + 1, strlen(ea),
                     (b ? strlen(fmt_b) + strlen(eb) : 0), &n) &&
        (out = (char *) malloc(n)) != NULL) {
        snprintf(out, n, "%s%s%s%s%s", fmt_a, ea, b ? fmt_b : "", b ? eb : "", fmt_end);
    }
    free(ea); free(eb);
    return out;
}

/* One exact tag-element match inside the stored tags JSON, for compact and
 * spaced JSON: (tags LIKE ? ESCAPE '\' OR tags LIKE ? ESCAPE '\'). */
static void sq_tag_value(sq_query_t *q, const char *name, const char *value) {
    sq_sql(q, "tags LIKE ? ESCAPE '\\'");
    sq_owned(q, like_pattern("%[\"", name, "\",\"", value, "\"]%"));
    sq_sql(q, " OR tags LIKE ? ESCAPE '\\'");
    sq_owned(q, like_pattern("%[\"", name, "\", \"", value, "\"]%"));
}

/* ----------------------------------------------------------- compiler --- */
ng_status_t sq_build(sq_query_t *q, const filter_t *f, bool do_count, int limit) {
    q->status = NG_OK;
    sq_sql(q, do_count ? "SELECT COUNT(id) FROM event"
                       : "SELECT lower(hex(id)), lower(hex(pubkey)), created_at, kind, tags, content, "
                         "lower(hex(sig)) FROM event");
    const char *sep = " WHERE ";
#define NEXT() (sq_sql(q, sep), sep = " AND ")

    if (f->ids_count > 0) {
        NEXT();
        if (f->ids_count == 1) sq_sql(q, "id = unhex(?)");
        else { sq_sql(q, "id IN ("); sq_list(q, "unhex(?)", f->ids_count); sq_sql(q, ")"); }
        for (size_t i = 0; i < f->ids_count; i++) sq_text(q, f->ids[i]);
    }
    if (f->authors_count > 0) {
        /* NIP-26: {authors: [A]} matches the event pubkey or a delegator,
         * resolved through the indexed delegation side table. */
        NEXT();
        sq_sql(q, "(pubkey IN (");
        sq_list(q, "unhex(?)", f->authors_count);
        sq_sql(q, ") OR id IN (SELECT event_id FROM delegation WHERE delegator IN (");
        sq_list(q, "unhex(?)", f->authors_count);
        sq_sql(q, ")))");
        for (int pass = 0; pass < 2; pass++)
            for (size_t i = 0; i < f->authors_count; i++) sq_text(q, f->authors[i]);
    }
    if (f->kinds_count > 0) {
        NEXT();
        if (f->kinds_count == 1) sq_sql(q, "kind = ?");
        else { sq_sql(q, "kind IN ("); sq_list(q, "?", f->kinds_count); sq_sql(q, ")"); }
        for (size_t i = 0; i < f->kinds_count; i++) sq_int(q, f->kinds[i]);
    }
    if (f->since > 0) {
        char s[48];
        snprintf(s, sizeof(s), "created_at >= %lld", (long long) f->since);
        NEXT(); sq_sql(q, s);
    }
    if (f->until > 0) {
        char s[48];
        snprintf(s, sizeof(s), "created_at <= %lld", (long long) f->until);
        NEXT(); sq_sql(q, s);
    }
    if (f->tags_count > 0) {
        /* AND across tag names, OR across the values of one name. */
        NEXT(); sq_sql(q, "(");
        for (size_t t = 0; t < f->tags_count; t++) {
            const tag_t *tag = &f->tags[t];
            if (t) sq_sql(q, " AND ");
            if (tag->count < 2) { sq_fail(q, NG_E_INVALID); break; }   /* name without values */
            sq_sql(q, "(");
            for (size_t v = 1; v < tag->count; v++) {
                if (v > 1) sq_sql(q, " OR ");
                sq_tag_value(q, tag->elements[0], tag->elements[v]);
            }
            sq_sql(q, ")");
        }
        sq_sql(q, ")");
    }
    if (f->search && f->search[0]) {
        NEXT();
        sq_sql(q, "content LIKE ? ESCAPE '\\'");
        sq_owned(q, like_pattern("%", f->search, NULL, NULL, "%"));
    }
#undef NEXT
    if (!do_count) {
        sq_sql(q, " ORDER BY created_at DESC LIMIT ?");
        sq_int(q, limit);
    }
    return q->status;
}
