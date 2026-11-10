#include "platform/ng_platform.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "crypto.h"
#include "json_lite.h"
#include "json_util.h"
#include "nostrogotho.h"
#include "dedupe.h"
#include "relay_conn_internal.h"
#include "relay_core.h"
#include "dedupe.h"
#include "storage.h"
#include "nips/nip01.h"
#include "nips/nip_event.h"
#include "nips/nip_plugin.h"
#include "platform/ng_alloc.h"
#include "ng_config.h"
#include "ratelimit.h"

/* Protocol limits: ng_limits (ng_config.h, nostrogotho.conf). */

/* ============================================================================
 * NIP PLUGIN ARCHITECTURE
 *
 * The core has ZERO knowledge of any specific NIP. Every NIP is a plugin in
 * src/nips/ (*.c) registering hooks via nip_plugin_t; the core walks the
 * registry and invokes the generic hooks (on_connect, on_disconnect,
 * on_message, accept_publish, can_deliver, eose_auth_hint,
 * build_count, timer, info_document).
 * ============================================================================ */

typedef struct sub_entry {
    struct sub_entry *next, **pprev;   /* bucket chain */
    struct subscription *sub;
    const filter_t *filter;
} sub_entry_t;

typedef struct subscription {
    relay_conn_t *connection;
    char *id;
    char *id_json; size_t id_json_len;            /* JSON-encoded id, with quotes */
    filter_t *filters;
    size_t filters_count;
    sub_entry_t *entries; size_t entries_count;   /* index entries */
    uint64_t gen;                                 /* last broadcast delivered */
    struct subscription *shard_prev, *shard_next; /* shard-wide list */
    struct subscription *conn_next;               /* per-connection list */
} subscription_t;

typedef struct {
    subscription_t *subs;
    int count;
    unsigned char ipkey[16];   /* rate-limit key of the peer (ratelimit.h) */
    size_t ipkey_len;          /* 0: unknown peer, never IP-limited */
} core_conn_t;

/* One unit of rate class c for this connection's peer IP. */
static bool ip_allow(relay_conn_t *connection, rl_class_t c) {
    const core_conn_t *cc = (const core_conn_t *) connection->core;
    return !rl_enabled(c) || !cc || !cc->ipkey_len || rl_allow(c, cc->ipkey, cc->ipkey_len);
}

/* Per-shard subscription index. Each filter is indexed under the keys of its
 * most selective exact-match field (ids > authors > single-letter tag values >
 * kinds) or on the wildcard list. An event probes the buckets of its own id,
 * pubkey, tag values and kind plus the wildcard list, so only plausible
 * filters are evaluated; collisions are harmless (full match follows). */
#define IDX_BUCKETS 16384
typedef struct {
    sub_entry_t *buckets[IDX_BUCKETS];
    sub_entry_t *wild;
    uint64_t gen;
    size_t n_subs;
} shard_index_t;

static subscription_t *shard_subs[RELAY_MAX_SHARDS];
static shard_index_t *shard_idx[RELAY_MAX_SHARDS];
static storage_context_t *storage_ctx;
static int min_pow_difficulty;
static time_t created_at_lower_limit;
static time_t created_at_upper_limit;
static char service_url[256];
static bool debug_logging;
static relay_publish_fn publisher;
static relay_admit_fn admission;

/* Per-thread query context for the storage streaming callback. */
static NG_THREAD_LOCAL relay_conn_t *query_connection;
static NG_THREAD_LOCAL filter_t *query_filters;
static NG_THREAD_LOCAL size_t query_filters_count;
static NG_THREAD_LOCAL size_t query_bytes;
static NG_THREAD_LOCAL bool query_render_failed;   /* a stored row could not be rendered */
static size_t query_bytes_max;    /* 0 = unlimited */
void relay_core_set_query_bytes_max(size_t n) { query_bytes_max = n; }

void relay_core_set_debug(bool enabled) { debug_logging = enabled; }
bool relay_core_debug(void) { return debug_logging; }
storage_context_t *relay_core_storage(void) { return storage_ctx; }
void relay_core_set_publisher(relay_publish_fn fn) { publisher = fn; }
void relay_core_set_admission(relay_admit_fn fn) { admission = fn; }

static void log_message(relay_conn_t *connection, const char *fmt, ...) {
    va_list args;
    if (!debug_logging) return;
    time_t now = time(NULL);
    struct tm tmv;
    char stamp[32];
    if (localtime_r(&now, &tmv) && strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tmv))
        fprintf(stdout, "[%s] ", stamp);
    if (connection) fprintf(stdout, "peer=%s ", relay_conn_peer(connection));
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fputc('\n', stdout);
    fflush(stdout);
}

static core_conn_t *core_of(relay_conn_t *conn) { return (core_conn_t *) conn->core; }

/* ------------------------------------------------------------ index ---- */
static uint64_t key_hash(char type, const char *s, size_t n) {
    uint64_t h = 1469598103934665603ull ^ (uint64_t) (unsigned char) type;
    h *= 1099511628211ull;
    for (size_t i = 0; i < n; i++) { h ^= (unsigned char) s[i]; h *= 1099511628211ull; }
    return h ^ (h >> 29);
}
static uint64_t kind_hash(int kind) { char b[16]; int n = snprintf(b, sizeof(b), "%d", kind); return key_hash('k', b, (size_t) n); }

static shard_index_t *index_of(int shard) {
    if (!shard_idx[shard]) shard_idx[shard] = (shard_index_t *) calloc(1, sizeof(shard_index_t));
    return shard_idx[shard];
}

static void entry_link(sub_entry_t **head, sub_entry_t *e) {
    e->next = *head; e->pprev = head;
    if (*head) (*head)->pprev = &e->next;
    *head = e;
}
static void entry_unlink(sub_entry_t *e) {
    if (!e->pprev) return;
    *e->pprev = e->next;
    if (e->next) e->next->pprev = e->pprev;
    e->next = NULL; e->pprev = NULL;
}

static bool all_len(char **v, size_t n, size_t want) {
    for (size_t i = 0; i < n; i++) if (strlen(v[i]) != want) return false;
    return n > 0;
}

/* Number of index keys a filter is stored under; the keys are written to
 * keys when it is not NULL. Every value of the chosen field is a key (a
 * filter must be found by any of its values), 0 = wildcard. */
static size_t filter_keys(const filter_t *f, uint64_t *keys) {
    size_t n = 0;
    if (f->ids_count && all_len(f->ids, f->ids_count, 64)) {
        for (size_t i = 0; i < f->ids_count; i++, n++) if (keys) keys[n] = key_hash('i', f->ids[i], 64);
        return n;
    }
    if (f->authors_count && all_len(f->authors, f->authors_count, 64)) {
        for (size_t i = 0; i < f->authors_count; i++, n++) if (keys) keys[n] = key_hash('a', f->authors[i], 64);
        return n;
    }
    for (size_t t = 0; t < f->tags_count; t++) {
        const tag_t *tg = &f->tags[t];
        if (tg->count < 2 || strlen(tg->elements[0]) != 1) continue;
        for (size_t v = 1; v < tg->count; v++, n++)
            if (keys) keys[n] = key_hash((char) (tg->elements[0][0] | 0x80), tg->elements[v], strlen(tg->elements[v]));
        return n;
    }
    for (size_t i = 0; i < f->kinds_count; i++, n++) if (keys) keys[n] = kind_hash(f->kinds[i]);
    return n;
}

/* Index s under its filters' keys. false on OOM: s is then not indexed
 * (entries == NULL) and the caller must not keep it. */
static bool index_add(int shard, subscription_t *s) {
    shard_index_t *ix = index_of(shard);
    if (!ix) return false;
    size_t total = 0, most = 0;
    for (size_t i = 0; i < s->filters_count; i++) {
        size_t nk = filter_keys(&s->filters[i], NULL);
        if (nk > most) most = nk;
        if (!ng_size_add(total, nk ? nk : 1, &total)) return false;
    }
    uint64_t *keys = (uint64_t *) ng_malloc_array(most ? most : 1, sizeof(uint64_t));
    s->entries = keys ? (sub_entry_t *) calloc(total ? total : 1, sizeof(sub_entry_t)) : NULL;
    if (!s->entries) { free(keys); return false; }
    size_t e = 0;
    for (size_t i = 0; i < s->filters_count; i++) {
        size_t nk = filter_keys(&s->filters[i], keys);
        if (!nk) { s->entries[e].sub = s; s->entries[e].filter = &s->filters[i]; entry_link(&ix->wild, &s->entries[e]); e++; continue; }
        for (size_t k = 0; k < nk; k++) {
            s->entries[e].sub = s; s->entries[e].filter = &s->filters[i];
            entry_link(&ix->buckets[keys[k] & (IDX_BUCKETS - 1)], &s->entries[e]);
            e++;
        }
    }
    free(keys);
    s->entries_count = e;
    ix->n_subs++;
    return true;
}

static void index_del(int shard, subscription_t *s) {
    if (!s->entries) return;                 /* never indexed */
    for (size_t i = 0; i < s->entries_count; i++) entry_unlink(&s->entries[i]);
    free(s->entries); s->entries = NULL; s->entries_count = 0;
    if (shard_idx[shard] && shard_idx[shard]->n_subs) shard_idx[shard]->n_subs--;
}

/* ------------------------------------------------------- event tags ---- */
bool relay_tags_parse(const event_t *ev, relay_tags_t *out) {
    memset(out, 0, sizeof(*out));
    if (!ev->tags_json || !ev->tags_json[0]) return true;
    jstr_t tags = jl_str(ev->tags_json), k, tag;
    size_t o = 0, cap = 0;
    while ((o = jl_next(tags, o, &k, &tag)) != 0) cap++;
    if (!cap) return true;
    size_t store_len;   /* unescaped names/values never exceed the JSON, + 2 NULs per tag */
    if (!ng_size_flex(strlen(ev->tags_json) + 1, cap, 2, &store_len)) return false;
    out->p = (relay_tagpair_t *) ng_malloc_array(cap, sizeof(relay_tagpair_t));
    out->store = (char *) malloc(store_len);
    if (!out->p || !out->store) { free(out->p); free(out->store); out->p = NULL; out->store = NULL; return false; }
    size_t so = 0; o = 0;
    while ((o = jl_next(tags, o, &k, &tag)) != 0) {
        jstr_t kk, n, v; size_t to = 0;
        if ((to = jl_next(tag, 0, &kk, &n)) == 0) continue;
        if (jl_next(tag, to, &kk, &v) == 0) { v.buf = NULL; v.len = 0; }
        if (!n.buf || n.buf[0] != '"') continue;
        size_t nl;
        if (!jl_unescape(n, out->store + so, &nl)) continue;
        relay_tagpair_t *tp = &out->p[out->n];
        tp->name = out->store + so; tp->nlen = nl; so += nl; out->store[so++] = '\0';
        tp->val = NULL; tp->vlen = 0;
        if (v.buf && v.buf[0] == '"') {
            size_t vl;
            if (jl_unescape(v, out->store + so, &vl)) { tp->val = out->store + so; tp->vlen = vl; so += vl; out->store[so++] = '\0'; }
        }
        out->n++;
    }
    return true;
}
void relay_tags_free(relay_tags_t *t) { free(t->p); free(t->store); memset(t, 0, sizeof(*t)); }

static bool tags_have(const relay_tags_t *t, const char *name, const char *value) {
    size_t nl = strlen(name), vl = strlen(value);
    for (size_t i = 0; i < t->n; i++)
        if (t->p[i].nlen == nl && t->p[i].val && t->p[i].vlen == vl &&
            memcmp(t->p[i].name, name, nl) == 0 && memcmp(t->p[i].val, value, vl) == 0) return true;
    return false;
}


static void subscription_free(subscription_t *s) {
    for (size_t i = 0; i < s->filters_count; i++) filter_release(&s->filters[i]);
    free(s->filters); free(s->id); free(s->id_json); free(s->entries); free(s);
}

static void shard_unlink(int shard, subscription_t *s) {
    index_del(shard, s);
    if (s->shard_prev) s->shard_prev->shard_next = s->shard_next;
    else shard_subs[shard] = s->shard_next;
    if (s->shard_next) s->shard_next->shard_prev = s->shard_prev;
}

/* Remove subscriptions of `connection` (all, or only `id`). */
static void remove_subscriptions(relay_conn_t *connection, const char *id) {
    core_conn_t *cc = core_of(connection);
    if (!cc) return;
    subscription_t **link = &cc->subs;
    while (*link) {
        subscription_t *s = *link;
        if (!id || strcmp(s->id, id) == 0) {
            *link = s->conn_next;
            shard_unlink(connection->shard, s);
            subscription_free(s);
            cc->count--;
        } else link = &s->conn_next;
    }
}

/* live: also apply the NIP-50 search terms. Stored rows skip them: the
 * FTS5 index already selected the row (and folds more than ASCII), and a
 * row matched by one filter's SQL is delivered whatever the others say. */
static bool matches_filter(const filter_t *filter, const event_t *event, const relay_tags_t *tags,
                           bool live) {
    if (filter->since && event->created_at < filter->since) return false;
    if (filter->until && event->created_at > filter->until) return false;
    if (filter->kinds_count) {
        bool matched = false;
        for (size_t i = 0; i < filter->kinds_count && !matched; i++) if (event->kind == filter->kinds[i]) matched = true;
        if (!matched) return false;
    }
    if (filter->ids_count) {
        bool matched = false;
        for (size_t i = 0; i < filter->ids_count && !matched; i++) if (strncmp(event->id, filter->ids[i], strlen(filter->ids[i])) == 0) matched = true;
        if (!matched) return false;
    }
    if (filter->authors_count) {
        bool matched = false;
        for (size_t i = 0; i < filter->authors_count && !matched; i++) if (strncmp(event->pubkey, filter->authors[i], strlen(filter->authors[i])) == 0) matched = true;
        if (!matched) return false;
    }
    for (size_t i = 0; i < filter->tags_count; i++) {
        bool matched = false;
        tag_t *tag = &filter->tags[i];
        for (size_t j = 1; j < tag->count && !matched; j++) {
            if (tags ? tags_have(tags, tag->elements[0], tag->elements[j])
                     : nip_event_has_tag(event, tag->elements[0], tag->elements[j])) matched = true;
        }
        if (!matched) return false;
    }
    if (live && filter->search &&
        !ng_search_match(filter->search, event->kind, event->content, event->content_len)) return false;
    return true;
}

static bool plugins_accept_publish(relay_conn_t *connection, const event_t *event,
                                   char *reason, size_t reason_size) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->accept_publish && !plugin->accept_publish(connection, event, reason, reason_size, plugin->ctx)) {
            if (!reason[0]) snprintf(reason, reason_size, "invalid: event not accepted");
            return false;
        }
    }
    return true;
}

static bool plugins_accept_query(relay_conn_t *connection, filter_t *filters, size_t count,
                                 bool is_count, char *reason, size_t reason_size) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->accept_query &&
            !plugin->accept_query(connection, filters, count, is_count, reason, reason_size, plugin->ctx)) {
            if (!reason[0]) snprintf(reason, reason_size, "restricted: query not allowed");
            return false;
        }
    }
    return true;
}

static int plugins_count_hll_offset(const filter_t *filters, size_t count) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next)
        if (plugin->count_hll_offset) return plugin->count_hll_offset(filters, count, plugin->ctx);
    return -1;
}

static bool plugins_can_deliver(const event_t *event, relay_conn_t *connection) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->can_deliver && !plugin->can_deliver(event, connection, plugin->ctx)) return false;
    }
    return true;
}

relay_bcast_t *relay_bcast_new(event_t *ev) {
    relay_bcast_t *b = (relay_bcast_t *) calloc(1, sizeof(*b));
    if (!b) { event_release(ev); return NULL; }   /* ev is consumed either way */
    b->ev = *ev;                       /* ownership of tags/content moves */
    json_builder_t *body = json_builder_scratch(JSON_SCRATCH_BCAST);
    json_serialize_event(&b->ev, body);
    const char *j = json_builder_finish(body);    /* "[{...}]", NULL on OOM / cap */
    size_t jl = j ? json_builder_length(body) : 0;
    b->body = jl >= 2 ? relay_body_new(j + 1, jl - 2) : NULL;
    bool tags_ok = relay_tags_parse(&b->ev, &b->tags);
    if (!b->body || !tags_ok) { relay_bcast_free(b); return NULL; }   /* never fan out partial tags */
    return b;
}

void relay_bcast_free(relay_bcast_t *b) {
    if (!b) return;
    relay_body_release(b->body);
    relay_tags_free(&b->tags);
    event_release(&b->ev);
    free(b);
}

static void probe(shard_index_t *ix, sub_entry_t *e, const relay_bcast_t *b) {
    for (; e; e = e->next) {
        subscription_t *s = e->sub;
        if (s->gen == ix->gen) continue;
        if (!matches_filter(e->filter, &b->ev, &b->tags, true)) continue;
        s->gen = ix->gen;                       /* at most once per subscription */
        if (!plugins_can_deliver(&b->ev, s->connection)) continue;
        relay_conn_send_event(s->connection, s->id_json, s->id_json_len, b->body);
    }
}

/* Match one event against the subscriptions of `shard` (owner thread only). */
void relay_core_broadcast_shard(int shard, const relay_bcast_t *b) {
    shard_index_t *ix = shard_idx[shard];
    if (!ix || !ix->n_subs) return;
    ix->gen++;
    const event_t *ev = &b->ev;
    probe(ix, ix->buckets[key_hash('i', ev->id, strlen(ev->id)) & (IDX_BUCKETS - 1)], b);
    probe(ix, ix->buckets[key_hash('a', ev->pubkey, strlen(ev->pubkey)) & (IDX_BUCKETS - 1)], b);
    for (size_t i = 0; i < b->tags.n; i++) {
        const relay_tagpair_t *t = &b->tags.p[i];
        if (t->nlen != 1 || !t->val) continue;
        probe(ix, ix->buckets[key_hash((char) (t->name[0] | 0x80), t->val, t->vlen) & (IDX_BUCKETS - 1)], b);
    }
    probe(ix, ix->buckets[kind_hash(ev->kind) & (IDX_BUCKETS - 1)], b);
    probe(ix, ix->wild, b);
}

static void query_sender(const char *json, const event_t *event) {
    if (!query_connection || !event) return;
    if (!json) { query_render_failed = true; return; }   /* storage could not render the row */
    relay_tags_t tags;
    if (!relay_tags_parse(event, &tags)) return;   /* OOM: tag filters cannot be evaluated; skip */
    bool matched = false;
    for (size_t i = 0; i < query_filters_count && !matched; i++)
        if (matches_filter(&query_filters[i], event, &tags, false)) matched = true;
    relay_tags_free(&tags);
    if (matched && plugins_can_deliver(event, query_connection)) {
        size_t n = strlen(json);
        /* Byte budget per stored-event reply: a REQ may not queue more than
         * the connection's output budget allows in one burst; the rest is
         * dropped and the reply still ends with EOSE (clients paginate). */
        if (query_bytes_max && query_bytes + n > query_bytes_max) return;
        query_bytes += n;
        relay_conn_send(query_connection, json, n);
    }
}

/* Stored-event phase of a REQ/COUNT. false when the query was refused or
 * failed: CLOSED (with the NIP-01 reason) was sent instead of EOSE/COUNT
 * and the caller must drop the subscription. */
static bool query_events(relay_conn_t *connection, const char *sub,
                         filter_t *filters, size_t count, bool do_count) {
    int total_count = 0;
    query_connection = connection;
    query_bytes = 0;
    query_render_failed = false;
    query_filters = filters;
    query_filters_count = count;
    uint8_t hll[256];
    bool have_hll = false;
    int hll_offset = do_count && storage_ctx->count_hll ? plugins_count_hll_offset(filters, count) : -1;
    ng_status_t st;
    if (hll_offset >= 0 && count == 1) {
        st = storage_ctx->count_hll(&filters[0], hll_offset, &total_count, hll);
        have_hll = st == NG_OK;
    } else {
        st = storage_ctx->send_records(query_sender, sub, filters, count, do_count, &total_count);
    }
    query_connection = NULL;
    query_filters = NULL;
    query_filters_count = 0;
    if (st != NG_OK) {
        nip_plugin_send_status(connection, "CLOSED", sub, false,
            st == NG_E_TOOBIG ? "error: query too complex (see NIP-11 limitation)"
          : st == NG_E_NOMEM ? "error: server unavailable (out of memory)"
                             : "error: query failed");
        return false;
    }

    char *response = NULL;
    if (do_count) {
        for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
            if (plugin->build_count) { response = plugin->build_count(sub, (unsigned long) total_count, have_hll ? hll : NULL, plugin->ctx); break; }
        }
        if (!response) {
            json_builder_t builder;
            json_builder_start(&builder);
            json_builder_append_string(&builder, "COUNT");
            json_builder_append_string(&builder, sub);
            json_builder_start_object(&builder);
            json_builder_object_key_number(&builder, "count", (long long) total_count);
            json_builder_end_object(&builder);
            const char *j = json_builder_finish(&builder);
            response = j ? string_dup(j) : NULL;
            json_builder_free(&builder);
        }
    } else {
        /* Hook kept for its side effect (NIP-17 sends an AUTH challenge). */
        for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next)
            if (plugin->eose_auth_hint && plugin->eose_auth_hint(connection, filters, count, plugin->ctx)) break;
        {
            json_builder_t builder;
            json_builder_start(&builder);
            json_builder_append_string(&builder, "EOSE");
            json_builder_append_string(&builder, sub);  /* NIP-01: ["EOSE",<sub_id>] */
            const char *j = json_builder_finish(&builder);
            response = j ? string_dup(j) : NULL;
            json_builder_free(&builder);
        }
    }
    if (query_render_failed)
        nip_plugin_send_json(connection, "[\"NOTICE\",\"error: some stored events could not be sent (out of memory)\"]");
    if (response) {
        nip_plugin_send_json(connection, response);
        free(response);
    } else {
        nip_plugin_send_json(connection, "[\"NOTICE\",\"error: could not build query response (out of memory)\"]");
    }
    return true;
}

static void release_filters(filter_t *filters, size_t n);

/* Parse a REQ/COUNT's filters. Accepted layouts:
 *   ["REQ"/"COUNT", id, {filter1}, {filter2}, ...]   (standard)
 *   ["REQ"/"COUNT", id, [{filter1}, {filter2}]]      (wrapped array)
 * NULL on success (*out owns *out_count >= 1 filters), else the NIP-01
 * reason for CLOSED: one bad filter or a breached complexity limit rejects
 * the whole request (never a silently narrowed subscription). */
static const char *collect_filters(json_value_t *values, size_t count, filter_t **out, size_t *out_count) {
    json_value_t inner[MAX_JSON_ARRAY_ELEMENTS] = {{0}};
    size_t inner_count = 0;
    json_value_t *list = values + 2;
    size_t n = count > 2 ? count - 2 : 0;
    if (count == 3 && values[2].type == JSON_TYPE_ARRAY) {
        inner_count = json_array_parse(values[2].value.string_val, inner, MAX_JSON_ARRAY_ELEMENTS);
        list = inner; n = inner_count;
    }
    const char *why = NULL;
    filter_t *filters = NULL;
    size_t got = 0, authors = 0;
    if (n == 0) why = "invalid: no filters";
    else if (n > (size_t) ng_limits.max_filters) why = "error: too many filters (see NIP-11 limitation)";
    else if (!(filters = (filter_t *) calloc(n, sizeof(*filters)))) why = "error: server unavailable";
    for (size_t i = 0; !why && i < n; i++) {
        if (list[i].type != JSON_TYPE_OBJECT) { why = "invalid: filters must be objects"; break; }
        if (!json_parse_filter_why(list[i].value.string_val, &filters[got], &why)) break;
        if (!ng_limits.search && filters[got].search) {
            why = "unsupported: search (NIP-50) is disabled on this relay";
            got++;
            break;
        }
        authors += filters[got++].authors_count;
        if (authors > (size_t) ng_limits.max_req_authors) why = "error: too many authors in one request (see NIP-11 limitation)";
    }
    if (inner_count) json_array_free(inner, inner_count);
    if (why) { if (filters) release_filters(filters, got); return why; }
    *out = filters; *out_count = got;
    return NULL;
}

static void release_filters(filter_t *filters, size_t n) {
    for (size_t i = 0; i < n; i++) filter_release(&filters[i]);
    free(filters);
}

static void handle_req(relay_conn_t *connection, json_value_t *values, size_t count, bool do_count) {
    const char *sub = json_array_get_string(values, count, 1);
    filter_t *filters = NULL;
    size_t filter_count = 0;
    if (!sub || !*sub || strlen(sub) > (size_t) ng_limits.max_subid_length) {
        nip_plugin_send_status(connection, "CLOSED", sub, false, "invalid: subscription id must be 1 to max_subid_length characters"); return;
    }
    if (!ip_allow(connection, RL_REQ_IP)) {
        nip_plugin_send_status(connection, "CLOSED", sub, false, "rate-limited: too many requests from your IP, slow down");
        return;
    }
    const char *bad = count < 3 ? "invalid: no filters" : collect_filters(values, count, &filters, &filter_count);
    if (bad) { nip_plugin_send_status(connection, "CLOSED", sub, false, bad); return; }
    const char *why = NULL;
    if (admission && !admission(connection, RELAY_ADMIT_REQ, &why)) {
        release_filters(filters, filter_count);
        nip_plugin_send_status(connection, "CLOSED", sub, false, why); return;
    }
    char reason[256] = {0};
    if (!plugins_accept_query(connection, filters, filter_count, do_count, reason, sizeof(reason))) {
        release_filters(filters, filter_count);
        nip_plugin_send_status(connection, "CLOSED", sub, false, reason); return;
    }
    if (do_count) {
        (void) query_events(connection, sub, filters, filter_count, true);
        release_filters(filters, filter_count);
        return;
    }
    core_conn_t *cc = core_of(connection);
    int others = 0;
    for (subscription_t *s = cc->subs; s; s = s->conn_next) if (strcmp(s->id, sub) != 0) others++;
    if (others >= ng_limits.max_subscriptions) {
        release_filters(filters, filter_count);
        nip_plugin_send_status(connection, "CLOSED", sub, false, "error: too many subscriptions"); return;
    }
    remove_subscriptions(connection, sub);
    subscription_t *s = (subscription_t *) calloc(1, sizeof(*s));
    if (!s || !(s->id = string_dup(sub))) {
        free(s); release_filters(filters, filter_count);
        nip_plugin_send_status(connection, "CLOSED", sub, false, "error: server unavailable"); return;
    }
    s->connection = connection; s->filters = filters; s->filters_count = filter_count;
    {
        json_builder_t jb; json_builder_start(&jb); json_builder_append_string(&jb, sub);
        const char *j = json_builder_finish(&jb);        /* ["<escaped>"] */
        size_t jl = j ? json_builder_length(&jb) : 0;
        if (jl >= 2) {
            s->id_json_len = jl - 2;
            s->id_json = (char *) malloc(jl - 1);
            if (s->id_json) { memcpy(s->id_json, j + 1, jl - 2); s->id_json[jl - 2] = '\0'; }
        }
        json_builder_free(&jb);
    }
    if (!s->id_json) {
        free(s->id); free(s); release_filters(filters, filter_count);
        nip_plugin_send_status(connection, "CLOSED", sub, false, "error: server unavailable"); return;
    }
    int shard = connection->shard;
    if (!index_add(shard, s)) {
        subscription_free(s);                    /* owns filters now */
        nip_plugin_send_status(connection, "CLOSED", sub, false, "error: server unavailable"); return;
    }
    s->conn_next = cc->subs; cc->subs = s; cc->count++;
    s->shard_next = shard_subs[shard];
    if (s->shard_next) s->shard_next->shard_prev = s;
    shard_subs[shard] = s;
    if (!query_events(connection, sub, filters, filter_count, false))
        remove_subscriptions(connection, sub);          /* CLOSED was sent */
}

nip01_process_result_t relay_core_commit_event(relay_conn_t *conn, const event_t *event) {
    return nip01_dispatch_event(conn, event, storage_ctx, service_url);
}

/* ---- relay-generated events (writer thread) ---------------------------- */

#define EMIT_MAX 256
static NG_THREAD_LOCAL relay_bcast_t *emits[EMIT_MAX];
static NG_THREAD_LOCAL size_t n_emits;

bool relay_core_emit(event_t *ev) {
    bool ok = n_emits < EMIT_MAX && storage_ctx && crypto_sign_event(ev);
    bool repl = ev->kind == 0 || ev->kind == 3 || (ev->kind >= 10000 && ev->kind < 20000);
    bool addr = ev->kind >= 30000 && ev->kind < 40000;
    if (ok && (repl || addr) && storage_ctx->replaceable_admit) {
        char *d = addr ? nip_event_tag_value(ev, "d") : NULL;
        ok = storage_ctx->replaceable_admit(ev, addr ? (d ? d : "") : NULL) == STORAGE_ADMIT_NEWEST;
        free(d);
    }
    if (ok) ok = storage_ctx->insert_event(ev) == STORAGE_PUT_INSERTED;
    if (ok) dedupe_forget(ev->id);
    relay_bcast_t *b = relay_bcast_new(ev);           /* consumes ev */
    if (!ok || !b) { relay_bcast_free(b); return false; }
    emits[n_emits++] = b;
    return true;
}

size_t relay_core_take_emits(relay_bcast_t **out, size_t cap) {
    size_t n = n_emits < cap ? n_emits : cap;
    memcpy(out, emits, n * sizeof(*out));
    for (size_t i = n; i < n_emits; i++) relay_bcast_free(emits[i]);
    n_emits = 0;
    return n;
}

void relay_core_drop_emits(void) {
    for (size_t i = 0; i < n_emits; i++) relay_bcast_free(emits[i]);
    n_emits = 0;
}

void relay_core_dedupe_settle(const event_t *event, const nip01_process_result_t *r) {
    if (event->kind >= 20000 && event->kind < 30000) return;
    /* Stored, already present, superseded or tombstoned: remember the id.
     * Anything else (errors, policy rejects, rollback) frees it for a retry. */
    if (r->accepted || strncmp(r->response_msg, "blocked: this event was deleted", 31) == 0)
        dedupe_resolve(event->id);
    else dedupe_release(event->id);
}

void relay_core_send_ok(relay_conn_t *conn, const event_t *event, const nip01_process_result_t *result) {
    nip_plugin_send_status(conn, "OK", event->id, result->accepted, result->response_msg);
}

static void handle_event(relay_conn_t *connection, json_value_t *values, size_t count) {
    event_t event;
    char reject_reason[256] = {0};

    const char *bad = NULL;
    if (count != 2 || values[1].type != JSON_TYPE_OBJECT || !json_parse_event_why(values[1].value.string_val, &event, &bad)) {
        /* NIP-01: answer OK false when the event names an id, else NOTICE. */
        char hint[MAX_ID_SIZE + 1];
        if (count == 2 && values[1].type == JSON_TYPE_OBJECT && json_event_id_hint(values[1].value.string_val, hint))
            nip_plugin_send_status(connection, "OK", hint, false, bad ? bad : "invalid: malformed event");
        else
            nip_plugin_send_status(connection, "NOTICE", NULL, false, bad ? bad : "invalid: malformed event");
        return;
    }
    log_message(connection, "event kind=%d id=%.*s pubkey=%.*s created_at=%lld",
                event.kind, (int) sizeof(event.id), event.id,
                (int) sizeof(event.pubkey), event.pubkey, (long long) event.created_at);

    const char *why = NULL;
    if (admission && !admission(connection, RELAY_ADMIT_EVENT, &why)) {
        nip_plugin_send_status(connection, "OK", event.id, false, why);
        event_release(&event);
        return;
    }

    /* Cheap refusals first: before the id hash and the signature check. */
    if (rl_pubkey_banned(event.pubkey)) {
        nip_plugin_send_status(connection, "OK", event.id, false, "blocked: this pubkey is banned from this relay");
        event_release(&event);
        return;
    }
    if (!ip_allow(connection, RL_EVENT_IP)) {
        nip_plugin_send_status(connection, "OK", event.id, false, "rate-limited: too many events from your IP, slow down");
        event_release(&event);
        return;
    }

    /* Ephemeral kinds are never stored, so they are exempt from dedupe. */
    bool guarded = !(event.kind >= 20000 && event.kind < 30000);

    /* CPU-bound, stateless: id hash, schnorr signature, size, timestamps. */
    nip01_process_result_t result = nip01_precheck_event(&event, ng_limits.max_content_length,
        created_at_lower_limit, created_at_upper_limit, min_pow_difficulty);
    /* Per pubkey only once the signature proved the author (a forger must
     * not be able to spend someone else's budget). */
    if (result.accepted && !rl_allow(RL_EVENT_PUBKEY, event.pubkey, 64)) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "%s",
                 "rate-limited: too many events from this pubkey, slow down");
    }
    if (result.accepted && !plugins_accept_publish(connection, &event, reject_reason, sizeof(reject_reason))) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg), "%s", reject_reason);
    }
    if (!result.accepted) {
        relay_core_send_ok(connection, &event, &result);
        event_release(&event);
        return;
    }

    /* Claim the (now verified) id; a copy verified concurrently on another
     * worker loses the race here and is answered as a duplicate. */
    if (guarded && !dedupe_claim(event.id)) {
        nip_plugin_send_status(connection, "OK", event.id, true, "duplicate: already have this event");
        event_release(&event);
        return;
    }

    if (publisher) {
        relay_bcast_t *b = relay_bcast_new(&event);   /* takes ownership */
        if (!b) {
            dedupe_release(event.id);
            nip_plugin_send_status(connection, "OK", event.id, false, "error: out of memory");
            return;
        }
        relay_conn_retain(connection); /* released by the writer */
        publisher(connection, b);
        return;
    }

    result = relay_core_commit_event(connection, &event);
    if (guarded) relay_core_dedupe_settle(&event, &result);
    relay_core_send_ok(connection, &event, &result);
    {
        relay_bcast_t *em[EMIT_MAX];
        size_t m = relay_core_take_emits(em, EMIT_MAX);
        for (size_t i = 0; i < m; i++) { relay_core_broadcast_shard(0, em[i]); relay_bcast_free(em[i]); }
    }
    if (result.accepted && result.should_broadcast && !result.duplicate) {
        relay_bcast_t *b = relay_bcast_new(&event);       /* takes ownership */
        if (b) { relay_core_broadcast_shard(0, b); relay_bcast_free(b); }
        return;
    }
    event_release(&event);
}

void relay_core_on_message(relay_conn_t *connection, char *payload, size_t len) {
    json_value_t values[MAX_JSON_ARRAY_ELEMENTS] = {{0}};
    size_t count; const char *method;
    if (len > ng_limits.max_message_length) { nip_plugin_send_status(connection, "NOTICE", NULL, false, "error: message too large"); return; }
    log_message(connection, "recv: %s", payload);
    count = json_array_parse(payload, values, MAX_JSON_ARRAY_ELEMENTS);
    method = json_array_get_string(values, count, 0);

    bool consumed = false;
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->on_message && plugin->on_message(connection, values, count, plugin->ctx)) { consumed = true; break; }
    }
    if (!consumed) {
        if (!method || count < 2) nip_plugin_send_status(connection, "NOTICE", NULL, false, "error: invalid request");
        else if (strcmp(method, "REQ") == 0) handle_req(connection, values, count, false);
        else if (strcmp(method, "COUNT") == 0) handle_req(connection, values, count, true);
        else if (strcmp(method, "CLOSE") == 0) { const char *sub = json_array_get_string(values, count, 1); if (sub) remove_subscriptions(connection, sub); }
        else if (strcmp(method, "EVENT") == 0) handle_event(connection, values, count);
        else nip_plugin_send_status(connection, "NOTICE", NULL, false, "error: invalid request");
    }
    json_array_free(values, count);
}

void relay_core_on_open(relay_conn_t *connection) {
    connection->core = calloc(1, sizeof(core_conn_t));
    if (!connection->core) {             /* cannot serve it: say so and close */
        nip_plugin_send_status(connection, "NOTICE", NULL, false, "error: server unavailable");
        relay_conn_close(connection);
        return;
    }
    core_conn_t *cc = (core_conn_t *) connection->core;
    cc->ipkey_len = rl_peer_key(connection->peer, cc->ipkey);
    log_message(connection, "client connected (websocket open)");
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->on_connect) plugin->on_connect(connection, plugin->ctx);
    }
    /* After on_connect so every plugin sees the usual connect/disconnect pair. */
    if (rl_peer_banned(connection->peer)) {
        nip_plugin_send_status(connection, "NOTICE", NULL, false, "blocked: your IP is banned from this relay");
        relay_conn_close(connection);
    }
}

void relay_core_on_close(relay_conn_t *connection) {
    log_message(connection, "client disconnected");
    remove_subscriptions(connection, NULL);
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->on_disconnect) plugin->on_disconnect(connection, plugin->ctx);
    }
    free(connection->core);
    connection->core = NULL;
}

const char *relay_core_info_document(void) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->info_document) return plugin->info_document(plugin->ctx);
    }
    return NULL;
}

unsigned relay_core_timer_interval(void) {
    unsigned interval = 0;
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->timer && (interval == 0 || plugin->timer_interval_ms < interval)) interval = plugin->timer_interval_ms;
    }
    return interval;
}

void relay_core_run_timers(void) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->timer) plugin->timer(storage_ctx, plugin->ctx);
    }
}

void relay_core_configure(storage_context_t *storage, const char *relay_url, int min_pow,
                          time_t lower_limit, time_t upper_limit) {
    {
        const char *v = getenv("NG_DEDUPE_RECENT");
        static bool dedupe_ready;
        if (!dedupe_ready) { dedupe_init(v ? (size_t) strtoull(v, NULL, 10) : 131072); dedupe_ready = true; }
    }
    storage_ctx = storage; min_pow_difficulty = min_pow < 0 ? 0 : min_pow;
    snprintf(service_url, sizeof(service_url), "%s", relay_url ? relay_url : "");
    created_at_lower_limit = lower_limit < 0 ? 0 : lower_limit;
    created_at_upper_limit = upper_limit < 0 ? 0 : upper_limit;

    relay_config_t config;
    memset(&config, 0, sizeof(config));
    config.service_url = service_url;
    config.storage = storage;
    config.max_message_length = (int) ng_limits.max_message_length;
    config.max_subscriptions = ng_limits.max_subscriptions;
    config.max_filters = ng_limits.max_filters;
    config.max_subid_length = ng_limits.max_subid_length;
    config.max_event_tags = ng_limits.max_event_tags;
    config.max_content_length = (int) ng_limits.max_content_length;
    config.min_pow_difficulty = min_pow_difficulty;
    config.max_limit = ng_limits.max_limit;
    config.default_limit = ng_limits.default_limit;
    config.created_at_lower_limit = created_at_lower_limit;
    config.created_at_upper_limit = created_at_upper_limit;
    config.auth_required = false;
    config.restricted_writes = false;
    nip_plugins_init(&config);
}

void relay_core_shutdown(void) {
    for (int i = 0; i < RELAY_MAX_SHARDS; i++) {
        while (shard_subs[i]) {
            subscription_t *s = shard_subs[i];
            shard_subs[i] = s->shard_next;
            subscription_free(s);
        }
        free(shard_idx[i]); shard_idx[i] = NULL;
    }
}

/* server.h compatibility (shared by every backend). */
#include "server.h"
void server_configure(storage_context_t *storage, const char *relay_url, int min_pow,
                      time_t lower_limit, time_t upper_limit) {
    relay_core_configure(storage, relay_url, min_pow, lower_limit, upper_limit);
}
void server_set_debug(bool enabled) { relay_core_set_debug(enabled); }
