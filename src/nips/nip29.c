/* nip29 - NIP-29 relay-based groups.
 *
 * Active only when the relay has a signing key (relay_secret_key_file):
 * the relay signs the group state events (kinds 39000-39003) and the
 * put-user / remove-user events that answer join / leave requests.
 *
 * State: an in-memory table of groups (metadata flags, members with roles,
 * invite codes) behind one rwlock. Workers take the read lock only for
 * events / filters that name a group (h tag, or d tag on 39000-39003);
 * everything else never touches it. The writer is the only mutator (kind
 * listeners for the moderation and join/leave kinds run there, inside the
 * batch transaction). The table is rebuilt at startup by replaying the
 * stored state-changing events (9007, 9000, 9001, 9002, 9008, 9009) in
 * insertion order; every one of them was authorized when it was stored.
 *
 * Roles (kind 39003): "admin" may do everything; "moderator" may put and
 * remove plain members and delete events. The creator of a group (9007)
 * becomes its admin.
 *
 * Not implemented (see NIPS.md): "previous" timeline references, the
 * late-publication policy, subgroups (parent / child), pinned events
 * (9010 / 39005), LiveKit AV rooms (39004), kind 39002 member lists are
 * published in full.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "nip_plugin.h"
#include "nip_event.h"
#include "nip42.h"
#include "../crypto.h"
#include "../dedupe.h"
#include "../relay_core.h"
#include "../platform/ng_alloc.h"

#define GID_MAX 64
#define ROLES_MAX 96

enum { F_PRIVATE = 1, F_RESTRICTED = 2, F_HIDDEN = 4, F_CLOSED = 8 };

typedef struct { char pk[65]; char roles[ROLES_MAX]; } member_t;   /* roles: "" or "admin" / "moderator" ... (space separated) */

typedef struct {
    char id[GID_MAX + 1];
    char *name, *picture, *about, *banner;
    unsigned flags;
    int *kinds; size_t n_kinds; bool kinds_set;   /* supported_kinds */
    member_t *m; size_t n_m, cap_m;               /* sorted by pk */
    char **codes; size_t n_codes;
    time_t last_ts[4];                            /* per 39000..39003: strictly increasing */
} group_t;

static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
static group_t **groups;
static size_t n_groups, cap_groups;
static bool enabled;
static storage_context_t *store;

/* ---- table helpers (caller holds the lock) ------------------------------ */

static bool gid_ok(const char *id) {
    size_t n = id ? strlen(id) : 0;
    if (n == 0 || n > GID_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        char c = id[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'))
            return false;
    }
    return true;
}

static group_t *find(const char *id) {
    if (!id) return NULL;
    for (size_t i = 0; i < n_groups; i++) if (!strcmp(groups[i]->id, id)) return groups[i];
    return NULL;
}

static member_t *member(group_t *g, const char *pk) {
    size_t lo = 0, hi = g->n_m;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        int c = strcmp(g->m[mid].pk, pk);
        if (!c) return &g->m[mid];
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return NULL;
}

static bool has_role(const member_t *m, const char *role) {
    if (!m) return false;
    size_t rl = strlen(role);
    for (const char *p = m->roles; (p = strstr(p, role)) != NULL; p += rl)
        if ((p == m->roles || p[-1] == ' ') && (p[rl] == '\0' || p[rl] == ' ')) return true;
    return false;
}

static bool put_member(group_t *g, const char *pk, const char *roles) {
    member_t *m = member(g, pk);
    if (!m) {
        if (g->n_m == g->cap_m) {
            size_t cap = ng_grow_cap(g->cap_m, g->n_m + 1, 8);
            member_t *p = (member_t *) ng_realloc_array(g->m, cap, sizeof(*p));
            if (!p) return false;
            g->m = p; g->cap_m = cap;
        }
        size_t i = 0;
        while (i < g->n_m && strcmp(g->m[i].pk, pk) < 0) i++;
        memmove(&g->m[i + 1], &g->m[i], (g->n_m - i) * sizeof(member_t));
        g->n_m++;
        m = &g->m[i];
        snprintf(m->pk, sizeof m->pk, "%s", pk);
        m->roles[0] = '\0';
    }
    if (roles) snprintf(m->roles, sizeof m->roles, "%s", roles);
    return true;
}

static void remove_member(group_t *g, const char *pk) {
    member_t *m = member(g, pk);
    if (!m) return;
    size_t i = (size_t) (m - g->m);
    memmove(&g->m[i], &g->m[i + 1], (g->n_m - i - 1) * sizeof(member_t));
    g->n_m--;
}

static void group_free(group_t *g) {
    if (!g) return;
    free(g->name); free(g->picture); free(g->about); free(g->banner);
    free(g->kinds); free(g->m);
    for (size_t i = 0; i < g->n_codes; i++) free(g->codes[i]);
    free(g->codes);
    free(g);
}

static group_t *create(const char *id) {
    if (n_groups == cap_groups) {
        size_t cap = ng_grow_cap(cap_groups, n_groups + 1, 16);
        group_t **p = (group_t **) ng_realloc_array(groups, cap, sizeof(*p));
        if (!p) return NULL;
        groups = p; cap_groups = cap;
    }
    group_t *g = (group_t *) calloc(1, sizeof(*g));
    if (!g) return NULL;
    snprintf(g->id, sizeof g->id, "%s", id);
    groups[n_groups++] = g;
    return g;
}

static void drop(group_t *g) {
    for (size_t i = 0; i < n_groups; i++)
        if (groups[i] == g) { groups[i] = groups[--n_groups]; group_free(g); return; }
}

/* ---- event tag helpers --------------------------------------------------- */

typedef bool (*tag_fn)(jstr_t tag, void *arg);
static void each_tag(const event_t *ev, tag_fn fn, void *arg) {
    jstr_t key, tag, tags = jl_str(ev->tags_json ? ev->tags_json : "[]");
    size_t off = 0;
    while ((off = jl_next(tags, off, &key, &tag)) != 0) if (!fn(tag, arg)) return;
}

static bool tag_is(jstr_t tag, const char *name) {
    char *n = nip_tag_element(tag, 0);
    bool r = n && !strcmp(n, name);
    free(n);
    return r;
}

/* Apply the group-metadata fields of a 9002 / 9007 event. */
typedef struct { group_t *g; unsigned flags; bool kinds_seen; int *kinds; size_t nk; bool oom; } meta_t;

static void set_str(char **dst, char *v) { free(*dst); *dst = v; }

static bool meta_tag(jstr_t tag, void *arg) {
    meta_t *mt = (meta_t *) arg;
    char *n = nip_tag_element(tag, 0);
    if (!n) return true;
    if (!strcmp(n, "name")) set_str(&mt->g->name, nip_tag_element(tag, 1));
    else if (!strcmp(n, "picture")) set_str(&mt->g->picture, nip_tag_element(tag, 1));
    else if (!strcmp(n, "about")) set_str(&mt->g->about, nip_tag_element(tag, 1));
    else if (!strcmp(n, "banner")) set_str(&mt->g->banner, nip_tag_element(tag, 1));
    else if (!strcmp(n, "private")) mt->flags |= F_PRIVATE;
    else if (!strcmp(n, "restricted")) mt->flags |= F_RESTRICTED;
    else if (!strcmp(n, "hidden")) mt->flags |= F_HIDDEN;
    else if (!strcmp(n, "closed")) mt->flags |= F_CLOSED;
    else if (!strcmp(n, "public")) mt->flags &= ~(unsigned) F_PRIVATE;
    else if (!strcmp(n, "open")) mt->flags &= ~(unsigned) F_CLOSED;
    else if (!strcmp(n, "supported_kinds")) {
        mt->kinds_seen = true;
        for (size_t i = 1;; i++) {
            char *v = nip_tag_element(tag, i);
            if (!v) break;
            int *p = (int *) ng_realloc_array(mt->kinds, mt->nk + 1, sizeof(int));
            if (!p) { free(v); mt->oom = true; break; }
            mt->kinds = p; mt->kinds[mt->nk++] = atoi(v);
            free(v);
        }
    }
    free(n);
    return true;
}

static void apply_metadata(group_t *g, const event_t *ev) {
    meta_t mt = { g, 0, false, NULL, 0, false };
    each_tag(ev, meta_tag, &mt);
    g->flags = mt.flags;
    free(g->kinds);
    g->kinds = mt.kinds; g->n_kinds = mt.nk; g->kinds_set = mt.kinds_seen;
}

/* ---- relay-generated events (writer) ------------------------------------ */

static time_t next_ts(group_t *g, int slot) {
    time_t now = time(NULL);
    if (now <= g->last_ts[slot]) now = g->last_ts[slot] + 1;
    g->last_ts[slot] = now;
    return now;
}

static void tag2(json_builder_t *b, const char *k, const char *v) {
    json_builder_start_array(b); json_builder_append_string(b, k);
    if (v) json_builder_append_string(b, v);
    json_builder_end_array(b);
}

/* Emit a relay-signed event; tags built by fill(b, arg) after ["d"/"h", id]. */
static bool emit(group_t *g, int kind, int slot, const char *idtag, const char *content,
                 void (*fill)(json_builder_t *, group_t *, const void *), const void *arg) {
    json_builder_t b;
    json_builder_start(&b);
    tag2(&b, idtag, g->id);
    if (fill) fill(&b, g, arg);
    const char *j = json_builder_finish(&b);
    event_t ev; memset(&ev, 0, sizeof ev);
    ev.kind = kind;
    ev.created_at = slot >= 0 ? next_ts(g, slot) : time(NULL);
    ev.tags_json = j ? string_dup(j) : NULL;
    ev.tags_json_len = ev.tags_json ? strlen(ev.tags_json) : 0;
    ev.content = string_dup(content ? content : "");
    ev.content_len = ev.content ? strlen(ev.content) : 0;
    json_builder_free(&b);
    if (!ev.tags_json || !ev.content) { event_release(&ev); return false; }
    return relay_core_emit(&ev);
}

static void fill_meta(json_builder_t *b, group_t *g, const void *a) {
    (void) a;
    if (g->name) tag2(b, "name", g->name);
    if (g->picture) tag2(b, "picture", g->picture);
    if (g->about) tag2(b, "about", g->about);
    if (g->banner) tag2(b, "banner", g->banner);
    if (g->flags & F_PRIVATE) tag2(b, "private", NULL); else tag2(b, "public", NULL);
    if (g->flags & F_RESTRICTED) tag2(b, "restricted", NULL);
    if (g->flags & F_HIDDEN) tag2(b, "hidden", NULL);
    if (g->flags & F_CLOSED) tag2(b, "closed", NULL); else tag2(b, "open", NULL);
    if (g->kinds_set) {
        json_builder_start_array(b);
        json_builder_append_string(b, "supported_kinds");
        for (size_t i = 0; i < g->n_kinds; i++) {
            char k[16]; snprintf(k, sizeof k, "%d", g->kinds[i]);
            json_builder_append_string(b, k);
        }
        json_builder_end_array(b);
    }
}

static void fill_admins(json_builder_t *b, group_t *g, const void *a) {
    (void) a;
    for (size_t i = 0; i < g->n_m; i++) {
        if (!g->m[i].roles[0]) continue;
        json_builder_start_array(b);
        json_builder_append_string(b, "p");
        json_builder_append_string(b, g->m[i].pk);
        char roles[ROLES_MAX];
        snprintf(roles, sizeof roles, "%s", g->m[i].roles);
        for (char *s = strtok(roles, " "); s; s = strtok(NULL, " ")) json_builder_append_string(b, s);
        json_builder_end_array(b);
    }
}

static void fill_members(json_builder_t *b, group_t *g, const void *a) {
    (void) a;
    for (size_t i = 0; i < g->n_m; i++) tag2(b, "p", g->m[i].pk);
}

static void fill_roles(json_builder_t *b, group_t *g, const void *a) {
    (void) g; (void) a;
    json_builder_start_array(b);
    json_builder_append_string(b, "role"); json_builder_append_string(b, "admin");
    json_builder_append_string(b, "edit metadata, manage members and roles, invites, delete events, delete the group");
    json_builder_end_array(b);
    json_builder_start_array(b);
    json_builder_append_string(b, "role"); json_builder_append_string(b, "moderator");
    json_builder_append_string(b, "add and remove plain members, delete events");
    json_builder_end_array(b);
}

static void fill_p(json_builder_t *b, group_t *g, const void *a) { (void) g; tag2(b, "p", (const char *) a); }

static bool emit_state(group_t *g, bool meta, bool admins, bool members) {
    bool ok = true;
    if (meta) ok &= emit(g, 39000, 0, "d", "", fill_meta, NULL);
    if (admins) ok &= emit(g, 39001, 1, "d", "", fill_admins, NULL);
    if (members) ok &= emit(g, 39002, 2, "d", "", fill_members, NULL);
    return ok;
}

/* ---- moderation (writer) ------------------------------------------------- */

typedef struct { group_t *g; bool admin; bool ok; const char *why; } mod_t;

static bool put_user_tag(jstr_t tag, void *arg) {
    mod_t *m = (mod_t *) arg;
    if (!tag_is(tag, "p")) return true;
    char *pk = nip_tag_element(tag, 1);
    if (!pk || strlen(pk) != 64) { free(pk); m->ok = false; m->why = "invalid: p tag needs a pubkey"; return false; }
    char roles[ROLES_MAX] = "";
    size_t len = 0;
    for (size_t i = 2;; i++) {
        char *r = nip_tag_element(tag, i);
        if (!r) break;
        int w = snprintf(roles + len, sizeof roles - len, "%s%s", len ? " " : "", r);
        free(r);
        if (w < 0 || (size_t) w >= sizeof roles - len) break;
        len += (size_t) w;
    }
    if (len && !m->admin) { free(pk); m->ok = false; m->why = "restricted: only admins assign roles"; return false; }
    member_t *cur = member(m->g, pk);
    if (cur && cur->roles[0] && !m->admin) { free(pk); m->ok = false; m->why = "restricted: only admins change admins"; return false; }
    if (!put_member(m->g, pk, len || m->admin ? roles : (cur ? cur->roles : ""))) { m->ok = false; m->why = "error: out of memory"; }
    free(pk);
    return m->ok;
}

static bool remove_user_tag(jstr_t tag, void *arg) {
    mod_t *m = (mod_t *) arg;
    if (!tag_is(tag, "p")) return true;
    char *pk = nip_tag_element(tag, 1);
    if (!pk) return true;
    member_t *cur = member(m->g, pk);
    if (cur && cur->roles[0] && !m->admin) { m->ok = false; m->why = "restricted: only admins remove admins"; }
    else remove_member(m->g, pk);
    free(pk);
    return m->ok;
}

static bool delete_event_tag(jstr_t tag, void *arg) {
    mod_t *m = (mod_t *) arg;
    if (!tag_is(tag, "e")) return true;
    char *id = nip_tag_element(tag, 1);
    if (id && strlen(id) == 64 && store->get_event_by_id) {
        event_t *t = store->get_event_by_id(id);
        if (t) {
            char *h = nip_event_tag_value(t, "h");
            if (h && !strcmp(h, m->g->id)) {
                if (store->delete_by_id(id, NULL)) { dedupe_forget(id); store->add_tombstone(id, t->pubkey); }
                else { m->ok = false; m->why = "error: delete failed"; }
            }
            free(h);
            event_free(t);
        }
    }
    free(id);
    return m->ok;
}

static bool code_tag(jstr_t tag, void *arg) {
    group_t *g = (group_t *) arg;
    if (!tag_is(tag, "code")) return true;
    char *c = nip_tag_element(tag, 1);
    if (!c || !*c) { free(c); return true; }
    char **p = (char **) ng_realloc_array(g->codes, g->n_codes + 1, sizeof(char *));
    if (!p) { free(c); return false; }
    g->codes = p; g->codes[g->n_codes++] = c;
    return true;
}

typedef struct { group_t *g; bool hit; } code_t;
static bool code_match(jstr_t tag, void *arg) {
    code_t *c = (code_t *) arg;
    if (!tag_is(tag, "code")) return true;
    char *v = nip_tag_element(tag, 1);
    for (size_t i = 0; v && i < c->g->n_codes; i++) if (!strcmp(c->g->codes[i], v)) c->hit = true;
    free(v);
    return !c->hit;
}

/* Apply one state-changing event (writer, lock held). replay: from the
 * database at startup (already authorized, no emits). Returns the NIP-01
 * reason on refusal, NULL when applied. */
static const char *apply(const event_t *ev, bool replay) {
    char *gid = nip_event_tag_value(ev, "h");
    const char *why = NULL;
    group_t *g = find(gid);
    const char *relay_pk = crypto_relay_pubkey();
    bool by_relay = relay_pk && !strcmp(ev->pubkey, relay_pk);
    member_t *actor = g ? member(g, ev->pubkey) : NULL;
    bool admin = by_relay || has_role(actor, "admin");
    bool mod = admin || has_role(actor, "moderator");

    if (!gid_ok(gid)) { why = "invalid: h tag must name a group (1-64 of a-z A-Z 0-9 - _)"; goto out; }
    if (ev->kind == 9007) {
        if (g) { why = "duplicate: group already exists"; goto out; }
        if (!(g = create(gid))) { why = "error: out of memory"; goto out; }
        apply_metadata(g, ev);
        if (!g->name) g->name = string_dup(gid);
        if (!by_relay && !put_member(g, ev->pubkey, "admin")) { drop(g); why = "error: out of memory"; goto out; }
        if (!replay && !(emit_state(g, true, true, true) && emit(g, 39003, 3, "d", "", fill_roles, NULL)))
            why = "error: could not publish the group state";
        goto out;
    }
    if (!g) { why = "invalid: group does not exist"; goto out; }
    switch (ev->kind) {
    case 9000: case 9001: {
        if (!mod) { why = "restricted: not a group admin or moderator"; break; }
        mod_t m = { g, admin, true, NULL };
        each_tag(ev, ev->kind == 9000 ? put_user_tag : remove_user_tag, &m);
        if (!m.ok) why = m.why;
        else if (!replay && !emit_state(g, false, true, true)) why = "error: could not publish the group state";
        break;
    }
    case 9002:
        if (!admin) { why = "restricted: only admins edit metadata"; break; }
        apply_metadata(g, ev);
        if (!replay && !emit_state(g, true, false, false)) why = "error: could not publish the group state";
        break;
    case 9005: {
        if (!mod) { why = "restricted: not a group admin or moderator"; break; }
        if (replay) break;                               /* the deletes are already in the database */
        mod_t m = { g, admin, true, NULL };
        each_tag(ev, delete_event_tag, &m);
        if (!m.ok) why = m.why;
        break;
    }
    case 9008:
        if (!admin) { why = "restricted: only admins delete the group"; break; }
        if (!replay) {
            size_t n = 0;
            char *el[2] = { (char *) "d", g->id };
            tag_t d = { el, 2, 2 };
            bool ok = store->delete_by_tag('h', g->id, dedupe_forget, &n);
            for (int k = 39000; ok && k <= 39003; k++)   /* this relay's state events only */
                ok = store->delete_record_by_kind_and_pubkey_and_dtag(k, relay_pk, &d, (time_t) 1 << 40, &n);
            if (!ok) { why = "error: delete failed"; break; }
        }
        drop(g);
        break;
    case 9009:
        if (!admin) { why = "restricted: only admins create invites"; break; }
        each_tag(ev, code_tag, g);
        break;
    default:
        why = "invalid: unsupported group moderation kind";
    }
out:
    free(gid);
    return why;
}

/* ---- kind listeners (writer) --------------------------------------------- */

static nip01_process_result_t on_event(relay_conn_t *c, const event_t *ev, storage_context_t *st,
                                       const char *relay_url) {
    (void) c; (void) relay_url;
    if (!enabled) return nip_plugin_reject("unsupported: groups (NIP-29) are not enabled on this relay");
    if (!st) return nip_plugin_reject("error: storage unavailable");
    pthread_rwlock_wrlock(&lock);
    const char *why = NULL;
    nip01_process_result_t r;
    if (ev->kind == 9021 || ev->kind == 9022) {
        char *gid = nip_event_tag_value(ev, "h");
        group_t *g = find(gid);
        if (!g) why = "invalid: group does not exist";
        else if (ev->kind == 9021) {
            code_t cm = { g, false };
            each_tag(ev, code_match, &cm);
            if (member(g, ev->pubkey)) { r = nip_plugin_duplicate("duplicate: already a member"); free(gid); goto stored_dup; }
            if ((g->flags & F_CLOSED) && !cm.hit) why = "restricted: this group is closed; joining needs an invite code";
            else if (!put_member(g, ev->pubkey, "")) why = "error: out of memory";
            else if (!emit(g, 9000, -1, "h", "", fill_p, ev->pubkey) || !emit_state(g, false, false, true))
                why = "error: could not publish the group state";
        } else {
            if (!member(g, ev->pubkey)) why = "invalid: not a member of this group";
            else {
                remove_member(g, ev->pubkey);
                if (!emit(g, 9001, -1, "h", "", fill_p, ev->pubkey) || !emit_state(g, false, true, true))
                    why = "error: could not publish the group state";
            }
        }
        free(gid);
    } else {
        why = apply(ev, false);
    }
    r = why ? nip_plugin_reject(why) : nip_plugin_store_and_broadcast(st, ev);
stored_dup:
    pthread_rwlock_unlock(&lock);
    return r;
}

/* ---- read side (workers, read lock) ------------------------------------- */

static bool is_meta_kind(int k) { return k >= 39000 && k <= 39003; }

static bool accept_publish(relay_conn_t *c, const event_t *ev, char *reason, size_t rs, void *ctx) {
    (void) c; (void) ctx;
    if (!enabled) return true;
    if (is_meta_kind(ev->kind)) {
        snprintf(reason, rs, "blocked: group state events are published by this relay only");
        return false;
    }
    if (ev->kind == 9007 || (ev->kind >= 9000 && ev->kind <= 9022)) return true;   /* decided by the writer */
    if (!nip_event_has_tag(ev, "h", NULL)) return true;
    char *gid = nip_event_tag_value(ev, "h");
    bool ok = true;
    pthread_rwlock_rdlock(&lock);
    group_t *g = find(gid);
    if (!g) { ok = false; snprintf(reason, rs, "invalid: group does not exist"); }
    else if ((g->flags & F_RESTRICTED) && !member(g, ev->pubkey)) {
        ok = false; snprintf(reason, rs, "restricted: only members can write to this group");
    } else if (g->kinds_set) {
        bool k = false;
        for (size_t i = 0; i < g->n_kinds; i++) if (g->kinds[i] == ev->kind) k = true;
        if (!k) { ok = false; snprintf(reason, rs, "invalid: kind %d is not supported by this group", ev->kind); }
    }
    pthread_rwlock_unlock(&lock);
    free(gid);
    return ok;
}

/* private groups: only authenticated members read h-tagged events;
 * hidden groups: only members see the 39000-39003 state events. */
static bool can_deliver(const event_t *ev, relay_conn_t *c, void *ctx) {
    (void) ctx;
    if (!enabled) return true;
    bool meta = is_meta_kind(ev->kind);
    if (!meta && !nip_event_has_tag(ev, "h", NULL)) return true;
    char *gid = nip_event_tag_value(ev, meta ? "d" : "h");
    const char *who = nip42_authenticated_pubkey(c);
    bool ok = true;
    pthread_rwlock_rdlock(&lock);
    group_t *g = find(gid);
    if (g && (g->flags & (meta ? F_HIDDEN : F_PRIVATE)) && !(who && member(g, who))) ok = false;
    pthread_rwlock_unlock(&lock);
    free(gid);
    return ok;
}

/* A REQ for #h of a private group before AUTH: CLOSED auth-required:. */
static bool accept_query(relay_conn_t *c, filter_t *filters, size_t count, bool is_count,
                         char *reason, size_t rs, void *ctx) {
    (void) is_count; (void) ctx;
    if (!enabled || nip42_authenticated_pubkey(c)) return true;
    bool need = false;
    pthread_rwlock_rdlock(&lock);
    for (size_t i = 0; i < count && !need; i++)
        for (size_t t = 0; t < filters[i].tags_count && !need; t++) {
            const tag_t *tag = &filters[i].tags[t];
            if (strcmp(tag->elements[0], "h")) continue;
            for (size_t v = 1; v < tag->count && !need; v++) {
                group_t *g = find(tag->elements[v]);
                if (g && (g->flags & F_PRIVATE)) need = true;
            }
        }
    pthread_rwlock_unlock(&lock);
    if (!need) return true;
    nip42_send_challenge(c);
    snprintf(reason, rs, "auth-required: this group is private");
    return false;
}

/* ---- lifecycle ----------------------------------------------------------- */

static void replay_one(const event_t *ev, void *arg) {
    (void) arg;
    (void) apply(ev, true);
}

static void init(const relay_config_t *config, void *ctx) {
    (void) ctx;
    store = config->storage;
    enabled = crypto_relay_pubkey() != NULL && store && store->scan_kinds && store->delete_by_tag;
    if (!enabled) return;
    static const int kinds[] = { 9007, 9000, 9001, 9002, 9008, 9009 };
    pthread_rwlock_wrlock(&lock);
    if (!store->scan_kinds(kinds, sizeof kinds / sizeof kinds[0], replay_one, NULL))
        fprintf(stderr, "nip29: could not replay the group state\n");
    pthread_rwlock_unlock(&lock);
}

static nip_plugin_t nip29_plugin = {
    .name = "nip29",
    .kinds = { { 9000, 9009 }, { 9021, 9022 } },
    .kinds_count = 2,
    .on_event = on_event,
    .init = init,
    .accept_publish = accept_publish,
    .can_deliver = can_deliver,
    .accept_query = accept_query,
};

__attribute__((constructor)) static void nip29_register_at_startup(void) {
    nip_plugin_register(&nip29_plugin);
}
