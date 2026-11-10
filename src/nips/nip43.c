/* nip43 - NIP-43 relay access metadata and requests.
 *
 * Active when nip43 = 1 and the relay has a signing key
 * (relay_secret_key_file). The relay keeps a member set and publishes it
 * as its own kind 13534 list (NIP-70 "-" tagged); claims and leaves:
 *
 *   28934 join request  ["-"], ["claim", code]: code must be one of
 *                       invite_codes; the relay adds the author, emits
 *                       8000 (add user) and a new 13534.
 *                       OK true "duplicate: ..." for an existing member.
 *   28936 leave request ["-"]: the relay removes the author, emits 8001
 *                       (remove user) and a new 13534.
 *
 * Both are ephemeral and must be within NIP43_SKEW seconds of now. The
 * NIP-70 "-" tag means the client has to AUTH as the author first (nip42.c).
 * Claims are never broadcast (they carry the code).
 *
 * members_only = 1 turns membership into the write policy: only members
 * (and the operator, relay_pubkey) may publish, except join requests;
 * NIP-11 then reports limitation.restricted_writes.
 *
 * 8000 / 8001 / 13534 / 33534 are accepted only from the relay key.
 *
 * State: a sorted pubkey array behind a rwlock; the writer is the only
 * mutator, workers read it in accept_publish. Rebuilt at startup from
 * the relay's stored 13534.
 *
 * Not implemented: 33534 role definitions (no roles are configured),
 * kind 28935 relay-issued claims and the NIP-86 createclaim method.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "nip_plugin.h"
#include "nip_event.h"
#include "../crypto.h"
#include "../ng_config.h"
#include "../relay_core.h"
#include "../platform/ng_alloc.h"

#define NIP43_SKEW 300

typedef char pk_t[65];

static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
static pk_t *members;
static size_t n_members, cap_members;
static time_t last_list_ts;
static bool enabled;

static int pk_cmp(const void *a, const void *b) { return strcmp((const char *) a, (const char *) b); }

static bool is_member(const char *pk) {
    return pk && n_members && bsearch(pk, members, n_members, sizeof(pk_t), pk_cmp) != NULL;
}

static bool add_member(const char *pk) {
    if (strlen(pk) != 64 || is_member(pk)) return true;
    if (n_members == cap_members) {
        size_t cap = ng_grow_cap(cap_members, n_members + 1, 16);
        pk_t *p = (pk_t *) ng_realloc_array(members, cap, sizeof(pk_t));
        if (!p) return false;
        members = p; cap_members = cap;
    }
    size_t i = 0;
    while (i < n_members && strcmp(members[i], pk) < 0) i++;
    memmove(&members[i + 1], &members[i], (n_members - i) * sizeof(pk_t));
    snprintf(members[i], sizeof(pk_t), "%s", pk);
    n_members++;
    return true;
}

static void remove_member(const char *pk) {
    pk_t *m = n_members ? (pk_t *) bsearch(pk, members, n_members, sizeof(pk_t), pk_cmp) : NULL;
    if (!m) return;
    size_t i = (size_t) (m - members);
    memmove(&members[i], &members[i + 1], (n_members - i - 1) * sizeof(pk_t));
    n_members--;
}

static bool code_ok(const char *code) {
    if (!code || !*code) return false;
    size_t n = strlen(code);
    for (const char *p = ng_relay_info.invite_codes; *p;) {
        while (*p == ',' || *p == ' ') p++;
        const char *e = p;
        while (*e && *e != ',') e++;
        const char *t = e;
        while (t > p && t[-1] == ' ') t--;
        if ((size_t) (t - p) == n && !memcmp(p, code, n)) return true;
        p = e;
    }
    return false;
}

/* ---- relay-generated events (writer, lock held) -------------------------- */

static bool emit(int kind, const char *p_tag) {
    json_builder_t b;
    json_builder_start(&b);
    json_builder_start_array(&b); json_builder_append_string(&b, "-"); json_builder_end_array(&b);
    if (p_tag) {
        json_builder_start_array(&b); json_builder_append_string(&b, "p");
        json_builder_append_string(&b, p_tag); json_builder_end_array(&b);
    } else {
        for (size_t i = 0; i < n_members; i++) {
            json_builder_start_array(&b); json_builder_append_string(&b, "member");
            json_builder_append_string(&b, members[i]); json_builder_end_array(&b);
        }
    }
    const char *j = json_builder_finish(&b);
    event_t ev; memset(&ev, 0, sizeof ev);
    ev.kind = kind;
    ev.created_at = time(NULL);
    if (!p_tag) {                       /* replaceable: strictly newer each time */
        if (ev.created_at <= last_list_ts) ev.created_at = last_list_ts + 1;
        last_list_ts = ev.created_at;
    }
    ev.tags_json = j ? string_dup(j) : NULL;
    ev.tags_json_len = ev.tags_json ? strlen(ev.tags_json) : 0;
    ev.content = string_dup("");
    ev.content_len = 0;
    json_builder_free(&b);
    if (!ev.tags_json || !ev.content) { event_release(&ev); return false; }
    return relay_core_emit(&ev);
}

static nip01_process_result_t ok_quiet(const char *msg) {
    nip01_process_result_t r = {0};
    r.accepted = true;                  /* never broadcast: a claim carries its code */
    snprintf(r.response_msg, sizeof r.response_msg, "%s", msg);
    return r;
}

static nip01_process_result_t on_event(relay_conn_t *c, const event_t *ev, storage_context_t *st,
                                       const char *relay_url) {
    (void) c; (void) st;
    if (!enabled) return nip_plugin_reject("unsupported: relay membership (NIP-43) is not enabled on this relay");
    time_t now = time(NULL);
    if (ev->created_at < now - NIP43_SKEW || ev->created_at > now + NIP43_SKEW)
        return nip_plugin_reject("invalid: created_at must be within 5 minutes of now");
    if (!nip_event_has_tag(ev, "-", NULL)) return nip_plugin_reject("invalid: missing the NIP-70 \"-\" tag");
    nip01_process_result_t r;
    pthread_rwlock_wrlock(&lock);
    if (ev->kind == 28934) {
        char *code = nip_event_tag_value(ev, "claim");
        if (is_member(ev->pubkey)) r = nip_plugin_duplicate("duplicate: you are already a member of this relay.");
        else if (!code_ok(code)) r = nip_plugin_reject("restricted: that is an invalid invite code.");
        else if (!add_member(ev->pubkey)) r = nip_plugin_reject("error: out of memory");
        else if (!emit(8000, ev->pubkey) || !emit(13534, NULL)) r = nip_plugin_reject("error: could not publish the member list");
        else {
            char msg[300];
            const char *url = ng_relay_info.relay_url[0] ? ng_relay_info.relay_url : (relay_url ? relay_url : "this relay");
            snprintf(msg, sizeof msg, "info: welcome to %s!", url);
            r = ok_quiet(msg);
        }
        free(code);
    } else {
        if (!is_member(ev->pubkey)) r = ok_quiet("info: you are not a member of this relay");
        else {
            remove_member(ev->pubkey);
            r = (emit(8001, ev->pubkey) && emit(13534, NULL)) ? ok_quiet("info: your access was revoked")
                                                             : nip_plugin_reject("error: could not publish the member list");
        }
    }
    pthread_rwlock_unlock(&lock);
    return r;
}

/* ---- workers -------------------------------------------------------------- */

static bool relay_only_kind(int k) { return k == 8000 || k == 8001 || k == 13534 || k == 33534; }

static bool accept_publish(relay_conn_t *c, const event_t *ev, char *reason, size_t rs, void *ctx) {
    (void) c; (void) ctx;
    if (!enabled) return true;
    if (relay_only_kind(ev->kind)) {
        snprintf(reason, rs, "blocked: relay membership events are published by this relay only");
        return false;
    }
    if (!ng_relay_info.members_only || ev->kind == 28934 || ev->kind == 28936) return true;
    if (ng_relay_info.pubkey[0] && !strcmp(ev->pubkey, ng_relay_info.pubkey)) return true;
    pthread_rwlock_rdlock(&lock);
    bool ok = is_member(ev->pubkey);
    pthread_rwlock_unlock(&lock);
    if (!ok) snprintf(reason, rs, "restricted: this relay is members-only; join with an invite claim (NIP-43 kind 28934)");
    return ok;
}

/* ---- lifecycle ----------------------------------------------------------- */

typedef struct { const char *self; } load_t;

static void load_list(const event_t *ev, void *arg) {
    const load_t *l = (const load_t *) arg;
    if (strcmp(ev->pubkey, l->self) || ev->created_at < last_list_ts) return;
    last_list_ts = ev->created_at;
    n_members = 0;
    jstr_t key, tag, tags = jl_str(ev->tags_json ? ev->tags_json : "[]");
    size_t off = 0;
    while ((off = jl_next(tags, off, &key, &tag)) != 0) {
        char *n = nip_tag_element(tag, 0), *pk = nip_tag_element(tag, 1);
        if (n && pk && !strcmp(n, "member") && !add_member(pk)) fprintf(stderr, "nip43: out of memory\n");
        free(n); free(pk);
    }
}

static void init(const relay_config_t *config, void *ctx) {
    (void) ctx;
    storage_context_t *store = config->storage;
    const char *self = crypto_relay_pubkey();
    enabled = ng_relay_info.nip43 && self && store && store->scan_kinds;
    if (ng_relay_info.nip43 && !self) fprintf(stderr, "nip43: needs relay_secret_key_file; disabled\n");
    if (!enabled) return;
    static const int kinds[] = { 13534 };
    load_t l = { self };
    pthread_rwlock_wrlock(&lock);
    if (!store->scan_kinds(kinds, 1, load_list, &l)) fprintf(stderr, "nip43: could not load the member list\n");
    pthread_rwlock_unlock(&lock);
}

static nip_plugin_t nip43_plugin = {
    .name = "nip43",
    .kinds = { NIP_PLUGIN_KIND(28934), NIP_PLUGIN_KIND(28936) },
    .kinds_count = 2,
    .on_event = on_event,
    .init = init,
    .accept_publish = accept_publish,
};

__attribute__((constructor)) static void nip43_register(void) { nip_plugin_register(&nip43_plugin); }
