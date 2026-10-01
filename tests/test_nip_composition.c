/* ============================================================================
 * Integration tests for src/nips/nip_capability.c composition rules.
 *
 * A mock registry holding two CONFLICTING policies per type proves the
 * documented composition semantics:
 *   publication : AND  (any deny wins, order-independent)
 *   delivery    : veto (any veto wins, order-independent)
 *   kind handler: AND  (any reject wins, order-independent)
 *   query       : AND  (any deny wins, order-independent)
 *   maintenance : ALL run
 *   eose/count/metadata: FIRST non-NULL wins (last registered = head)
 *   auth hint   : OR   (any true wins)
 *   challenge   : ALL hooks fire
 * plus registry lifecycle (clear/re-register = hot-reload swap pattern)
 * and NULL-safety of every composition entry point.
 *
 * Build (from repo root): link tests/test_nip_composition.c with
 *   src/nips/nip_capability.c only (it has no link dependencies beyond libc).
 * Run: build/test_nip_composition(.exe) -- exit code is failure count.
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nip_capability.h"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (cond) {                                                            \
            g_pass++;                                                          \
            printf("PASS: %s\n", label);                                       \
        } else {                                                               \
            g_fail++;                                                          \
            printf("FAIL: %s\n", label);                                       \
        }                                                                      \
    } while (0)

/* --- Mock policies --- */

static bool pub_allow(uintptr_t id, const event_t *ev, char *reason,
                      size_t reason_size, void *ctx) {
    (void)id; (void)ev; (void)reason; (void)reason_size; (void)ctx;
    return true;
}

static bool pub_deny(uintptr_t id, const event_t *ev, char *reason,
                     size_t reason_size, void *ctx) {
    const char *tag = ctx ? (const char *)ctx : "mock";
    (void)id; (void)ev;
    snprintf(reason, reason_size, "denied by %s", tag);
    return false;
}

static int deliver_calls = 0;
static bool del_allow(const event_t *ev, uintptr_t id, void *ctx) {
    (void)ev; (void)id; (void)ctx;
    deliver_calls++;
    return true;
}

static bool del_veto(const event_t *ev, uintptr_t id, void *ctx) {
    (void)ev; (void)id; (void)ctx;
    deliver_calls++;
    return false;
}

static bool kind_is_1(int kind, void *ctx) {
    (void)ctx;
    return kind == 1;
}

static nip01_process_result_t kind_accept(uintptr_t id, const event_t *ev,
                                          storage_context_t *st,
                                          const char *url, void *ctx) {
    nip01_process_result_t r = {0};
    (void)id; (void)ev; (void)st; (void)url;
    r.accepted = true;
    r.should_broadcast = true;
    r.should_store = true;
    snprintf(r.response_msg, sizeof(r.response_msg), "ok by %s",
             ctx ? (const char *)ctx : "mock");
    return r;
}

static nip01_process_result_t kind_reject(uintptr_t id, const event_t *ev,
                                          storage_context_t *st,
                                          const char *url, void *ctx) {
    nip01_process_result_t r = {0};
    (void)id; (void)ev; (void)st; (void)url;
    r.accepted = false;
    snprintf(r.response_msg, sizeof(r.response_msg), "no by %s",
             ctx ? (const char *)ctx : "mock");
    return r;
}

static bool query_allow(uintptr_t id, filter_t *f, size_t n, char *reason,
                        size_t reason_size, void *ctx) {
    (void)id; (void)f; (void)n; (void)reason; (void)reason_size; (void)ctx;
    return true;
}

static bool query_deny(uintptr_t id, filter_t *f, size_t n, char *reason,
                       size_t reason_size, void *ctx) {
    (void)id; (void)f; (void)n; (void)ctx;
    snprintf(reason, reason_size, "query denied");
    return false;
}

static int maint_runs = 0;
static void maint_tick(storage_context_t *st, void *ctx) {
    (void)st;
    maint_runs += ctx ? *(int *)ctx : 1;
}

static char *eose_a(const char *sub, bool more, bool hint, void *ctx) {
    (void)sub; (void)more; (void)hint; (void)ctx;
    return strdup("EOSE-A");
}

static char *eose_b(const char *sub, bool more, bool hint, void *ctx) {
    (void)sub; (void)more; (void)hint; (void)ctx;
    return strdup("EOSE-B");
}

static const char *meta_a(void *ctx) {
    (void)ctx;
    return "{\"relay\":\"a\"}";
}

static const char *meta_b(void *ctx) {
    (void)ctx;
    return "{\"relay\":\"b\"}";
}

static bool hint_false(const filter_t *f, size_t n, uintptr_t id, void *ctx) {
    (void)f; (void)n; (void)id; (void)ctx;
    return false;
}

static bool hint_true(const filter_t *f, size_t n, uintptr_t id, void *ctx) {
    (void)f; (void)n; (void)id; (void)ctx;
    return true;
}

static int challenge_calls = 0;
static void challenge_hook(uintptr_t id, void *ctx) {
    (void)id;
    challenge_calls += ctx ? *(int *)ctx : 1;
}

static event_t dummy_event(void) {
    event_t ev;
    memset(&ev, 0, sizeof(ev));
    snprintf(ev.id, sizeof(ev.id),
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    snprintf(ev.pubkey, sizeof(ev.pubkey),
             "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    ev.kind = 1;
    return ev;
}

/* --- Tests --- */

static void test_registry_basics(void) {
    nip_registry_t *reg = nip_registry_create();
    CHECK(reg != NULL && reg->count == 0, "registry creates empty");
    CHECK(nip_registry_get_by_type(reg, NIP_CAP_PUBLICATION_POLICY) == NULL,
          "get_by_type misses on empty registry");

    nip_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.name = "mock-pub";
    cap.type = NIP_CAP_PUBLICATION_POLICY;
    cap.caps.publication_policy.accept_publish = pub_allow;
    nip_registry_register(reg, &cap);
    CHECK(reg->count == 1, "register increments count");
    CHECK(nip_registry_get_by_type(reg, NIP_CAP_PUBLICATION_POLICY) != NULL,
          "get_by_type hits after register");
    CHECK(nip_registry_get_by_type(reg, NIP_CAP_DELIVERY_POLICY) == NULL,
          "get_by_type misses other types");

    /* Deep copy: mutating/freeing the template must not affect the node. */
    cap.caps.publication_policy.accept_publish = pub_deny;
    {
        nip_capability_t *node =
            nip_registry_get_by_type(reg, NIP_CAP_PUBLICATION_POLICY);
        char reason[64] = {0};
        event_t ev = dummy_event();
        CHECK(node->caps.publication_policy.accept_publish(7, &ev, reason,
                                                           sizeof(reason),
                                                           NULL),
              "registry deep-copies descriptor, not pointer");
    }

    nip_registry_clear(reg);
    CHECK(reg->count == 0 &&
          nip_registry_get_by_type(reg, NIP_CAP_PUBLICATION_POLICY) == NULL,
          "clear empties registry");

    /* NULL-safety: none of these may crash. */
    nip_registry_register(NULL, &cap);
    nip_registry_register(reg, NULL);
    nip_registry_clear(NULL);
    nip_registry_destroy(NULL);
    nip_registry_iterate(NULL, NIP_CAP_PUBLICATION_POLICY, NULL, NULL);
    CHECK(1, "NULL registry/capability calls are safe");

    nip_registry_destroy(reg);
}

static void test_publication_conflict(void) {
    /* Order 1: allow registered first, deny second. */
    {
        nip_registry_t *reg = nip_registry_create();
        nip_capability_t cap;
        event_t ev = dummy_event();
        char reason[128] = {0};
        memset(&cap, 0, sizeof(cap));
        cap.name = "allow";
        cap.type = NIP_CAP_PUBLICATION_POLICY;
        cap.caps.publication_policy.accept_publish = pub_allow;
        nip_registry_register(reg, &cap);
        cap.name = "deny";
        cap.caps.publication_policy.accept_publish = pub_deny;
        cap.ctx = (void *)"second";
        nip_registry_register(reg, &cap);
        CHECK(!nip_composition_check_publication(reg, 1, &ev, reason,
                                                 sizeof(reason)),
              "publication conflict denies (allow,deny)");
        CHECK(strstr(reason, "second") != NULL,
              "denier reason survives composition");
        nip_registry_destroy(reg);
    }
    /* Order 2: deny first, allow second -- same verdict (AND). */
    {
        nip_registry_t *reg = nip_registry_create();
        nip_capability_t cap;
        event_t ev = dummy_event();
        char reason[128] = {0};
        memset(&cap, 0, sizeof(cap));
        cap.name = "deny";
        cap.type = NIP_CAP_PUBLICATION_POLICY;
        cap.caps.publication_policy.accept_publish = pub_deny;
        cap.ctx = (void *)"first";
        nip_registry_register(reg, &cap);
        cap.name = "allow";
        cap.caps.publication_policy.accept_publish = pub_allow;
        cap.ctx = NULL;
        nip_registry_register(reg, &cap);
        CHECK(!nip_composition_check_publication(reg, 1, &ev, reason,
                                                 sizeof(reason)),
              "publication conflict denies (deny,allow)");
        nip_registry_destroy(reg);
    }
    /* Unanimous allow. */
    {
        nip_registry_t *reg = nip_registry_create();
        nip_capability_t cap;
        event_t ev = dummy_event();
        char reason[128] = {0};
        memset(&cap, 0, sizeof(cap));
        cap.name = "a1";
        cap.type = NIP_CAP_PUBLICATION_POLICY;
        cap.caps.publication_policy.accept_publish = pub_allow;
        nip_registry_register(reg, &cap);
        cap.name = "a2";
        nip_registry_register(reg, &cap);
        CHECK(nip_composition_check_publication(reg, 1, &ev, reason,
                                                sizeof(reason)),
              "unanimous allow permits");
        nip_registry_destroy(reg);
    }
    /* NULL hook is skipped, not fatal. */
    {
        nip_registry_t *reg = nip_registry_create();
        nip_capability_t cap;
        event_t ev = dummy_event();
        char reason[128] = {0};
        memset(&cap, 0, sizeof(cap));
        cap.name = "null-hook";
        cap.type = NIP_CAP_PUBLICATION_POLICY;
        cap.caps.publication_policy.accept_publish = NULL;
        nip_registry_register(reg, &cap);
        CHECK(nip_composition_check_publication(reg, 1, &ev, reason,
                                                sizeof(reason)),
              "NULL accept_publish hook is skipped");
        nip_registry_destroy(reg);
    }
    CHECK(nip_composition_check_publication(NULL, 1, NULL, NULL, 0),
          "NULL registry permits publication");
}

static void test_delivery_conflict(void) {
    event_t ev = dummy_event();
    {
        nip_registry_t *reg = nip_registry_create();
        nip_capability_t cap;
        memset(&cap, 0, sizeof(cap));
        cap.name = "allow";
        cap.type = NIP_CAP_DELIVERY_POLICY;
        cap.caps.delivery_policy.can_deliver = del_allow;
        nip_registry_register(reg, &cap);
        cap.name = "veto";
        cap.caps.delivery_policy.can_deliver = del_veto;
        nip_registry_register(reg, &cap);
        deliver_calls = 0;
        CHECK(!nip_composition_check_delivery(reg, &ev, 1),
              "delivery veto wins over allow");
        /* Veto short-circuits (veto was registered last, so it runs first):
         * the allow hook is never consulted. */
        CHECK(deliver_calls == 1, "delivery veto short-circuits evaluation");
        nip_registry_destroy(reg);
    }
    {
        nip_registry_t *reg = nip_registry_create();
        nip_capability_t cap;
        memset(&cap, 0, sizeof(cap));
        cap.name = "allow";
        cap.type = NIP_CAP_DELIVERY_POLICY;
        cap.caps.delivery_policy.can_deliver = del_allow;
        nip_registry_register(reg, &cap);
        deliver_calls = 0;
        CHECK(nip_composition_check_delivery(reg, &ev, 1),
              "unanimous delivery allow permits");
        CHECK(deliver_calls == 1, "single delivery hook consulted once");
        nip_registry_destroy(reg);
    }
    CHECK(nip_composition_check_delivery(NULL, &ev, 1),
          "NULL registry permits delivery");
}

static void test_kind_handlers(void) {
    event_t ev = dummy_event();
    /* Single accepter. */
    {
        nip_registry_t *reg = nip_registry_create();
        nip_capability_t cap;
        memset(&cap, 0, sizeof(cap));
        cap.name = "h";
        cap.type = NIP_CAP_KIND_HANDLER;
        cap.caps.kind_handler.handles_kind = kind_is_1;
        cap.caps.kind_handler.process_event = kind_accept;
        cap.ctx = (void *)"solo";
        nip_registry_register(reg, &cap);
        nip_kind_composition_result_t r =
            nip_composition_process_kind(reg, 1, &ev, NULL, "wss://x");
        CHECK(r.any_handler_matched && r.result.accepted &&
              r.result.should_broadcast && r.result.should_store,
              "single kind handler accepts with flags");
        nip_registry_destroy(reg);
    }
    /* No handler matches the kind. */
    {
        nip_registry_t *reg = nip_registry_create();
        nip_capability_t cap;
        memset(&cap, 0, sizeof(cap));
        cap.name = "h";
        cap.type = NIP_CAP_KIND_HANDLER;
        cap.caps.kind_handler.handles_kind = kind_is_1;
        cap.caps.kind_handler.process_event = kind_accept;
        nip_registry_register(reg, &cap);
        ev.kind = 2;
        nip_kind_composition_result_t r =
            nip_composition_process_kind(reg, 1, &ev, NULL, "wss://x");
        ev.kind = 1;
        CHECK(!r.any_handler_matched && !r.result.accepted,
              "unmatched kind leaves default reject");
        nip_registry_destroy(reg);
    }
    /* Conflict, both registration orders: reject wins either way and the
     * verdict is deterministic across repeated evaluation. */
    {
        const char *orders[2][2] = {{"acc", "rej"}, {"rej", "acc"}};
        for (int o = 0; o < 2; o++) {
            nip_registry_t *reg = nip_registry_create();
            nip_capability_t cap;
            memset(&cap, 0, sizeof(cap));
            for (int k = 0; k < 2; k++) {
                cap.name = orders[o][k];
                cap.type = NIP_CAP_KIND_HANDLER;
                cap.caps.kind_handler.handles_kind = kind_is_1;
                cap.ctx = (void *)orders[o][k];
                cap.caps.kind_handler.process_event =
                    strcmp(orders[o][k], "acc") == 0 ? kind_accept : kind_reject;
                nip_registry_register(reg, &cap);
            }
            nip_kind_composition_result_t r1 =
                nip_composition_process_kind(reg, 1, &ev, NULL, "wss://x");
            nip_kind_composition_result_t r2 =
                nip_composition_process_kind(reg, 1, &ev, NULL, "wss://x");
            char label[96];
            snprintf(label, sizeof(label),
                     "kind conflict rejects (%s,%s)", orders[o][0], orders[o][1]);
            CHECK(r1.any_handler_matched && !r1.result.accepted, label);
            CHECK(r2.result.accepted == r1.result.accepted &&
                  strcmp(r2.result.response_msg, r1.result.response_msg) == 0,
                  "kind conflict verdict is deterministic");
            nip_registry_destroy(reg);
        }
    }
    /* Unanimous accept across two handlers. */
    {
        nip_registry_t *reg = nip_registry_create();
        nip_capability_t cap;
        memset(&cap, 0, sizeof(cap));
        cap.name = "a";
        cap.type = NIP_CAP_KIND_HANDLER;
        cap.caps.kind_handler.handles_kind = kind_is_1;
        cap.caps.kind_handler.process_event = kind_accept;
        nip_registry_register(reg, &cap);
        cap.name = "b";
        nip_registry_register(reg, &cap);
        nip_kind_composition_result_t r =
            nip_composition_process_kind(reg, 1, &ev, NULL, "wss://x");
        CHECK(r.result.accepted, "unanimous kind accept permits");
        nip_registry_destroy(reg);
    }
}

static void test_query_conflict(void) {
    filter_t filters;
    char reason[128];
    memset(&filters, 0, sizeof(filters));
    {
        nip_registry_t *reg = nip_registry_create();
        nip_capability_t cap;
        memset(&cap, 0, sizeof(cap));
        cap.name = "allow";
        cap.type = NIP_CAP_QUERY_POLICY;
        cap.caps.query_policy.authorize_query = query_allow;
        cap.caps.query_policy.modify_results = NULL;
        nip_registry_register(reg, &cap);
        cap.name = "deny";
        cap.caps.query_policy.authorize_query = query_deny;
        nip_registry_register(reg, &cap);
        memset(reason, 0, sizeof(reason));
        CHECK(!nip_composition_authorize_query(reg, 1, &filters, 1, reason,
                                              sizeof(reason)),
              "query conflict denies");
        CHECK(strstr(reason, "query denied") != NULL,
              "query denier reason survives");
        nip_registry_destroy(reg);
    }
    {
        nip_registry_t *reg = nip_registry_create();
        nip_capability_t cap;
        memset(&cap, 0, sizeof(cap));
        cap.name = "allow";
        cap.type = NIP_CAP_QUERY_POLICY;
        cap.caps.query_policy.authorize_query = query_allow;
        nip_registry_register(reg, &cap);
        memset(reason, 0, sizeof(reason));
        CHECK(nip_composition_authorize_query(reg, 1, &filters, 1, reason,
                                              sizeof(reason)),
              "unanimous query allow permits");
        nip_registry_destroy(reg);
    }
    CHECK(nip_composition_authorize_query(NULL, 1, &filters, 1, reason,
                                          sizeof(reason)),
          "NULL registry permits query");
}

static void test_maintenance_and_broadcast(void) {
    nip_registry_t *reg = nip_registry_create();
    nip_capability_t cap;
    int w1 = 1, w2 = 10, c1 = 100, c2 = 5;
    memset(&cap, 0, sizeof(cap));
    cap.name = "m1";
    cap.type = NIP_CAP_MAINTENANCE;
    cap.caps.maintenance.timer = maint_tick;
    cap.caps.maintenance.interval_ms = 1000;
    cap.ctx = &w1;
    nip_registry_register(reg, &cap);
    cap.name = "m2";
    cap.ctx = &w2;
    nip_registry_register(reg, &cap);
    maint_runs = 0;
    nip_composition_run_maintenance(reg, NULL);
    CHECK(maint_runs == 11, "all maintenance timers run");

    cap.name = "ch1";
    cap.type = NIP_CAP_PROTOCOL_RESPONSE;
    memset(&cap.caps, 0, sizeof(cap.caps));
    cap.caps.protocol_response.send_auth_challenge = challenge_hook;
    cap.ctx = &c1;
    nip_registry_register(reg, &cap);
    cap.name = "ch2";
    cap.ctx = &c2;
    nip_registry_register(reg, &cap);
    challenge_calls = 0;
    nip_composition_send_auth_challenge(reg, 9);
    CHECK(challenge_calls == 105, "challenge broadcast reaches all hooks");
    nip_composition_send_auth_challenge(NULL, 9);
    nip_composition_run_maintenance(NULL, NULL);
    CHECK(1, "NULL-registry broadcast/maintenance are safe");
    nip_registry_destroy(reg);
}

static void test_first_wins(void) {
    /* Registry prepends: the LAST registered capability is consulted first,
     * so "first wins" means last-registered wins. Pin both orders. */
    {
        nip_registry_t *reg = nip_registry_create();
        nip_capability_t cap;
        char *out;
        memset(&cap, 0, sizeof(cap));
        cap.name = "A";
        cap.type = NIP_CAP_PROTOCOL_RESPONSE;
        cap.caps.protocol_response.build_eose = eose_a;
        nip_registry_register(reg, &cap);
        cap.name = "B";
        cap.caps.protocol_response.build_eose = eose_b;
        nip_registry_register(reg, &cap);
        out = nip_composition_build_eose(reg, "s", false, false);
        CHECK(out && strcmp(out, "EOSE-B") == 0, "eose first-wins (B last)");
        free(out);
        out = nip_composition_build_count(reg, "s", 3);
        CHECK(out == NULL, "count NULL when no builder set");
        nip_registry_destroy(reg);
    }
    {
        nip_registry_t *reg = nip_registry_create();
        nip_capability_t cap;
        const char *doc;
        memset(&cap, 0, sizeof(cap));
        cap.name = "B";
        cap.type = NIP_CAP_METADATA;
        cap.caps.metadata.info_document = meta_b;
        nip_registry_register(reg, &cap);
        cap.name = "A";
        cap.caps.metadata.info_document = meta_a;
        nip_registry_register(reg, &cap);
        doc = nip_composition_get_info_document(reg);
        CHECK(doc && strcmp(doc, "{\"relay\":\"a\"}") == 0,
              "metadata first-wins (A last)");
        nip_registry_destroy(reg);
    }
    CHECK(nip_composition_build_eose(NULL, "s", false, false) == NULL,
          "NULL registry builds nothing");
    CHECK(nip_composition_get_info_document(NULL) == NULL,
          "NULL registry has no metadata");
}

static void test_auth_hint_or(void) {
    filter_t filters;
    memset(&filters, 0, sizeof(filters));
    {
        nip_registry_t *reg = nip_registry_create();
        nip_capability_t cap;
        memset(&cap, 0, sizeof(cap));
        cap.name = "no";
        cap.type = NIP_CAP_PROTOCOL_RESPONSE;
        cap.caps.protocol_response.needs_auth_hint = hint_false;
        nip_registry_register(reg, &cap);
        cap.name = "yes";
        cap.caps.protocol_response.needs_auth_hint = hint_true;
        nip_registry_register(reg, &cap);
        CHECK(nip_composition_needs_auth_hint(reg, &filters, 1, 4),
              "auth hint OR: one true wins");
        nip_registry_destroy(reg);
    }
    {
        nip_registry_t *reg = nip_registry_create();
        nip_capability_t cap;
        memset(&cap, 0, sizeof(cap));
        cap.name = "no1";
        cap.type = NIP_CAP_PROTOCOL_RESPONSE;
        cap.caps.protocol_response.needs_auth_hint = hint_false;
        nip_registry_register(reg, &cap);
        cap.name = "no2";
        nip_registry_register(reg, &cap);
        CHECK(!nip_composition_needs_auth_hint(reg, &filters, 1, 4),
              "auth hint OR: all false stays false");
        nip_registry_destroy(reg);
    }
    CHECK(!nip_composition_needs_auth_hint(NULL, &filters, 1, 4),
          "NULL registry needs no hint");
}

/* Hot-reload swap pattern: clear() then re-register the new generation.
 * Old function pointers must be unreachable afterwards. */
static void test_reload_swap(void) {
    nip_registry_t *reg = nip_registry_create();
    nip_capability_t cap;
    event_t ev = dummy_event();
    char reason[128];
    memset(&cap, 0, sizeof(cap));

    cap.name = "gen1-pub";
    cap.type = NIP_CAP_PUBLICATION_POLICY;
    cap.caps.publication_policy.accept_publish = pub_allow;
    nip_registry_register(reg, &cap);
    memset(reason, 0, sizeof(reason));
    CHECK(nip_composition_check_publication(reg, 1, &ev, reason, sizeof(reason)),
          "gen1 allow active");

    nip_registry_clear(reg);
    CHECK(reg->count == 0, "clear drops generation");

    cap.name = "gen2-pub";
    cap.caps.publication_policy.accept_publish = pub_deny;
    cap.ctx = (void *)"gen2";
    nip_registry_register(reg, &cap);
    memset(reason, 0, sizeof(reason));
    CHECK(!nip_composition_check_publication(reg, 1, &ev, reason,
                                             sizeof(reason)) &&
          strstr(reason, "gen2") != NULL,
          "gen2 deny active after swap, gen1 unreachable");
    CHECK(reg->count == 1, "swap leaves exactly one generation");
    nip_registry_destroy(reg);
}

static void count_iter_fn(nip_capability_t *c, void *ud) {
    (void)c;
    (*(int *)ud)++;
}

static void test_iterate(void) {
    nip_registry_t *reg = nip_registry_create();
    nip_capability_t cap;
    int seen = 0;
    memset(&cap, 0, sizeof(cap));
    cap.name = "m1";
    cap.type = NIP_CAP_MAINTENANCE;
    cap.caps.maintenance.timer = maint_tick;
    nip_registry_register(reg, &cap);
    cap.name = "m2";
    nip_registry_register(reg, &cap);
    cap.name = "pub";
    cap.type = NIP_CAP_PUBLICATION_POLICY;
    cap.caps.publication_policy.accept_publish = pub_allow;
    nip_registry_register(reg, &cap);
    nip_registry_iterate(reg, NIP_CAP_MAINTENANCE, count_iter_fn, &seen);
    CHECK(seen == 2, "iterate visits every capability of a type");
    CHECK(reg->count == 3, "mixed-type registry counts all nodes");
    nip_registry_destroy(reg);
}

int main(void) {
    printf("Running nip_capability composition tests...\n");
    test_registry_basics();
    test_publication_conflict();
    test_delivery_conflict();
    test_kind_handlers();
    test_query_conflict();
    test_maintenance_and_broadcast();
    test_first_wins();
    test_auth_hint_or();
    test_reload_swap();
    test_iterate();
    printf("composition: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
