/* ============================================================================
 * NIP-XX Template — copy this file to create a new NIP.
 *
 * A NIP is a single self-contained file in src/nips/. It links itself into
 * the relay purely by being compiled: the build globs src/nips/*.c (except
 * nip_template.c), and the constructor below registers the NIP at startup
 * in monolithic builds and on every hot-reload activation in -hr builds.
 * No header, no registration list: logic + capability table + constructor
 * all live here.
 *
 * To create a new NIP:
 *   1. Copy this file to src/nips/nipXX.c.
 *   2. Rename every "nipxx_" symbol below.
 *   3. Fill in ONLY the hooks you need; delete the rest.
 *   4. Rebuild: `nob` (monolithic) or save while `nob [win|linux] -hr`
 *      watches — the new behavior swaps in without dropping sockets.
 *
 * Rules (enforced by the architecture, not just convention):
 *   - NIP code NEVER sees Mongoose (`struct mg_connection`) or SQLite.
 *     Connections are opaque `connection_id_t`; storage goes through
 *     `storage_context_t`; replies are built with protocol_serialize_* and
 *     sent with nip_env_send_json() from nips/nip_env.h (same call in
 *     monolithic and hot-reload module builds — never include
 *     relay/relay.h or nhr_module.h here, and never test
 *     NHR_BUILD_MODULE: nip_env.c owns that branch).
 *   - No NIP sends OK/EOSE/CLOSED itself for the normal EVENT/REQ flow.
 *     Return a policy decision; the relay core owns framing + transport.
 *   - State that must survive `nob -hr` reloads lives in host-owned
 *     sessions (via nip_env_session_* in nips/nip_env.h) or is re-derivable in
 *     lifecycle init. Module statics die with the old .so/.dll — never
 *     rely on them across a reload. Empty migration state is valid.
 *   - Composition is deterministic, never registration-order dependent:
 *       publication policy : ALL must permit (AND)
 *       delivery policy    : ANY may veto
 *       kind handlers      : ALL matched consulted; any rejection wins (AND on accepted), broadcast/store are OR
 *       maintenance        : ALL run every interval tick
 *       EOSE/COUNT/metadata: FIRST non-NULL wins (explicit priority)
 *
 * The capability interface is documented in nip_capability.h.
 * ============================================================================
 */

#include "nip_capability.h"
#include "nips/nip_env.h"    /* send/session/validate: same call in all builds */
#include "protocol/tag_iter.h"
#include "protocol/protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Per-NIP state
 *
 * Prefer NO state. When you need config, keep a small static ctx shared by
 * all caps of this NIP (module statics are per-generation: they are fresh
 * after every reload, which is exactly what you want for re-derivable
 * state). Heap-allocating per register call leaks across reloads because
 * the registry never frees ctx (several caps share one ctx); if you must
 * heap-allocate, free it once in lifecycle shutdown guarded against
 * repeated calls, or in module shutdown.
 * ============================================================================
 */

typedef struct {
    char service_url[256];          /* captured from relay_config_t in init() */
} nipxx_ctx_t;

static nipxx_ctx_t nipxx_ctx;

/* Send a JSON frame without touching transport types. */
static void nipxx_send_json(connection_id_t id, const char *json) {
    nip_env_send_json(id, json);
}

/* ============================================================================
 * Capability hooks — implement only what your NIP needs, delete the rest.
 * ============================================================================
 */

/* Called once per process (monolithic) or per module generation (-hr init /
 * post_reload) before any traffic. */
static void nipxx_lifecycle_init(const relay_config_t *config, void *ctx) {
    nipxx_ctx_t *c = (nipxx_ctx_t *)ctx;
    if (c && config)
        snprintf(c->service_url, sizeof(c->service_url), "%s", config->service_url);
}

static void nipxx_lifecycle_shutdown(void *ctx) {
    (void)ctx;
    /* Free heap ctx here ONLY if you heap-allocated it (guard: runs once
     * per cap sharing the ctx — prefer the static ctx above instead). */
}

/* Connection open/close (e.g. NIP-42 sends its AUTH challenge here). */
static void nipxx_on_connect(connection_id_t id, void *ctx) {
    (void)id; (void)ctx;
}

static void nipxx_on_disconnect(connection_id_t id, void *ctx) {
    (void)id; (void)ctx;
}

/* Intercept a parsed protocol message. Return true ONLY if this NIP fully
 * consumed it (custom verb, AUTH response). Otherwise return false and the
 * relay runs default REQ/COUNT/CLOSE/EVENT dispatch. */
static bool nipxx_on_message(connection_id_t id, const protocol_message_t *msg, void *ctx) {
    (void)id; (void)msg; (void)ctx;
    return false;
}

/* Publication policy: return false + fill `reason` to reject an EVENT
 * before kind dispatch (e.g. expiry, auth-required). ALL policies must
 * permit for the event to proceed. */
static bool nipxx_accept_publish(connection_id_t id, const event_t *event,
                                 char *reason, size_t reason_size, void *ctx) {
    (void)id; (void)event; (void)reason; (void)reason_size; (void)ctx;
    return true;
}

/* Kind handler: claim disjoint kinds in handles_kind; process_event performs
 * any storage work through storage_context_t and returns a policy decision
 * (accepted / should_broadcast), never transport output. */
static bool nipxx_handles_kind(int kind, void *ctx) {
    (void)ctx;
    return kind == 12345;           /* replace with your NIP's kind(s) */
}

static nip01_process_result_t nipxx_process_event(connection_id_t id, const event_t *event,
                                                  storage_context_t *storage,
                                                  const char *relay_url, void *ctx) {
    (void)id; (void)relay_url; (void)ctx;
    nip01_process_result_t r = {0};
    storage_insert_result_t sr = storage->insert_record(event, NULL, 0);
    if (sr.result == STORAGE_OK || sr.result == STORAGE_DUPLICATE) {
        r.accepted = true;
        r.should_store = true;
        r.should_broadcast = true;
    } else {
        snprintf(r.response_msg, sizeof(r.response_msg), "error: %s", sr.error_message);
    }
    return r;
}

/* Delivery policy: return false to suppress an event for this connection on
 * BOTH stored queries and live broadcasts. ANY veto wins. */
static bool nipxx_can_deliver(const event_t *event, connection_id_t id, void *ctx) {
    (void)event; (void)id; (void)ctx;
    return true;
}

/* Periodic maintenance, driven by the smallest registered interval_ms
 * (e.g. expired-event GC). Every registered timer runs each tick. */
static void nipxx_timer(storage_context_t *storage, void *ctx) {
    (void)storage; (void)ctx;
}

/* NIP-11 relay information document fragment (HTTP). First non-NULL wins. */
static const char *nipxx_info_document(void *ctx) {
    (void)ctx;
    return NULL;
}

/* Query policy: authorize REQ queries. */
static bool nipxx_authorize_query(connection_id_t id, filter_t *filters, size_t count,
                                   char *reason, size_t reason_size, void *ctx) {
    (void)id; (void)filters; (void)count; (void)reason; (void)reason_size; (void)ctx;
    return true;
}

/* Protocol response: custom EOSE/COUNT (optional). First non-NULL wins. */
static char *nipxx_build_eose(const char *sub, bool has_more, bool auth_hint, void *ctx) {
    (void)sub; (void)has_more; (void)auth_hint; (void)ctx;
    return NULL;
}

static char *nipxx_build_count(const char *sub, unsigned long count, void *ctx) {
    (void)sub; (void)count; (void)ctx;
    return NULL;
}

/* ============================================================================
 * Capability descriptors — one per capability type you implement.
 * `ctx` points at the shared static above: no alloc, no leak, no
 * cross-reload dangling (registry deep-copies the descriptor; the static
 * dies with its own module generation).
 * ============================================================================
 */

static nip_capability_t nipxx_caps[] = {
    /* Uncomment the capabilities your NIP actually needs:
    {
        .name = "nipxx-lifecycle", .type = NIP_CAP_LIFECYCLE, .ctx = &nipxx_ctx,
        .caps.lifecycle = { .init = nipxx_lifecycle_init, .shutdown = nipxx_lifecycle_shutdown },
    },
    {
        .name = "nipxx-connection", .type = NIP_CAP_CONNECTION, .ctx = &nipxx_ctx,
        .caps.connection = { .on_connect = nipxx_on_connect, .on_disconnect = nipxx_on_disconnect },
    },
    {
        .name = "nipxx-message", .type = NIP_CAP_MESSAGE_INTERCEPT, .ctx = &nipxx_ctx,
        .caps.message_intercept = { .on_message = nipxx_on_message },
    },
    {
        .name = "nipxx-publication", .type = NIP_CAP_PUBLICATION_POLICY, .ctx = &nipxx_ctx,
        .caps.publication_policy = { .accept_publish = nipxx_accept_publish },
    },
    {
        .name = "nipxx-kind", .type = NIP_CAP_KIND_HANDLER, .ctx = &nipxx_ctx,
        .caps.kind_handler = { .handles_kind = nipxx_handles_kind, .process_event = nipxx_process_event },
    },
    {
        .name = "nipxx-delivery", .type = NIP_CAP_DELIVERY_POLICY, .ctx = &nipxx_ctx,
        .caps.delivery_policy = { .can_deliver = nipxx_can_deliver },
    },
    {
        .name = "nipxx-query", .type = NIP_CAP_QUERY_POLICY, .ctx = &nipxx_ctx,
        .caps.query_policy = { .authorize_query = nipxx_authorize_query },
    },
    {
        .name = "nipxx-maintenance", .type = NIP_CAP_MAINTENANCE, .ctx = &nipxx_ctx,
        .caps.maintenance = { .timer = nipxx_timer, .interval_ms = 60 * 1000 },
    },
    {
        .name = "nipxx-metadata", .type = NIP_CAP_METADATA, .ctx = &nipxx_ctx,
        .caps.metadata = { .info_document = nipxx_info_document },
    },
    {
        .name = "nipxx-protocol", .type = NIP_CAP_PROTOCOL_RESPONSE, .ctx = &nipxx_ctx,
        .caps.protocol_response = { .build_eose = nipxx_build_eose, .build_count = nipxx_build_count },
    },
     */
};

/* Trim the table above to what you implement, then register it using the
 * NIP_REGISTER macro. This is the ONLY registration call a NIP needs. */

NIP_REGISTER(nipxx, nipxx_caps)