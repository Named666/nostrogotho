/* ============================================================================
 * NIP-XX Template — copy this file to create a new NIP plugin.
 *
 * A plugin is a self-contained module in src/nips/. It links itself into the
 * relay purely by being compiled: the build tool globs src/nips/*.c, and the
 * __attribute__((constructor)) below registers the plugin at startup.
 *
 * To create a new NIP:
 *   1. Copy this file to src/nips/nipXX.c (and nipXX.h if you need to export
 *      symbols to other modules).
 *   2. Rename every "nipXX_" / "nip_xx" symbol below.
 *   3. Fill in the hooks you need; delete the ones you don't (NULL = unused).
 *   4. Rebuild with .\nob.exe — nothing else to wire up.
 *
 * The plugin interface (nip_plugin_t) is documented in nip_plugin.h.
 * ============================================================================
 */

#include "nip_plugin.h"
#include "nip01.h"
#include "nip_event.h"
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Per-plugin state
 *
 * Instead of file-scope static globals, keep state in a struct and point
 * plugin.ctx at it. Every hook receives ctx back, so the plugin is fully
 * re-entrant and self-contained.
 * ============================================================================
 */

typedef struct {
    const char *service_url;   /* captured from relay_config_t in init() */
    int some_counter;          /* example state */
} nip_xx_state_t;

static nip_xx_state_t nip_xx_state;

/* ============================================================================
 * Kind listener
 *
 * Declare the event kinds this plugin handles in plugin.kinds[] and provide
 * on_event. The NIP-01 dispatcher calls on_event for every event whose kind
 * falls inside a declared range. The first listener to accept wins; if every
 * matching listener rejects, the event is rejected.
 *
 * Use the ergonomic result constructors instead of hand-rolling the struct:
 *   nip_plugin_accept()                          -> accepted + broadcast
 *   nip_plugin_reject("invalid: ...")            -> rejected with reason
 *   nip_plugin_store_and_broadcast(storage, ev)  -> insert + accept
 *   nip_plugin_store_only(storage, ev)           -> insert, no broadcast
 * ============================================================================
 */

static nip01_process_result_t nip_xx_on_event(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {

    (void) connection;
    (void) relay_url;

    /* Example: reject events whose content is empty. */
    if (!event->content || !event->content[0]) {
        return nip_plugin_reject("invalid: empty content");
    }

    /* Example: store and broadcast. */
    return nip_plugin_store_and_broadcast(storage, event);
}

/* ============================================================================
 * Lifecycle hooks (optional — delete the ones you don't need)
 * ============================================================================
 */

/* Called once during server_configure() with the relay's runtime config. */
static void nip_xx_init(const relay_config_t *config, void *ctx) {
    nip_xx_state_t *state = (nip_xx_state_t *) ctx;
    state->service_url = config->service_url;
}

/* Connection opened / closed (e.g. NIP-42 sends its AUTH challenge here). */
static void nip_xx_on_connect(struct mg_connection *connection, void *ctx) {
    (void) connection;
    (void) ctx;
}

static void nip_xx_on_disconnect(struct mg_connection *connection, void *ctx) {
    (void) connection;
    (void) ctx;
}

/* Return true if the plugin consumed the message (e.g. NIP-42 "AUTH"). */
static bool nip_xx_on_message(struct mg_connection *connection,
                              json_value_t *values, size_t count, void *ctx) {
    (void) connection;
    (void) values;
    (void) count;
    (void) ctx;
    return false;
}

/* Publish policy. Return false and fill `reason` to reject an EVENT before
 * kind dispatch (e.g. NIP-40 expiry, NIP-42 restricted tags). */
static bool nip_xx_accept_publish(struct mg_connection *connection,
                                  const event_t *event,
                                  char *reason, size_t reason_size, void *ctx) {
    (void) connection;
    (void) event;
    (void) reason;
    (void) reason_size;
    (void) ctx;
    return true;
}

/* Delivery policy. Return false to suppress an event for this connection on
 * both stored queries and broadcasts (NIP-40, NIP-17). */
static bool nip_xx_can_deliver(const event_t *event,
                               struct mg_connection *connection, void *ctx) {
    (void) event;
    (void) connection;
    (void) ctx;
    return true;
}

/* Called when a REQ finishes. May emit its own protocol traffic and returns
 * true to make the EOSE carry the "auth" completeness hint (NIP-17/67). */
static bool nip_xx_eose_auth_hint(struct mg_connection *connection,
                                  const filter_t *filters, size_t count,
                                  void *ctx) {
    (void) connection;
    (void) filters;
    (void) count;
    (void) ctx;
    return false;
}

/* Build the ["EOSE", ...] / ["COUNT", ...] response (malloc'd, caller frees).
 * The first plugin providing the hook wins; otherwise the server falls back
 * to a bare protocol-default response. */
static char *nip_xx_build_eose(const char *sub, bool has_more, bool auth_hint,
                               void *ctx) {
    (void) sub;
    (void) has_more;
    (void) auth_hint;
    (void) ctx;
    return NULL;
}

static char *nip_xx_build_count(const char *sub, unsigned long count, void *ctx) {
    (void) sub;
    (void) count;
    (void) ctx;
    return NULL;
}

/* Periodic maintenance, driven every timer_interval_ms inside the event
 * loop (e.g. NIP-40 expired-event GC). */
static void nip_xx_timer(storage_context_t *storage, void *ctx) {
    (void) storage;
    (void) ctx;
}

/* NIP-11 relay information document (HTTP, Accept: application/nostr+json). */
static const char *nip_xx_info_document(void *ctx) {
    (void) ctx;
    return NULL;
}

/* ============================================================================
 * Plugin registration
 *
 * This is the ONLY registration call a plugin needs. Declaring kinds[] and
 * on_event wires the plugin into the NIP-01 event dispatcher; every other
 * hook is optional. The constructor runs before main() on MinGW/GCC.
 * ============================================================================
 */

static nip_plugin_t nip_xx_plugin = {
    .name = "nipXX",
    .ctx = &nip_xx_state,
    .kinds = {
        NIP_PLUGIN_KIND(1),        /* listen for a single kind */
        /* { 10000, 19999 },       /* or a range of kinds */
    },
    .kinds_count = 1,
    .on_event = nip_xx_on_event,
    .init = nip_xx_init,
    .on_connect = nip_xx_on_connect,
    .on_disconnect = nip_xx_on_disconnect,
    .on_message = nip_xx_on_message,
    .accept_publish = nip_xx_accept_publish,
    .can_deliver = nip_xx_can_deliver,
    .eose_auth_hint = nip_xx_eose_auth_hint,
    .build_eose = nip_xx_build_eose,
    .build_count = nip_xx_build_count,
    .timer = nip_xx_timer,
    .timer_interval_ms = 0,        /* 0 = no periodic timer */
    .info_document = nip_xx_info_document,
};

__attribute__((constructor)) static void nip_xx_register_at_startup(void) {
    nip_plugin_register(&nip_xx_plugin);
}