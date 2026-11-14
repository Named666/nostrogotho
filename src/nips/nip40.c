#include "nip40.h"
#include "nip_event.h"
#include "nip_plugin.h"
#include "../storage.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

/* ============================================================================
 * NIP-40: Expiration Timestamp
 *
 * Events may carry an ["expiration", "<unix timestamp>"] tag. Relays:
 *   - SHOULD drop any events published to them if they are expired,
 *   - SHOULD NOT send expired events to clients, even if they are stored.
 *
 * Expiration does not affect the storage of ephemeral events (kinds
 * 20000-29999), which are never stored in the first place.
 * ============================================================================ */

/* nip40_event_is_expired - Check whether an event's expiration tag has passed.
 *
 * Scans the event's raw tags JSON for an "expiration" tag and compares the
 * parsed unix timestamp against the current time. NULL-safe.
 */
bool nip40_event_is_expired(const event_t *event) {
    if (!event || !event->tags_json) return false;

    jstr_t key, tag, value, tags = jl_str(event->tags_json);
    size_t offset = 0;
    time_t now = 0;

    /* Runs per delivery candidate and per stored row: no allocation unless
     * the value is unusually long. An expired tag governs even if another
     * expiration tag is not expired; a non-string value is ignored. */
    while ((offset = jl_next(tags, offset, &key, &tag)) != 0) {
        if (!nip_tag_named(tag, "expiration", &value) || !value.buf || value.buf[0] != '"') continue;
        char small[40], *heap = NULL, *text = small;
        size_t len = 0;
        if (value.len <= sizeof(small)) {
            if (!jl_unescape(value, small, &len)) continue;
            small[len] = '\0';
        } else if (!(text = heap = jl_unquote(value))) {
            continue;
        }
        time_t expiration = (time_t) strtoll(text, NULL, 10);
        free(heap);
        if (!now) now = time(NULL);
        if (expiration <= now) return true;
    }
    return false;
}

/* nip40_garbage_collect - Background sweep of NIP-40 expired events.
 *
 * Callback for a periodic relay timer. Runs on the storage writer path (so it never races the storage backend) and asks the storage
 * layer to delete every event whose expiration timestamp has passed.
 *
 * The storage layer is best-effort; we only log the outcome and never fail
 * the server on a purge error.
 *
 * Args:
 *   arg - storage_context_t* (the backend to sweep). May be NULL / may lack
 *         purge_expired(); either case is a no-op.
 */
void nip40_garbage_collect(void *arg) {
    storage_context_t *storage = (storage_context_t *) arg;
    if (!storage || !storage->purge_expired) return;

    size_t deleted = 0;
    bool ok = storage->purge_expired(time(NULL), &deleted);
    if (deleted > 0) fprintf(stdout, "[NIP-40 GC] deleted %zu expired event(s)\n", deleted);
    if (!ok) fprintf(stderr, "NIP-40 GC: purge failed\n");
}

/* ============================================================================
 * Plugin registration
 *
 * NIP-40 participates in the relay entirely through the plugin hooks below.
 * Removing nip40.c from the build removes: publication-time expiry checks,
 * per-delivery expiry filtering, the background GC sweep — nothing else in
 * the relay references this module.
 * ============================================================================ */

/* Publish policy: "Relays SHOULD drop any events that are published to them
 * if they are expired." */
static bool nip40_accept_publish(relay_conn_t *connection,
                                 const event_t *event,
                                 char *reason, size_t reason_size,
                                 void *ctx) {
    (void) connection;
    (void) ctx;
    if (nip40_event_is_expired(event)) {
        snprintf(reason, reason_size, "invalid: event is expired");
        return false;
    }
    return true;
}

/* Delivery policy: "Relays SHOULD NOT send expired events to clients, even
 * if they are stored." */
static bool nip40_can_deliver(const event_t *event, relay_conn_t *connection,
                              void *ctx) {
    (void) connection;
    (void) ctx;
    return !nip40_event_is_expired(event);
}

/* Maintenance: periodic sweep of stored expired events. */
static void nip40_plugin_timer(storage_context_t *storage, void *ctx) {
    (void) ctx;
    nip40_garbage_collect(storage);
}

static nip_plugin_t nip40_plugin = {
    .name = "nip40",
    .accept_publish = nip40_accept_publish,
    .can_deliver = nip40_can_deliver,
    .timer = nip40_plugin_timer,
    .timer_interval_ms = 60 * 1000,
};

__attribute__((constructor)) static void nip40_register_at_startup(void) {
    nip_plugin_register(&nip40_plugin);
}
