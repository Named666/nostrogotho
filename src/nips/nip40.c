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

    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    time_t now = time(NULL);

    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = nip_tag_element(tag, 0);
        if (name && strcmp(name, "expiration") == 0) {
            char *value = nip_tag_element(tag, 1);
            bool expired = false;
            if (value) {
                time_t expiration = (time_t) strtoll(value, NULL, 10);
                expired = expiration <= now;
            }
            free(value);
            free(name);
            if (expired) return true;
            /* An expired tag governs even if another tag is unexpired. */
        } else {
            free(name);
        }
    }
    return false;
}

static bool nip40_expiry_predicate(const event_t *event, void *userdata) {
    (void)userdata;
    return nip40_event_is_expired(event);
}

/* nip40_garbage_collect - Background sweep of NIP-40 expired events.
 *
 * Callback for a periodic mongoose timer. Runs inside the single-threaded
 * event loop (so it never races the storage backend) and asks the storage
 * layer to delete every event whose expiration timestamp has passed.
 *
 * The storage layer is best-effort; we only log the outcome and never fail
 * the server on a purge error.
 *
 * Args:
 *   arg - storage_context_t* (the backend to sweep). May be NULL; then this
 *         operation is a no-op.
 */
void nip40_garbage_collect(void *arg) {
    storage_context_t *storage = (storage_context_t *) arg;
    storage_event_scope_t scope = {0};
    char cursor[MAX_ID_SIZE + 1] = "";
    size_t total = 0;
    bool more = false;
    if (!storage || !storage->delete_matching) return;
    do {
        size_t deleted = 0;
        char next_id[MAX_ID_SIZE + 1] = "";
        scope.after_id = cursor[0] ? cursor : NULL;
        if (!storage->delete_matching(&scope,
                                      nip40_expiry_predicate,
                                      NULL, &deleted, next_id, sizeof(next_id),
                                      &more)) {
            fprintf(stderr, "NIP-40 GC: storage selection failed\n");
            return;
        }
        total += deleted;
        snprintf(cursor, sizeof(cursor), "%s", next_id);
    } while (more);
    if (total > 0) fprintf(stdout, "[NIP-40 GC] deleted %lu expired event(s)\n",
                           (unsigned long)total);
}

/* ============================================================================
 * Plugin registration
 *
 * NIP-40 participates in the relay entirely through the plugin hooks below.
 * Removing nip40.c from the build removes: publication-time expiry checks,
 * per-delivery expiry filtering, the background GC sweep — nothing else in
 * the relay references this module.
 * ============================================================================ */

static void nip40_plugin_init(const relay_config_t *config, void *ctx) {
    (void) config; /* No configuration needed. */
    (void) ctx;
}

/* Publish policy: "Relays SHOULD drop any events that are published to them
 * if they are expired." */
static bool nip40_accept_publish(struct mg_connection *connection,
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
static bool nip40_can_deliver(const event_t *event, struct mg_connection *connection,
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
