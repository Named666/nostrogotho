/* ============================================================================
 * NIP-40: Expiration Timestamp
 *
 * Single-file NIP: expiry helpers + publication/delivery policy + periodic
 * GC + capability table + self-registration. Compiling this file enables the
 * NIP; deleting it removes it. No header, no registration list.
 *
 * Events may carry an ["expiration", "<unix timestamp>"] tag. Relays:
 *   - SHOULD drop any events published to them if they are expired,
 *   - SHOULD NOT send expired events to clients, even if they are stored.
 *
 * Expiration does not affect the storage of ephemeral events (kinds
 * 20000-29999), which are never stored in the first place.
 * ============================================================================ */

#include "nip_capability.h"
#include "model/tag_iter.h"
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

/* Check whether an event's expiration tag has passed. Scans the raw tags
 * JSON for an "expiration" tag and compares against now. NULL-safe. */
static bool nip40_event_is_expired(const event_t *event) {
    if (!event || !event->tags_json) return false;

    char *expiration_str = tag_find_value(event, "expiration");
    if (!expiration_str) return false;
    
    time_t expiration = (time_t) strtoll(expiration_str, NULL, 10);
    free(expiration_str);
    
    time_t now = time(NULL);
    return expiration <= now;
}

static bool nip40_expiry_predicate(const event_t *event, void *userdata) {
    (void)userdata;
    return nip40_event_is_expired(event);
}

/* Background sweep of expired events. Runs inside the single-threaded event
 * loop (never races storage) and asks the storage layer to delete every
 * event whose expiration timestamp has passed. Best-effort: logs and never
 * fails the server. `arg` is a storage_context_t* (NULL-safe no-op). */
static void nip40_garbage_collect(void *arg) {
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
 * Capabilities: reject expired publishes, suppress expired delivery,
 * sweep stored expirations on a timer.
 * ============================================================================ */

static bool nip40_publication_policy_fn(connection_id_t connection_id, const event_t *event,
                                        char *reason, size_t reason_size, void *ctx) {
    (void)connection_id;
    (void)ctx;

    if (nip40_event_is_expired(event)) {
        snprintf(reason, reason_size, "invalid: event is expired");
        return false;
    }
    return true;
}

static bool nip40_delivery_policy_fn(const event_t *event, connection_id_t connection_id, void *ctx) {
    (void)connection_id;
    (void)ctx;
    return !nip40_event_is_expired(event);
}

static void nip40_maintenance_timer(storage_context_t *storage, void *ctx) {
    (void)ctx;
    nip40_garbage_collect(storage);
}

static nip_capability_t nip40_caps[] = {
    {
        .name = "nip40-pub-policy",
        .type = NIP_CAP_PUBLICATION_POLICY,
        .ctx = NULL,
        .caps.publication_policy = { .accept_publish = nip40_publication_policy_fn },
        .next = NULL,
    },
    {
        .name = "nip40-delivery",
        .type = NIP_CAP_DELIVERY_POLICY,
        .ctx = NULL,
        .caps.delivery_policy = { .can_deliver = nip40_delivery_policy_fn },
        .next = NULL,
    },
    {
        .name = "nip40-maintenance",
        .type = NIP_CAP_MAINTENANCE,
        .ctx = NULL,
        .caps.maintenance = { .timer = nip40_maintenance_timer, .interval_ms = 60 * 1000 },
        .next = NULL,
    },
};

/* ============================================================================
 * Registration (using macro to eliminate boilerplate)
 * ============================================================================ */

NIP_REGISTER(nip40, nip40_caps)