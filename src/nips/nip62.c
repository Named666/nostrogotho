#include <stdio.h>
#include "nip62.h"
#include "nip_event.h"
#include "nip01.h"
#include "../storage.h"

bool nip62_should_vanish(const event_t *event, const char *service_url) {
    return nip_event_has_tag(event, "relay", "ALL_RELAYS") ||
           (service_url && *service_url && nip_event_has_relay_tag(event, service_url));
}

/* Listener for kind 62 (Request to Vanish) events. */
static nip01_process_result_t nip62_listener(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {

    (void)connection;

    nip01_process_result_t result = {0};

    if (!storage) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "error: storage unavailable");
        return result;
    }

    if (nip62_should_vanish(event, relay_url)) {
        int deleted = storage->delete_all_events_by_pubkey(event->pubkey, event->created_at);
        if (deleted < 0) {
            result.accepted = false;
            snprintf(result.response_msg, sizeof(result.response_msg),
                    "error: failed to vanish events");
            return result;
        }
    }

    if (!storage->insert_record(event)) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "duplicate: event already exists");
        return result;
    }

    result.accepted = true;
    result.should_broadcast = true;
    result.response_msg[0] = '\0';

    return result;
}

/* Auto-register this NIP's listener at program startup */
__attribute__((constructor)) static void nip62_register_at_startup(void) {
    nip01_register_listener(62, 62, nip62_listener);
}