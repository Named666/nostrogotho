#include <stdio.h>
#include "nip16.h"
#include "nip01.h"

bool nip16_replace_event(const event_t *event, storage_context_t *storage) {
    return storage->delete_record_by_kind_and_pubkey(event->kind, event->pubkey, event->created_at) >= 0;
}

/* Listener for replaceable events (kinds 0, 3, 10000-19999). */
static nip01_process_result_t nip16_listener(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {

    (void)connection;
    (void)relay_url;

    nip01_process_result_t result = {0};

    if (!storage) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "error: storage unavailable");
        return result;
    }

    if (!nip16_replace_event(event, storage)) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "error: failed to replace event");
        return result;
    }

    result.accepted = true;
    result.should_broadcast = true;
    result.response_msg[0] = '\0';

    return result;
}

/* Auto-register this NIP's listener at program startup */
__attribute__((constructor)) static void nip16_register_at_startup(void) {
    nip01_register_listener(0, 0, nip16_listener);
    nip01_register_listener(3, 3, nip16_listener);
    nip01_register_listener(10000, 19999, nip16_listener);
}