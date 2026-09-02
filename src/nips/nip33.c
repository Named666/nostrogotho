#include <mongoose.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "nip33.h"
#include "nip_event.h"
#include "nip01.h"

bool nip33_replace_event(const event_t *event, storage_context_t *storage) {
    struct mg_str key, tag, tags = mg_str(event->tags_json); size_t offset = 0;
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = nip_tag_element(tag, 0);
        if (name && strcmp(name, "d") == 0) {
            char *value = nip_tag_element(tag, 1);
            tag_t dtag = {(char *[]) {"d", value ? value : ""}, 2, 2};
            free(name);
            if (!value || storage->delete_record_by_kind_and_pubkey_and_dtag(event->kind, event->pubkey, &dtag, event->created_at) < 0) { free(value); return false; }
            free(value); return true;
        }
        free(name);
    }
    return true;
}

/* Listener for addressable replaceable events (kinds 30000-39999). */
static nip01_process_result_t nip33_listener(
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

    if (!nip33_replace_event(event, storage)) {
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
__attribute__((constructor)) static void nip33_register_at_startup(void) {
    nip01_register_listener(30000, 39999, nip33_listener);
}