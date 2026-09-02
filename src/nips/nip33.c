#include <mongoose.h>
#include <stdlib.h>
#include <string.h>
#include "nip33.h"
#include "nip_event.h"
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