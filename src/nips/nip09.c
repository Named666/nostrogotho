#include <mongoose.h>
#include <stdlib.h>
#include <string.h>
#include "nip09.h"
#include "nip_event.h"

/* NIP-09 permits an author to delete only their own referenced events. */
bool nip09_delete_targets(const event_t *event, storage_context_t *storage) {
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    bool failed = false;

    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = nip_tag_element(tag, 0);
        if (name && strcmp(name, "e") == 0) {
            for (size_t index = 1;; index++) {
                char *id = nip_tag_element(tag, index);
                event_t *target;
                int result;
                if (!id) break;
                target = storage->get_event_by_id(id);
                if (target) {
                    tag_t recipient = {(char *[]) {"p", (char *) event->pubkey}, 2, 2};
                    result = target->kind == 1059
                        ? storage->delete_record_by_id_and_kind_and_ptag(id, 1059, &recipient)
                        : storage->delete_record_by_id_and_pubkey(id, event->pubkey);
                    if (result <= 0) failed = true;
                    event_free(target);
                }
                free(id);
            }
        }
        free(name);
    }
    return !failed;
}