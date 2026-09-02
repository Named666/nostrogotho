#include "nip16.h"
bool nip16_replace_event(const event_t *event, storage_context_t *storage) {
    return storage->delete_record_by_kind_and_pubkey(event->kind, event->pubkey, event->created_at) >= 0;
}