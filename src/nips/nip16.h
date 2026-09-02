#ifndef NIP16_H_
#define NIP16_H_
#include <stdbool.h>
#include "storage.h"
/* Remove older replaceable events before storing the newer NIP-16 event. */
bool nip16_replace_event(const event_t *event, storage_context_t *storage);
#endif /* NIP16_H_ */