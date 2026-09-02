#ifndef NIP33_H_
#define NIP33_H_
#include <stdbool.h>
#include "storage.h"
/* Replace older parameterized events sharing the NIP-33 d tag. */
bool nip33_replace_event(const event_t *event, storage_context_t *storage);
#endif /* NIP33_H_ */