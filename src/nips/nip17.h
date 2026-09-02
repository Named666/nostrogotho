#ifndef NIP17_H_
#define NIP17_H_
#include <stdbool.h>
#include "cagliostr.h"
/* Enforce authenticated-recipient delivery for gift-wrap events. */
bool nip17_can_deliver(const event_t *event, const char *authenticated_pubkey);
#endif /* NIP17_H_ */