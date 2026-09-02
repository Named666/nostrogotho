#ifndef NIP13_H_
#define NIP13_H_
#include <stdbool.h>
#include "cagliostr.h"
/* Return whether an event ID meets the configured NIP-13 difficulty. */
bool nip13_meets_difficulty(const event_t *event, int minimum_difficulty);
#endif /* NIP13_H_ */