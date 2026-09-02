#include "crypto.h"
#include "nip13.h"

bool nip13_meets_difficulty(const event_t *event, int minimum_difficulty) {
    return !minimum_difficulty || count_leading_zero_bits(event->id) >= minimum_difficulty;
}