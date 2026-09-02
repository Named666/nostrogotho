#include "nip40.h"
#include <time.h>
#include <string.h>
#include <stdlib.h>

/* ============================================================================
 * NIP-40: Expiration Timestamp
 * 
 * Implementation of expiration filtering. Events marked with an expiration
 * tag older than the current time are considered expired.
 * ============================================================================ */

bool nip40_is_expired(const tags_array_t *tags) {
    if (!tags) return false;
    
    time_t now = time(NULL);
    
    for (size_t i = 0; i < tags->count; i++) {
        tag_t *tag = &tags->tags[i];
        
        if (tag->count >= 2 && strcmp(tag->elements[0], "expiration") == 0) {
            time_t expiration = (time_t)strtol(tag->elements[1], NULL, 10);
            if (expiration <= now) {
                return true;
            }
        }
    }
    
    return false;
}
