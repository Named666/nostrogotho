#include "crypto.h"
#include "nip13.h"
#include "nip_event.h"
#include <stdlib.h>

/* ============================================================================
 * NIP-13: Proof of Work
 *
 * difficulty = number of leading zero bits of the NIP-01 event id.
 *
 * When the event carries a ["nonce", "<value>", "<target>"] tag with a
 * committed target difficulty (third element), the committed target is the
 * authoritative requirement: an id that happens to exceed a lower committed
 * target is not enough. This protects against bulk spammers committing to a
 * low difficulty and getting lucky with a higher one (spec: "Committing to a
 * target difficulty is something all honest miners should be ok with").
 * ============================================================================ */

/* nip13_committed_target - Return the nonce tag's committed target difficulty,
 * or 0 when the event does not commit to one. */
static int nip13_committed_target(const event_t *event) {
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    int target = 0;

    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = nip_tag_element(tag, 0);
        if (name && strcmp(name, "nonce") == 0) {
            char *value = nip_tag_element(tag, 2);
            free(name);
            if (value) {
                char *end = NULL;
                long parsed = strtol(value, &end, 10);
                if (end && *end == '\0' && parsed > 0 && parsed <= 256) {
                    target = (int) parsed;
                }
                free(value);
            }
            return target;
        }
        free(name);
    }
    return target;
}

bool nip13_meets_difficulty(const event_t *event, int minimum_difficulty) {
    if (minimum_difficulty <= 0) return true;

    int committed = nip13_committed_target(event);
    int required = committed > minimum_difficulty ? committed : minimum_difficulty;
    return count_leading_zero_bits(event->id) >= required;
}