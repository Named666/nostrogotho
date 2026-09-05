#include "crypto.h"
#include "nip13.h"
#include "nip_event.h"
#include "nip_plugin.h"
#include <stdio.h>
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
 *
 * Enforcement is a plugin publish-policy hook (same architecture as NIP-40):
 * when the relay is configured with min_pow_difficulty > 0, every EVENT must
 * present at least that many leading zero bits before it is dispatched.
 * Removing nip13.c from the build removes PoW enforcement with it.
 * ============================================================================ */

static int nip13_min_difficulty;

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

/* ============================================================================
 * Plugin registration
 *
 * Publish policy: when the relay requires PoW, verify the id actually carries
 * the committed/configured work. The rejection message follows the spec's
 * example format ("pow: difficulty 25>=24") so clients can see how close they
 * were.
 * ============================================================================ */

static void nip13_plugin_init(const relay_config_t *config) {
    nip13_min_difficulty = config->min_pow_difficulty;
}

static bool nip13_accept_publish(struct mg_connection *connection,
                                 const event_t *event,
                                 char *reason, size_t reason_size) {
    (void) connection;
    if (nip13_min_difficulty <= 0) return true;

    int committed = nip13_committed_target(event);
    int required = committed > nip13_min_difficulty ? committed : nip13_min_difficulty;
    int bits = count_leading_zero_bits(event->id);
    if (bits >= required) return true;

    snprintf(reason, reason_size, "pow: difficulty %d>=%d", bits, required);
    return false;
}

static nip_plugin_t nip13_plugin = {
    .name = "nip13",
    .init = nip13_plugin_init,
    .accept_publish = nip13_accept_publish,
};

__attribute__((constructor)) static void nip13_register_at_startup(void) {
    nip_plugin_register(&nip13_plugin);
}