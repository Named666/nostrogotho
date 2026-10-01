/* ============================================================================
 * NIP Template - Reference Implementation for New NIPs
 * ============================================================================
 * 
 * This demonstrates the new declarative capability registration macros.
 * Copy this directory to src/nips/nipXX/ and customize.
 * 
 * Structure:
 *   nip_template.h      - Public API (if any)
 *   nip_template.c      - Implementation (this file)
 *   nip_template_capability.c - Capability declarations ONLY
 * ============================================================================ */

#include "nip_template.h"
#include "nip_capability.h"
#include "nip_macros.h"
#include "protocol/event_tags.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * Module Context (optional - for stateful NIPs)
 * ============================================================================ */

typedef struct {
    int event_count;
    const char *custom_config;
} nip_template_ctx_t;

NIP_DECLARE_CTX(nip_template, nip_template_ctx_t) = {0};

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

static bool nip_template_is_target_kind(int kind) {
    /* Example: handle parameterized replaceable events (kinds 30000-39999) */
    return kind >= 30000 && kind < 40000;
}

static const char *nip_template_get_d_tag(const event_t *event) {
    return event_tag_value(event, "d");
}

/* ============================================================================
 * Capability Implementations
 * ============================================================================ */

/* Lifecycle */
static void nip_template_init(const relay_config_t *config, void *ctx) {
    nip_template_ctx_t *c = (nip_template_ctx_t *)ctx;
    if (c) {
        c->event_count = 0;
        c->custom_config = config ? "example" : "default";
    }
}

static void nip_template_shutdown(void *ctx) {
    nip_template_ctx_t *c = (nip_template_ctx_t *)ctx;
    if (c) {
        c->event_count = 0;
    }
}

/* Publication Policy: accept/reject before storage */
static bool nip_template_accept_publish(uintptr_t connection_id, const event_t *event,
                                         char *reason, size_t reason_size, void *ctx) {
    nip_template_ctx_t *c = (nip_template_ctx_t *)ctx;
    if (c) c->event_count++;

    /* Example: reject events without a d-tag for parameterized kinds */
    if (nip_template_is_target_kind(event->kind)) {
        if (!nip_template_get_d_tag(event)) {
            if (reason && reason_size > 0) {
                snprintf(reason, reason_size, "missing d-tag for parameterized event");
            }
            return false;
        }
    }
    return true;
}

/* Kind Handler: process specific event kinds */
static bool nip_template_handles_kind(int kind, void *ctx) {
    (void)ctx;
    return nip_template_is_target_kind(kind);
}

static nip01_process_result_t nip_template_process_event(uintptr_t connection_id,
                                                          const event_t *event,
                                                          storage_context_t *storage,
                                                          const char *relay_url,
                                                          void *ctx) {
    nip01_process_result_t result = {0};
    result.accepted = true;
    result.should_store = true;
    result.should_broadcast = true;
    snprintf(result.response_msg, sizeof(result.response_msg), "accepted by nip_template");

    /* Example: use event_tags_foreach to inspect all tags */
    static bool template_tag_cb(const char *name, char **values, size_t count, void *ctx) {
        (void)ctx;
        (void)name; (void)values; (void)count;
        return true;
    }
    event_tags_foreach(event, template_tag_cb, NULL);

    return result;
}

/* Delivery Policy: filter who receives events */
static bool nip_template_can_deliver(const event_t *event, uintptr_t connection_id, void *ctx) {
    (void)event;
    (void)connection_id;
    (void)ctx;
    /* Example: could check subscription filters, auth status, etc. */
    return true;
}

/* Query Policy: authorize/modify REQ/COUNT queries */
static bool nip_template_authorize_query(uintptr_t connection_id, filter_t *filters,
                                          size_t count, void *ctx) {
    (void)connection_id;
    (void)filters;
    (void)count;
    (void)ctx;
    /* Example: enforce max filters, block certain kinds, etc. */
    return true;
}

/* Maintenance: periodic cleanup */
static void nip_template_timer(storage_context_t *storage, void *ctx) {
    (void)storage;
    (void)ctx;
    /* Example: cleanup expired events, refresh caches, etc. */
}

/* Metadata: NIP-11 info document contribution */
static const char *nip_template_info_document(void *ctx) {
    (void)ctx;
    /* Return JSON fragment for NIP-11 supported_nips or custom fields */
    return "{\"nip_template\":{\"description\":\"Example NIP implementation\"}}";
}

/* Protocol Response: custom EOSE, COUNT, auth hints */
static char *nip_template_build_eose(const char *sub, bool has_more, bool auth_hint, void *ctx) {
    (void)sub;
    (void)has_more;
    (void)auth_hint;
    (void)ctx;
    /* Return custom EOSE or NULL to use default */
    return NULL;
}

static bool nip_template_needs_auth_hint(const filter_t *filters, size_t filters_count,
                                          uintptr_t connection_id, void *ctx) {
    (void)filters;
    (void)filters_count;
    (void)connection_id;
    (void)ctx;
    /* Return true if this NIP requires auth hint for certain queries */
    return false;
}

/* ============================================================================
 * Declarative Capability Registration
 * ============================================================================
 * 
 * Each macro expands to a static capability + constructor registration.
 * No manual registration code needed!
 */

NIP_LIFECYCLE(nip_template,
    .init = nip_template_init,
    .shutdown = nip_template_shutdown
);

NIP_PUBLICATION_POLICY(nip_template,
    .accept_publish = nip_template_accept_publish
);

NIP_KIND_HANDLER(nip_template,
    .kind = 30000,  /* example kind */
    .handles_kind = nip_template_handles_kind,
    .process_event = nip_template_process_event
);

NIP_DELIVERY_POLICY(nip_template,
    .can_deliver = nip_template_can_deliver
);

NIP_QUERY_POLICY(nip_template,
    .authorize_query = nip_template_authorize_query
);

NIP_MAINTENANCE(nip_template,
    .timer = nip_template_timer,
    .interval_ms = 60000  /* run every 60 seconds */
);

NIP_METADATA(nip_template,
    .info_document = nip_template_info_document
);

NIP_PROTOCOL_RESPONSE(nip_template,
    .build_eose = nip_template_build_eose,
    .needs_auth_hint = nip_template_needs_auth_hint
);