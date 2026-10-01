#include "nip_capability.h"
#include "nostrogotho.h"
#include "storage.h"
#include "relay/connection_session.h"
#include "protocol/protocol.h"
#include <stdlib.h>
#include <string.h>

/* Provider list for self-registration */
typedef struct nip_provider_node {
    nip_capability_provider_fn provider;
    struct nip_provider_node *next;
} nip_provider_node_t;

static nip_provider_node_t *providers = NULL;

void nip_capability_add_provider(nip_capability_provider_fn provider) {
    nip_provider_node_t *node = malloc(sizeof(*node));
    if (!node) return;
    node->provider = provider;
    node->next = providers;
    providers = node;
}

void nip_registry_register_providers(nip_registry_t *registry) {
    if (!registry) return;
    for (nip_provider_node_t *n = providers; n; n = n->next) {
        if (n->provider) n->provider(registry);
    }
}

nip_registry_t *nip_registry_create(void) {
    return calloc(1, sizeof(nip_registry_t));
}

void nip_registry_destroy(nip_registry_t *registry) {
    if (!registry) return;
    nip_capability_t *cap = registry->capabilities;
    while (cap) {
        nip_capability_t *next = cap->next;
        free(cap);
        cap = next;
    }
    free(registry);
}

void nip_registry_register(nip_registry_t *registry, const nip_capability_t *capability) {
    if (!registry || !capability) return;
    
    nip_capability_t *node = malloc(sizeof(*node));
    if (!node) return;
    
    *node = *capability;
    node->name = strdup(capability->name);
    node->next = registry->capabilities;
    registry->capabilities = node;
    registry->count++;
}

void nip_registry_clear(nip_registry_t *registry) {
    if (!registry) return;
    nip_capability_t *cap = registry->capabilities;
    while (cap) {
        nip_capability_t *next = cap->next;
        free((void *)cap->name);
        free(cap);
        cap = next;
    }
    registry->capabilities = NULL;
    registry->count = 0;
}

nip_capability_t *nip_registry_get_by_type(nip_registry_t *registry, nip_capability_type_t type) {
    if (!registry) return NULL;
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == type) return cap;
    }
    return NULL;
}

void nip_registry_iterate(nip_registry_t *registry, nip_capability_type_t type,
                          nip_capability_iter_fn fn, void *userdata) {
    if (!registry || !fn) return;
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == type) {
            fn(cap, userdata);
        }
    }
}

/* ============================================================================
 * Composition Rules (Deterministic)
 * ============================================================================ */

/* Publication policies: ALL must permit (AND composition) */
bool nip_composition_check_publication(nip_registry_t *registry, uintptr_t connection_id,
                                        const event_t *event, char *reason, size_t reason_size) {
    if (!registry) return true;
    
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_PUBLICATION_POLICY && cap->caps.publication_policy.accept_publish) {
            if (!cap->caps.publication_policy.accept_publish(connection_id, event, reason, reason_size, cap->ctx)) {
                return false;
            }
        }
    }
    return true;
}

/* Delivery policies: ANY may veto (OR composition for veto) */
bool nip_composition_check_delivery(nip_registry_t *registry, const event_t *event,
                                     uintptr_t connection_id) {
    if (!registry) return true;
    
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_DELIVERY_POLICY && cap->caps.delivery_policy.can_deliver) {
            if (!cap->caps.delivery_policy.can_deliver(event, connection_id, cap->ctx)) {
                return false;
            }
        }
    }
    return true;
}

/* Kind handlers: ALL applicable handlers are consulted */
nip_kind_composition_result_t nip_composition_process_kind(nip_registry_t *registry,
                                                            uintptr_t connection_id,
                                                            const event_t *event,
                                                            storage_context_t *storage,
                                                            const char *relay_url) {
    nip_kind_composition_result_t result = {0};
    bool saw_reject = false;
    result.result.accepted = false;
    result.result.should_broadcast = false;
    result.result.should_store = false;
    result.result.response_msg[0] = '\0';
    
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_KIND_HANDLER && cap->caps.kind_handler.handles_kind) {
            if (cap->caps.kind_handler.handles_kind(event->kind, cap->ctx)) {
                result.any_handler_matched = true;
                nip01_process_result_t r = cap->caps.kind_handler.process_event(connection_id, event, storage, relay_url, cap->ctx);
                
                /* Composition: accepted is the AND of all matched handlers --
                 * any rejection wins regardless of registration order (a later
                 * accept must not flip a prior reject back to true). The
                 * rejecting handler's message wins; broadcast/store stay OR
                 * (the relay only acts on them when accepted is true). */
                if (!r.accepted) {
                    result.result.accepted = false;
                    saw_reject = true;
                    strncpy(result.result.response_msg, r.response_msg, sizeof(result.result.response_msg) - 1);
                } else if (!saw_reject && !result.result.accepted) {
                    result.result.accepted = true;
                }
                if (r.should_broadcast) result.result.should_broadcast = true;
                if (r.should_store) result.result.should_store = true;
                if (r.response_msg[0] && result.result.response_msg[0] == '\0') {
                    strncpy(result.result.response_msg, r.response_msg, sizeof(result.result.response_msg) - 1);
                }
            }
        }
    }
    return result;
}

/* Maintenance: ALL registered timers run */
void nip_composition_run_maintenance(nip_registry_t *registry, storage_context_t *storage) {
    if (!registry) return;
    
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_MAINTENANCE && cap->caps.maintenance.timer) {
            cap->caps.maintenance.timer(storage, cap->ctx);
        }
    }
}

/* Query policy: ALL authorize_query must permit */
bool nip_composition_authorize_query(nip_registry_t *registry, uintptr_t connection_id,
                                      filter_t *filters, size_t count,
                                      char *reason, size_t reason_size) {
    if (!registry) return true;
    
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_QUERY_POLICY && cap->caps.query_policy.authorize_query) {
            if (!cap->caps.query_policy.authorize_query(connection_id, filters, count, reason, reason_size, cap->ctx)) {
                return false;
            }
        }
    }
    return true;
}

char *nip_composition_build_eose(nip_registry_t *registry, const char *sub,
                                  bool has_more, bool auth_hint) {
    if (!registry) return NULL;
    
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_PROTOCOL_RESPONSE && cap->caps.protocol_response.build_eose) {
            char *response = cap->caps.protocol_response.build_eose(sub, has_more, auth_hint, cap->ctx);
            if (response) return response;
        }
    }
    return NULL;
}

char *nip_composition_build_count(nip_registry_t *registry, const char *sub,
                                   unsigned long count) {
    if (!registry) return NULL;
    
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_PROTOCOL_RESPONSE && cap->caps.protocol_response.build_count) {
            char *response = cap->caps.protocol_response.build_count(sub, count, cap->ctx);
            if (response) return response;
        }
    }
    return NULL;
}

/* Metadata: FIRST non-NULL wins */
const char *nip_composition_get_info_document(nip_registry_t *registry) {
    if (!registry) return NULL;
    
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_METADATA && cap->caps.metadata.info_document) {
            const char *doc = cap->caps.metadata.info_document(cap->ctx);
            if (doc) return doc;
        }
    }
    return NULL;
}

/* Auth hint: ANY provider may request it (OR composition) */
bool nip_composition_needs_auth_hint(nip_registry_t *registry,
                                      const filter_t *filters, size_t filters_count,
                                      uintptr_t connection_id) {
    if (!registry) return false;
    
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_PROTOCOL_RESPONSE && cap->caps.protocol_response.needs_auth_hint) {
            if (cap->caps.protocol_response.needs_auth_hint(filters, filters_count, connection_id, cap->ctx)) {
                return true;
            }
        }
    }
    return false;
}

/* Auth challenge: ALL providers with the hook send one */
void nip_composition_send_auth_challenge(nip_registry_t *registry,
                                          uintptr_t connection_id) {
    if (!registry) return;
    
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_PROTOCOL_RESPONSE && cap->caps.protocol_response.send_auth_challenge) {
            cap->caps.protocol_response.send_auth_challenge(connection_id, cap->ctx);
        }
    }
}