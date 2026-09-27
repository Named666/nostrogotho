#include "nip_capability.h"
#include "../protocol/protocol.h"
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * NIP_CAPABILITY.C - NIP Capability Registry Implementation
 * ============================================================================ */

nip_registry_t *nip_registry_create(void) {
    nip_registry_t *registry = calloc(1, sizeof(*registry));
    return registry;
}

static void nip_registry_free_nodes(nip_registry_t *registry) {
    nip_capability_t *cap = registry->capabilities;
    while (cap) {
        nip_capability_t *next = cap->next;
        /* name was duplicated at register time; ctx is registrant-owned. */
        free((void *)cap->name);
        free(cap);
        cap = next;
    }
    registry->capabilities = NULL;
    registry->count = 0;
}

void nip_registry_destroy(nip_registry_t *registry) {
    if (!registry) return;
    nip_registry_free_nodes(registry);
    free(registry);
}

void nip_registry_clear(nip_registry_t *registry) {
    if (!registry) return;
    nip_registry_free_nodes(registry);
}

/* ============================================================================
 * Capability Providers (self-registration)
 * ============================================================================ */

#define NIP_CAPABILITY_MAX_PROVIDERS 32

static nip_capability_provider_fn capability_providers[NIP_CAPABILITY_MAX_PROVIDERS];
static size_t capability_provider_count;

void nip_capability_add_provider(nip_capability_provider_fn provider) {
    if (!provider || capability_provider_count >= NIP_CAPABILITY_MAX_PROVIDERS) return;
    /* Guard against double registration of the same provider. */
    for (size_t i = 0; i < capability_provider_count; i++) {
        if (capability_providers[i] == provider) return;
    }
    capability_providers[capability_provider_count++] = provider;
}

void nip_registry_register_providers(nip_registry_t *registry) {
    if (!registry) return;
    for (size_t i = 0; i < capability_provider_count; i++) {
        capability_providers[i](registry);
    }
}

void nip_registry_register(nip_registry_t *registry, const nip_capability_t *capability) {
    nip_capability_t *copy;
    if (!registry || !capability) return;

    copy = (nip_capability_t *)calloc(1, sizeof(*copy));
    if (!copy) return;
    /* Copy descriptor by value (function pointers + ctx pointer). */
    *copy = *capability;
    copy->next = NULL;
    /* Duplicate the debug name so statics can be re-registered safely. */
    if (capability->name) {
        size_t len = strlen(capability->name) + 1;
        char *dup = (char *)malloc(len);
        if (!dup) { free(copy); return; }
        memcpy(dup, capability->name, len);
        copy->name = dup;
    }

    copy->next = registry->capabilities;
    registry->capabilities = copy;
    registry->count++;
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
 * Composition Rules Implementation
 * ============================================================================ */

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

nip_kind_composition_result_t nip_composition_process_kind(nip_registry_t *registry,
                                                           uintptr_t connection_id,
                                                           const event_t *event,
                                                           storage_context_t *storage,
                                                           const char *relay_url) {
    nip_kind_composition_result_t result = {0};
    result.result.accepted = false;
    result.any_handler_matched = false;
    
    if (!registry) return result;
    
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_KIND_HANDLER && cap->caps.kind_handler.handles_kind) {
            if (cap->caps.kind_handler.handles_kind(event->kind, cap->ctx)) {
                result.any_handler_matched = true;
                if (cap->caps.kind_handler.process_event) {
                    nip01_process_result_t handler_result = cap->caps.kind_handler.process_event(
                        connection_id, event, storage, relay_url, cap->ctx);
                    
                    if (handler_result.accepted) {
                        result.result = handler_result;
                        return result;
                    }
                    
                    /* If handler rejected, keep its reason if we don't have one yet */
                    if (!result.result.accepted && handler_result.response_msg[0] != '\0' && 
                        result.result.response_msg[0] == '\0') {
                        snprintf(result.result.response_msg, sizeof(result.result.response_msg), 
                                "%s", handler_result.response_msg);
                    }
                }
            }
        }
    }
    
    return result;
}

void nip_composition_run_maintenance(nip_registry_t *registry, storage_context_t *storage) {
    if (!registry || !storage) return;
    
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_MAINTENANCE && cap->caps.maintenance.timer) {
            cap->caps.maintenance.timer(storage, cap->ctx);
        }
    }
}

bool nip_composition_authorize_query(nip_registry_t *registry, uintptr_t connection_id,
                                     filter_t *filters, size_t count) {
    if (!registry) return true;
    
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_QUERY_POLICY && cap->caps.query_policy.authorize_query) {
            if (!cap->caps.query_policy.authorize_query(connection_id, filters, count, cap->ctx)) {
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

bool nip_composition_needs_auth_hint(nip_registry_t *registry,
                                     const filter_t *filters, size_t filters_count,
                                     uintptr_t connection_id) {
    if (!registry) return false;

    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_PROTOCOL_RESPONSE &&
            cap->caps.protocol_response.needs_auth_hint) {
            if (cap->caps.protocol_response.needs_auth_hint(filters, filters_count,
                                                            connection_id, cap->ctx)) {
                return true;
            }
        }
    }
    return false;
}

void nip_composition_send_auth_challenge(nip_registry_t *registry,
                                         uintptr_t connection_id) {
    if (!registry) return;

    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_PROTOCOL_RESPONSE &&
            cap->caps.protocol_response.send_auth_challenge) {
            cap->caps.protocol_response.send_auth_challenge(connection_id, cap->ctx);
        }
    }
}