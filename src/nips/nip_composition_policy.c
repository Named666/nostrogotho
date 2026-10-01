#include "nip_composition_policy.h"
#include <string.h>

/* ============================================================================
 * Defaults — match current deterministic behavior exactly
 * ============================================================================ */

void nip_composition_policy_init(nip_composition_policy_t *policy) {
    if (!policy) return;

    policy->publication = (nip_composition_publication_t){
        .mode = NIP_COMPOSITION_AND,
        .enabled = true,
    };

    policy->delivery = (nip_composition_delivery_t){
        .mode = NIP_COMPOSITION_OR,   /* any veto wins */
        .enabled = true,
    };

    policy->kind = (nip_composition_kind_t){
        .mode = NIP_COMPOSITION_ALL,  /* all handlers run, AND-accept */
        .enabled = true,
    };

    policy->query = (nip_composition_query_t){
        .mode = NIP_COMPOSITION_AND,
        .enabled = true,
    };

    policy->protocol_response = (nip_composition_protocol_response_t){
        .mode = NIP_COMPOSITION_FIRST,
        .enabled = true,
    };

    policy->metadata = (nip_composition_metadata_t){
        .mode = NIP_COMPOSITION_FIRST,
        .enabled = true,
    };

    policy->auth_hint = (nip_composition_auth_hint_t){
        .mode = NIP_COMPOSITION_OR,
        .enabled = true,
    };

    policy->auth_challenge = (nip_composition_auth_challenge_t){
        .mode = NIP_COMPOSITION_ALL,
        .enabled = true,
    };

    policy->maintenance = (nip_composition_maintenance_t){
        .mode = NIP_COMPOSITION_ALL,
        .enabled = true,
    };
}

bool nip_composition_policy_validate(const nip_composition_policy_t *policy,
                                     char *err, size_t errsz) {
    if (!policy) return false;

    /* Validate mode enums are in range */
    #define CHECK_MODE(mode, max) \
        do { \
            if (mode < 0 || mode > max) { \
                if (err) snprintf(err, errsz, "invalid composition mode: %d", mode); \
                return false; \
            } \
        } while (0)

    CHECK_MODE(policy->publication.mode, NIP_COMPOSITION_OR);
    CHECK_MODE(policy->delivery.mode, NIP_COMPOSITION_AND);
    CHECK_MODE(policy->kind.mode, NIP_COMPOSITION_ALL);
    CHECK_MODE(policy->query.mode, NIP_COMPOSITION_OR);
    CHECK_MODE(policy->protocol_response.mode, NIP_COMPOSITION_FIRST);
    CHECK_MODE(policy->metadata.mode, NIP_COMPOSITION_FIRST);
    CHECK_MODE(policy->auth_hint.mode, NIP_COMPOSITION_OR);
    CHECK_MODE(policy->auth_challenge.mode, NIP_COMPOSITION_ALL);
    CHECK_MODE(policy->maintenance.mode, NIP_COMPOSITION_ALL);

    return true;
}

/* ============================================================================
 * Mode parsing helpers
 * ============================================================================ */

static const struct { const char *name; nip_composition_mode_t mode; } mode_names[] = {
    {"and", NIP_COMPOSITION_AND},
    {"or", NIP_COMPOSITION_OR},
    {"first", NIP_COMPOSITION_FIRST},
    {"all", NIP_COMPOSITION_ALL},
};

nip_composition_mode_t nip_composition_mode_from_string(const char *s) {
    if (!s) return NIP_COMPOSITION_AND;
    for (size_t i = 0; i < sizeof(mode_names)/sizeof(mode_names[0]); i++) {
        if (strcmp(s, mode_names[i].name) == 0) return mode_names[i].mode;
    }
    return NIP_COMPOSITION_AND;  /* default */
}

const char *nip_composition_mode_to_string(nip_composition_mode_t mode) {
    for (size_t i = 0; i < sizeof(mode_names)/sizeof(mode_names[0]); i++) {
        if (mode_names[i].mode == mode) return mode_names[i].name;
    }
    return "and";
}

/* ============================================================================
 * Policy-aware composition implementations
 * ============================================================================ */

bool nip_composition_check_publication_policy(const nip_composition_policy_t *policy,
                                               nip_registry_t *registry, uintptr_t connection_id,
                                               const event_t *event, char *reason, size_t reason_size) {
    if (!policy || !policy->publication.enabled) return true;
    if (!registry) return true;

    if (policy->publication.mode == NIP_COMPOSITION_OR) {
        /* OR: any rejection wins — first reject stops */
        for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
            if (cap->type == NIP_CAP_PUBLICATION_POLICY && cap->caps.publication_policy.accept_publish) {
                if (!cap->caps.publication_policy.accept_publish(connection_id, event, reason, reason_size, cap->ctx)) {
                    return false;
                }
            }
        }
        return true;
    }

    /* AND (default): all must permit — same as current */
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_PUBLICATION_POLICY && cap->caps.publication_policy.accept_publish) {
            if (!cap->caps.publication_policy.accept_publish(connection_id, event, reason, reason_size, cap->ctx)) {
                return false;
            }
        }
    }
    return true;
}

bool nip_composition_check_delivery_policy(const nip_composition_policy_t *policy,
                                            nip_registry_t *registry, const event_t *event,
                                            uintptr_t connection_id) {
    if (!policy || !policy->delivery.enabled) return true;
    if (!registry) return true;

    if (policy->delivery.mode == NIP_COMPOSITION_AND) {
        /* AND: all must permit delivery */
        for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
            if (cap->type == NIP_CAP_DELIVERY_POLICY && cap->caps.delivery_policy.can_deliver) {
                if (!cap->caps.delivery_policy.can_deliver(event, connection_id, cap->ctx)) {
                    return false;
                }
            }
        }
        return true;
    }

    /* OR (default): any veto wins */
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_DELIVERY_POLICY && cap->caps.delivery_policy.can_deliver) {
            if (!cap->caps.delivery_policy.can_deliver(event, connection_id, cap->ctx)) {
                return false;
            }
        }
    }
    return true;
}

nip_kind_composition_result_t nip_composition_process_kind_policy(const nip_composition_policy_t *policy,
                                                                   nip_registry_t *registry,
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

    if (!policy || !policy->kind.enabled) return result;
    if (!registry) return result;

    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_KIND_HANDLER && cap->caps.kind_handler.handles_kind) {
            if (cap->caps.kind_handler.handles_kind(event->kind, cap->ctx)) {
                result.any_handler_matched = true;
                nip01_process_result_t r = cap->caps.kind_handler.process_event(connection_id, event, storage, relay_url, cap->ctx);

                /* AND-accept: any rejection wins regardless of order */
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

void nip_composition_run_maintenance_policy(const nip_composition_policy_t *policy,
                                             nip_registry_t *registry, storage_context_t *storage) {
    if (!policy || !policy->maintenance.enabled) return;
    if (!registry) return;

    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_MAINTENANCE && cap->caps.maintenance.timer) {
            cap->caps.maintenance.timer(storage, cap->ctx);
        }
    }
}

bool nip_composition_authorize_query_policy(const nip_composition_policy_t *policy,
                                             nip_registry_t *registry, uintptr_t connection_id,
                                             filter_t *filters, size_t count,
                                             char *reason, size_t reason_size) {
    if (!policy || !policy->query.enabled) return true;
    if (!registry) return true;

    if (policy->query.mode == NIP_COMPOSITION_OR) {
        /* OR: any permit wins — first permit stops (opposite of AND) */
        for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
            if (cap->type == NIP_CAP_QUERY_POLICY && cap->caps.query_policy.authorize_query) {
                if (cap->caps.query_policy.authorize_query(connection_id, filters, count, reason, reason_size, cap->ctx)) {
                    return true;
                }
            }
        }
        return false;  /* none permitted */
    }

    /* AND (default): all must permit */
    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_QUERY_POLICY && cap->caps.query_policy.authorize_query) {
            if (!cap->caps.query_policy.authorize_query(connection_id, filters, count, reason, reason_size, cap->ctx)) {
                return false;
            }
        }
    }
    return true;
}

char *nip_composition_build_eose_policy(const nip_composition_policy_t *policy,
                                         nip_registry_t *registry, const char *sub,
                                         bool has_more, bool auth_hint) {
    if (!policy || !policy->protocol_response.enabled) return NULL;
    if (!registry) return NULL;

    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_PROTOCOL_RESPONSE && cap->caps.protocol_response.build_eose) {
            char *response = cap->caps.protocol_response.build_eose(sub, has_more, auth_hint, cap->ctx);
            if (response) return response;  /* FIRST non-NULL wins */
        }
    }
    return NULL;
}

char *nip_composition_build_count_policy(const nip_composition_policy_t *policy,
                                          nip_registry_t *registry, const char *sub,
                                          unsigned long count) {
    if (!policy || !policy->protocol_response.enabled) return NULL;
    if (!registry) return NULL;

    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_PROTOCOL_RESPONSE && cap->caps.protocol_response.build_count) {
            char *response = cap->caps.protocol_response.build_count(sub, count, cap->ctx);
            if (response) return response;
        }
    }
    return NULL;
}

const char *nip_composition_get_info_document_policy(const nip_composition_policy_t *policy,
                                                      nip_registry_t *registry) {
    if (!policy || !policy->metadata.enabled) return NULL;
    if (!registry) return NULL;

    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_METADATA && cap->caps.metadata.info_document) {
            const char *doc = cap->caps.metadata.info_document(cap->ctx);
            if (doc) return doc;
        }
    }
    return NULL;
}

bool nip_composition_needs_auth_hint_policy(const nip_composition_policy_t *policy,
                                             nip_registry_t *registry,
                                             const filter_t *filters, size_t filters_count,
                                             uintptr_t connection_id) {
    if (!policy || !policy->auth_hint.enabled) return false;
    if (!registry) return false;

    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_PROTOCOL_RESPONSE && cap->caps.protocol_response.needs_auth_hint) {
            if (cap->caps.protocol_response.needs_auth_hint(filters, filters_count, connection_id, cap->ctx)) {
                return true;  /* OR: any can request */
            }
        }
    }
    return false;
}

void nip_composition_send_auth_challenge_policy(const nip_composition_policy_t *policy,
                                                 nip_registry_t *registry,
                                                 uintptr_t connection_id) {
    if (!policy || !policy->auth_challenge.enabled) return;
    if (!registry) return;

    for (nip_capability_t *cap = registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_PROTOCOL_RESPONSE && cap->caps.protocol_response.send_auth_challenge) {
            cap->caps.protocol_response.send_auth_challenge(connection_id, cap->ctx);
        }
    }
}