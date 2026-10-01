#ifndef NIP_COMPOSITION_POLICY_H_
#define NIP_COMPOSITION_POLICY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nip_capability.h"

/* ============================================================================
 * Composition Policy — Host-Owned, Configurable
 * ============================================================================
 *
 * Defines how registered capabilities are combined. Lives in host (relay_config_t),
 * never crosses NHR boundary. NIPs still just register capabilities; the relay
 * decides the combinator at startup / reload.
 *
 * Default = current deterministic behavior (see nip_capability.c).
 * Overridable via config.json "composition.*" keys.
 * ============================================================================ */

/* Combinator mode for AND/OR-like policies */
typedef enum {
    NIP_COMPOSITION_AND  = 0,  /* All must permit / first reject wins */
    NIP_COMPOSITION_OR   = 1,  /* Any permit wins / any veto wins */
    NIP_COMPOSITION_FIRST = 2, /* First non-NULL by registration order */
    NIP_COMPOSITION_ALL   = 3, /* All run, aggregate results (kind handlers) */
} nip_composition_mode_t;

/* Publication policy combinator: AND (default) or OR (any can reject) */
typedef struct {
    nip_composition_mode_t mode;      /* NIP_COMPOSITION_AND | NIP_COMPOSITION_OR */
    bool enabled;                     /* false = always permit */
} nip_composition_publication_t;

/* Delivery policy combinator: OR-ANY-VETO (default) or AND-ALL-MUST-PERMIT */
typedef struct {
    nip_composition_mode_t mode;      /* NIP_COMPOSITION_OR | NIP_COMPOSITION_AND */
    bool enabled;                     /* false = always permit */
} nip_composition_delivery_t;

/* Kind handler aggregation mode */
typedef struct {
    nip_composition_mode_t mode;      /* NIP_COMPOSITION_ALL (default) */
    bool enabled;                     /* false = no kind handlers run */
} nip_composition_kind_t;

/* Query authorization combinator */
typedef struct {
    nip_composition_mode_t mode;      /* NIP_COMPOSITION_AND (default) | OR */
    bool enabled;                     /* false = always permit */
} nip_composition_query_t;

/* Protocol response: first non-NULL wins (default) or concat all */
typedef struct {
    nip_composition_mode_t mode;      /* NIP_COMPOSITION_FIRST (default) */
    bool enabled;                     /* false = no custom response */
} nip_composition_protocol_response_t;

/* Metadata: first non-NULL wins (default) */
typedef struct {
    nip_composition_mode_t mode;      /* NIP_COMPOSITION_FIRST (default) */
    bool enabled;                     /* false = no NIP-11 document */
} nip_composition_metadata_t;

/* Auth hint: OR (default) — any provider can request */
typedef struct {
    nip_composition_mode_t mode;      /* NIP_COMPOSITION_OR (default) */
    bool enabled;                     /* false = never hint */
} nip_composition_auth_hint_t;

/* Auth challenge: ALL run (default) */
typedef struct {
    nip_composition_mode_t mode;      /* NIP_COMPOSITION_ALL (default) */
    bool enabled;                     /* false = no challenges sent */
} nip_composition_auth_challenge_t;

/* Maintenance: ALL run (default) */
typedef struct {
    nip_composition_mode_t mode;      /* NIP_COMPOSITION_ALL (default) */
    bool enabled;                     /* false = no maintenance */
} nip_composition_maintenance_t;

/* Complete composition policy — one per relay */
typedef struct {
    nip_composition_publication_t      publication;
    nip_composition_delivery_t         delivery;
    nip_composition_kind_t             kind;
    nip_composition_query_t            query;
    nip_composition_protocol_response_t protocol_response;
    nip_composition_metadata_t         metadata;
    nip_composition_auth_hint_t        auth_hint;
    nip_composition_auth_challenge_t   auth_challenge;
    nip_composition_maintenance_t      maintenance;
} nip_composition_policy_t;

/* Initialize with defaults matching current deterministic behavior */
void nip_composition_policy_init(nip_composition_policy_t *policy);

/* Validate policy (mode values in range) */
bool nip_composition_policy_validate(const nip_composition_policy_t *policy,
                                     char *err, size_t errsz);

/* Composition functions now take explicit policy (host passes its config's policy) */
bool nip_composition_check_publication_policy(const nip_composition_policy_t *policy,
                                               nip_registry_t *registry, uintptr_t connection_id,
                                               const event_t *event, char *reason, size_t reason_size);

bool nip_composition_check_delivery_policy(const nip_composition_policy_t *policy,
                                            nip_registry_t *registry, const event_t *event,
                                            uintptr_t connection_id);

nip_kind_composition_result_t nip_composition_process_kind_policy(const nip_composition_policy_t *policy,
                                                                   nip_registry_t *registry,
                                                                   uintptr_t connection_id,
                                                                   const event_t *event,
                                                                   storage_context_t *storage,
                                                                   const char *relay_url);

void nip_composition_run_maintenance_policy(const nip_composition_policy_t *policy,
                                             nip_registry_t *registry, storage_context_t *storage);

bool nip_composition_authorize_query_policy(const nip_composition_policy_t *policy,
                                             nip_registry_t *registry, uintptr_t connection_id,
                                             filter_t *filters, size_t count,
                                             char *reason, size_t reason_size);

char *nip_composition_build_eose_policy(const nip_composition_policy_t *policy,
                                         nip_registry_t *registry, const char *sub,
                                         bool has_more, bool auth_hint);

char *nip_composition_build_count_policy(const nip_composition_policy_t *policy,
                                          nip_registry_t *registry, const char *sub,
                                          unsigned long count);

const char *nip_composition_get_info_document_policy(const nip_composition_policy_t *policy,
                                                      nip_registry_t *registry);

bool nip_composition_needs_auth_hint_policy(const nip_composition_policy_t *policy,
                                             nip_registry_t *registry,
                                             const filter_t *filters, size_t filters_count,
                                             uintptr_t connection_id);

void nip_composition_send_auth_challenge_policy(const nip_composition_policy_t *policy,
                                                 nip_registry_t *registry,
                                                 uintptr_t connection_id);

/* Helper: parse mode string from config */
nip_composition_mode_t nip_composition_mode_from_string(const char *s);
const char *nip_composition_mode_to_string(nip_composition_mode_t mode);

#endif /* NIP_COMPOSITION_POLICY_H_ */