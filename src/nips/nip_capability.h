#ifndef NIP_CAPABILITY_H_
#define NIP_CAPABILITY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "nostrogotho.h"
#include "storage.h"
#include "../protocol/protocol.h"
#include "relay/connection_session.h"
#include "relay/config.h"

/* ============================================================================
 * NIP_CAPABILITY.H - NIP Capability Interface (Transport-Agnostic)
 * 
 * Redesigned NIP plugin interface that removes transport leakage.
 * NIP modules declare capabilities; the relay core handles transport.
 * ============================================================================ */

/* Forward declarations */
typedef struct nip_capability nip_capability_t;

/* ============================================================================
 * Kind-handler policy result (NIP-01)
 *
 * Returned by kind handlers. The relay core owns storage/broadcast/OK
 * framing; handlers only return this decision. Lives here (not in a per-NIP
 * header) because every NIP file shares it and each NIP is a single .c file.
 * ============================================================================ */
typedef struct {
    bool accepted;              /* true if event accepted, false if rejected */
    bool should_broadcast;      /* true if event should be sent to subscribers */
    bool should_store;          /* true if event should be stored */
    char response_msg[256];     /* Human-readable reason (OK or rejection message) */
} nip01_process_result_t;

/* Registry structure - fully defined here for access.
 *
 * OWNERSHIP (hot-reload safe):
 * - nip_registry_register() DEEP-COPIES the descriptor into host-owned heap.
 *   Callers may pass pointers to static templates; the registry never retains
 *   the caller's pointer. `name` is duplicated; the `caps` union (function
 *   pointers) is copied by value.
 * - `ctx` is NOT copied. The pointed-to state stays owned by the registrant.
 *   For hot-reloadable modules, ctx must either be stateless, re-derivable on
 *   init/post_reload, or explicitly migrated via Nhr_State. The registry does
 *   NOT free ctx on clear/destroy (shared ctx across several caps would
 *   double-free). Each capability file owns its ctx lifetime and frees it in
 *   its lifecycle shutdown or module shutdown.
 * - Because the registry owns its nodes, the host may atomically
 *   nip_registry_clear() then re-register a new generation's capabilities
 *   during reload without dangling into an unloaded image, provided no
 *   dispatch runs concurrently with the swap (reload runs synchronously on
 *   the host event-loop thread).
 */
typedef struct nip_registry {
    nip_capability_t *capabilities;
    size_t count;
} nip_registry_t;

/* Capability types - each NIP module can implement multiple capabilities */
typedef enum {
    NIP_CAP_LIFECYCLE = 1,        /* init, shutdown */
    NIP_CAP_CONNECTION = 2,       /* connection open/close */
    NIP_CAP_MESSAGE_INTERCEPT = 3, /* intercept protocol messages */
    NIP_CAP_PUBLICATION_POLICY = 4, /* accept/reject events */
    NIP_CAP_KIND_HANDLER = 5,     /* handle specific event kinds */
    NIP_CAP_DELIVERY_POLICY = 6,  /* filter event delivery */
    NIP_CAP_QUERY_POLICY = 7,     /* modify/authorize queries */
    NIP_CAP_MAINTENANCE = 8,      /* periodic timer work */
    NIP_CAP_METADATA = 9,         /* NIP-11 info document */
    NIP_CAP_PROTOCOL_RESPONSE = 10 /* build protocol responses */
} nip_capability_type_t;

/* ============================================================================
 * Capability Structures
 * ============================================================================ */

/* Lifecycle capability */
typedef struct {
    void (*init)(const relay_config_t *config, void *ctx);
    void (*shutdown)(void *ctx);
} nip_lifecycle_capability_t;

/* Connection capability - uses opaque connection ID instead of Mongoose pointer */
typedef struct {
    void (*on_connect)(uintptr_t connection_id, void *ctx);
    void (*on_disconnect)(uintptr_t connection_id, void *ctx);
} nip_connection_capability_t;

/* Message intercept capability - operates on parsed protocol messages */
typedef struct {
    bool (*on_message)(uintptr_t connection_id, const protocol_message_t *msg, void *ctx);
} nip_message_intercept_capability_t;

/* Publication policy capability */
typedef struct {
    bool (*accept_publish)(uintptr_t connection_id, const event_t *event, 
                           char *reason, size_t reason_size, void *ctx);
} nip_publication_policy_capability_t;

/* Kind handler capability - replaces on_event with explicit policy result */
typedef struct {
    /* Returns true if this handler applies to the given kind */
    bool (*handles_kind)(int kind, void *ctx);
    
    /* Process event - returns policy decision, not transport action */
    nip01_process_result_t (*process_event)(uintptr_t connection_id, const event_t *event,
                                            storage_context_t *storage, const char *relay_url,
                                            void *ctx);
} nip_kind_handler_capability_t;

/* Delivery policy capability */
typedef struct {
    bool (*can_deliver)(const event_t *event, uintptr_t connection_id, void *ctx);
} nip_delivery_policy_capability_t;

/* Query policy capability */
typedef struct {
    /* Called before query execution - can modify filters or reject.
     * Returns true to allow, false to reject. On reject, fills reason buffer. */
    bool (*authorize_query)(uintptr_t connection_id, filter_t *filters, size_t count,
                            char *reason, size_t reason_size, void *ctx);
    
    /* Called after query - can modify results or add hints */
    bool (*modify_results)(uintptr_t connection_id, const filter_t *filters, size_t count,
                           bool has_more, int total_count, void *ctx);
} nip_query_policy_capability_t;

/* Maintenance capability */
typedef struct {
    void (*timer)(storage_context_t *storage, void *ctx);
    unsigned interval_ms;
} nip_maintenance_capability_t;

/* Metadata capability */
typedef struct {
    const char *(*info_document)(void *ctx);
} nip_metadata_capability_t;

/* Protocol response capability */
typedef struct {
    char *(*build_eose)(const char *sub, bool has_more, bool auth_hint, void *ctx);
    char *(*build_count)(const char *sub, unsigned long count, void *ctx);
    /* True when this query needs the NIP-67 "auth" completeness hint
     * (e.g. NIP-17 gift-wrap filters on an unauthenticated connection). */
    bool (*needs_auth_hint)(const filter_t *filters, size_t filters_count,
                            uintptr_t connection_id, void *ctx);
    /* Re-issue an authentication challenge to this connection (NIP-42). */
    void (*send_auth_challenge)(uintptr_t connection_id, void *ctx);
} nip_protocol_response_capability_t;

/* ============================================================================
 * Unified Capability Structure
 * ============================================================================ */

struct nip_capability {
    const char *name;
    nip_capability_type_t type;
    void *ctx;
    
    union {
        nip_lifecycle_capability_t lifecycle;
        nip_connection_capability_t connection;
        nip_message_intercept_capability_t message_intercept;
        nip_publication_policy_capability_t publication_policy;
        nip_kind_handler_capability_t kind_handler;
        nip_delivery_policy_capability_t delivery_policy;
        nip_query_policy_capability_t query_policy;
        nip_maintenance_capability_t maintenance;
        nip_metadata_capability_t metadata;
        nip_protocol_response_capability_t protocol_response;
    } caps;
    
    struct nip_capability *next;
};

/* ============================================================================
 * Registry Operations
 * ============================================================================ */

/* New NIPs declare ONE static table (see nip_template.c) -- one entry per
 * capability type implemented. No heap allocation: point .ctx at a static
 * struct (or NULL when the hooks need no state). nip_registry_register()
 * deep-copies each entry, so statics are safe and nothing leaks across
 * hot-reload generations:
 *
 *   static nip_capability_t nipxx_caps[] = {
 *       { .name = "nipxx-kind", .type = NIP_CAP_KIND_HANDLER, .ctx = &nipxx_ctx,
 *         .caps.kind_handler = { .handles_kind = h, .process_event = p },
 *         .next = NULL },
 *   };
 */

/* Create a new capability registry */
nip_registry_t *nip_registry_create(void);

/* Destroy registry and all capabilities */
void nip_registry_destroy(nip_registry_t *registry);

/* Register a capability (deep-copies descriptor into registry-owned heap).
 * Safe to pass a pointer to a static template; may be called repeatedly. */
void nip_registry_register(nip_registry_t *registry, const nip_capability_t *capability);

/* Remove all capabilities from the registry and free registry-owned nodes.
 * Does NOT free ctx pointers (owned by registrant). Used for atomic
 * hot-reload swaps: clear, then re-register the new generation. */
void nip_registry_clear(nip_registry_t *registry);

/* Get capabilities by type */
nip_capability_t *nip_registry_get_by_type(nip_registry_t *registry, nip_capability_type_t type);

/* Iterate all capabilities of a type */
typedef void (*nip_capability_iter_fn)(nip_capability_t *cap, void *userdata);
void nip_registry_iterate(nip_registry_t *registry, nip_capability_type_t type,
                          nip_capability_iter_fn fn, void *userdata);

/* ============================================================================
 * Composition Rules (Deterministic)
 * ============================================================================ */

/* Publication policies: ALL must permit (AND composition) */
bool nip_composition_check_publication(nip_registry_t *registry, uintptr_t connection_id,
                                        const event_t *event, char *reason, size_t reason_size);

/* Delivery policies: ANY may veto (OR composition for veto) */
bool nip_composition_check_delivery(nip_registry_t *registry, const event_t *event,
                                     uintptr_t connection_id);

/* Kind handlers: ALL applicable handlers are consulted */
typedef struct {
    nip01_process_result_t result;
    bool any_handler_matched;
} nip_kind_composition_result_t;

nip_kind_composition_result_t nip_composition_process_kind(nip_registry_t *registry,
                                                            uintptr_t connection_id,
                                                            const event_t *event,
                                                            storage_context_t *storage,
                                                            const char *relay_url);

/* Maintenance: ALL registered timers run */
void nip_composition_run_maintenance(nip_registry_t *registry, storage_context_t *storage);

/* Query policy: ALL authorize_query must permit */
bool nip_composition_authorize_query(nip_registry_t *registry, uintptr_t connection_id,
                                      filter_t *filters, size_t count,
                                      char *reason, size_t reason_size);

/* Protocol response: FIRST non-NULL wins (explicit priority) */
char *nip_composition_build_eose(nip_registry_t *registry, const char *sub,
                                  bool has_more, bool auth_hint);
char *nip_composition_build_count(nip_registry_t *registry, const char *sub,
                                   unsigned long count);

/* Metadata: FIRST non-NULL wins */
const char *nip_composition_get_info_document(nip_registry_t *registry);

/* Auth hint: ANY provider may request it (OR composition) */
bool nip_composition_needs_auth_hint(nip_registry_t *registry,
                                      const filter_t *filters, size_t filters_count,
                                      uintptr_t connection_id);

/* Auth challenge: ALL providers with the hook send one */
void nip_composition_send_auth_challenge(nip_registry_t *registry,
                                          uintptr_t connection_id);

/* ============================================================================
 * Capability Providers (self-registration)
 * ============================================================================ */

/* A provider registers one NIP's full capability set into a registry.
 * Every src/nips/nipXX.c exposes one via a constructor, so adding or
 * removing a NIP source file changes the relay's feature set without
 * touching protocol/transport code or registration lists. */
typedef void (*nip_capability_provider_fn)(nip_registry_t *registry);

/* Called once from each NIP file's constructor. */
void nip_capability_add_provider(nip_capability_provider_fn provider);

/* Register every provider linked into this image (monolithic or module). */
void nip_registry_register_providers(nip_registry_t *registry);

/* ============================================================================
 * Registration Boilerplate Macro
 * ============================================================================
 * 
 * Reduces NIP file boilerplate. Usage in nipXX.c:
 * 
 *   static nip_capability_t nipXX_caps[] = { ... };
 *   
 *   NIP_REGISTER(nipXX, nipXX_caps)
 * 
 * Expands to:
 *   void nipXX_register(nip_registry_t *registry) { ... }
 *   __attribute__((constructor)) static void nipXX_register_provider(void) { ... }
 * ============================================================================ */

#define NIP_REGISTER(nip_name, caps_array) \
    void nip_name##_register(nip_registry_t *registry) { \
        if (!registry) return; \
        for (size_t i = 0; i < sizeof(caps_array) / sizeof(caps_array[0]); i++) \
            nip_registry_register(registry, &caps_array[i]); \
    } \
    __attribute__((constructor)) static void nip_name##_register_provider(void) { \
        nip_capability_add_provider(nip_name##_register); \
    }

#endif /* NIP_CAPABILITY_H_ */