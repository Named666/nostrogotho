#ifndef NIP_MACROS_H
#define NIP_MACROS_H

#include "nip_capability.h"

/* ============================================================================
 * Declarative Capability Registration Macros
 * ============================================================================
 * 
 * Usage in nipXX.c:
 * 
 *   static void nipXX_init(const relay_config_t *cfg, void *ctx) { ... }
 *   static void nipXX_shutdown(void *ctx) { ... }
 *   static bool nipXX_accept_publish(uintptr_t conn, const event_t *e, char *r, size_t sz, void *ctx) { ... }
 *   static nip01_process_result_t nipXX_process(uintptr_t conn, const event_t *e, storage_context_t *s, const char *url, void *ctx) { ... }
 *   
 *   NIP_LIFECYCLE(nipXX,
 *       .init = nipXX_init,
 *       .shutdown = nipXX_shutdown
 *   );
 *   
 *   NIP_PUBLICATION_POLICY(nipXX,
 *       .accept_publish = nipXX_accept_publish
 *   );
 *   
 *   NIP_KIND_HANDLER(nipXX,
 *       .kind = 30000,
 *       .handles_kind = nipXX_handles,
 *       .process_event = nipXX_process
 *   );
 * 
 * Each macro expands to:
 * 1. Static capability descriptor (const nip_capability_t)
 * 2. Constructor-attribute registration function
 * 3. Automatic nip_capability_add_provider call
 * 
 * NO manual registration code needed.
 * ============================================================================ */

/* Internal: Generate unique symbol names */
#define NIP_CONCAT_(a, b) a##b
#define NIP_CONCAT(a, b) NIP_CONCAT_(a, b)
#define NIP_UNIQUE(name) NIP_CONCAT(name, __COUNTER__)

/* Base capability initializer - common fields */
#define NIP_CAP_BASE(name) \
    .name = #name, \
    .ctx = &NIP_CONCAT(name, _ctx)

/* Lifecycle: init + shutdown */
#define NIP_LIFECYCLE(nip_name, ...) \
    static nip_lifecycle_capability_t NIP_CONCAT(nip_name, _lifecycle) = { __VA_ARGS__ }; \
    static const nip_capability_t NIP_CONCAT(nip_name, _lifecycle_cap) = { \
        NIP_CAP_BASE(NIP_CONCAT(nip_name, _lifecycle)), \
        .type = NIP_CAP_LIFECYCLE, \
        .caps.lifecycle = NIP_CONCAT(nip_name, _lifecycle) \
    }; \
    static void NIP_CONCAT(nip_name, _register_lifecycle)(nip_registry_t *r) { \
        if (r) nip_registry_register(r, &NIP_CONCAT(nip_name, _lifecycle_cap)); \
    } \
    __attribute__((constructor)) static void NIP_CONCAT(nip_name, _auto_lifecycle)(void) { \
        nip_capability_add_provider(NIP_CONCAT(nip_name, _register_lifecycle)); \
    }

/* Publication Policy: accept/reject events */
#define NIP_PUBLICATION_POLICY(nip_name, ...) \
    static nip_publication_policy_capability_t NIP_CONCAT(nip_name, _pubpol) = { __VA_ARGS__ }; \
    static const nip_capability_t NIP_CONCAT(nip_name, _pubpol_cap) = { \
        NIP_CAP_BASE(NIP_CONCAT(nip_name, _pubpol)), \
        .type = NIP_CAP_PUBLICATION_POLICY, \
        .caps.publication_policy = NIP_CONCAT(nip_name, _pubpol) \
    }; \
    static void NIP_CONCAT(nip_name, _register_pubpol)(nip_registry_t *r) { \
        if (r) nip_registry_register(r, &NIP_CONCAT(nip_name, _pubpol_cap)); \
    } \
    __attribute__((constructor)) static void NIP_CONCAT(nip_name, _auto_pubpol)(void) { \
        nip_capability_add_provider(NIP_CONCAT(nip_name, _register_pubpol)); \
    }

/* Kind Handler: process specific event kinds */
#define NIP_KIND_HANDLER(nip_name, ...) \
    static nip_kind_handler_capability_t NIP_CONCAT(nip_name, _kind) = { __VA_ARGS__ }; \
    static const nip_capability_t NIP_CONCAT(nip_name, _kind_cap) = { \
        NIP_CAP_BASE(NIP_CONCAT(nip_name, _kind)), \
        .type = NIP_CAP_KIND_HANDLER, \
        .caps.kind_handler = NIP_CONCAT(nip_name, _kind) \
    }; \
    static void NIP_CONCAT(nip_name, _register_kind)(nip_registry_t *r) { \
        if (r) nip_registry_register(r, &NIP_CONCAT(nip_name, _kind_cap)); \
    } \
    __attribute__((constructor)) static void NIP_CONCAT(nip_name, _auto_kind)(void) { \
        nip_capability_add_provider(NIP_CONCAT(nip_name, _register_kind)); \
    }

/* Delivery Policy: filter event delivery */
#define NIP_DELIVERY_POLICY(nip_name, ...) \
    static nip_delivery_policy_capability_t NIP_CONCAT(nip_name, _deliver) = { __VA_ARGS__ }; \
    static const nip_capability_t NIP_CONCAT(nip_name, _deliver_cap) = { \
        NIP_CAP_BASE(NIP_CONCAT(nip_name, _deliver)), \
        .type = NIP_CAP_DELIVERY_POLICY, \
        .caps.delivery_policy = NIP_CONCAT(nip_name, _deliver) \
    }; \
    static void NIP_CONCAT(nip_name, _register_deliver)(nip_registry_t *r) { \
        if (r) nip_registry_register(r, &NIP_CONCAT(nip_name, _deliver_cap)); \
    } \
    __attribute__((constructor)) static void NIP_CONCAT(nip_name, _auto_deliver)(void) { \
        nip_capability_add_provider(NIP_CONCAT(nip_name, _register_deliver)); \
    }

/* Query Policy: authorize/modify queries */
#define NIP_QUERY_POLICY(nip_name, ...) \
    static nip_query_policy_capability_t NIP_CONCAT(nip_name, _query) = { __VA_ARGS__ }; \
    static const nip_capability_t NIP_CONCAT(nip_name, _query_cap) = { \
        NIP_CAP_BASE(NIP_CONCAT(nip_name, _query)), \
        .type = NIP_CAP_QUERY_POLICY, \
        .caps.query_policy = NIP_CONCAT(nip_name, _query) \
    }; \
    static void NIP_CONCAT(nip_name, _register_query)(nip_registry_t *r) { \
        if (r) nip_registry_register(r, &NIP_CONCAT(nip_name, _query_cap)); \
    } \
    __attribute__((constructor)) static void NIP_CONCAT(nip_name, _auto_query)(void) { \
        nip_capability_add_provider(NIP_CONCAT(nip_name, _register_query)); \
    }

/* Maintenance: periodic timers */
#define NIP_MAINTENANCE(nip_name, ...) \
    static nip_maintenance_capability_t NIP_CONCAT(nip_name, _maint) = { __VA_ARGS__ }; \
    static const nip_capability_t NIP_CONCAT(nip_name, _maint_cap) = { \
        NIP_CAP_BASE(NIP_CONCAT(nip_name, _maint)), \
        .type = NIP_CAP_MAINTENANCE, \
        .caps.maintenance = NIP_CONCAT(nip_name, _maint) \
    }; \
    static void NIP_CONCAT(nip_name, _register_maint)(nip_registry_t *r) { \
        if (r) nip_registry_register(r, &NIP_CONCAT(nip_name, _maint_cap)); \
    } \
    __attribute__((constructor)) static void NIP_CONCAT(nip_name, _auto_maint)(void) { \
        nip_capability_add_provider(NIP_CONCAT(nip_name, _register_maint)); \
    }

/* Metadata: info document */
#define NIP_METADATA(nip_name, ...) \
    static nip_metadata_capability_t NIP_CONCAT(nip_name, _meta) = { __VA_ARGS__ }; \
    static const nip_capability_t NIP_CONCAT(nip_name, _meta_cap) = { \
        NIP_CAP_BASE(NIP_CONCAT(nip_name, _meta)), \
        .type = NIP_CAP_METADATA, \
        .caps.metadata = NIP_CONCAT(nip_name, _meta) \
    }; \
    static void NIP_CONCAT(nip_name, _register_meta)(nip_registry_t *r) { \
        if (r) nip_registry_register(r, &NIP_CONCAT(nip_name, _meta_cap)); \
    } \
    __attribute__((constructor)) static void NIP_CONCAT(nip_name, _auto_meta)(void) { \
        nip_capability_add_provider(NIP_CONCAT(nip_name, _register_meta)); \
    }

/* Protocol Response: custom EOSE, COUNT, auth hints */
#define NIP_PROTOCOL_RESPONSE(nip_name, ...) \
    static nip_protocol_response_capability_t NIP_CONCAT(nip_name, _proto) = { __VA_ARGS__ }; \
    static const nip_capability_t NIP_CONCAT(nip_name, _proto_cap) = { \
        NIP_CAP_BASE(NIP_CONCAT(nip_name, _proto)), \
        .type = NIP_CAP_PROTOCOL_RESPONSE, \
        .caps.protocol_response = NIP_CONCAT(nip_name, _proto) \
    }; \
    static void NIP_CONCAT(nip_name, _register_proto)(nip_registry_t *r) { \
        if (r) nip_registry_register(r, &NIP_CONCAT(nip_name, _proto_cap)); \
    } \
    __attribute__((constructor)) static void NIP_CONCAT(nip_name, _auto_proto)(void) { \
        nip_capability_add_provider(NIP_CONCAT(nip_name, _register_proto)); \
    }

/* Connection: on_connect / on_disconnect */
#define NIP_CONNECTION(nip_name, ...) \
    static nip_connection_capability_t NIP_CONCAT(nip_name, _conn) = { __VA_ARGS__ }; \
    static const nip_capability_t NIP_CONCAT(nip_name, _conn_cap) = { \
        NIP_CAP_BASE(NIP_CONCAT(nip_name, _conn)), \
        .type = NIP_CAP_CONNECTION, \
        .caps.connection = NIP_CONCAT(nip_name, _conn) \
    }; \
    static void NIP_CONCAT(nip_name, _register_conn)(nip_registry_t *r) { \
        if (r) nip_registry_register(r, &NIP_CONCAT(nip_name, _conn_cap)); \
    } \
    __attribute__((constructor)) static void NIP_CONCAT(nip_name, _auto_conn)(void) { \
        nip_capability_add_provider(NIP_CONCAT(nip_name, _register_conn)); \
    }

/* Message Intercept: inspect/modify protocol messages */
#define NIP_MESSAGE_INTERCEPT(nip_name, ...) \
    static nip_message_intercept_capability_t NIP_CONCAT(nip_name, _msg) = { __VA_ARGS__ }; \
    static const nip_capability_t NIP_CONCAT(nip_name, _msg_cap) = { \
        NIP_CAP_BASE(NIP_CONCAT(nip_name, _msg)), \
        .type = NIP_CAP_MESSAGE_INTERCEPT, \
        .caps.message_intercept = NIP_CONCAT(nip_name, _msg) \
    }; \
    static void NIP_CONCAT(nip_name, _register_msg)(nip_registry_t *r) { \
        if (r) nip_registry_register(r, &NIP_CONCAT(nip_name, _msg_cap)); \
    } \
    __attribute__((constructor)) static void NIP_CONCAT(nip_name, _auto_msg)(void) { \
        nip_capability_add_provider(NIP_CONCAT(nip_name, _register_msg)); \
    }

/* ============================================================================
 * Context Helper Macros
 * ============================================================================
 * 
 * For capabilities that need state, declare a static context struct:
 * 
 *   typedef struct { int counter; char *config_value; } nipXX_ctx_t;
 *   static nipXX_ctx_t nipXX_ctx = { .counter = 0 };
 * 
 * The NIP_CAP_BASE macro automatically sets .ctx = &nipXX_ctx
 * (assuming context variable is named nipXX_ctx)
 * ============================================================================ */

/* Declare a static context for the NIP (optional) */
#define NIP_DECLARE_CTX(nip_name, ctx_type) \
    static ctx_type NIP_CONCAT(nip_name, _ctx)

/* Initialize context in lifecycle init (if needed) */
#define NIP_CTX_INIT(nip_name) (&NIP_CONCAT(nip_name, _ctx))

#endif