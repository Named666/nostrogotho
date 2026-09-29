/* ============================================================================
 * NIP Template - Capability Declarations Only
 * ============================================================================
 * 
 * This file exists ONLY to declare capabilities. It is the minimal file
 * needed for a NIP to participate in the capability system.
 * 
 * The actual implementation is in nip_template.c
 * This file would be the one compiled into the module if separating
 * capability declarations from implementation.
 * ============================================================================ */

#include "nip_template.h"
#include "nip_macros.h"
#include <stdint.h>

/* Context declaration (must match nip_template.c) */
typedef struct {
    int event_count;
    const char *custom_config;
} nip_template_ctx_t;

NIP_DECLARE_CTX(nip_template, nip_template_ctx_t);

/* Forward declarations of implementations (in nip_template.c) */
extern void nip_template_init(const relay_config_t *config, void *ctx);
extern void nip_template_shutdown(void *ctx);
extern bool nip_template_accept_publish(uintptr_t connection_id, const event_t *event,
                                         char *reason, size_t reason_size, void *ctx);
extern bool nip_template_handles_kind(int kind, void *ctx);
extern nip01_process_result_t nip_template_process_event(uintptr_t connection_id,
                                                          const event_t *event,
                                                          storage_context_t *storage,
                                                          const char *relay_url,
                                                          void *ctx);
extern bool nip_template_can_deliver(const event_t *event, uintptr_t connection_id, void *ctx);
extern bool nip_template_authorize_query(uintptr_t connection_id, filter_t *filters,
                                          size_t count, void *ctx);
extern void nip_template_timer(storage_context_t *storage, void *ctx);
extern const char *nip_template_info_document(void *ctx);
extern char *nip_template_build_eose(const char *sub, bool has_more, bool auth_hint, void *ctx);
extern bool nip_template_needs_auth_hint(const filter_t *filters, size_t filters_count,
                                          uintptr_t connection_id, void *ctx);

/* Declarative capability registration - each macro creates a static
 * capability descriptor + constructor for auto-registration */

NIP_LIFECYCLE(nip_template,
    .init = nip_template_init,
    .shutdown = nip_template_shutdown
);

NIP_PUBLICATION_POLICY(nip_template,
    .accept_publish = nip_template_accept_publish
);

NIP_KIND_HANDLER(nip_template,
    .kind = 30000,
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
    .interval_ms = 60000
);

NIP_METADATA(nip_template,
    .info_document = nip_template_info_document
);

NIP_PROTOCOL_RESPONSE(nip_template,
    .build_eose = nip_template_build_eose,
    .needs_auth_hint = nip_template_needs_auth_hint
);