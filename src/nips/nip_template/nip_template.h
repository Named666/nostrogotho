#ifndef NIP_TEMPLATE_H
#define NIP_TEMPLATE_H

#include <stdbool.h>
#include <stddef.h>
#include "nostrogotho.h"
#include "storage.h"

/* ============================================================================
 * NIP Template - Public API
 * ============================================================================
 * 
 * Only declare public functions here if other NIPs or the host need to call them.
 * Most NIPs are self-contained and need no public API.
 * ============================================================================ */

/* Example: Public helper for other NIPs */
bool nip_template_validate_event(const event_t *event, char *reason, size_t reason_size);

/* Example: Custom storage query */
size_t nip_template_query_events(storage_context_t *storage, const filter_t *filters,
                                 size_t filter_count, event_t **out_events, size_t max_events);

#endif