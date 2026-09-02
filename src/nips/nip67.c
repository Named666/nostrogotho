#include "nip67.h"
#include "../json_util.h"
#include <stdlib.h>

/* ============================================================================
 * NIP-67: Efficiently Returning All Events Stored at a Relay
 * 
 * Implementation of EOSE (End Of Stored Events) responses with completeness
 * hints. Signals to clients when query results are complete or if more events
 * exist beyond the relay's limit.
 * ============================================================================ */

char *nip67_build_eose_response(const char *sub_id, bool has_more) {
    if (!sub_id) return NULL;
    
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "EOSE");
    json_builder_append_string(&builder, sub_id);
    json_builder_start_array(&builder);
    json_builder_append_string(&builder, has_more ? "more" : "finish");
    json_builder_end_array(&builder);
    
    const char *result = json_builder_finish(&builder);
    if (!result) return NULL;
    
    /* json_builder_finish returns a pointer to internal buffer,
     * so we need to duplicate it for caller to own */
    return string_dup(result);
}
