#include "nip45.h"
#include "nip_plugin.h"
#include "../json_util.h"
#include <stdlib.h>

/* ============================================================================
 * NIP-45: COUNT Request / Response
 * 
 * Implementation of COUNT query responses. Builds JSON-formatted COUNT
 * responses that indicate the number of events matching query filters.
 * ============================================================================ */

char *nip45_build_count_response(const char *sub_id, unsigned long count) {
    if (!sub_id) return NULL;
    
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "COUNT");
    json_builder_append_string(&builder, sub_id);
    json_builder_start_object(&builder);
    json_builder_object_key_number(&builder, "count", (long long)count);
    json_builder_end_object(&builder);
    
    const char *result = json_builder_finish(&builder);
    if (!result) return NULL;
    
    /* json_builder_finish returns a pointer to internal buffer,
     * so we need to duplicate it for caller to own */
    return string_dup(result);
}

static char *nip45_plugin_build_count(const char *sub, unsigned long count) {
    return nip45_build_count_response(sub, count);
}

static nip_plugin_t nip45_plugin = {
    .name = "nip45",
    .build_count = nip45_plugin_build_count,
};

__attribute__((constructor)) static void nip45_register_at_startup(void) {
    nip_plugin_register(&nip45_plugin);
}
