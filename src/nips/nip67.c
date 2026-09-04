#include "nip67.h"
#include "nip_plugin.h"
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
    return nip67_build_eose_response_ex(sub_id, has_more, false);
}

char *nip67_build_eose_response_ex(const char *sub_id, bool has_more,
                                   bool auth_hint) {
    if (!sub_id) return NULL;

    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "EOSE");
    json_builder_append_string(&builder, sub_id);
    json_builder_start_array(&builder);
    if (auth_hint) {
        json_builder_append_string(&builder, "auth");
    }
    json_builder_append_string(&builder, has_more ? "more" : "finish");
    json_builder_end_array(&builder);

    const char *result = json_builder_finish(&builder);
    if (!result) return NULL;

    /* json_builder_finish returns a pointer to internal buffer,
     * so we need to duplicate it for caller to own */
    return string_dup(result);
}

static char *nip67_plugin_build_eose(const char *sub, bool has_more, bool auth_hint) {
    return nip67_build_eose_response_ex(sub, has_more, auth_hint);
}

static nip_plugin_t nip67_plugin = {
    .name = "nip67",
    .build_eose = nip67_plugin_build_eose,
};

__attribute__((constructor)) static void nip67_register_at_startup(void) {
    nip_plugin_register(&nip67_plugin);
}
