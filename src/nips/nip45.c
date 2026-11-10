#include "nip45.h"
#include "nip_plugin.h"
#include "../json_util.h"
#include <stdlib.h>
#include <string.h>
#include "../crypto.h"

/* ============================================================================
 * NIP-45: COUNT Request / Response
 * 
 * Implementation of COUNT query responses. Builds JSON-formatted COUNT
 * responses that indicate the number of events matching query filters.
 * ============================================================================ */

char *nip45_build_count_response(const char *sub_id, unsigned long count, const uint8_t *hll) {
    if (!sub_id) return NULL;
    
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "COUNT");
    json_builder_append_string(&builder, sub_id);
    json_builder_start_object(&builder);
    json_builder_object_key_number(&builder, "count", (long long)count);
    if (hll) {
        static const char hex[] = "0123456789abcdef";
        char text[513];
        for (int i = 0; i < 256; i++) { text[2 * i] = hex[hll[i] >> 4]; text[2 * i + 1] = hex[hll[i] & 15]; }
        text[512] = '\0';
        json_builder_object_key_string(&builder, "hll", text);
    }
    json_builder_end_object(&builder);
    
    const char *result = json_builder_finish(&builder);
    /* finish() points into the builder: duplicate for the caller. */
    char *out = result ? string_dup(result) : NULL;
    json_builder_free(&builder);
    return out;
}

static char *nip45_plugin_build_count(const char *sub, unsigned long count, const uint8_t *hll, void *ctx) {
    (void) ctx;
    return nip45_build_count_response(sub, count, hll);
}

static bool hex64(const char *s, size_t n) {
    if (n != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

static int hexval(char c) { return c <= '9' ? c - '0' : c - 'a' + 10; }

int nip45_hll_offset(const filter_t *filters, size_t count) {
    /* Eligible: one filter whose first tag attribute has one value (the
     * NIP-45 "common filters": reactions, reposts, quotes, replies,
     * comments, followers). */
    if (count != 1 || filters[0].tags_count != 1 || filters[0].tags[0].count != 2) return -1;
    const char *v = filters[0].tags[0].elements[1];
    size_t n = strlen(v);
    if (hex64(v, n)) return hexval(v[32]) + 8;
    const char *c1 = strchr(v, ':');                  /* address <kind>:<pubkey>:<d> */
    const char *c2 = c1 ? strchr(c1 + 1, ':') : NULL;
    if (c1 && c2 && hex64(c1 + 1, (size_t) (c2 - c1 - 1))) return hexval(c1[1 + 32]) + 8;
    uint8_t digest[32];
    sha256((const uint8_t *) v, n, digest);
    return (digest[16] >> 4) + 8;                      /* hex character 32 = high nibble of byte 16 */
}

static int nip45_plugin_count_hll_offset(const filter_t *filters, size_t count, void *ctx) {
    (void) ctx;
    return nip45_hll_offset(filters, count);
}

static nip_plugin_t nip45_plugin = {
    .name = "nip45",
    .build_count = nip45_plugin_build_count,
    .count_hll_offset = nip45_plugin_count_hll_offset,
};

__attribute__((constructor)) static void nip45_register_at_startup(void) {
    nip_plugin_register(&nip45_plugin);
}
