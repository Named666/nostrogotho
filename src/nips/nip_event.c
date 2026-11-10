#include <strings.h>
#include "json_lite.h"
#include "relay_conn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nip_event.h"

/* The tag slice yielded by jl_next is itself a complete JSON array
 * (e.g. ["d","<identifier>"]), so element extraction is a plain $[index]
 * lookup on it. */
char *nip_tag_element(jstr_t tag, size_t index) {
    char path[16];
    snprintf(path, sizeof(path), "$[%llu]", (unsigned long long) index);
    return jl_get_str(tag, path);
}

/* First two element tokens of a tag array, without allocating. */
static bool tag_name_value(jstr_t tag, jstr_t *name, jstr_t *value) {
    jstr_t k; size_t o = 0;
    name->buf = value->buf = NULL; name->len = value->len = 0;
    if ((o = jl_next(tag, o, &k, name)) == 0) return false;
    if ((o = jl_next(tag, o, &k, value)) == 0) value->buf = NULL;
    return true;
}

bool nip_event_has_tag(const event_t *event, const char *name, const char *value) {
    jstr_t key, tag, tags = jl_str(event->tags_json); size_t offset = 0;
    while ((offset = jl_next(tags, offset, &key, &tag)) != 0) {
        jstr_t n, v;
        if (!tag_name_value(tag, &n, &v) || !jl_tok_eq(n, name)) continue;
        if (!value || (v.buf && jl_tok_eq(v, value))) return true;
    }
    return false;
}

bool nip_event_has_relay_tag(const event_t *event, const char *relay) {
    jstr_t key, tag, tags = jl_str(event->tags_json); size_t offset = 0, relay_length = strlen(relay);
    while (relay_length && relay[relay_length - 1] == '/') relay_length--;
    while ((offset = jl_next(tags, offset, &key, &tag)) != 0) {
        jstr_t n, v;
        if (!tag_name_value(tag, &n, &v) || !v.buf || !jl_tok_eq(n, "relay")) continue;
        char sb[1024];
        char *b = v.len <= sizeof(sb) ? sb : (char *) malloc(v.len);
        if (!b) continue;
        size_t vl;
        bool found = false;
        if (jl_unescape(v, b, &vl)) {
            while (vl && b[vl - 1] == '/') vl--;
            if (relay_length) found = vl == relay_length && strncasecmp(b, relay, relay_length) == 0;
            else found = (vl > 5 && strncasecmp(b, "ws://", 5) == 0) || (vl > 6 && strncasecmp(b, "wss://", 6) == 0);
        }
        if (b != sb) free(b);
        if (found) return true;
    }
    return false;
}
