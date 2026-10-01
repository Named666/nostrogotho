#include "tag_iter.h"
#include "event_tags.h"
#include "json_util.h" /* fallback string decoder (mongoose ceiling) */
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Tag Element Access
 * ============================================================================ */

char *tag_iter_element(tag_iter_t *it, size_t index) {
    char path[32];
    int32_t written = snprintf(path, sizeof(path), "$[%llu]", (unsigned long long)index);
    if (written <= 0 || (size_t)written >= sizeof(path)) {
        return NULL;
    }
    {
        char *fast = mg_json_get_str(it->tags, path);
        if (fast) return fast;
        /* Fallback: mongoose's decoder returns NULL for some valid escapes
         * (BMP \uXXXX above U+00FF, surrogate pairs, \/). Decode the raw
         * i-th token ourselves. Non-string tokens (e.g. sub-arrays when
         * misused on an outer iterator) still yield NULL. Only fires where
         * decoding previously failed. */
        tag_iter_t w = *it;
        struct mg_str ek, elem;
        size_t i = 0;
        w.offset = 0;
        while (tag_iter_next(&w, &ek, &elem)) {
            if (i++ == index) {
                char *out;
                if (elem.len < 2 || !elem.buf || elem.buf[0] != '"') {
                    return NULL;
                }
                out = (char *)malloc(elem.len + 1);
                if (!out) return NULL;
                if (!json_decode_string_token(elem.buf, elem.buf + elem.len,
                                              out, elem.len + 1)) {
                    free(out);
                    return NULL;
                }
                return out;
            }
        }
        return NULL;
    }
}

bool tag_iter_next(tag_iter_t *it, struct mg_str *out_key, struct mg_str *out_tag) {
    size_t next = mg_json_next(it->tags, it->offset, out_key, out_tag);
    if (next == 0) {
        return false;
    }
    it->offset = next;
    return true;
}

/* ============================================================================
 * Tag Matching Predicates (single implementation via event_tags API).
 * The old copies scanned with the outer iterator (always NULL) and only
 * compared tag[1] of the first matching tag. They now delegate to
 * event_tag_has()/event_tag_has_value() so multi-tag and multi-value
 * events match consistently with matches_filter and storage.
 * ============================================================================ */

bool tag_predicate_match_name(const event_t *event, void *userdata) {
    const tag_match_name_t *match = (const tag_match_name_t *)userdata;
    if (!match || !match->name) return false;
    return event_tag_has(event, match->name);
}

bool tag_predicate_match_name_value(const event_t *event, void *userdata) {
    const tag_match_name_value_t *match = (const tag_match_name_value_t *)userdata;
    if (!match || !match->name || !match->value) return false;
    return event_tag_has_value(event, match->name, match->value);
}

bool tag_predicate_match_name_value_opt(const event_t *event, void *userdata) {
    const tag_match_name_value_opt_t *match = (const tag_match_name_value_opt_t *)userdata;
    if (!match || !match->name || !match->value) return false;
    if (!event_tag_has(event, match->name)) {
        return match->empty_value_when_missing && match->value[0] == '\0';
    }
    return event_tag_has_value(event, match->name, match->value);
}

bool tag_predicate_match_d_tag(const event_t *event, void *userdata) {
    const char *identifier = (const char *)userdata;
    if (!identifier) return false;
    if (!event_tag_has(event, "d")) {
        return identifier[0] == '\0';
    }
    return event_tag_has_value(event, "d", identifier);
}

bool tag_predicate_match_k_tag(const event_t *event, void *userdata) {
    int *target_kind = (int *)userdata;
    size_t ntags = 0;
    char ***all;
    bool matched = false;
    if (!target_kind) return false;
    if (!event_tag_has(event, "k")) return true;
    all = event_tag_get_all(event, "k", &ntags);
    if (!all) return false;
    for (size_t t = 0; !matched && t < ntags; t++) {
        if (!all[t]) continue;
        for (size_t i = 0; all[t][i]; i++) {
            char *end = NULL;
            long parsed = strtol(all[t][i], &end, 10);
            if (end && *end == '\0' && parsed == *target_kind) {
                matched = true;
                break;
            }
        }
    }
    event_tag_free_all(all, ntags);
    return matched;
}