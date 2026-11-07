#ifndef JSON_LITE_H_
#define JSON_LITE_H_

/* ============================================================================
 * json_lite - tiny, dependency-free JSON token scanner (MIT, in-tree).
 *
 * Small allocation-free JSON scanner used across the relay, so the relay
 * core no longer depends on GPL code. Semantics intentionally mirror the
 * previous helpers:
 *   - jl_next(obj, ofs, &key, &val): iterate an object or array. Start with
 *     ofs = 0; returns the next offset or 0 when done/invalid. For arrays
 *     key = {NULL,0}; for objects key is the raw (quoted) key token.
 *   - jl_get(json, path, &len): locate the token at "$", "$.name" or
 *     "$[N]" (one level, top-level only). Returns offset or -1.
 *   - jl_get_tok / jl_get_str / jl_get_num: typed accessors. jl_get_str
 *     returns a malloc'd, unescaped UTF-8 string (handles \uXXXX and
 *     surrogate pairs) or NULL if the token is not a string.
 * ============================================================================ */

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    const char *buf;
    size_t len;
} jstr_t;

jstr_t jl_str(const char *s);
jstr_t jl_str_n(const char *s, size_t n);
bool jl_str_contains(jstr_t haystack, const char *needle);

/* Length of the JSON value starting at s[0] (skips nothing); 0 if invalid. */
size_t jl_value_len(const char *s, size_t n);

size_t jl_next(jstr_t obj, size_t ofs, jstr_t *key, jstr_t *val);
int jl_get(jstr_t json, const char *path, int *toklen);
jstr_t jl_get_tok(jstr_t json, const char *path);
char *jl_get_str(jstr_t json, const char *path);
bool jl_get_num(jstr_t json, const char *path, double *v);

/* Unescape a quoted JSON string token into a malloc'd C string. */
char *jl_unquote(jstr_t tok);
/* Decode quoted string token into out (>= tok.len bytes); (size_t)-1 = invalid. */
size_t jl_unescape(jstr_t tok, char *out);
/* Compare a quoted string token with s without allocating (common case). */
bool jl_tok_eq(jstr_t tok, const char *s);

#endif /* JSON_LITE_H_ */
