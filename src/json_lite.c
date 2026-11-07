#include "json_lite.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

jstr_t jl_str(const char *s) { jstr_t r = { s, s ? strlen(s) : 0 }; return r; }
jstr_t jl_str_n(const char *s, size_t n) { jstr_t r = { s, n }; return r; }

bool jl_str_contains(jstr_t h, const char *needle) {
    size_t n = strlen(needle);
    if (n == 0) return true;
    if (!h.buf || n > h.len) return false;
    for (size_t i = 0; i + n <= h.len; i++)
        if (h.buf[i] == needle[0] && memcmp(h.buf + i, needle, n) == 0) return true;
    return false;
}

static int is_ws(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

static size_t skip_ws(const char *s, size_t n, size_t i) {
    while (i < n && is_ws(s[i])) i++;
    return i;
}

static size_t string_len(const char *s, size_t n) {
    /* s[0] == '"' */
    for (size_t i = 1; i < n; i++) {
        unsigned char c = (unsigned char) s[i];
        if (c == '\\') { if (++i >= n) return 0; continue; }
        if (c == '"') return i + 1;
        if (c < 0x20) return 0;
    }
    return 0;
}

static size_t scalar_len(const char *s, size_t n) {
    size_t i = 0;
    if (n >= 4 && memcmp(s, "true", 4) == 0) return 4;
    if (n >= 5 && memcmp(s, "false", 5) == 0) return 5;
    if (n >= 4 && memcmp(s, "null", 4) == 0) return 4;
    if (i < n && s[i] == '-') i++;
    size_t digits = 0;
    while (i < n && s[i] >= '0' && s[i] <= '9') i++, digits++;
    if (!digits) return 0;
    if (i < n && s[i] == '.') { i++; while (i < n && s[i] >= '0' && s[i] <= '9') i++; }
    if (i < n && (s[i] == 'e' || s[i] == 'E')) {
        i++; if (i < n && (s[i] == '+' || s[i] == '-')) i++;
        while (i < n && s[i] >= '0' && s[i] <= '9') i++;
    }
    return i;
}

/* Iterative container scan with a depth limit to avoid stack abuse. */
size_t jl_value_len(const char *s, size_t n) {
    if (!s || n == 0) return 0;
    if (s[0] == '"') return string_len(s, n);
    if (s[0] != '{' && s[0] != '[') return scalar_len(s, n);
    char stack[128];
    int depth = 0;
    size_t i = 0;
    while (i < n) {
        char c = s[i];
        if (c == '"') {
            size_t l = string_len(s + i, n - i);
            if (!l) return 0;
            i += l; continue;
        }
        if (c == '{' || c == '[') {
            if (depth >= (int) sizeof(stack)) return 0;
            stack[depth++] = c == '{' ? '}' : ']';
        } else if (c == '}' || c == ']') {
            if (depth == 0 || stack[depth - 1] != c) return 0;
            if (--depth == 0) return i + 1;
        }
        i++;
    }
    return 0;
}

size_t jl_next(jstr_t obj, size_t ofs, jstr_t *key, jstr_t *val) {
    const char *s = obj.buf; size_t n = obj.len;
    if (!s || n < 2 || (s[0] != '{' && s[0] != '[') || ofs >= n) return 0;
    bool is_obj = s[0] == '{';
    size_t i = ofs == 0 ? 1 : ofs;
    i = skip_ws(s, n, i);
    if (i < n && s[i] == ',') i = skip_ws(s, n, i + 1);
    if (i >= n || s[i] == '}' || s[i] == ']') return 0;
    if (is_obj) {
        if (s[i] != '"') return 0;
        size_t kl = string_len(s + i, n - i);
        if (!kl) return 0;
        if (key) *key = jl_str_n(s + i, kl);
        i = skip_ws(s, n, i + kl);
        if (i >= n || s[i] != ':') return 0;
        i = skip_ws(s, n, i + 1);
    } else if (key) {
        *key = jl_str_n(NULL, 0);
    }
    size_t vl = jl_value_len(s + i, n - i);
    if (!vl) return 0;
    if (val) *val = jl_str_n(s + i, vl);
    i = skip_ws(s, n, i + vl);
    if (i >= n || (s[i] != ',' && s[i] != '}' && s[i] != ']')) return 0;
    return i;
}

int jl_get(jstr_t json, const char *path, int *toklen) {
    if (toklen) *toklen = 0;
    if (!json.buf || !path || path[0] != '$') return -1;
    size_t start = skip_ws(json.buf, json.len, 0);
    if (start >= json.len) return -1;
    jstr_t v = jl_str_n(json.buf + start, json.len - start);
    if (path[1] == '\0') {
        size_t l = jl_value_len(v.buf, v.len);
        if (!l) return -1;
        if (toklen) *toklen = (int) l;
        return (int) start;
    }
    jstr_t k, val; size_t ofs = 0;
    if (path[1] == '.') {
        const char *name = path + 2; size_t nl = strlen(name);
        if (v.buf[0] != '{') return -1;
        while ((ofs = jl_next(v, ofs, &k, &val)) != 0) {
            if (k.len == nl + 2 && memcmp(k.buf + 1, name, nl) == 0) {
                if (toklen) *toklen = (int) val.len;
                return (int) (val.buf - json.buf);
            }
        }
        return -1;
    }
    if (path[1] == '[') {
        char *end; long idx = strtol(path + 2, &end, 10);
        if (*end != ']' || idx < 0 || v.buf[0] != '[') return -1;
        long i = 0;
        while ((ofs = jl_next(v, ofs, &k, &val)) != 0) {
            if (i++ == idx) {
                if (toklen) *toklen = (int) val.len;
                return (int) (val.buf - json.buf);
            }
        }
    }
    return -1;
}

jstr_t jl_get_tok(jstr_t json, const char *path) {
    int len = 0, off = jl_get(json, path, &len);
    return off < 0 ? jl_str_n(NULL, 0) : jl_str_n(json.buf + off, (size_t) len);
}

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int read_u4(const char *p, uint32_t *out) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) { int h = hexv(p[i]); if (h < 0) return 0; v = v << 4 | (uint32_t) h; }
    *out = v; return 1;
}

static size_t put_utf8(char *o, uint32_t cp) {
    if (cp < 0x80) { o[0] = (char) cp; return 1; }
    if (cp < 0x800) { o[0] = (char) (0xC0 | cp >> 6); o[1] = (char) (0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000) { o[0] = (char) (0xE0 | cp >> 12); o[1] = (char) (0x80 | ((cp >> 6) & 0x3F)); o[2] = (char) (0x80 | (cp & 0x3F)); return 3; }
    o[0] = (char) (0xF0 | cp >> 18); o[1] = (char) (0x80 | ((cp >> 12) & 0x3F));
    o[2] = (char) (0x80 | ((cp >> 6) & 0x3F)); o[3] = (char) (0x80 | (cp & 0x3F)); return 4;
}

char *jl_unquote(jstr_t t) {
    if (!t.buf || t.len < 2 || t.buf[0] != '"' || t.buf[t.len - 1] != '"') return NULL;
    char *out = (char *) malloc(t.len); /* unescaped is never longer */
    if (!out) return NULL;
    size_t o = 0;
    for (size_t i = 1; i + 1 < t.len; i++) {
        char c = t.buf[i];
        if (c != '\\') { out[o++] = c; continue; }
        if (++i + 1 > t.len - 1) { free(out); return NULL; }
        switch (t.buf[i]) {
            case '"': out[o++] = '"'; break;
            case '\\': out[o++] = '\\'; break;
            case '/': out[o++] = '/'; break;
            case 'b': out[o++] = '\b'; break;
            case 'f': out[o++] = '\f'; break;
            case 'n': out[o++] = '\n'; break;
            case 'r': out[o++] = '\r'; break;
            case 't': out[o++] = '\t'; break;
            case 'u': {
                uint32_t cp, lo;
                if (i + 4 >= t.len || !read_u4(t.buf + i + 1, &cp)) { free(out); return NULL; }
                i += 4;
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    if (i + 6 < t.len && t.buf[i + 1] == '\\' && t.buf[i + 2] == 'u' &&
                        read_u4(t.buf + i + 3, &lo) && lo >= 0xDC00 && lo <= 0xDFFF) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        i += 6;
                    } else cp = 0xFFFD;
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) cp = 0xFFFD;
                o += put_utf8(out + o, cp);
                break;
            }
            default: free(out); return NULL;
        }
    }
    out[o] = '\0';
    return out;
}

char *jl_get_str(jstr_t json, const char *path) {
    jstr_t t = jl_get_tok(json, path);
    if (!t.buf || t.buf[0] != '"') return NULL;
    return jl_unquote(t);
}

bool jl_get_num(jstr_t json, const char *path, double *v) {
    jstr_t t = jl_get_tok(json, path);
    if (!t.buf || !((t.buf[0] >= '0' && t.buf[0] <= '9') || t.buf[0] == '-')) return false;
    char tmp[64];
    if (t.len >= sizeof(tmp)) return false;
    memcpy(tmp, t.buf, t.len); tmp[t.len] = '\0';
    char *end; double d = strtod(tmp, &end);
    if (*end) return false;
    if (v) *v = d;
    return true;
}
