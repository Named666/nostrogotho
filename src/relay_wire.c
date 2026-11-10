/* relay_wire - see relay_wire.h. */
#include "relay_wire.h"

#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "json_lite.h"

static size_t skip_ws(const char **d, size_t len) {
    while (len && (**d == ' ' || **d == '\t' || **d == '\r' || **d == '\n')) { (*d)++; len--; }
    return len;
}

size_t relay_wire_overload_reply(const char *data, size_t len, const char *why,
                                 char *out, size_t cap) {
    len = skip_ws(&data, len);
    jstr_t arr = jl_str_n(data, len), k, v0, v1;
    int n = 0;
    size_t o = jl_next(arr, 0, &k, &v0);
    if (o && jl_next(arr, o, &k, &v1)) {
        if (jl_tok_eq(v0, "EVENT") && v1.buf[0] == '{') {
            jstr_t kk, vv; size_t q = 0;
            while ((q = jl_next(v1, q, &kk, &vv)) != 0) {
                if (kk.len == 4 && memcmp(kk.buf, "\"id\"", 4) == 0) {
                    bool hex = vv.len == 66 && vv.buf[0] == '"' && vv.buf[65] == '"';
                    for (size_t i = 1; hex && i < 65; i++)
                        hex = (vv.buf[i] >= '0' && vv.buf[i] <= '9') || (vv.buf[i] >= 'a' && vv.buf[i] <= 'f');
                    if (hex) n = snprintf(out, cap, "[\"OK\",%.*s,false,\"%s\"]", 66, vv.buf, why);
                    break;
                }
            }
        } else if ((jl_tok_eq(v0, "REQ") || jl_tok_eq(v0, "COUNT")) && v1.buf[0] == '"' && v1.len <= 2 + 200) {
            bool clean = true;   /* echo the raw sub-id token only if it is plain */
            for (size_t i = 1; clean && i + 1 < v1.len; i++)
                clean = (unsigned char) v1.buf[i] >= 0x20 && v1.buf[i] != '"' && v1.buf[i] != '\\';
            if (clean) n = snprintf(out, cap, "[\"CLOSED\",%.*s,\"%s\"]", (int) v1.len, v1.buf, why);
        }
    }
    if (n <= 0 || (size_t) n >= cap) n = snprintf(out, cap, "[\"NOTICE\",\"%s\"]", why);
    return n > 0 && (size_t) n < cap ? (size_t) n : 0;
}

static bool hex_field(jstr_t v, size_t nbytes, uint8_t *out) {
    size_t got;
    return v.len == 2 * nbytes + 2 && v.buf[0] == '"' &&
           hex_to_bytes(v.buf + 1, 2 * nbytes, out, nbytes, &got) && got == nbytes;
}

bool relay_wire_event_sig(const char *d, size_t len,
                          uint8_t id[32], uint8_t pubkey[32], uint8_t sig[64]) {
    len = skip_ws(&d, len);
    if (len < 10 || memcmp(d, "[\"EVENT\"", 8) != 0) return false;
    jstr_t arr = jl_str_n(d, len), k, v0, ev;
    size_t o = jl_next(arr, 0, &k, &v0);
    if (!o || !jl_next(arr, o, &k, &ev) || ev.buf[0] != '{') return false;
    uint8_t tid[32], tpk[32], tsig[64];
    int have = 0; jstr_t kk, vv; size_t q = 0;
    while (have != 7 && (q = jl_next(ev, q, &kk, &vv)) != 0) {
        if (kk.len == 4 && memcmp(kk.buf, "\"id\"", 4) == 0) have |= hex_field(vv, 32, tid) ? 1 : 0;
        else if (kk.len == 8 && memcmp(kk.buf, "\"pubkey\"", 8) == 0) have |= hex_field(vv, 32, tpk) ? 2 : 0;
        else if (kk.len == 5 && memcmp(kk.buf, "\"sig\"", 5) == 0) have |= hex_field(vv, 64, tsig) ? 4 : 0;
    }
    if (have != 7) return false;
    memcpy(id, tid, 32); memcpy(pubkey, tpk, 32); memcpy(sig, tsig, 64);
    return true;
}
