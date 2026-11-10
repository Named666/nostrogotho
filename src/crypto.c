#include "platform/ng_platform.h"
#include "crypto.h"
#include "json_lite.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#endif
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include "schnorr_batch.h"
#include "platform/ng_alloc.h"

#ifdef _WIN32
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#endif

/* ============================================================================
 * Portable SHA-256 implementation (used on non-Windows platforms; Windows
 * uses CNG/BCrypt in sha256() below).
 * ============================================================================ */
#ifndef _WIN32

#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    uint32_t datalen;
} sha256_ctx;

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t sha256_rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256_transform(sha256_ctx *ctx, const uint8_t data[64]) {
    uint32_t m[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;

    for (uint32_t i = 0, j = 0; i < 16; i++, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) |
               ((uint32_t)data[j+2] << 8) | (uint32_t)data[j+3];
    for (uint32_t i = 16; i < 64; i++) {
        uint32_t s0 = sha256_rotr(m[i-15], 7) ^ sha256_rotr(m[i-15], 18) ^ (m[i-15] >> 3);
        uint32_t s1 = sha256_rotr(m[i-2], 17) ^ sha256_rotr(m[i-2], 19) ^ (m[i-2] >> 10);
        m[i] = m[i-16] + s0 + m[i-7] + s1;
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (uint32_t i = 0; i < 64; i++) {
        uint32_t S1 = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + sha256_k[i] + m[i];
        uint32_t S0 = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t hash[32]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; i++) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }
}

#endif /* !_WIN32 */

/* ============================================================================
 * Cryptographic Context
 * 
 * Global secp256k1 context used for all signature verification operations.
 * Lazily initialized on first use, safely handles multiple init calls.
 * ============================================================================ */

static secp256k1_context *verify_ctx = NULL;

/* crypto_init - Initialize cryptographic context
 * 
 * Creates a secp256k1 verification context for Schnorr signature checks.
 * Safe to call multiple times (idempotent); subsequent calls return true.
 * Thread-unsafe; must be called during single-threaded startup.
 */
bool crypto_init(void) {
    if (verify_ctx != NULL) {
        return true;  /* Already initialized */
    }
    
    verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!verify_ctx) {
        return false;
    }
    
    return true;
}

/* crypto_deinit - Cleanup cryptographic context
 * 
 * Releases the secp256k1 context and prevents further crypto operations.
 * Safe to call multiple times (idempotent).
 * Thread-unsafe; must be called during single-threaded shutdown.
 */
void crypto_deinit(void) {
    if (verify_ctx) {
        secp256k1_context_destroy(verify_ctx);
        verify_ctx = NULL;
    }
}

/* ============================================================================
 * Batch pre-verification (per thread)
 *
 * crypto_batch_verify() checks many (sig, key, msg) triples with one
 * multi-scalar multiplication (schnorr_batch.c). Triples proven valid are
 * remembered in a small thread-local table until crypto_preverified_clear();
 * signature_verify() consults it first, so the normal per-event validation
 * path (id hash, then signature) stays the single source of truth and only
 * skips curve work already done for exactly these bytes. A failed batch is
 * split in halves (down to 4) so a few bad signatures do not make the whole
 * batch fall back to individual checks.
 * ============================================================================ */
#define PV_SLOTS 4096                         /* power of two, > 2 * max batch */
#define PV_MAX_BATCH 256
typedef struct { uint8_t sig[64], pk[32], msg[32]; unsigned gen; } pv_slot_t;
static NG_THREAD_LOCAL pv_slot_t *pv_tab;
static NG_THREAD_LOCAL unsigned pv_gen = 1, pv_count;
static NG_THREAD_LOCAL ng_batch_scratch_t *pv_scratch;

static size_t pv_hash(const uint8_t *sig) { uint64_t h; memcpy(&h, sig + 32, 8); return (size_t) (h * 0x9E3779B97F4A7C15ull >> 52) & (PV_SLOTS - 1); }

bool crypto_preverified(const uint8_t sig[64], const uint8_t pk[32], const uint8_t msg[32]) {
    if (!pv_tab || !pv_count) return false;
    for (size_t i = pv_hash(sig), k = 0; k < PV_SLOTS; i = (i + 1) & (PV_SLOTS - 1), k++) {
        pv_slot_t *e = &pv_tab[i];
        if (e->gen != pv_gen) return false;
        if (memcmp(e->sig, sig, 64) == 0 && memcmp(e->pk, pk, 32) == 0 && memcmp(e->msg, msg, 32) == 0) return true;
    }
    return false;
}

static void pv_add(const uint8_t *sig, const uint8_t *pk, const uint8_t *msg) {
    if (pv_count >= PV_SLOTS / 2) return;     /* keep probing short; caller verifies normally */
    for (size_t i = pv_hash(sig);; i = (i + 1) & (PV_SLOTS - 1)) {
        pv_slot_t *e = &pv_tab[i];
        if (e->gen != pv_gen) { memcpy(e->sig, sig, 64); memcpy(e->pk, pk, 32); memcpy(e->msg, msg, 32); e->gen = pv_gen; pv_count++; return; }
    }
}

void crypto_preverified_clear(void) {
    if (!pv_count) return;
    pv_count = 0;
    if (++pv_gen == 0) { if (pv_tab) memset(pv_tab, 0, PV_SLOTS * sizeof(*pv_tab)); pv_gen = 1; }
}

static size_t pv_verify(const uint8_t *const *sig, const uint8_t *const *msg, const uint8_t *const *pk, size_t n) {
    if (n == 0) return 0;
    if (n < 2) return 0;                       /* single: the normal path verifies it */
    if (ng_schnorrsig_verify_batch(verify_ctx, pv_scratch, sig, msg, pk, n)) {
        for (size_t i = 0; i < n; i++) pv_add(sig[i], pk[i], msg[i]);
        return n;
    }
    if (n <= 4) return 0;
    size_t h = n / 2;
    return pv_verify(sig, msg, pk, h) + pv_verify(sig + h, msg + h, pk + h, n - h);
}

size_t crypto_batch_verify(const uint8_t *const *sig64, const uint8_t *const *msg32,
                           const uint8_t *const *pk32, size_t n) {
    if (!verify_ctx || n < 2) return 0;
    if (!pv_tab && !(pv_tab = (pv_slot_t *) calloc(PV_SLOTS, sizeof(*pv_tab)))) return 0;
    if (!pv_scratch && !(pv_scratch = ng_batch_scratch_create(verify_ctx, PV_MAX_BATCH))) return 0;
    size_t ok = 0;
    for (size_t i = 0; i < n; i += PV_MAX_BATCH) {
        size_t k = n - i < PV_MAX_BATCH ? n - i : PV_MAX_BATCH;
        ok += pv_verify(sig64 + i, msg32 + i, pk32 + i, k);
    }
    return ok;
}

void crypto_thread_cleanup(void) {
    if (pv_scratch) { ng_batch_scratch_destroy(verify_ctx, pv_scratch); pv_scratch = NULL; }
    free(pv_tab); pv_tab = NULL; pv_count = 0;
}

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/* hex_value - Convert a single hex character to numeric value
 * 
 * Converts '0'-'9', 'a'-'f', 'A'-'F' to 0-15.
 * 
 * Args: c - character to convert
 * Returns: 0-15 on valid hex digit, -1 if not hex
 */
static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* json_escape_string - Escape a string for use in JSON
 *
 * Escapes special JSON characters in a string so it can be safely
 * included in a JSON string literal (within double quotes).
 *
 * Characters escaped:
 *   "  -> \"
 *   \  -> \\
 *   \b -> (backspace)
 *   \f -> (formfeed)
 *   \n -> (newline)
 *   \r -> (carriage return)
 *   \t -> (tab)
 *
 * NOTE: '/' is deliberately NOT escaped. This escaper produces the input to
 * the event-id hash, which per NIP-01 must be the canonical serialization
 * clients compute (JSON.stringify semantics: '/' stays literal). Escaping
 * it made every event whose content contains '/' fail id verification.
 *
 * Args:
 *   src - source string (must not be NULL)
 *   dst - destination buffer (must not be NULL)
 *   dst_size - size of destination buffer
 *
 * Returns: number of bytes written (including null terminator),
 *          0 if buffer too small to fit escaped string
 */
static size_t json_escape_string(const char *src, char *dst, size_t dst_size) {
    if (!src || !dst || dst_size == 0) return 0;
    
    size_t out_pos = 0;
    
    for (const char *p = src; *p && out_pos < dst_size - 1; p++) {
        char c = *p;
        const char *escape = NULL;
        size_t escape_len = 0;
        
        switch (c) {
            case '"':  escape = "\\\""; escape_len = 2; break;
            case '\\': escape = "\\\\"; escape_len = 2; break;
            case '\b': escape = "\\b"; escape_len = 2; break;
            case '\f': escape = "\\f"; escape_len = 2; break;
            case '\n': escape = "\\n"; escape_len = 2; break;
            case '\r': escape = "\\r"; escape_len = 2; break;
            case '\t': escape = "\\t"; escape_len = 2; break;
            default:
                if ((unsigned char)c < 32) {
                    /* Control characters: output as \uXXXX */
                    static const char hex[] = "0123456789abcdef";
                    unsigned char uc = (unsigned char)c;
                    if (out_pos + 6 >= dst_size) return 0;
                    memcpy(dst + out_pos, "\\u00", 4);
                    dst[out_pos + 4] = hex[uc >> 4];
                    dst[out_pos + 5] = hex[uc & 0xf];
                    out_pos += 6;
                    continue;
                }
                escape = NULL;
                break;
        }
        
        if (escape) {
            if (out_pos + escape_len >= dst_size) return 0;
            memcpy(dst + out_pos, escape, escape_len);
            out_pos += escape_len;
        } else {
            dst[out_pos++] = c;
        }
    }
    
    if (out_pos >= dst_size) return 0;
    dst[out_pos] = '\0';
    return out_pos + 1;
}

/* ============================================================================
 * Hex Encoding/Decoding
 * ============================================================================ */

/* bytes_to_hex - Encode bytes as lowercase hex string
 * 
 * Converts binary data to hex representation. Each byte becomes 2 hex chars.
 * Output is lowercase, null-terminated, with no prefix or spacing.
 * 
 * Args:
 *   bytes - input bytes (must not be NULL)
 *   len   - number of bytes
 * 
 * Returns: malloc'd hex string, or NULL if bytes is NULL or malloc fails
 * 
 * Caller responsibility: Must free result with free()
 * 
 * Example: [0xAB, 0xCD] -> "abcd\0"
 */
char *bytes_to_hex(const uint8_t *bytes, size_t len) {
    if (!bytes || len == 0) return NULL;
    
    char *hex = (char *) ng_malloc_flex(1, len, 2);
    if (!hex) return NULL;
    
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i * 2] = digits[bytes[i] >> 4];
        hex[i * 2 + 1] = digits[bytes[i] & 0x0f];
    }
    hex[len * 2] = '\0';
    
    return hex;
}

/* hex_to_bytes - Decode hex string to bytes
 * 
 * Converts hex string to binary. Each pair of hex chars becomes one byte.
 * Accepts uppercase or lowercase hex digits. Hex string need not be null-terminated.
 * 
 * Args:
 *   hex      - hex string (must not be NULL)
 *   hex_len  - number of chars to process (must be even)
 *   bytes    - output buffer (must not be NULL, must have at least hex_len/2 capacity)
 *   max_bytes - size of bytes buffer
 *   out_len  - if not NULL, stores count of decoded bytes
 * 
 * Returns: true on success, false if:
 *   - hex_len is odd
 *   - result would exceed max_bytes
 *   - hex contains non-hex characters
 * 
 * On failure: out_len is not modified, bytes buffer is partially filled
 * 
 * Example: "abcd" (4 chars) -> [0xAB, 0xCD] (2 bytes)
 */
bool hex_to_bytes(const char *hex, size_t hex_len, uint8_t *bytes,
                  size_t max_bytes, size_t *out_len) {
    if (!hex || hex_len == 0 || !bytes) return false;
    
    size_t byte_count = hex_len / 2;
    if (byte_count > max_bytes || hex_len % 2 != 0) {
        return false;
    }
    
    for (size_t i = 0; i < byte_count; i++) {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        
        if (hi < 0 || lo < 0) {
            return false;
        }
        
        bytes[i] = (uint8_t)((hi << 4) | lo);
    }
    
    if (out_len) *out_len = byte_count;
    return true;
}

/* ============================================================================
 * Hashing
 * ============================================================================ */

/* sha256 - Compute SHA256 hash
 * 
 * Computes the standard SHA256 cryptographic hash of input data.
 * Uses the bundled SHA-256 implementation.
 * 
 * Args:
 *   data   - bytes to hash (must not be NULL)
 *   len    - number of bytes
 *   digest - 32-byte output buffer (must not be NULL)
 * 
 * Returns: nothing
 * 
 * Note: digest should point to at least 32 bytes; no return value for errors,
 * caller must ensure valid inputs
 */
void sha256(const uint8_t *data, size_t len, uint8_t digest[32]) {
#ifndef _WIN32
    sha256_ctx ctx;
    if (!data || !digest) return;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
#else
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    DWORD hash_object_size = 0;
    DWORD result_size = 0;
    PUCHAR hash_object = NULL;

    if (!data || !digest || len > ULONG_MAX) return;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                    NULL, 0) != STATUS_SUCCESS) {
        return;
    }
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                          (PUCHAR)&hash_object_size, sizeof(hash_object_size),
                          &result_size, 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return;
    }

    hash_object = malloc(hash_object_size);
    if (!hash_object || BCryptCreateHash(algorithm, &hash, hash_object,
                                         hash_object_size, NULL, 0, 0) != STATUS_SUCCESS ||
        BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0) != STATUS_SUCCESS ||
        BCryptFinishHash(hash, digest, 32, 0) != STATUS_SUCCESS) {
        if (hash) BCryptDestroyHash(hash);
        free(hash_object);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return;
    }

    BCryptDestroyHash(hash);
    free(hash_object);
    BCryptCloseAlgorithmProvider(algorithm, 0);
#endif /* _WIN32 */
}

/* ============================================================================
 * Signature Verification
 * ============================================================================ */

/* signature_verify - Verify a Schnorr signature (NIP-01)
 * 
 * Verifies a Schnorr signature using secp256k1 x-only public key verification.
 * Used to authenticate Nostr events by verifying they were signed by the claimed pubkey.
 * 
 * Args:
 *   sig_hex    - 64-char hex string representing 64-byte signature
 *   pubkey_hex - 64-char hex string representing 32-byte x-only public key
 *   digest     - 32-byte SHA256 hash of event data to verify
 * 
 * Returns: true if signature is valid, false otherwise
 *   - Returns false if signature or pubkey hex is malformed
 *   - Returns false if secp256k1 verification fails
 *   - Returns false if context not initialized
 * 
 * Requirements:
 *   - crypto_init() must have been called successfully
 *   - digest must point to exactly 32 bytes (SHA256 output)
 * 
 * Note: Signature is in secp256k1 Schnorr format (64 bytes), not DER encoded
 */
bool signature_verify(const char *sig_hex, const char *pubkey_hex, const uint8_t digest[32]) {
    if (!sig_hex || !pubkey_hex || !digest) return false;
    if (!verify_ctx) return false;
    
    /* Convert hex strings to bytes */
    uint8_t sig_bytes[64];
    uint8_t pubkey_bytes[32];
    size_t sig_len, pubkey_len;
    
    if (!hex_to_bytes(sig_hex, strlen(sig_hex), sig_bytes, sizeof(sig_bytes), &sig_len)) {
        return false;
    }
    if (!hex_to_bytes(pubkey_hex, strlen(pubkey_hex), pubkey_bytes, sizeof(pubkey_bytes), &pubkey_len)) {
        return false;
    }
    
    if (sig_len != 64 || pubkey_len != 32) {
        return false;
    }
    
    if (crypto_preverified(sig_bytes, pubkey_bytes, digest)) return true;

    /* Parse x-only public key */
    secp256k1_xonly_pubkey xonly_pubkey;
    if (!secp256k1_xonly_pubkey_parse(verify_ctx, &xonly_pubkey, pubkey_bytes)) {
        return false;
    }
    
    /* Verify signature */
    return secp256k1_schnorrsig_verify(verify_ctx, sig_bytes, digest, 32, &xonly_pubkey);
}

/* ============================================================================
 * Canonical tags serialization (event id)
 * ============================================================================ */

/* Already canonical: only [ ] , and strings outside strings (no
 * whitespace), and inside strings no control bytes and only the escapes
 * the canonical form itself uses. The structure was validated by
 * json_parse_event. Most clients send exactly this, so the id can be
 * hashed over the raw bytes without re-serializing. */
static bool tags_json_is_canonical(const char *s, size_t n) {
    bool in_str = false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char) s[i];
        if (!in_str) {
            if (c == '"') in_str = true;
            else if (c != '[' && c != ']' && c != ',') return false;
            continue;
        }
        if (c < 0x20) return false;
        if (c == '"') { in_str = false; continue; }
        if (c == '\\') {
            if (++i >= n) return false;
            c = (unsigned char) s[i];
            if (c != '"' && c != '\\' && c != 'n' && c != 'r' && c != 't' && c != 'b' && c != 'f') return false;
        }
    }
    return !in_str;
}

/* canonical_tags_json - re-serialize tags in NIP-01 canonical form (no
 * whitespace, minimal escaping, every element decoded including \uXXXX
 * escapes and surrogate pairs) so the id is computed over the canonical
 * serialization rather than the client's raw bytes. Empty tags are kept.
 * The input must have passed json_parse_event (an array of string arrays).
 * Returns a malloc'd string or NULL (malformed input or out of memory). */
static char *canonical_tags_json(const char *raw) {
    jstr_t all = jl_str(raw), key, tag;
    /* Output bound: every decoded byte escapes to at most 6 bytes and a
     * decoded element is never longer than its token. */
    size_t cap;
    if (!ng_size_flex(3, all.len, 6, &cap)) return NULL;
    char *out = (char *) malloc(cap);
    char *tmp = (char *) ng_malloc_add(all.len, 1);
    if (!out || !tmp) { free(out); free(tmp); return NULL; }
    size_t len = 0, offset = 0;
    bool ok = all.len >= 2 && all.buf[0] == '[';
    out[len++] = '[';
    for (bool first = true; ok && (offset = jl_next(all, offset, &key, &tag)) != 0; first = false) {
        if (key.buf || tag.len < 2 || tag.buf[0] != '[') { ok = false; break; }
        if (!first) out[len++] = ',';
        out[len++] = '[';
        jstr_t ek, el;
        size_t eo = 0;
        for (bool efirst = true; ok && (eo = jl_next(tag, eo, &ek, &el)) != 0; efirst = false) {
            size_t n = 0;
            if (ek.buf || !jl_unescape(el, tmp, &n) || memchr(tmp, 0, n)) { ok = false; break; }
            tmp[n] = '\0';
            if (!efirst) out[len++] = ',';
            out[len++] = '"';
            size_t w = json_escape_string(tmp, out + len, cap - len);
            if (!w) { ok = false; break; }
            len += w - 1;
            out[len++] = '"';
        }
        if (ok) out[len++] = ']';
    }
    free(tmp);
    if (!ok || len + 2 > cap) { free(out); return NULL; }
    out[len++] = ']';
    out[len] = '\0';
    return out;
}

/* ============================================================================
 * Event Validation (NIP-01)
 * ============================================================================ */

/* check_event - Validate a complete Nostr event
 * 
 * Performs comprehensive event validation:
 * 1. Reconstructs event hash from event data: [0, pubkey, created_at, kind, tags, content]
 * 2. Computes SHA256 of this JSON
 * 3. Verifies computed ID matches event.id
 * 4. Verifies signature with event.pubkey
 * 
 * Args: ev - event to validate (must not be NULL)
 * Returns: true if all checks pass, false if any check fails
 * 
 * Requirements:
 *   - crypto_init() must have been called
 *   - Event must have all required fields initialized
 * 
 * Note: Does NOT check:
 *   - Timestamp validity (checked separately for NIP-22)
 *   - Proof-of-work (checked separately for NIP-13)
 *   - Event size limits (checked separately)
 * 
 * Fails gracefully with detailed logging on any step failure.
 */
bool check_event(const event_t *ev) {
    if (!ev) return false;
    
    /* Build the event hash input: [0, pubkey, created_at, kind, tags, content]
     * Content and pubkey must be JSON-escaped for proper serialization.
     *
     * Stack usage is kept minimal: the content escape buffer and the
     * serialization buffer are heap-allocated because this function runs on
     * every incoming event (possibly concurrently). Worst case for JSON
     * escaping is 6 output bytes per input byte (\u00XX for control chars).
     */
    char escaped_pubkey[MAX_PUBKEY_SIZE * 2 + 1];
    
    /* Escape pubkey for JSON (64 hex chars -> 129-byte stack buffer, safe) */
    if (!json_escape_string(ev->pubkey, escaped_pubkey, sizeof(escaped_pubkey))) {
        return false;
    }
    
    /* Escape content for JSON - heap allocated, sized for worst-case escaping */
    const char *content = ev->content ? ev->content : "";
    size_t content_len = strlen(content);
    
    size_t escaped_content_cap;
    if (!ng_size_flex(1, content_len, 6, &escaped_content_cap)) return false;
    char *escaped_content = (char *) malloc(escaped_content_cap);
    if (!escaped_content) {
        return false;
    }
    if (!json_escape_string(content, escaped_content, escaped_content_cap)) {
        free(escaped_content);
        return false;
    }
    
    /* Size the serialization buffer: fixed overhead + tags + escaped content */
    char *canon_tags = NULL;
    const char *tags_json = "[]";
    if (ev->tags_json) {
        if (tags_json_is_canonical(ev->tags_json, strlen(ev->tags_json))) tags_json = ev->tags_json;
        else if (!(canon_tags = canonical_tags_json(ev->tags_json))) { free(escaped_content); return false; }
        else tags_json = canon_tags;
    }
    size_t tags_len = strlen(tags_json);
    size_t buffer_cap;
    char *buffer = ng_size_add3(128 + 1, tags_len, strlen(escaped_content), &buffer_cap) ? (char *) malloc(buffer_cap) : NULL;
    if (!buffer) {
        free(escaped_content);
        free(canon_tags);
        return false;
    }
    
    int written = snprintf(buffer, buffer_cap,
                          "[0,\"%s\",%lld,%d,%s,\"%s\"]",
                          escaped_pubkey, (long long)ev->created_at, ev->kind,
                          tags_json,
                          escaped_content);
    free(escaped_content);
    escaped_content = NULL;
    free(canon_tags);
    
    if (written < 0 || (size_t)written >= buffer_cap) {
        free(buffer);
        return false;
    }
    
    /* Compute SHA256 hash */
    uint8_t digest[32];
    sha256((const uint8_t *)buffer, strlen(buffer), digest);
    free(buffer);
    buffer = NULL;
    
    /* Convert digest to hex and compare with event ID */
    char *id_hex = bytes_to_hex(digest, 32);
    if (!id_hex) return false;
    
    bool id_matches = (strcmp(id_hex, ev->id) == 0);
    free(id_hex);
    
    if (!id_matches) return false;
    
    /* Verify signature */
    if (!signature_verify(ev->sig, ev->pubkey, digest)) {
        return false;
    }
    
    return true;
}

/* ============================================================================
 * Proof of Work (NIP-13)
 * ============================================================================ */

/* count_leading_zero_bits - Count leading zero bits in event ID
 * 
 * Calculates proof-of-work difficulty by counting leading zero bits
 * in the hexadecimal event ID (SHA256 hash).
 * 
 * NIP-13 defines this as: "clients MAY require events to include a proof
 * of work token, an arbitrary string appended to the content before
 * hashing such that the hash of the resulting string starts with N zero bits."
 * 
 * Algorithm:
 *   1. Process hex string from left to right
 *   2. Each '0' nibble (0x0) contributes 4 bits
 *   3. When first non-zero nibble found:
 *      - 0x1,0x2,0x4: add 3 bits
 *      - 0x3,0x5,0x6,0x7: add 2 bits
 *      - 0x9-0xF: add 1 bit
 *   4. Return total bit count
 * 
 * Args: hex - event ID as hex string (64 chars for SHA256, NULL-safe)
 * Returns: number of leading zero bits (0-256 for SHA256)
 * 
 * Examples:
 *   - "0000000..." -> 4, 8, 12, ... (multiples of 4)
 *   - "00000001..." -> 31 bits (7 zero nibbles = 28 bits, 0x1 = 3 bits)
 *   - "1abc..." -> 0 bits (first nibble is non-zero)
 * 
 * Note: Returns 0 if hex is NULL; this is not an error condition
 */
int count_leading_zero_bits(const char *hex) {
    if (!hex) return 0;
    
    /* Validate that all characters are valid hex digits */
    for (const char *p = hex; *p; p++) {
        if (hex_value(*p) < 0) return 0;  /* Invalid hex, return 0 */
    }
    
    int count = 0;
    
    for (const char *p = hex; *p; p++) {
        int nibble = hex_value(*p);
        
        if (nibble == 0) {
            count += 4;
            continue;
        }
        
        if (nibble <= 1) {
            count += 3;
        } else if (nibble <= 3) {
            count += 2;
        } else if (nibble <= 7) {
            count += 1;
        }
        
        break;
    }
    
    return count;
}
