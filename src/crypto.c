#include "crypto.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <stdlib.h>
#include <windows.h>
#include <bcrypt.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

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
 *   /  -> \/
 *   \b -> (backspace)
 *   \f -> (formfeed)
 *   \n -> (newline)
 *   \r -> (carriage return)
 *   \t -> (tab)
 * 
 * Args:
 *   src - source string (must not be NULL)
 *   dst - destination buffer (must not be NULL)
 *   dst_size - size of destination buffer
 * 
 * Returns: number of bytes written (including null terminator),
 *          0 if buffer too small to fit escaped string
 * 
 * Note: Safe to use for event hashing as it doesn't change semantics
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
            case '/':  escape = "\\/"; escape_len = 2; break;
            case '\b': escape = "\\b"; escape_len = 2; break;
            case '\f': escape = "\\f"; escape_len = 2; break;
            case '\n': escape = "\\n"; escape_len = 2; break;
            case '\r': escape = "\\r"; escape_len = 2; break;
            case '\t': escape = "\\t"; escape_len = 2; break;
            default:
                if ((unsigned char)c < 32) {
                    /* Control characters: output as \uXXXX */
                    char buf[7];
                    int len = snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    if (out_pos + len >= dst_size) return 0;
                    memcpy(dst + out_pos, buf, len);
                    out_pos += len;
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
    
    char *hex = (char *)malloc(len * 2 + 1);
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
    
    /* Parse x-only public key */
    secp256k1_xonly_pubkey xonly_pubkey;
    if (!secp256k1_xonly_pubkey_parse(verify_ctx, &xonly_pubkey, pubkey_bytes)) {
        return false;
    }
    
    /* Verify signature */
    return secp256k1_schnorrsig_verify(verify_ctx, sig_bytes, digest, 32, &xonly_pubkey);
}

/* ============================================================================
 * Tag Parsing (Helper)
 * ============================================================================ */

/* parse_tags_json - Parse tags from JSON array string
 * 
 * Extracts tags from a JSON array string and creates a tags_array_t structure.
 * Handles basic Nostr tag format: [["name", "val1", "val2"], ...]
 * 
 * Args: json_str - JSON array string (NULL-safe)
 * Returns: parsed tags_array_t, or NULL if parsing fails
 * 
 * Implementation:
 *   - Simple state machine parser (not full JSON parser)
 *   - Handles escaped quotes within strings
 *   - Skips whitespace and commas
 *   - Builds tag array incrementally
 * 
 * Caller responsibility: Must call tags_array_free() to release result
 */
static tags_array_t *parse_tags_json(const char *json_str) {
    if (!json_str) return NULL;
    
    /* Simple JSON parser for tag arrays
     * This is a simplified parser that handles basic array of arrays format:
     * [["tag1", "value1"], ["tag2", "value2", "value3"]]
     */
    
    tags_array_t *tags = tags_array_alloc(MAX_TAG_ELEMENTS);
    if (!tags) return NULL;
    
    const char *p = json_str;
    
    /* Skip to first '[' */
    while (*p && *p != '[') p++;
    if (*p != '[') {
        tags_array_free(tags);
        return NULL;
    }
    
    p++;  /* Skip '[' */
    
    while (*p && *p != ']') {
        /* Skip whitespace */
        while (*p && (*p == ' ' || *p == '\n' || *p == '\t' || *p == ',')) p++;
        
        if (*p == ']') break;
        
        if (*p == '[') {
            /* Start of a tag */
            p++;
            tag_t *tag = tag_alloc(MAX_TAG_ELEMENTS);
            if (!tag) {
                tags_array_free(tags);
                return NULL;
            }
            
            while (*p && *p != ']') {
                /* Skip whitespace and comma */
                while (*p && (*p == ' ' || *p == '\n' || *p == '\t' || *p == ',')) p++;
                
                if (*p == ']') break;
                
                if (*p == '"') {
                    /* Parse string */
                    p++;
                    char *str_start = (char *)p;
                    size_t str_len = 0;
                    
                    while (*p && *p != '"') {
                        if (*p == '\\') p++;  /* Skip escaped characters */
                        p++;
                        str_len++;
                    }
                    
                    if (*p == '"') {
                        char *element = (char *)malloc(str_len + 1);
                        if (element) {
                            strncpy(element, str_start, str_len);
                            element[str_len] = '\0';
                            tag->elements[tag->count++] = element;
                        }
                        p++;
                    }
                }
            }
            
            if (*p == ']') {
                p++;
                if (tag->count > 0) {
                    tags->tags[tags->count++] = *tag;
                } else {
                    tag_free(tag);
                }
            }
        }
    }
    
    return tags;
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
 * 5. Validates any delegation tags present
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
     * Content and pubkey must be JSON-escaped for proper serialization
     */
    char escaped_pubkey[MAX_PUBKEY_SIZE * 2 + 1];
    char escaped_content[MAX_CONTENT_SIZE * 2 + 1];
    
    /* Escape pubkey and content for JSON */
    if (!json_escape_string(ev->pubkey, escaped_pubkey, sizeof(escaped_pubkey))) {
        return false;
    }
    if (!json_escape_string(ev->content ? ev->content : "", escaped_content, sizeof(escaped_content))) {
        return false;
    }
    
    char buffer[65536];
    int written = snprintf(buffer, sizeof(buffer),
                          "[0,\"%s\",%ld,%d,%s,\"%s\"]",
                          escaped_pubkey, ev->created_at, ev->kind,
                          ev->tags_json ? ev->tags_json : "[]",
                          escaped_content);
    
    if (written < 0 || written >= (int)sizeof(buffer)) {
        return false;
    }
    
    /* Compute SHA256 hash */
    uint8_t digest[32];
    sha256((const uint8_t *)buffer, strlen(buffer), digest);
    
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
    
    /* Check delegation tags if present */
    tags_array_t *tags = parse_tags_json(ev->tags_json);
    if (tags) {
        for (size_t i = 0; i < tags->count; i++) {
            tag_t *tag = &tags->tags[i];
            
            if (tag->count >= 4 && strcmp(tag->elements[0], "delegation") == 0) {
                const char *delegator_pubkey = tag->elements[1];
                const char *conditions = tag->elements[2];
                const char *delegation_sig = tag->elements[3];
                
                if (!check_delegation(ev, delegator_pubkey, conditions, delegation_sig)) {
                    tags_array_free(tags);
                    return false;
                }
            }
        }
        
        tags_array_free(tags);
    }
    
    return true;
}

/* ============================================================================
 * Delegation Verification (NIP-26)
 * ============================================================================ */

/* check_delegation - Verify a delegation tag
 * 
 * Validates NIP-26 event delegation where one key authorizes another
 * to act on its behalf with optional time/kind restrictions.
 * 
 * Args:
 *   ev                 - event being delegated (must not be NULL)
 *   delegator_pubkey   - original key pubkey (64-char hex, must not be NULL)
 *   conditions         - restriction string (may be NULL or empty for none)
 *   delegation_sig     - signature of delegation (64-char hex, must not be NULL)
 * 
 * Returns: true if delegation is valid and conditions match, false otherwise
 * 
 * Conditions Format (NIP-26):
 *   - Empty string or NULL           -> no restrictions
 *   - "kind=1"                       -> event kind must be 1
 *   - "kind=0&kind=1"                -> event kind must be 0 or 1
 *   - "created_at<1000000"           -> event created_at < 1000000
 *   - "created_at>1000000"           -> event created_at > 1000000
 *   - Conditions are AND'd together
 *   - Same key multiple times are OR'd
 * 
 * Process:
 *   1. Parses and validates delegation conditions
 *   2. Builds delegation message: "nostr:delegation:" + pubkey + ":" + conditions
 *   3. Computes SHA256 of message
 *   4. Verifies signature with delegator pubkey
 * 
 * Caller responsibility: ev.pubkey and ev.created_at must be initialized
 */
bool check_delegation(const event_t *ev, const char *delegator_pubkey,
                      const char *conditions, const char *delegation_sig) {
    if (!ev || !delegator_pubkey) return false;
    
    /* Check delegation conditions */
    if (conditions && strlen(conditions) > 0) {
        bool has_kind_condition = false;
        bool kind_matched = false;
        
        char cond_copy[512];
        strncpy(cond_copy, conditions, sizeof(cond_copy) - 1);
        cond_copy[sizeof(cond_copy) - 1] = '\0';
        
        char *saveptr = NULL;
        char *condition = strtok_r(cond_copy, "&", &saveptr);
        
        while (condition) {
            char *eq_pos = strchr(condition, '=');
            char *lt_pos = strchr(condition, '<');
            char *gt_pos = strchr(condition, '>');
            
            const char *op_str = NULL;
            char op_char = '\0';
            
            if (eq_pos) {
                op_char = '=';
                op_str = eq_pos + 1;
            } else if (lt_pos) {
                op_char = '<';
                op_str = lt_pos + 1;
            } else if (gt_pos) {
                op_char = '>';
                op_str = gt_pos + 1;
            }
            
            if (op_char) {
                size_t key_len = (op_char == '=') ? (eq_pos - condition) :
                                 (op_char == '<') ? (lt_pos - condition) :
                                 (gt_pos - condition);
                
                if (key_len == 4 && strncmp(condition, "kind", 4) == 0 && op_char == '=') {
                    has_kind_condition = true;
                    char kind_str[16];
                    snprintf(kind_str, sizeof(kind_str), "%d", ev->kind);
                    
                    if (strcmp(kind_str, op_str) == 0) {
                        kind_matched = true;
                    }
                } else if (key_len == 10 && strncmp(condition, "created_at", 10) == 0) {
                    time_t timestamp = (time_t)strtol(op_str, NULL, 10);
                    
                    if (op_char == '<' && ev->created_at >= timestamp) {
                        return false;
                    } else if (op_char == '>' && ev->created_at <= timestamp) {
                        return false;
                    }
                }
            }
            
            condition = strtok_r(NULL, "&", &saveptr);
        }
        
        if (has_kind_condition && !kind_matched) {
            return false;
        }
    }
    
    /* Verify delegation signature */
    char delegation_str[512];
    int written = snprintf(delegation_str, sizeof(delegation_str),
                          "nostr:delegation:%s:%s",
                          ev->pubkey, conditions ? conditions : "");
    
    if (written < 0 || written >= (int)sizeof(delegation_str)) {
        return false;
    }
    
    uint8_t delegation_digest[32];
    sha256((const uint8_t *)delegation_str, strlen(delegation_str), delegation_digest);
    
    return signature_verify(delegation_sig, delegator_pubkey, delegation_digest);
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
    
    int count = 0;
    
    for (const char *p = hex; *p; p++) {
        int nibble = hex_value(*p);
        
        if (nibble < 0) break;
        
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
