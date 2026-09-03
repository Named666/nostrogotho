#ifndef CRYPTO_H_
#define CRYPTO_H_

#include "nostrogotho.h"
#include <stdint.h>
#include <stdbool.h>

/* ============================================================================
 * CRYPTO.H - Cryptographic Operations for Nostr Events
 * 
 * Provides cryptographic functions for:
 * - Event validation (SHA256 hashing and Schnorr signature verification)
 * - Delegation verification (NIP-26)
 * - Proof of work validation (NIP-13)
 * 
 * Hashing uses Windows CNG; signatures use libsecp256k1.
 * ============================================================================ */

/* ============================================================================
 * Initialization and Cleanup
 * ============================================================================ */

/* crypto_init - Initialize cryptographic context
 * 
 * Must be called exactly once at application startup before any other
 * crypto functions. Creates a secp256k1 context for signature verification.
 * 
 * Returns: true on success, false if context creation fails
 * 
 * Caller responsibility: Must call crypto_deinit() at shutdown
 * 
 * Thread safety: Not thread-safe; call during single-threaded initialization
 */
bool crypto_init(void);

/* crypto_deinit - Cleanup cryptographic context
 * 
 * Releases the secp256k1 verification context. Should be called exactly once
 * at application shutdown, after all crypto functions are complete.
 * 
 * Thread safety: Not thread-safe; call during single-threaded shutdown
 */
void crypto_deinit(void);

/* ============================================================================
 * Hashing Functions
 * ============================================================================ */

/* sha256 - Compute SHA256 hash of data
 * 
 * Computes the SHA256 cryptographic hash of input data.
 * 
 * Args:
 *   data   - bytes to hash (must not be NULL)
 *   len    - number of bytes to hash
 *   digest - output buffer for 32-byte hash (must be pre-allocated, not NULL)
 * 
 * Returns: nothing (digest is filled on success, unchanged on error)
 * 
 * Note: digest must point to at least 32 bytes of writable memory
 */
void sha256(const uint8_t *data, size_t len, uint8_t digest[32]);

/* ============================================================================
 * Hex Encoding and Decoding
 * ============================================================================ */

/* bytes_to_hex - Convert bytes to hex string representation
 * 
 * Encodes binary data as a hex string (e.g., \xAB\xCD -> "abcd").
 * Output is lowercase hex with no spacing or prefix.
 * 
 * Args:
 *   bytes - input bytes to encode (must not be NULL)
 *   len   - number of bytes
 * Returns: malloc'd hex string (2*len + 1 chars), or NULL on failure
 * 
 * Caller responsibility: Must free result with free()
 * 
 * Examples:
 *   - 1 byte  (0xAB)     -> "ab" (2 chars + null)
 *   - 32 bytes (SHA256)  -> 64 hex chars + null
 */
char *bytes_to_hex(const uint8_t *bytes, size_t len);

/* hex_to_bytes - Convert hex string to binary bytes
 * 
 * Decodes a hex string to binary (e.g., "abcd" -> \xAB\xCD).
 * Accepts both uppercase and lowercase hex digits.
 * 
 * Args:
 *   hex      - hex string (must not be NULL)
 *   hex_len  - length of hex string (must be even, not including null)
 *   bytes    - output buffer for decoded bytes (must not be NULL)
 *   max_bytes - size of bytes buffer
 *   out_len  - if not NULL, stores number of decoded bytes
 * 
 * Returns: true on success, false if:
 *   - hex_len is odd
 *   - decoded size exceeds max_bytes
 *   - hex string contains non-hex characters
 * 
 * Note: hex string need not be null-terminated (uses hex_len)
 */
bool hex_to_bytes(const char *hex, size_t hex_len, uint8_t *bytes,
                  size_t max_bytes, size_t *out_len);

/* ============================================================================
 * Signature Verification (NIP-01)
 * ============================================================================ */

/* signature_verify - Verify a Schnorr signature
 * 
 * Verifies a Schnorr signature (secp256k1 x-only) against a message hash
 * and public key. Used to validate Nostr event authenticity.
 * 
 * Args:
 *   sig_hex     - signature as 64-char hex string (128 bytes -> 64 hex chars)
 *   pubkey_hex  - public key as 64-char hex string (32 bytes -> 64 hex chars)
 *   digest      - SHA256 hash of message (32 bytes)
 * 
 * Returns: true if signature is valid, false otherwise
 * 
 * Requirements:
 *   - crypto_init() must have been called
 *   - sig_hex must be valid 64-char hex (128-bit/64-byte signature)
 *   - pubkey_hex must be valid 64-char hex (256-bit/32-byte public key)
 *   - digest must point to 32-byte hash
 * 
 * Note: Returns false on invalid input, not an error (no stderr output)
 */
bool signature_verify(const char *sig_hex, const char *pubkey_hex,
                      const uint8_t digest[32]);

/* ============================================================================
 * Event Validation (NIP-01, NIP-26)
 * ============================================================================ */

/* check_event - Validate a complete Nostr event
 * 
 * Performs full validation of a Nostr event:
 * 1. Verifies event ID is correct SHA256 hash of event data
 * 2. Verifies signature with public key
 * 3. If delegation tags present, verifies each delegation
 * 
 * Args: ev - event to validate (must not be NULL)
 * 
 * Returns: true if event is completely valid, false if any check fails
 * 
 * Requirements:
 *   - crypto_init() must have been called
 *   - event must have all fields properly initialized
 * 
 * Note: Does NOT check timestamps or proof-of-work; those are checked separately
 */
bool check_event(const event_t *ev);

/* check_delegation - Verify a delegation tag (NIP-26)
 * 
 * Validates a delegation tag that allows one key to act on behalf of another.
 * Checks both delegation conditions and signature.
 * 
 * Args:
 *   ev                  - event being delegated
 *   delegator_pubkey    - original key's pubkey (64-char hex)
 *   conditions          - conditions string (e.g., "kind=1&created_at<100")
 *   delegation_sig      - signature of delegation (64-char hex)
 * 
 * Returns: true if delegation is valid and conditions match, false otherwise
 * 
 * Conditions (NIP-26):
 *   - kind=N             event kind must equal N
 *   - kind=M&kind=N      event kind must be M or N (multiple kinds OR'd)
 *   - created_at<N       event created_at must be less than N
 *   - created_at>N       event created_at must be greater than N
 *   - Conditions are AND'd unless same key, then OR'd
 * 
 * Requirements:
 *   - crypto_init() must have been called
 *   - ev must be initialized with pubkey and created_at
 * 
 * Note: Empty conditions string is treated as "no restrictions"
 */
bool check_delegation(const event_t *ev, const char *delegator_pubkey,
                      const char *conditions, const char *delegation_sig);

/* ============================================================================
 * Proof of Work (NIP-13)
 * ============================================================================ */

/* count_leading_zero_bits - Count leading zero bits in event ID (NIP-13)
 * 
 * Calculates the proof-of-work difficulty of an event ID by counting
 * the leading zero bits in the hex-encoded SHA256 hash.
 * 
 * Algorithm:
 *   - Process hex string from left to right
 *   - Each '0' nibble contributes 4 bits
 *   - Partial zeros in non-zero nibble: 1-3 bits
 *   - Stop at first non-zero nibble
 * 
 * Args: hex - event ID as hex string (64 chars for SHA256)
 * 
 * Returns: number of leading zero bits (0-256)
 * 
 * Examples:
 *   - "0000000..." -> 4, 8, 12, ... (multiples of 4)
 *   - "0000001f..." -> 31 (31 zero bits, then bit 1 is set in 0x1f)
 *   - "1abc..."    -> 0 (no leading zeros)
 * 
 * Note: Returns 0 if hex is NULL, not an error
 */
int count_leading_zero_bits(const char *hex);

#endif /* CRYPTO_H_ */
