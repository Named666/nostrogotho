/* ============================================================================
 * Unit tests for src/crypto.c: hex conversion, SHA-256, event ID
 * computation (against OS-independent vectors), Schnorr verification,
 * full event validation (incl. NIP-26 delegation), and NIP-13 difficulty.
 *
 * Signing is done in-test through libsecp256k1 directly (fixed keys, fixed
 * aux randomness => deterministic), while verification goes through
 * crypto.c -- so sign/verify form a differential pair, not a tautology.
 * Event-ID vectors were hashed independently with the OS provider.
 *
 * Build (from repo root, mirroring nob's module flags):
 *   gcc -std=c99 -DSECP256K1_STATIC -DENABLE_MODULE_ECDH=1 ... (see nob -test)
 * Run: build/test_crypto(.exe) -- exit code is the failure count (0 = green).
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "crypto.h"

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (cond) {                                                            \
            g_pass++;                                                          \
            printf("PASS: %s\n", label);                                       \
        } else {                                                               \
            g_fail++;                                                          \
            printf("FAIL: %s\n", label);                                       \
        }                                                                      \
    } while (0)

/* G (seckey = 1) x-only pubkey, the standard Nostr test key. */
#define G_XONLY \
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

/* Canonical NIP-01 serializations (exact bytes hashed for the vectors). */
#define EV1_CANON \
    "[0,\"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"" \
    ",1700000000,1,[],\"hello\"]"
#define EV1_ID "bde202ea7642ff9910600c7edc948a1f4220f0cbf5e4fb2b7efafa681bbb5285"

#define EV2_CANON \
    "[0,\"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"" \
    ",1700000000,1," \
    "[[\"p\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]," \
    "[\"e\",\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"," \
    "\"wss://relay.example\"]]," \
    "\"hi \\\"q\\\"\\nend\"]"
#define EV2_ID "5d1aceab594325e66d2e2960c66ce8acbd3eaa76d709a25892b177a1badcf147"
/* Provenance: EV2_CANON bytes were hashed with the OS provider
 * (Get-FileHash, Windows CNG) and agree with event_compute_id --
 * an independent SHA-256 cross-check, not a self-derived vector. */

static secp256k1_context *sign_ctx = NULL;

/* Derive the x-only pubkey for a 32-byte big-endian secret key. */
static int test_xonly(const uint8_t seckey[32], uint8_t xonly[32]) {
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xp;
    int parity = 0;
    if (!secp256k1_keypair_create(sign_ctx, &kp, seckey)) return 0;
    if (!secp256k1_keypair_xonly_pub(sign_ctx, &xp, &parity, &kp)) return 0;
    if (!secp256k1_xonly_pubkey_serialize(sign_ctx, xonly, &xp)) return 0;
    return 1;
}

/* Deterministic BIP-340 sign (aux_rand = zeros). */
static int test_sign(const uint8_t seckey[32], const uint8_t msg32[32],
                     uint8_t sig64[64]) {
    static const uint8_t aux[32] = {0};
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(sign_ctx, &kp, seckey)) return 0;
    if (!secp256k1_schnorrsig_sign32(sign_ctx, sig64, msg32, &kp, aux)) return 0;
    return 1;
}

static void fill_event(event_t *ev, const char *pubkey, time_t created_at,
                       int kind, const char *tags_json, const char *content) {
    memset(ev, 0, sizeof(*ev));
    snprintf(ev->id, sizeof(ev->id),
             "0000000000000000000000000000000000000000000000000000000000000000");
    snprintf(ev->pubkey, sizeof(ev->pubkey), "%s", pubkey);
    ev->created_at = created_at;
    ev->kind = kind;
    ev->tags_json = tags_json ? strdup(tags_json) : NULL;
    ev->tags_json_len = tags_json ? strlen(tags_json) : 0;
    ev->content = content ? strdup(content) : NULL;
    ev->content_len = content ? strlen(content) : 0;
    memset(ev->sig, '0', MAX_SIG_SIZE);
    ev->sig[MAX_SIG_SIZE] = '\0';
}

/* Stamp a computed id + hex signature onto the event. */
static void stamp_id_sig(event_t *ev, const char *id_hex, const char *sig_hex) {
    snprintf(ev->id, sizeof(ev->id), "%s", id_hex);
    snprintf(ev->sig, sizeof(ev->sig), "%s", sig_hex);
}

/* --- SHA-256 known-answer tests (NIST vectors; independent of crypto.c) --- */
static void test_sha256_kat(void) {
    static const struct {
        const char *input;
        const char *expected_hex;
    } vectors[] = {
        { "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
    };
    for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        uint8_t digest[32];
        char *hex;
        /* Avoid passing a NULL data pointer for the empty input. */
        uint8_t one = 0;
        sha256(vectors[i].input[0] ? (const uint8_t *)vectors[i].input : &one,
               strlen(vectors[i].input), digest);
        hex = bytes_to_hex(digest, 32);
        CHECK(hex && strcmp(hex, vectors[i].expected_hex) == 0,
              "sha256 KAT matches NIST vector");
        free(hex);
    }
}

/* --- Hex conversion --- */
static void test_hex(void) {
    const uint8_t bytes[] = {0x00, 0xff, 0xab, 0x01, 0x10};
    char *hex = bytes_to_hex(bytes, sizeof(bytes));
    CHECK(hex && strcmp(hex, "00ffab0110") == 0, "bytes_to_hex known value");
    free(hex);

    CHECK(bytes_to_hex(NULL, 4) == NULL, "bytes_to_hex NULL input");
    CHECK(bytes_to_hex(bytes, 0) == NULL, "bytes_to_hex zero length");

    {
        uint8_t out[8];
        size_t out_len = 0;
        CHECK(hex_to_bytes("00ffab0110", 10, out, sizeof(out), &out_len) &&
              out_len == 5 && memcmp(out, bytes, 5) == 0,
              "hex_to_bytes lowercase round trip");
    }
    {
        uint8_t out[8];
        CHECK(hex_to_bytes("AB12", 4, out, sizeof(out), NULL) &&
              out[0] == 0xab && out[1] == 0x12,
              "hex_to_bytes accepts uppercase");
    }
    {
        uint8_t out[8];
        CHECK(!hex_to_bytes("abc", 3, out, sizeof(out), NULL),
              "hex_to_bytes rejects odd length");
        CHECK(!hex_to_bytes("zz", 2, out, sizeof(out), NULL),
              "hex_to_bytes rejects non-hex");
        CHECK(!hex_to_bytes("0011", 4, out, 1, NULL),
              "hex_to_bytes rejects buffer overflow");
        CHECK(!hex_to_bytes(NULL, 4, out, sizeof(out), NULL),
              "hex_to_bytes rejects NULL hex");
        CHECK(!hex_to_bytes("0011", 4, NULL, 8, NULL),
              "hex_to_bytes rejects NULL output");
        CHECK(!hex_to_bytes("0011", 0, out, sizeof(out), NULL),
              "hex_to_bytes rejects zero length");
    }
    {
        /* Exact-fit boundary: byte_count == max_bytes must succeed. */
        uint8_t out[2];
        size_t out_len = 0;
        CHECK(hex_to_bytes("abcd", 4, out, 2, &out_len) && out_len == 2,
              "hex_to_bytes exact-fit boundary");
    }
    {
        /* Exhaustive single-byte + deterministic multi-byte round trips. */
        uint32_t rng = 0x12345678u;
        int ok = 1;
        for (int b = 0; b < 256 && ok; b++) {
            uint8_t one = (uint8_t)b, back = 0;
            char *h = bytes_to_hex(&one, 1);
            size_t n = 0;
            if (!h || !hex_to_bytes(h, 2, &back, 1, &n) || n != 1 || back != one)
                ok = 0;
            free(h);
            /* Uppercase decodes to the same byte. */
            if (ok) {
                char up[3];
                snprintf(up, sizeof(up), "%02X", b);
                uint8_t ub = 0;
                if (!hex_to_bytes(up, 2, &ub, 1, NULL) || ub != one) ok = 0;
            }
        }
        for (int iter = 0; iter < 64 && ok; iter++) {
            uint8_t buf[64], back[64];
            size_t len = (size_t)(iter % 64) + 1;
            for (size_t i = 0; i < len; i++) {
                rng = rng * 1664525u + 1013904223u;
                buf[i] = (uint8_t)(rng >> 24);
            }
            char *h = bytes_to_hex(buf, len);
            size_t n = 0;
            if (!h || !hex_to_bytes(h, len * 2, back, sizeof(back), &n) ||
                n != len || memcmp(back, buf, len) != 0)
                ok = 0;
            free(h);
        }
        CHECK(ok, "hex round trip exhaustive + deterministic");
    }
}

/* --- Event ID computation --- */
static void test_event_id(void) {
    event_t ev;
    char buf[1024];

    fill_event(&ev, G_XONLY, 1700000000, 1, "[]", "hello");
    CHECK(event_build_hash_input(&ev, buf, sizeof(buf)) == strlen(EV1_CANON) &&
          strcmp(buf, EV1_CANON) == 0,
          "hash input matches canonical serialization (ev1)");
    {
        char *id = event_compute_id(&ev);
        CHECK(id && strcmp(id, EV1_ID) == 0, "event id matches OS vector (ev1)");
        free(id);
    }
    CHECK(check_event_id(&ev) == false, "placeholder id does not validate");
    event_release(&ev);

    /* Tags + escaping vector, plus whitespace-tolerant canonicalization. */
    fill_event(&ev, G_XONLY, 1700000000, 1,
               "[[\"p\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"],"
               "[\"e\",\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
               "\"wss://relay.example\"]]",
               "hi \"q\"\nend");
    {
        char *id = event_compute_id(&ev);
        size_t n = event_build_hash_input(&ev, buf, sizeof(buf));
        CHECK(n == strlen(EV2_CANON) &&
              strcmp(buf, EV2_CANON) == 0,
          "hash input canonicalizes tags + escapes (ev2)");
        free(id);
    }
    {
        char *id = event_compute_id(&ev);
        CHECK(id && strcmp(id, EV2_ID) == 0, "event id matches OS vector (ev2)");
        free(id);
    }
    event_release(&ev);

    /* Same event with insignificant whitespace must hash identically. */
    fill_event(&ev, G_XONLY, 1700000000, 1,
               "[ [ \"p\" , \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" ] , "
               "[ \"e\" , \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\" , "
               "\"wss://relay.example\" ] ]",
               "hi \"q\"\nend");
    {
        char *id = event_compute_id(&ev);
        CHECK(id && strcmp(id, EV2_ID) == 0, "whitespace-tolerant tag canonicalization");
        free(id);
    }
    event_release(&ev);

    /* NULL tags/content degrade to [] and "". */
    fill_event(&ev, G_XONLY, 1700000000, 1, NULL, NULL);
    free(ev.tags_json);
    free(ev.content);
    ev.tags_json = NULL;
    ev.content = NULL;
    {
        char *id = event_compute_id(&ev);
        size_t n = event_build_hash_input(&ev, buf, sizeof(buf));
        CHECK(n > 0 && strstr(buf, ",[],\"\"]") != NULL,
              "NULL tags/content serialize as []/\"\"");
        free(id);
    }
    event_release(&ev);

    CHECK(event_compute_id(NULL) == NULL, "event_compute_id NULL");
    CHECK(event_build_hash_input(NULL, buf, sizeof(buf)) == 0,
          "event_build_hash_input NULL event");
    CHECK(event_hash_input_size(NULL) == 0, "event_hash_input_size NULL");

    /* Undersized buffer must fail closed, never truncate. The size
     * function intentionally overestimates, so the real invariant is
     * need >= actual+1, and exact-fit-1 must fail. */
    {
        event_t ev2;
        size_t need, actual;
        fill_event(&ev2, G_XONLY, 1700000000, 1, "[]", "hello");
        need = event_hash_input_size(&ev2);
        actual = strlen(EV1_CANON);
        CHECK(need >= actual + 1, "hash input size bounds actual length");
        CHECK(event_build_hash_input(&ev2, buf, actual) == 0,
              "exact-fit-minus-one fails closed");
        CHECK(event_build_hash_input(&ev2, buf, actual + 1) == actual &&
              strcmp(buf, EV1_CANON) == 0,
              "exact-fit succeeds byte-identical");
        event_release(&ev2);
    }
}

/* --- Signatures: differential sign (libsecp) vs verify (crypto.c) --- */
static uint8_t G_SECKEY[32] = {0};
static void test_signatures(void) {
    uint8_t xonly[32], digest[32], sig[64];
    char *sig_hex, *xonly_hex;
    event_t ev;

    G_SECKEY[31] = 0x01;
    CHECK(test_xonly(G_SECKEY, xonly), "test keypair derives");
    xonly_hex = bytes_to_hex(xonly, 32);
    CHECK(xonly_hex && strcmp(xonly_hex, G_XONLY) == 0,
          "seckey 1 derives the G test pubkey (setup sanity)");
    free(xonly_hex);

    /* Sign the ev1 digest. */
    fill_event(&ev, G_XONLY, 1700000000, 1, "[]", "hello");
    {
        char *id = event_compute_id(&ev);
        size_t n = 0;
        CHECK(id && strcmp(id, EV1_ID) == 0, "fixture id is ev1 vector");
        CHECK(hex_to_bytes(id, 64, digest, sizeof(digest), &n) && n == 32,
              "fixture digest decodes");
        free(id);
    }
    CHECK(test_sign(G_SECKEY, digest, sig), "in-test Schnorr sign");
    sig_hex = bytes_to_hex(sig, 64);

    /* Pre-init: verification must fail closed without a context. */
    CHECK(signature_verify(sig_hex, G_XONLY, digest) == false,
          "signature_verify fails closed before crypto_init");

    CHECK(crypto_init(), "crypto_init succeeds");
    CHECK(signature_verify(sig_hex, G_XONLY, digest), "valid signature verifies");

    /* Tamper matrix. */
    {
        char bad_sig[129], bad_pk[65];
        uint8_t bad_digest[32];
        snprintf(bad_sig, sizeof(bad_sig), "%s", sig_hex);
        bad_sig[0] = (bad_sig[0] == '0') ? '1' : '0';
        CHECK(!signature_verify(bad_sig, G_XONLY, digest), "flipped sig bit rejects");
        snprintf(bad_pk, sizeof(bad_pk), "%s", G_XONLY);
        bad_pk[63] = (bad_pk[63] == '0') ? '1' : '0';
        CHECK(!signature_verify(sig_hex, bad_pk, digest), "wrong pubkey rejects");
        memcpy(bad_digest, digest, 32);
        bad_digest[0] ^= 0x01;
        CHECK(!signature_verify(sig_hex, G_XONLY, bad_digest), "wrong digest rejects");
        {
            char short_sig[127];
            memcpy(short_sig, sig_hex, 126);
            short_sig[126] = '\0';
            CHECK(!signature_verify(short_sig, G_XONLY, digest), "short sig rejects");
        }
        {
            char nonhex[129];
            snprintf(nonhex, sizeof(nonhex), "%s", sig_hex);
            nonhex[10] = 'z';
            CHECK(!signature_verify(nonhex, G_XONLY, digest), "non-hex sig rejects");
        }
        CHECK(!signature_verify(NULL, G_XONLY, digest), "NULL sig rejects");
        CHECK(!signature_verify(sig_hex, NULL, digest), "NULL pubkey rejects");
        CHECK(!signature_verify(sig_hex, G_XONLY, NULL), "NULL digest rejects");
    }

    /* Full event validation on a properly stamped event. */
    stamp_id_sig(&ev, EV1_ID, sig_hex);
    CHECK(check_event_id(&ev), "check_event_id accepts stamped event");
    CHECK(check_signature(&ev), "check_signature accepts stamped event");
    CHECK(check_event_core(&ev), "check_event_core accepts stamped event");
    CHECK(check_event(&ev), "check_event accepts tagless event");

    /* Tampered content under a stale id/sig must fail everywhere. */
    free(ev.content);
    ev.content = strdup("tampered");
    ev.content_len = strlen(ev.content);
    CHECK(!check_event_id(&ev), "tampered content fails id check");
    CHECK(!check_event_core(&ev), "tampered content fails core check");
    CHECK(!check_event(&ev), "tampered content fails full check");
    CHECK(!check_signature(&ev), "stale sig fails signature check");

    free(sig_hex);
    event_release(&ev);

    CHECK(!check_event(NULL), "check_event NULL");
    CHECK(!check_event_id(NULL), "check_event_id NULL");
    CHECK(!check_signature(NULL), "check_signature NULL");
    CHECK(!check_event_core(NULL), "check_event_core NULL");
}

/* --- NIP-26 delegation through the full check_event path --- */
static void test_delegation(void) {
    /* Delegator key 2; delegatee is G (key 1). */
    static uint8_t delegator_sk[32] = {0};
    uint8_t delegator_xonly[32], digest[32], dsig[64];
    char *delegator_hex, *dsig_hex;
    char delegation_msg[512];
    char tags[1024];
    event_t ev;

    delegator_sk[31] = 0x02;
    CHECK(test_xonly(delegator_sk, delegator_xonly), "delegator keypair derives");
    delegator_hex = bytes_to_hex(delegator_xonly, 32);

    snprintf(delegation_msg, sizeof(delegation_msg), "nostr:delegation:%s:%s",
             G_XONLY, "kind=1");
    sha256((const uint8_t *)delegation_msg, strlen(delegation_msg), digest);
    CHECK(test_sign(delegator_sk, digest, dsig), "delegation signature mints");
    dsig_hex = bytes_to_hex(dsig, 64);

    /* Event carries the delegation tag as part of its signed content. */
    snprintf(tags, sizeof(tags),
             "[[\"delegation\",\"%s\",\"kind=1\",\"%s\"]]", delegator_hex, dsig_hex);
    fill_event(&ev, G_XONLY, 1700000000, 1, tags, "delegated note");
    {
        char *id = event_compute_id(&ev);
        size_t n = 0;
        uint8_t edigest[32], esig[64];
        char *esig_hex = NULL;
        CHECK(id != NULL, "delegated event id computes");
        CHECK(hex_to_bytes(id, 64, edigest, sizeof(edigest), &n) && n == 32,
              "delegated digest decodes");
        CHECK(test_sign(G_SECKEY, edigest, esig), "delegatee signs event");
        esig_hex = bytes_to_hex(esig, 64);
        stamp_id_sig(&ev, id, esig_hex);
        free(id);
        free(esig_hex);
    }
    CHECK(check_event(&ev), "valid delegation passes full check");

    /* Wrong-kind event under a kind=1 delegation must fail (core still fine). */
    {
        event_t ev2;
        char *id;
        size_t n = 0;
        uint8_t edigest[32], esig[64];
        char *esig_hex;
        fill_event(&ev2, G_XONLY, 1700000000, 2, tags, "delegated note");
        id = event_compute_id(&ev2);
        hex_to_bytes(id, 64, edigest, sizeof(edigest), &n);
        test_sign(G_SECKEY, edigest, esig);
        esig_hex = bytes_to_hex(esig, 64);
        stamp_id_sig(&ev2, id, esig_hex);
        CHECK(check_event_core(&ev2), "kind-2 event is core-valid");
        CHECK(!check_event(&ev2), "kind mismatch fails delegation conditions");
        free(id);
        free(esig_hex);
        event_release(&ev2);
    }

    /* Corrupt delegation signature must fail the full check. */
    {
        char *bad = strdup(dsig_hex);
        bad[5] = (bad[5] == 'a') ? 'b' : 'a';
        free(ev.tags_json);
        ev.tags_json = NULL;
        {
            char bad_tags[1024];
            snprintf(bad_tags, sizeof(bad_tags),
                     "[[\"delegation\",\"%s\",\"kind=1\",\"%s\"]]", delegator_hex, bad);
            ev.tags_json = strdup(bad_tags);
            ev.tags_json_len = strlen(bad_tags);
        }
        /* Re-stamp id/sig so only the delegation is at fault. */
        {
            char *id = event_compute_id(&ev);
            size_t n = 0;
            uint8_t edigest[32], esig[64];
            char *esig_hex;
            hex_to_bytes(id, 64, edigest, sizeof(edigest), &n);
            test_sign(G_SECKEY, edigest, esig);
            esig_hex = bytes_to_hex(esig, 64);
            stamp_id_sig(&ev, id, esig_hex);
            free(id);
            free(esig_hex);
        }
        CHECK(check_event_core(&ev), "re-stamped event is core-valid");
        CHECK(!check_event(&ev), "corrupt delegation signature fails full check");
        free(bad);
    }

    free(delegator_hex);
    free(dsig_hex);
    event_release(&ev);
}

/* --- NIP-13 difficulty (kept from the original suite, now counted) --- */
static void test_leading_zero_bits(void) {
    CHECK(count_leading_zero_bits("00000001") == 31, "clzb '00000001' = 31");
    CHECK(count_leading_zero_bits("1abc") == 3, "clzb '1abc' = 3");
    CHECK(count_leading_zero_bits(NULL) == 0, "clzb NULL = 0");
    CHECK(count_leading_zero_bits("xyz") == 0, "clzb invalid hex = 0");
    CHECK(count_leading_zero_bits("00") == 8, "clzb '00' = 8");
    CHECK(count_leading_zero_bits("0f") == 4, "clzb '0f' = 4");
    CHECK(count_leading_zero_bits("8f") == 0, "clzb '8f' = 0");
    CHECK(count_leading_zero_bits("7f") == 1, "clzb '7f' = 1");
    CHECK(count_leading_zero_bits(
              "0000000000000000000000000000000000000000000000000000000000000000") == 256,
          "clzb all-zero = 256");
    CHECK(count_leading_zero_bits("") == 0, "clzb empty = 0");
}

/* --- json_escape spot checks (NIP-01 table) --- */
static void test_json_escape(void) {
    char dst[64];
    CHECK(json_escape("a\"b\\c", dst, sizeof(dst)) > 0 &&
          strcmp(dst, "a\\\"b\\\\c") == 0,
          "json_escape quotes and backslash");
    CHECK(json_escape("x\ny\tz", dst, sizeof(dst)) > 0 &&
          strcmp(dst, "x\\ny\\tz") == 0,
          "json_escape short escapes, slash stays bare");
    CHECK(json_escape("a/b", dst, sizeof(dst)) > 0 && strcmp(dst, "a/b") == 0,
          "json_escape leaves '/' alone");
    CHECK(json_escape("\x01", dst, sizeof(dst)) > 0 && strcmp(dst, "\\u0001") == 0,
          "json_escape control as \\uXXXX");
    CHECK(json_escape("toolong", dst, 4) == 0, "json_escape fails closed");
    CHECK(json_escape(NULL, dst, sizeof(dst)) == 0, "json_escape NULL src");
}

int main(void) {
    printf("Running crypto unit tests...\n");

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                        SECP256K1_CONTEXT_VERIFY);
    if (!sign_ctx) {
        printf("FAIL: cannot create secp256k1 signing context\n");
        return 1;
    }

    test_sha256_kat();
    test_hex();
    test_event_id();
    test_signatures();   /* calls crypto_init() internally */
    test_delegation();
    test_leading_zero_bits();
    test_json_escape();

    secp256k1_context_destroy(sign_ctx);
    crypto_deinit();

    printf("crypto: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
