#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"

/* Test count_leading_zero_bits with valid hex */
static void test_count_leading_zero_bits(void) {
    /* Test: "00000001..." should give 31 leading zero bits (7 hex zeros = 28 bits + 3 bits for 0x1) */
    int result = count_leading_zero_bits("00000001");
    if (result == 31) {
        printf("PASS: count_leading_zero_bits '00000001' = 31\n");
    } else {
        printf("FAIL: count_leading_zero_bits '00000001' = %d (expected 31)\n", result);
    }
    
    /* Test: "1abc..." -> 0x1 = 0b0001: 3 leading zero bits (NIP-13 counts
     * bits, not hex digits; the old expectation of 0 was wrong and went
     * unnoticed because FAIL lines did not fail the run). */
    result = count_leading_zero_bits("1abc");
    if (result == 3) {
        printf("PASS: count_leading_zero_bits '1abc' = 3\n");
    } else {
        printf("FAIL: count_leading_zero_bits '1abc' = %d (expected 3)\n", result);
    }
    
    /* Test: NULL input */
    result = count_leading_zero_bits(NULL);
    if (result == 0) {
        printf("PASS: count_leading_zero_bits NULL = 0\n");
    } else {
        printf("FAIL: count_leading_zero_bits NULL = %d (expected 0)\n", result);
    }
    
    /* Test: invalid hex characters */
    result = count_leading_zero_bits("xyz");
    if (result == 0) {
        printf("PASS: count_leading_zero_bits 'xyz' = 0 (invalid hex)\n");
    } else {
        printf("FAIL: count_leading_zero_bits 'xyz' = %d (expected 0 for invalid hex)\n", result);
    }
}

/* Test signature_verify with valid inputs (requires initialized context) */
static void test_signature_verify(void) {
    /* This requires crypto_init() to be called first */
    printf("INFO: test_signature_verify - requires crypto_init first\n");
}

/* Relay key: BIP-340 test vector 1 (secret 3), sign -> verifies. */
static void test_relay_sign(void) {
    if (!crypto_init()) { printf("FAIL: crypto_init\n"); return; }
    int ok = !crypto_relay_key_load("zz") && !crypto_relay_pubkey() &&
             crypto_relay_key_load("0000000000000000000000000000000000000000000000000000000000000003") &&
             strcmp(crypto_relay_pubkey(), "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9") == 0;
    printf("%s: relay key load + pubkey\n", ok ? "PASS" : "FAIL");
    event_t ev; memset(&ev, 0, sizeof ev);
    ev.kind = 39000; ev.created_at = 1700000000;
    ev.tags_json = (char *) "[[\"d\",\"g1\"],[\"name\",\"caf\u00e9\"]]"; ev.tags_json_len = strlen(ev.tags_json);
    ev.content = (char *) "line\n\"q\""; ev.content_len = strlen(ev.content);
    ok = crypto_sign_event(&ev) && check_event_status(&ev) == CHECK_EVENT_OK &&
         strcmp(ev.pubkey, crypto_relay_pubkey()) == 0;
    printf("%s: crypto_sign_event -> check_event OK\n", ok ? "PASS" : "FAIL");
    ev.content = (char *) "tampered"; ev.content_len = 8;
    printf("%s: tampered -> BAD_ID\n", check_event_status(&ev) == CHECK_EVENT_BAD_ID ? "PASS" : "FAIL");
    crypto_relay_key_forget();
    printf("%s: forget\n", !crypto_relay_pubkey() && !crypto_sign_event(&ev) ? "PASS" : "FAIL");
    crypto_deinit();
}

int main(void) {
    printf("Running crypto tests...\n");
    test_count_leading_zero_bits();
    test_signature_verify();
    test_relay_sign();
    printf("Crypto tests complete.\n");
    return 0;
}