#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"

/* Test count_leading_zero_bits with valid hex */
void test_count_leading_zero_bits() {
    /* Test: "00000001..." should give 31 leading zero bits (7 hex zeros = 28 bits + 3 bits for 0x1) */
    int result = count_leading_zero_bits("00000001");
    if (result == 31) {
        printf("PASS: count_leading_zero_bits '00000001' = 31\n");
    } else {
        printf("FAIL: count_leading_zero_bits '00000001' = %d (expected 31)\n", result);
    }
    
    /* Test: "1abc..." should give 0 leading zero bits */
    result = count_leading_zero_bits("1abc");
    if (result == 0) {
        printf("PASS: count_leading_zero_bits '1abc' = 0\n");
    } else {
        printf("FAIL: count_leading_zero_bits '1abc' = %d (expected 0)\n", result);
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
void test_signature_verify() {
    /* This requires crypto_init() to be called first */
    printf("INFO: test_signature_verify - requires crypto_init first\n");
}

int main(void) {
    printf("Running crypto tests...\n");
    test_count_leading_zero_bits();
    test_signature_verify();
    printf("Crypto tests complete.\n");
    return 0;
}