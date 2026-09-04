#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "json_util.h"

/* Test parse_string_array with valid input */
void test_parse_string_array_valid() {
    const char *json = "{\"ids\": [\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"]}";
    filter_t *filter = NULL;
    size_t count = 0;
    
    bool result = json_parse_filter(json, &filter);
    if (result && filter != NULL) {
        printf("PASS: json_parse_filter valid ids\n");
        if (filter->ids_count > 0) {
            printf("  ids[0] = %s\n", filter->ids[0]);
        }
        filter_free(filter);
    } else {
        printf("FAIL: json_parse_filter valid ids\n");
    }
}

/* Test parse_string_array with hex 64 validation */
void test_parse_string_array_hex64() {
    const char *json = "{\"ids\": [\"short\"]}";  /* Only 5 chars, should fail */
    filter_t *filter = NULL;
    size_t count = 0;
    
    bool result = json_parse_filter(json, &filter);
    if (!result) {
        printf("PASS: json_parse_filter rejects short hex\n");
    } else {
        printf("FAIL: json_parse_filter should reject short hex\n");
        filter_free(filter);
    }
}

/* Test parse_string_array with empty JSON */
void test_parse_string_array_empty() {
    const char *json = "{}";
    filter_t *filter = NULL;
    size_t count = 0;
    
    bool result = json_parse_filter(json, &filter);
    if (!result) {
        printf("PASS: json_parse_filter rejects empty filter\n");
    } else {
        printf("FAIL: json_parse_filter should reject empty filter\n");
        filter_free(filter);
    }
}

/* Test json_builder_object_key_number format */
void test_json_builder_format() {
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_object_key_number(&builder, "test", 42);
    const char *result = json_builder_finish(&builder);
    
    if (result && strstr(result, "\"test\":42") != NULL) {
        printf("PASS: json_builder_object_key_number format\n");
    } else {
        printf("FAIL: json_builder_object_key_number format (got: %s)\n", result ? result : "(null)");
    }
}

int main(void) {
    printf("Running json_util tests...\n");
    test_parse_string_array_valid();
    test_parse_string_array_hex64();
    test_parse_string_array_empty();
    test_json_builder_format();
    printf("json_util tests complete.\n");
    return 0;
}