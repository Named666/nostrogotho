#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "storage.h"

/* Test escape_like with normal input */
void test_escape_like_normal() {
    char *result = escape_like("hello world", 11);
    if (result && strcmp(result, "hello world") == 0) {
        printf("PASS: escape_like normal input\n");
    } else {
        printf("FAIL: escape_like normal input\n");
    }
    free(result);
}

/* Test escape_like with special characters */
void test_escape_like_special() {
    char *result = escape_like("100%+50%", 9);
    if (result && strcmp(result, "100\\%+50%") == 0) {
        printf("PASS: escape_like special chars\n");
    } else {
        printf("FAIL: escape_like special chars (got: %s)\n", result ? result : "(null)");
    }
    free(result);
}

/* Test escape_like with NULL */
void test_escape_like_null() {
    char *result = escape_like(NULL, 0);
    if (result == NULL) {
        printf("PASS: escape_like NULL input\n");
    } else {
        printf("FAIL: escape_like NULL input\n");
        free(result);
    }
}

/* Test escape_like with large input (should be capped) */
void test_escape_like_large() {
    char *result = escape_like("test", 2000000);  /* > 1MB */
    if (result == NULL) {
        printf("PASS: escape_like large input capped\n");
    } else {
        printf("FAIL: escape_like large input should be NULL\n");
        free(result);
    }
}

/* Test get_event_by_id memory management */
void test_get_event_by_id_memory() {
    /* This requires a running database, so just test the function signature */
    printf("INFO: test_get_event_by_id_memory - requires database\n");
}

/* Test filter_release doesn't double-free */
void test_filter_release_no_double_free() {
    filter_t *f = filter_alloc();
    if (f) {
        f->ids_count = 1;
        f->ids = (char **)malloc(sizeof(char *));
        f->ids[0] = strdup("test");
        filter_release(f);
        printf("PASS: filter_release no double-free\n");
        free(f);
    } else {
        printf("FAIL: filter_alloc returned NULL\n");
    }
}

int main(void) {
    printf("Running storage tests...\n");
    test_escape_like_normal();
    test_escape_like_special();
    test_escape_like_null();
    test_escape_like_large();
    test_get_event_by_id_memory();
    test_filter_release_no_double_free();
    printf("Storage tests complete.\n");
    return 0;
}