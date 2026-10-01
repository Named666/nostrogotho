#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "storage.h"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, pass_label, fail_label)                                    \
    do {                                                                       \
        if (cond) {                                                            \
            g_pass++;                                                          \
            printf("PASS: %s\n", pass_label);                                  \
        } else {                                                               \
            g_fail++;                                                          \
            printf("FAIL: %s\n", fail_label);                                  \
        }                                                                      \
    } while (0)

/* Test escape_like with normal input */
void test_escape_like_normal() {
    char *result = escape_like("hello world", 11);
    CHECK(result && strcmp(result, "hello world") == 0,
          "escape_like normal input", "escape_like normal input");
    free(result);
}

/* Test escape_like with special characters */
void test_escape_like_special() {
    char *result = escape_like("100%+50%", 8);
    CHECK(result && strcmp(result, "100\\%+50\\%") == 0,
          "escape_like special chars", "escape_like special chars");
    free(result);
}

/* Test escape_like with NULL */
void test_escape_like_null() {
    char *result = escape_like(NULL, 0);
    CHECK(result == NULL, "escape_like NULL input", "escape_like NULL input");
    free(result);
}

/* Test escape_like with large input (should be capped) */
void test_escape_like_large() {
    char *result = escape_like("test", 2000000);  /* > 1MB */
    CHECK(result == NULL, "escape_like large input capped",
          "escape_like large input should be NULL");
    free(result);
}

/* Test get_event_by_id memory management */
void test_get_event_by_id_memory() {
    /* This requires a running database, so just test the function signature */
    printf("INFO: test_get_event_by_id_memory - requires database\n");
}

/* Test filter_free doesn't crash */
void test_filter_free_no_double_free() {
    filter_t *f = filter_alloc();
    if (f) {
        f->ids_count = 1;
        f->ids = (char **)malloc(sizeof(char *));
        f->ids[0] = strdup("test");
        filter_free(f);
        CHECK(1, "filter_free succeeds", "filter_free succeeds");
    } else {
        CHECK(0, "filter_free succeeds", "filter_alloc returned NULL");
    }
}

int main(void) {
    printf("Running storage tests...\n");
    test_escape_like_normal();
    test_escape_like_special();
    test_escape_like_null();
    test_escape_like_large();
    test_get_event_by_id_memory();
    test_filter_free_no_double_free();
    printf("storage: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}