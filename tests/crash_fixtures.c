/* Crash fixtures for manually checking the handler.
 * Run with: ./build/test_crash_fixtures <fixture_name>
 * Fixtures: null_deref, stack_overflow, abort_call, div_by_zero,
 *           heap_corruption, module_crash
 *
 * Each fixture crashes; the handler prints a stacktrace to stderr
 * with function + file:line. No files are written.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crash.h"

/* Null pointer dereference */
static void null_deref_inner(int *ptr) {
    *ptr = 42;
}

static void null_deref_middle(void) {
    int *ptr = NULL;
    null_deref_inner(ptr);
}

static void null_deref_outer(void) {
    null_deref_middle();
}

/* Stack overflow via infinite recursion */
static void stack_overflow_recurse(int depth) {
    char buf[1024];
    (void)buf[depth % 1024];
    stack_overflow_recurse(depth + 1);
}

/* abort() call */
static void abort_inner(void) {
    abort();
}

static void abort_middle(void) {
    abort_inner();
}

static void abort_outer(void) {
    abort_middle();
}

/* Division by zero */
static void div_zero_inner(int divisor) {
    volatile int result = 42 / divisor;
    (void)result;
}

static void div_zero_middle(void) {
    div_zero_inner(0);
}

static void div_zero_outer(void) {
    div_zero_middle();
}

/* Heap double free (glibc aborts; Windows may fastfail, falls back to abort). */
static void heap_corrupt_inner(void) {
    char *ptr = malloc(32);
    if (!ptr) abort();
    free(ptr);
#ifdef _WIN32
    abort();
#else
    free(ptr);
    abort();
#endif
}

static void heap_corrupt_middle(void) {
    heap_corrupt_inner();
}

static void heap_corrupt_outer(void) {
    heap_corrupt_middle();
}

/* Fixed-address crash */
static void module_crash_inner(void) {
    int *p = (int *)0x18;
    *p = 0;
}

static void module_crash_middle(void) {
    module_crash_inner();
}

static void module_crash_outer(void) {
    module_crash_middle();
}

/* Dispatch based on argv[1] */
int main(int argc, char **argv) {
    crash_install_handlers();

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <fixture>\n"
                "Fixtures: null_deref, stack_overflow, abort_call, "
                "div_by_zero, heap_corruption, module_crash\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "null_deref") == 0) {
        null_deref_outer();
    } else if (strcmp(argv[1], "stack_overflow") == 0) {
        stack_overflow_recurse(0);
    } else if (strcmp(argv[1], "abort_call") == 0) {
        abort_outer();
    } else if (strcmp(argv[1], "div_by_zero") == 0) {
        div_zero_outer();
    } else if (strcmp(argv[1], "heap_corruption") == 0) {
        heap_corrupt_outer();
    } else if (strcmp(argv[1], "module_crash") == 0) {
        module_crash_outer();
    } else {
        fprintf(stderr, "Unknown fixture: %s\n", argv[1]);
        return 1;
    }
    return 0;
}
