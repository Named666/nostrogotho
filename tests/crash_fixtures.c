/* Crash fixtures for validating crash handler accuracy.
 * Run with: ./build/test_crash_fixtures <fixture_name>
 * Fixtures: null_deref, stack_overflow, abort_call, div_by_zero,
 *           heap_corruption, module_crash
 *
 * Each fixture has EXPECT_LINE markers that the test harness verifies.
 * Format: /* EXPECT_LINE: <function> <file>:<line> */
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>

/* Null pointer dereference */
static void null_deref_inner(int *ptr) {
    /* EXPECT_LINE: null_deref_inner crash_fixtures.c:16 */
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
    /* EXPECT_LINE: stack_overflow_recurse crash_fixtures.c:32 */
    stack_overflow_recurse(depth + 1);
}

/* abort() call */
static void abort_inner(void) {
    /* EXPECT_LINE: abort_inner crash_fixtures.c:38 */
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
    /* EXPECT_LINE: div_zero_inner crash_fixtures.c:49 */
    volatile int result = 42 / divisor;
    (void)result;
}

static void div_zero_middle(void) {
    div_zero_inner(0);
}

static void div_zero_outer(void) {
    div_zero_middle();
}

/* Heap corruption (double free) */
static void heap_corrupt_inner(void) {
    char *ptr = malloc(32);
    free(ptr);
    /* EXPECT_LINE: heap_corrupt_inner crash_fixtures.c:60 */
    free(ptr);
}

static void heap_corrupt_middle(void) {
    heap_corrupt_inner();
}

static void heap_corrupt_outer(void) {
    heap_corrupt_middle();
}

/* Module crash - simulates crash in hot-reload module */
static void module_crash_inner(void) {
    /* EXPECT_LINE: module_crash_inner crash_fixtures.c:70 */
    int *p = (int *)0x18;
    *p = 0;
}

static void module_crash_middle(void) {
    module_crash_inner();
}

static void module_crash_outer(void) {
    module_crash_middle();
}

/* Signal handler for stack overflow to avoid infinite loop in handler */
static jmp_buf stack_overflow_jmp;
static void sigsegv_handler(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    longjmp(stack_overflow_jmp, 1);
}

/* Dispatch based on argv[1] */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <fixture>\n"
                "Fixtures: null_deref, stack_overflow, abort_call, "
                "div_by_zero, heap_corruption, module_crash\n", argv[0]);
        return 1;
    }

    struct sigaction sa = {0};
    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);

    /* Stack overflow needs alternate stack */
    if (strcmp(argv[1], "stack_overflow") == 0) {
        stack_t ss = {0};
        ss.ss_size = SIGSTKSZ * 4;
        ss.ss_sp = malloc(ss.ss_size);
        sigaltstack(&ss, NULL);
    }

    if (strcmp(argv[1], "null_deref") == 0) {
        null_deref_outer();
    } else if (strcmp(argv[1], "stack_overflow") == 0) {
        if (setjmp(stack_overflow_jmp) == 0) {
            stack_overflow_recurse(0);
        } else {
            fprintf(stderr, "Caught stack overflow via longjmp\n");
            return 0;
        }
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