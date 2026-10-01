/* Crash stack-trace smoke test: verifies crash_print_stacktrace() runs
 * without crashing and crash_install_handlers() can be installed.
 * Does NOT raise a fatal signal (that would terminate the test runner);
 * the fatal-signal path is exercised manually via a segfault binary. */
#include <stdio.h>
#include "crash.h"

static void inner_frame(void) {
    crash_print_stacktrace();
}

static void outer_frame(void) {
    inner_frame();
}

int main(void) {
    crash_install_handlers();
    fprintf(stderr, "TEST crash: printing stack trace (expect frames below)\n");
    outer_frame();
    fprintf(stderr, "TEST crash: stack trace printed OK\n");
    return 0;
}
