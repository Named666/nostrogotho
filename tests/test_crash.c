/* Crash handler test: verifies crash_install_handlers() catches fatal signals
 * and prints a stack trace. Spawns crash_fixtures as child processes to
 * test various crash types without killing the test runner.
 *
 * Each fixture crashes; the handler prints a stacktrace to stderr
 * with function + file:line. No files are written.
 *
 * Fixtures tested: null_deref, abort_call, div_by_zero, module_crash
 * (stack_overflow and heap_corruption are flaky across platforms, skipped)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#endif

#include "crash.h"

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

/* Spawn crash_fixtures binary with given fixture name, capture stderr,
 * verify it contains expected stack trace elements. */
static bool test_fixture(const char *fixture_name, const char *expected_frames[], int frame_count) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
#ifdef _WIN32
             "build\\test_crash_fixtures.exe %s 2>&1",
#else
             "./build/test_crash_fixtures %s 2>&1",
#endif
             fixture_name);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        printf("FAIL: %s - failed to spawn fixture\n", fixture_name);
        return false;
    }

    char output[8192] = {0};
    char buf[1024];
    size_t total = 0;
    while (fgets(buf, sizeof(buf), fp)) {
        size_t len = strlen(buf);
        if (total + len < sizeof(output) - 1) {
            strcat(output, buf);
            total += len;
        }
    }
    int status = pclose(fp);

    /* Crash fixtures should exit with non-zero status */
    bool crashed = status != 0;

    /* Check for expected stack frames in output */
    bool frames_ok = true;
    for (int i = 0; i < frame_count; i++) {
        if (strstr(output, expected_frames[i]) == NULL) {
            printf("  Missing expected frame: %s\n", expected_frames[i]);
            frames_ok = false;
        }
    }

    bool pass = crashed && frames_ok;
    CHECK(pass, fixture_name);
    if (!pass) {
        printf("  Exit status: %d\n", status);
        printf("  Output:\n%s\n", output);
    }
    return pass;
}

int main(void) {
    printf("Running crash handler tests...\n");

    crash_install_handlers();

    /* Test basic stack trace printing (non-crashing) */
    fprintf(stderr, "TEST crash: printing stack trace (expect frames below)\n");
    crash_print_stacktrace();
    fprintf(stderr, "TEST crash: stack trace printed OK\n");
    CHECK(true, "crash_print_stacktrace runs without crashing");

    /* Test each crash fixture */
    const char *null_deref_frames[] = { "null_deref_inner", "null_deref_middle", "null_deref_outer" };
    test_fixture("null_deref", null_deref_frames, 3);

    const char *abort_frames[] = { "abort_inner", "abort_middle", "abort_outer" };
    test_fixture("abort_call", abort_frames, 3);

    const char *div_zero_frames[] = { "div_zero_inner", "div_zero_middle", "div_zero_outer" };
    test_fixture("div_by_zero", div_zero_frames, 3);

    const char *module_crash_frames[] = { "module_crash_inner", "module_crash_middle", "module_crash_outer" };
    test_fixture("module_crash", module_crash_frames, 3);

    printf("crash: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
