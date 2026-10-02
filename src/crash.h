#ifndef CRASH_H_
#define CRASH_H_

/* Minimal crash handler: readable stacktrace on stderr, no files.
 *
 * On crash the handler prints function + file:line for each frame
 * (via batched addr2line) so you can find what led to the error.
 * Nothing is written to disk; no crashes/ folder, no records.
 *
 * Requires dev flags: -g -Og -fno-omit-frame-pointer -rdynamic
 * (Linux) / -g -Og -fno-omit-frame-pointer (MinGW) + -DCRASH_DEBUG.
 * Without CRASH_DEBUG everything compiles to nothing.
 */

void crash_install_handlers(void);

/* Print current stack to stderr (for smoke tests, never fatal). */
void crash_print_stacktrace(void);

#ifdef CRASH_DEBUG
void crash_assert_fail(const char *cond, const char *file, int line,
                       const char *fmt, ...);
#define CRASH_ASSERT(cond, fmt, ...) \
    do { if (!(cond)) crash_assert_fail(#cond, __FILE__, __LINE__, fmt, ##__VA_ARGS__); } while (0)
#else
#define CRASH_ASSERT(cond, fmt, ...) do {} while (0)
#endif

#endif /* CRASH_H_ */
