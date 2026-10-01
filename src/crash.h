#ifndef CRASH_H_
#define CRASH_H_

/* Crash stack-trace + handler installation.
 *
 * Linux: sigaction/SA_SIGINFO + backtrace() + dladdr() + addr2line, so
 * frames print as `func (file:line) [module addr]`. Requires `-g
 * -rdynamic` (see NOB_OS_DEBUG_FLAGS).
 *
 * Windows (MinGW/MSVC): CaptureStackBackTrace + DbgHelp for PDB, plus
 * automatic addr2line resolution for DWARF (MinGW). Frames print as
 * `func (file:line) [module+offset]`; system DLLs are shown without
 * addr2line probing. Requires `-g` and `-ldbghelp`.
 *
 * Output goes to stderr, which is inherited from the terminal that runs
 * `nob` / the relay, i.e. the same place debug logs are observed.
 */
void crash_install_handlers(void);
void crash_print_stacktrace(void);

#endif /* CRASH_H_ */
