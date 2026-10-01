#include "crash.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>

/* Readable Windows traces.
 *
 * DbgHelp resolves PDB symbols (MSVC). MinGW/DWARF has no PDB, so we
 * additionally shell out to addr2line (ships with the GCC toolchain) to
 * turn module+offset into function (file:line). System DLL frames are
 * shown without addr2line probing to keep the trace fast and focused.
 */

#define CRASH_MAX_FRAMES 32
#define CRASH_SKIP_FRAMES 1

static int crash_sym_initialized = 0;

static void crash_strip_newline(char *s) {
    size_t n;
    if (!s) return;
    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = '\0';
}

static const char *crash_file_name(const char *path) {
    const char *a, *b;
    if (!path || !*path) return path ? path : "";
    a = strrchr(path, '\\');
    b = strrchr(path, '/');
    if (a && b) return (a > b ? a : b) + 1;
    if (a) return a + 1;
    if (b) return b + 1;
    return path;
}

static int crash_is_system_module(const char *path) {
    size_t i;
    static const char *sys_hints[] = {
        "\\windows\\", "\\system32\\", "\\syswow64\\",
        "ntdll", "kernel32", "kernelbase", "msvcrt", "ucrtbase",
        "ws2_32", "winpthread", "bcrypt", "dbghelp",
    };
    char lower[MAX_PATH];
    size_t n;
    if (!path) return 1;
    n = strlen(path);
    if (n >= sizeof(lower)) n = sizeof(lower) - 1;
    for (i = 0; i < n; i++) {
        char c = path[i];
        lower[i] = (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
    }
    lower[n] = '\0';
    for (i = 0; i < sizeof(sys_hints) / sizeof(sys_hints[0]); i++) {
        if (strstr(lower, sys_hints[i]) != NULL) return 1;
    }
    return 0;
}

/* Preferred (link-time) image base from the file on disk. The in-memory
 * PE headers are rebased by ASLR, so they cannot be used. addr2line wants
 * file VMAs (preferred_base + RVA). */
static DWORD64 crash_file_preferred_base(const char *path) {
    FILE *f = NULL;
    unsigned char hdr[64];
    unsigned long e_lfanew;
    unsigned long sig;
    unsigned short magic;
    DWORD64 base = 0;
    if (!path || !*path) return 0;
    f = fopen(path, "rb");
    if (!f) return 0;
    if (fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) { fclose(f); return 0; }
    if (hdr[0] != 'M' || hdr[1] != 'Z') { fclose(f); return 0; }
    e_lfanew = (unsigned long)hdr[0x3c] |
               ((unsigned long)hdr[0x3d] << 8) |
               ((unsigned long)hdr[0x3e] << 16) |
               ((unsigned long)hdr[0x3f] << 24);
    if (fseek(f, (long)e_lfanew, SEEK_SET) != 0) { fclose(f); return 0; }
    if (fread(&sig, 4, 1, f) != 1 || sig != 0x00004550) { fclose(f); return 0; }
    if (fseek(f, (long)e_lfanew + 4 + 20, SEEK_SET) != 0) { fclose(f); return 0; }
    if (fread(&magic, 2, 1, f) != 1) { fclose(f); return 0; }
    if (magic == 0x20b) { /* PE32+ */
        unsigned char opt[112];
        DWORD64 img = 0;
        int i;
        if (fseek(f, (long)e_lfanew + 4 + 20 + 24, SEEK_SET) != 0) { fclose(f); return 0; }
        if (fread(opt, 1, 8, f) != 8) { fclose(f); return 0; }
        for (i = 7; i >= 0; i--) base = (base << 8) | opt[i];
        (void)img;
    } else if (magic == 0x10b) { /* PE32 */
        unsigned char opt[4];
        if (fseek(f, (long)e_lfanew + 4 + 20 + 28, SEEK_SET) != 0) { fclose(f); return 0; }
        if (fread(opt, 1, 4, f) != 4) { fclose(f); return 0; }
        base = (DWORD64)opt[0] | ((DWORD64)opt[1] << 8) |
               ((DWORD64)opt[2] << 16) | ((DWORD64)opt[3] << 24);
    }
    fclose(f);
    return base;
}

/* In-memory PEbase helper retained for diagnostics (file-based lookup
 * above is authoritative since ASLR rebases in-memory headers). */
static DWORD64 crash_preferred_base(HMODULE mod) {
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    if (!mod) return 0;
    dos = (PIMAGE_DOS_HEADER)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    nt = (PIMAGE_NT_HEADERS)((unsigned char *)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return (DWORD64)nt->OptionalHeader.ImageBase;
}

/* Resolve one frame via addr2line. Returns 1 on success (func not "??"). */
static int crash_addr2line(const char *module_path, DWORD64 vma,
                           char *func_out, size_t func_sz,
                           char *loc_out, size_t loc_sz) {
    char cmd[2048];
    FILE *pipe;
    char func[512] = {0};
    char loc[1024] = {0};
    int ok = 0;

    if (!module_path || !module_path[0]) return 0;
    snprintf(cmd, sizeof(cmd), "addr2line -e \"%s\" -f -C 0x%llx",
             module_path, (unsigned long long)vma);
    pipe = _popen(cmd, "r");
    if (!pipe) return 0;
    if (fgets(func, sizeof(func), pipe) != NULL &&
        fgets(loc, sizeof(loc), pipe) != NULL) {
        crash_strip_newline(func);
        crash_strip_newline(loc);
        if (func[0] && strcmp(func, "??") != 0) {
            if (func_out && func_sz) snprintf(func_out, func_sz, "%s", func);
            if (loc_out && loc_sz) snprintf(loc_out, loc_sz, "%s", loc);
            ok = 1;
        }
    }
    _pclose(pipe);
    return ok;
}

void crash_print_stacktrace(void) {
    void *frames[CRASH_MAX_FRAMES];
    USHORT captured;
    HANDLE process;
    SYMBOL_INFO_PACKAGE sym_pkg;
    PSYMBOL_INFO sym;
    int have_sym = 0;
    USHORT i;

    captured = CaptureStackBackTrace(CRASH_SKIP_FRAMES,
                                     CRASH_MAX_FRAMES - CRASH_SKIP_FRAMES,
                                     frames, NULL);
    if (captured == 0) {
        fprintf(stderr, "  <empty stack>\n");
        fflush(stderr);
        return;
    }

    process = GetCurrentProcess();
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    if (SymInitialize(process, NULL, TRUE)) {
        have_sym = 1;
        crash_sym_initialized = 1;
    } else {
        fprintf(stderr, "  (no PDB symbols; resolving via addr2line where possible)\n");
    }

    if (have_sym) {
        memset(&sym_pkg, 0, sizeof(sym_pkg));
        sym = &sym_pkg.si;
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen = MAX_SYM_NAME;
    } else {
        sym = NULL;
    }

    for (i = 0; i < captured; i++) {
        DWORD64 address = (DWORD64)(uintptr_t)frames[i];
        HMODULE mod = NULL;
        char mod_path[MAX_PATH] = {0};
        const char *mod_short = "<unknown>";
        DWORD64 rva = 0;
        int got_module = 0;
        DWORD64 displacement = 0;
        DWORD line_disp = 0;
        IMAGEHLP_LINE64 line;

        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)frames[i], &mod) && mod &&
            GetModuleFileNameA(mod, mod_path, sizeof(mod_path))) {
            got_module = 1;
            mod_short = crash_file_name(mod_path);
            rva = address - (DWORD64)(uintptr_t)mod;
        }

        fprintf(stderr, "  #%u  %p ", (unsigned)i, frames[i]);

        /* 1) PDB path (MSVC): function + source line. */
        if (have_sym && SymFromAddr(process, address, &displacement, sym)) {
            fprintf(stderr, "%s+0x%llx", sym->Name,
                    (unsigned long long)displacement);
            memset(&line, 0, sizeof(line));
            line.SizeOfStruct = sizeof(line);
            if (SymGetLineFromAddr64(process, address, &line_disp, &line)) {
                fprintf(stderr, " (%s:%lu)", line.FileName,
                        (unsigned long)line.LineNumber);
            }
            if (got_module) {
                fprintf(stderr, " [%s+0x%llx]", mod_short,
                        (unsigned long long)rva);
            }
            fprintf(stderr, "\n");
            continue;
        }

        /* 2) DWARF path (MinGW): addr2line on app modules only. */
        if (got_module && !crash_is_system_module(mod_path)) {
            DWORD64 pref = crash_file_preferred_base(mod_path);
            DWORD64 vma = pref ? pref + rva : address;
            char func[512] = {0};
            char loc[1024] = {0};
            if (crash_addr2line(mod_path, vma, func, sizeof(func),
                                loc, sizeof(loc))) {
                if (loc[0] && strcmp(loc, "??:?") != 0 && strcmp(loc, "??:0") != 0) {
                    fprintf(stderr, "%s (%s)", func, loc);
                } else {
                    fprintf(stderr, "%s", func);
                }
                fprintf(stderr, " [%s+0x%llx]\n", mod_short,
                        (unsigned long long)rva);
                continue;
            }
        }

        /* 3) Fallback: module+offset is still addr2line/gdb actionable. */
        if (got_module) {
            fprintf(stderr, "%s+0x%llx [abs %p]\n", mod_short,
                    (unsigned long long)rva, frames[i]);
        } else {
            fprintf(stderr, "<unknown> [abs %p]\n", frames[i]);
        }
    }
    fprintf(stderr, "  Tip: gdb -batch -ex bt --args <exe> <args>, or "
            "addr2line -e <module> -f -C <link-time-addr>\n");
    fflush(stderr);
    if (have_sym) SymCleanup(process);
}

static const char *crash_sig_name(int sig) {
    switch (sig) {
        case SIGSEGV: return "SIGSEGV (invalid memory access)";
        case SIGFPE:  return "SIGFPE (arithmetic fault)";
        case SIGILL:  return "SIGILL (illegal instruction)";
        case SIGABRT: return "SIGABRT (abort)";
        default: return "UNKNOWN";
    }
}

static void crash_signal_handler(int sig) {
    fprintf(stderr, "\nCRASH: Signal %d (%s).\n", sig, crash_sig_name(sig));
    crash_print_stacktrace();
    fflush(stderr);
    fflush(stdout);
    signal(sig, SIG_DFL);
    /* Non-zero exit lets the nob hot-reload supervisor detect the crash
     * and restart the host. */
    _exit(1);
}

static LONG WINAPI crash_seh_filter(EXCEPTION_POINTERS *info) {
    DWORD code = info && info->ExceptionRecord
        ? info->ExceptionRecord->ExceptionCode : 0;
    const char *name = "UNKNOWN";
    const char *op = "";
    void *fault = NULL;
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:         name = "ACCESS_VIOLATION (segfault-like)"; break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:       name = "INT_DIVIDE_BY_ZERO"; break;
        case EXCEPTION_ILLEGAL_INSTRUCTION:      name = "ILLEGAL_INSTRUCTION"; break;
        case EXCEPTION_STACK_OVERFLOW:           name = "STACK_OVERFLOW"; break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    name = "ARRAY_BOUNDS_EXCEEDED"; break;
        default: break;
    }
    if (info && info->ExceptionRecord &&
        info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        info->ExceptionRecord->NumberParameters >= 2) {
        ULONG_PTR w = info->ExceptionRecord->ExceptionInformation[0];
        fault = (void *)info->ExceptionRecord->ExceptionInformation[1];
        op = (w == 0) ? "read" : (w == 1) ? "write" : "execute";
    }
    fprintf(stderr, "\nCRASH: Exception 0x%08lX (%s)",
            (unsigned long)code, name);
    if (fault) fprintf(stderr, " while attempting to %s address %p", op, fault);
    fprintf(stderr, ".\n");
    crash_print_stacktrace();
    fflush(stderr);
    fflush(stdout);
    ExitProcess(1);
    return EXCEPTION_EXECUTE_HANDLER;
}

void crash_install_handlers(void) {
    signal(SIGSEGV, crash_signal_handler);
    signal(SIGFPE, crash_signal_handler);
    signal(SIGILL, crash_signal_handler);
    signal(SIGABRT, crash_signal_handler);
    SetUnhandledExceptionFilter(crash_seh_filter);
}

#else /* POSIX (Linux) */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>
#include <execinfo.h>
#include <dlfcn.h>
#include <sys/types.h>

#define CRASH_MAX_FRAMES 32
#define CRASH_SKIP_FRAMES 2

static void crash_strip_newline(char *s) {
    size_t n;
    if (!s) return;
    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = '\0';
}

/* Best-effort file:line via addr2line. Tries the ASLR absolute address
 * first, then the file-relative offset for PIE binaries. */
static int crash_addr2line(const char *module, void *addr, void *base,
                           char *out, size_t out_sz) {
    char cmd[2048];
    char exe[1024];
    FILE *pipe;
    char func[512] = {0};
    char loc[1024] = {0};

    if (!module || !module[0]) return 0;
    snprintf(exe, sizeof(exe), "%s", module);
    snprintf(cmd, sizeof(cmd), "addr2line -e \"%s\" -f -C %p",
             exe, addr);
    pipe = popen(cmd, "r");
    if (pipe) {
        int ok = 0;
        if (fgets(func, sizeof(func), pipe) != NULL &&
            fgets(loc, sizeof(loc), pipe) != NULL) {
            crash_strip_newline(func);
            crash_strip_newline(loc);
            if (func[0] && strcmp(func, "??") != 0) ok = 1;
        }
        pclose(pipe);
        if (ok) {
            if (loc[0] && strcmp(loc, "??:?") != 0 && strcmp(loc, "??:0") != 0)
                snprintf(out, out_sz, "%s (%s)", func, loc);
            else
                snprintf(out, out_sz, "%s", func);
            return 1;
        }
    }
    if (base) {
        unsigned long long off =
            (unsigned long long)((char *)addr - (char *)base);
        snprintf(cmd, sizeof(cmd), "addr2line -e \"%s\" -f -C 0x%llx",
                 exe, off);
        pipe = popen(cmd, "r");
        if (!pipe) return 0;
        {
            int ok = 0;
            if (fgets(func, sizeof(func), pipe) != NULL &&
                fgets(loc, sizeof(loc), pipe) != NULL) {
                crash_strip_newline(func);
                crash_strip_newline(loc);
                if (func[0] && strcmp(func, "??") != 0) ok = 1;
            }
            pclose(pipe);
            if (ok) {
                if (loc[0] && strcmp(loc, "??:?") != 0 && strcmp(loc, "??:0") != 0)
                    snprintf(out, out_sz, "%s (%s)", func, loc);
                else
                    snprintf(out, out_sz, "%s", func);
                return 1;
            }
        }
    }
    return 0;
}

static void crash_print_frames(void *const *array, int size, int skip) {
    int i;
    if (size <= skip) {
        fprintf(stderr, "  <empty stack>\n");
        fflush(stderr);
        return;
    }
    for (i = skip; i < size; i++) {
        Dl_info dlinfo;
        const char *func = NULL;
        const char *mod = NULL;
        unsigned long long off = 0;
        char resolved[1536] = {0};
        if (dladdr(array[i], &dlinfo) != 0) {
            func = dlinfo.dli_sname;
            mod = dlinfo.dli_fname;
            if (dlinfo.dli_saddr)
                off = (unsigned long long)((char *)array[i] -
                                           (char *)dlinfo.dli_saddr);
            else if (dlinfo.dli_fbase)
                off = (unsigned long long)((char *)array[i] -
                                           (char *)dlinfo.dli_fbase);
        }
        if (mod && crash_addr2line(mod, array[i], dlinfo.dli_fbase,
                                   resolved, sizeof(resolved))) {
            fprintf(stderr, "  #%d  %s [%s %p]\n", i - skip, resolved,
                    mod ? mod : "?", array[i]);
        } else if (func) {
            fprintf(stderr, "  #%d  %s+0x%llx [%s %p]\n", i - skip, func, off,
                    mod ? mod : "?", array[i]);
        } else {
            fprintf(stderr, "  #%d  %s [%p]\n", i - skip,
                    mod ? mod : "<unknown>", array[i]);
        }
    }
    fflush(stderr);
}

void crash_print_stacktrace(void) {
    void *array[CRASH_MAX_FRAMES];
    int size = backtrace(array, CRASH_MAX_FRAMES);
    if (size <= 0) {
        fprintf(stderr, "  <empty stack>\n");
        fflush(stderr);
        return;
    }
    crash_print_frames(array, size, 1);
}

static void crash_handler(int sig, siginfo_t *info, void *ctx) {
    void *array[CRASH_MAX_FRAMES];
    int size;
    const char *sig_name = strsignal(sig);
    void *fault = info ? info->si_addr : NULL;
    (void)ctx;

    fprintf(stderr, "\nCRASH: Signal %d (%s)",
            sig, sig_name ? sig_name : "UNKNOWN");
    if (fault) fprintf(stderr, " at address %p", fault);
    fprintf(stderr, ".\n");
    fflush(stderr);

    size = backtrace(array, CRASH_MAX_FRAMES);
    crash_print_frames(array, size, CRASH_SKIP_FRAMES);
    fprintf(stderr, "  Tip: rebuild with -g -rdynamic; "
            "gdb -batch -ex bt --args <exe> <args>\n");
    fflush(stdout);
    fflush(stderr);
    signal(sig, SIG_DFL);
    _exit(128 + sig);
}

void crash_install_handlers(void) {
    struct sigaction act;
    int sigs[] = { SIGSEGV, SIGFPE, SIGILL, SIGABRT,
#ifdef SIGBUS
        SIGBUS,
#endif
    };
    size_t i;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = crash_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO | SA_RESETHAND;
    for (i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
        sigaction(sigs[i], &act, NULL);
}

#endif /* _WIN32 */
