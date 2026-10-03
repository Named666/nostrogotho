/* Crash handler: readable terminal stacktrace, no files.
 *
 * Prints function + file:line per frame to stderr on fatal signals
 * (Linux) / unhandled exception + abort (Windows). Nothing is written
 * to disk.
 *
 * Safety domains (kept separate on purpose):
 *  handler  = signal/SEH context: FP-walk only, no backtrace().
 *  helper   = normal code (crash_print_stacktrace): backtrace() is fine.
 *
 * Requires: -g -Og -fno-omit-frame-pointer (+ -rdynamic on Linux).
 */

/* _GNU_SOURCE must precede ALL system headers (even via crash.h):
 * glibc locks in feature macros on first <features.h> inclusion,
 * which is what exposes Dl_info/dladdr and REG_RIP/REG_RBP. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "crash.h"

#ifndef CRASH_DEBUG

void crash_install_handlers(void) {}
void crash_print_stacktrace(void) {}
void crash_assert_fail(const char *c, const char *f, int l, const char *m, ...) {
    (void)c; (void)f; (void)l; (void)m;
}

#else /* CRASH_DEBUG */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#else
#include <ucontext.h>
#include <dlfcn.h>
#include <unistd.h>
#include <execinfo.h>
#endif

#define CRASH_MAX_FRAMES 64

static volatile sig_atomic_t crash_in_handler = 0;

/* --- tiny color helper (TTY only, respects NO_COLOR) --- */
static int use_color(void) {
    static int init = 0, val = 0;
    if (!init) {
        const char *no = getenv("NO_COLOR");
        const char *term = getenv("TERM");
        init = 1;
        val = !no && (!term || strcmp(term, "dumb") != 0);
#ifdef _WIN32
        val = val && _isatty(_fileno(stderr));
#else
        val = val && isatty(STDERR_FILENO);
#endif
    }
    return val;
}

static const char *c_red(void)   { return use_color() ? "\033[1;31m" : ""; }
static const char *c_cyan(void)  { return use_color() ? "\033[1;36m" : ""; }
static const char *c_dim(void)   { return use_color() ? "\033[2m" : ""; }
static const char *c_reset(void) { return use_color() ? "\033[0m" : ""; }

/* Last resort: runs with a trashed heap/stack, so only write() --
 * no formatting, no allocation. Tells the dev the handler itself died
 * instead of leaving a bare exit 127 with no output. */
static void nested_fault_note(void) {
    static const char msg[] =
        "CRASH: nested fault inside crash handler; trace unavailable (exit 127)\n";
#ifdef _WIN32
    write(2, msg, (unsigned)(sizeof(msg) - 1));
#else
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
#endif
}

static void strip_nl(char *s) {
    size_t n;
    if (!s) return;
    n = strlen(s);
    while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r')) s[--n] = '\0';
}

static const char *file_name(const char *p) {
    const char *a, *b;
    if (!p || !*p) return p ? p : "";
    a = strrchr(p, '\\');
    b = strrchr(p, '/');
    if (a && b) return (a > b ? a : b) + 1;
    if (a) return a + 1;
    if (b) return b + 1;
    return p;
}

static int is_system_module(const char *path) {
    static const char *hints[] = {
        "\\windows\\", "\\system32\\", "\\syswow64\\",
        "ntdll", "kernel32", "kernelbase", "msvcrt", "ucrtbase",
        "ws2_32", "winpthread", "bcrypt", "dbghelp",
        "libc.", "ld-linux", "libpthread", "libdl", "libm",
        "/lib/", "/usr/lib/",
    };
    char lower[1024];
    size_t n, i;
    if (!path) return 1;
    n = strlen(path);
    if (n >= sizeof(lower)) n = sizeof(lower) - 1;
    for (i = 0; i < n; i++) {
        char c = path[i];
        lower[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }
    lower[n] = '\0';
    for (i = 0; i < sizeof(hints) / sizeof(hints[0]); i++)
        if (strstr(lower, hints[i]) != NULL) return 1;
    return 0;
}

static int is_verbose(void) {
    const char *v = getenv("CRASH_VERBOSE");
    return v && v[0] && strcmp(v, "0") != 0;
}

/* --- platform shims in one place --- */
static FILE *crash_popen(const char *cmd) {
#ifdef _WIN32
    return _popen(cmd, "r");
#else
    return popen(cmd, "r");
#endif
}

static void crash_pclose(FILE *p) {
#ifdef _WIN32
    _pclose(p);
#else
    pclose(p);
#endif
}

/* PE preferred (link-time) base from file, for MinGW DWARF VMA math. */
#ifdef _WIN32
static unsigned long long pe_preferred_base(const char *path) {
    FILE *f = NULL;
    unsigned char hdr[64];
    unsigned long e_lfanew, sig;
    unsigned short magic;
    unsigned long long base = 0;
    int i;
    if (!path || !*path) return 0;
    f = fopen(path, "rb");
    if (!f) return 0;
    if (fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) { fclose(f); return 0; }
    if (hdr[0] != 'M' || hdr[1] != 'Z') { fclose(f); return 0; }
    e_lfanew = (unsigned long)hdr[0x3c] | ((unsigned long)hdr[0x3d] << 8) |
               ((unsigned long)hdr[0x3e] << 16) | ((unsigned long)hdr[0x3f] << 24);
    if (fseek(f, (long)e_lfanew, SEEK_SET) != 0) { fclose(f); return 0; }
    if (fread(&sig, 4, 1, f) != 1 || sig != 0x00004550) { fclose(f); return 0; }
    if (fseek(f, (long)e_lfanew + 4 + 20, SEEK_SET) != 0) { fclose(f); return 0; }
    if (fread(&magic, 2, 1, f) != 1) { fclose(f); return 0; }
    if (magic == 0x20b) {
        unsigned char opt[8];
        if (fseek(f, (long)e_lfanew + 4 + 20 + 24, SEEK_SET) != 0) { fclose(f); return 0; }
        if (fread(opt, 1, 8, f) != 8) { fclose(f); return 0; }
        for (i = 7; i >= 0; i--) base = (base << 8) | opt[i];
    } else if (magic == 0x10b) {
        unsigned char opt[4];
        if (fseek(f, (long)e_lfanew + 4 + 20 + 28, SEEK_SET) != 0) { fclose(f); return 0; }
        if (fread(opt, 1, 4, f) != 4) { fclose(f); return 0; }
        base = (unsigned long long)opt[0] | ((unsigned long long)opt[1] << 8) |
               ((unsigned long long)opt[2] << 16) | ((unsigned long long)opt[3] << 24);
    }
    fclose(f);
    return base;
}
#endif

/* Resolve an effective address to module + query address for addr2line.
 * Single platform branch; returns 1 with mod_path set when a module owns it. */
static int resolve_module(uintptr_t eff, char *mod_path, size_t mod_sz,
                          unsigned long long *qaddr, int *is_sys) {
    if (mod_path && mod_sz) mod_path[0] = '\0';
    if (qaddr) *qaddr = (unsigned long long)eff;
    if (is_sys) *is_sys = 0;
#ifdef _WIN32
    {
        HMODULE mod = NULL;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)(void *)eff, &mod) && mod &&
            GetModuleFileNameA(mod, mod_path, (DWORD)(mod_sz - 1))) {
            unsigned long long rva =
                (unsigned long long)eff - (unsigned long long)(uintptr_t)mod;
            unsigned long long pref = pe_preferred_base(mod_path);
            if (qaddr) *qaddr = pref ? pref + rva : rva;
            if (is_sys) *is_sys = is_system_module(mod_path);
            return 1;
        }
    }
#else
    {
        Dl_info li;
        if (dladdr((void *)eff, &li) != 0 && li.dli_fname) {
            snprintf(mod_path, mod_sz, "%s", li.dli_fname);
            if (li.dli_fbase && qaddr)
                *qaddr = (unsigned long long)eff -
                         (unsigned long long)(uintptr_t)li.dli_fbase;
            if (is_sys) *is_sys = is_system_module(mod_path);
            return 1;
        }
    }
#endif
    return 0;
}

/* One addr2line probe. Returns 1 when the function is known. */
static int addr2line_one(const char *mod, unsigned long long addr,
                         char *func, size_t func_sz,
                         char *loc, size_t loc_sz) {
    char cmd[2048];
    FILE *pipe;
    char fbuf[512] = {0}, lbuf[1024] = {0};
    int ok = 0;
    if (!mod || !mod[0]) return 0;
    snprintf(cmd, sizeof(cmd), "addr2line -e \"%s\" -f -C 0x%llx", mod, addr);
    pipe = crash_popen(cmd);
    if (!pipe) return 0;
    if (fgets(fbuf, sizeof(fbuf), pipe) && fgets(lbuf, sizeof(lbuf), pipe)) {
        strip_nl(fbuf);
        strip_nl(lbuf);
        if (fbuf[0] && strcmp(fbuf, "??") != 0) {
            snprintf(func, func_sz, "%s", fbuf);
            snprintf(loc, loc_sz, "%s", lbuf);
            ok = 1;
        }
    }
    crash_pclose(pipe);
    return ok;
}

static void rel_path(const char *abs, char *out, size_t out_sz) {
    const char *p;
    if (!abs || !out || out_sz == 0) return;
    p = strstr(abs, "src/");
    if (!p) p = strstr(abs, "tests/");
    if (!p) p = strstr(abs, "src\\");
    if (p) { snprintf(out, out_sz, "%s", p); return; }
    snprintf(out, out_sz, "%s", file_name(abs));
}

/* Source context with a fixed stack buffer (no malloc in crash path). */
static void print_src_context(const char *file, long line_no) {
    FILE *f;
    char line[2048];
    long cur = 0, start;
    char kept[7][512];
    int have[7] = {0};
    int i;
    if (!file || !file[0] || strstr(file, "??") != NULL || line_no <= 0) return;
    f = fopen(file, "r");
    if (!f) return;
    start = line_no - 3;
    if (start < 1) start = 1;
    while (fgets(line, sizeof(line), f) != NULL) {
        cur++;
        if (cur >= start && cur <= line_no + 3) {
            strip_nl(line);
            snprintf(kept[cur - start], sizeof(kept[0]), "%.511s", line);
            have[cur - start] = 1;
            if (cur == line_no + 3) break;
        }
        if (cur > line_no + 3) break;
    }
    fclose(f);
    for (i = 0; i < 7; i++) {
        if (!have[i]) continue;
        if (start + i == line_no)
            fprintf(stderr, "      %s> %ld | %s%s\n",
                    c_cyan(), start + i, kept[i], c_reset());
        else
            fprintf(stderr, "      %s  %ld | %s%s\n",
                    c_dim(), start + i, kept[i], c_reset());
    }
}

/* Resolve once: module offset first, then absolute (ELF PIE vs non-PIE). */
static int resolve_frame(const char *mod_path, unsigned long long query_addr,
                         unsigned long long raw_addr,
                         char *func, size_t func_sz,
                         char *loc, size_t loc_sz) {
    if (mod_path && mod_path[0]) {
        if (addr2line_one(mod_path, query_addr, func, func_sz, loc, loc_sz))
            return 1;
        if (query_addr != raw_addr)
            return addr2line_one(mod_path, raw_addr, func, func_sz, loc, loc_sz);
    }
    return 0;
}

/* Split "file:line" into filepart; returns the line number (0 if none). */
static long split_loc(const char *loc, char *filepart, size_t fp_sz) {
    char *colon = strrchr(loc, ':');
    if (colon) {
        size_t fl = (size_t)(colon - loc);
        if (fl >= fp_sz) fl = fp_sz - 1;
        memcpy(filepart, loc, fl);
        filepart[fl] = '\0';
        return atol(colon + 1);
    }
    snprintf(filepart, fp_sz, "%s", loc);
    return 0;
}

/* Print one resolved group: single frame, or "#a-#b ... (xN)" for a run
 * of identical frames (recursion). Context is shown once. */
static void print_group(int first, int count, const char *mod_path,
                        unsigned long long query_addr,
                        unsigned long long raw_addr,
                        const char *func, const char *loc, int ok) {
    if (ok) {
        char rel[1024] = {0}, filepart[1024] = {0};
        long lineno = split_loc(loc, filepart, sizeof(filepart));
        int known_loc = loc[0] && loc[0] != '?';
        rel_path(filepart[0] ? filepart : loc, rel, sizeof(rel));
        if (count > 1 && known_loc)
            fprintf(stderr, "  #%d-#%d  %s%s%s  %s%s%s  %s(x%d)%s\n",
                    first, first + count - 1,
                    c_cyan(), func, c_reset(), c_dim(), rel, c_reset(),
                    c_dim(), count, c_reset());
        else if (count > 1)
            fprintf(stderr, "  #%d-#%d  %s%s%s  %s(x%d)%s\n",
                    first, first + count - 1,
                    c_cyan(), func, c_reset(),
                    c_dim(), count, c_reset());
        else if (known_loc && strcmp(rel, "??:?") != 0 && strcmp(rel, "??:0") != 0)
            fprintf(stderr, "  #%d  %s%s%s  %s%s%s\n", first,
                    c_cyan(), func, c_reset(), c_dim(), rel, c_reset());
        else
            fprintf(stderr, "  #%d  %s%s%s\n", first, c_cyan(), func, c_reset());
        if (known_loc && filepart[0] && !strstr(filepart, "??") && lineno > 0)
            print_src_context(filepart, lineno);
    } else if (mod_path && mod_path[0]) {
        fprintf(stderr, "  #%d  %s+0x%llx %s[abs 0x%llx]%s\n",
                first, file_name(mod_path), query_addr,
                c_dim(), raw_addr, c_reset());
    } else {
        fprintf(stderr, "  #%d  %s[abs 0x%llx]%s\n",
                first, c_dim(), raw_addr, c_reset());
    }
}

/* FP-chain walk; needs -fno-omit-frame-pointer.
 *
 * Note what this can and cannot see: it records return addresses, so a
 * function that never returns (calls noreturn abort(), fastfails, or is
 * entered via frameless libc assembly) leaves no address behind and will
 * not appear as its own frame -- the trace stays truthful, just without
 * it (e.g. abort_inner is absent on Linux while present via Windows
 * unwind tables). Segfaults in user code always resolve exactly. */
static void fp_walk(uintptr_t fp, uintptr_t *out, int *count, int max) {
    int n = *count, steps;
    for (steps = 0; steps < 60 && n < max; steps++) {
        uintptr_t next_fp, ret;
        uintptr_t *p;
        if (fp == 0 || (fp & (sizeof(void *) - 1)) != 0) break;
        p = (uintptr_t *)fp;
        next_fp = p[0];
        ret = p[1];
        if (ret == 0) break;
        if (next_fp != 0 && (next_fp <= fp || next_fp - fp > (uintptr_t)(1024 * 1024))) break;
        out[n++] = ret;
        if (next_fp == 0) break;
        fp = next_fp;
    }
    *count = n;
}

static const char *sig_name(int sig) {
    if (sig == SIGSEGV) return "SIGSEGV";
    if (sig == SIGABRT) return "SIGABRT";
    if (sig == SIGFPE) return "SIGFPE";
    if (sig == SIGILL) return "SIGILL";
#ifdef SIGBUS
    if (sig == SIGBUS) return "SIGBUS";
#endif
    return "SIGNAL";
}

/* One pending group for collapsing runs of identical frames. */
typedef struct {
    char func[512], loc[1024], mod[1024];
    unsigned long long q, raw;
    int first, n, ok, sys, locok;
} frame_group_t;

static void flush_group(frame_group_t *g, int *shown,
                        int *app_n, int *app_ok, int *app_loc) {
    if (g->n <= 0) return;
    print_group(g->first, g->n, g->mod[0] ? g->mod : NULL,
                g->q, g->raw, g->func, g->loc, g->ok);
    *shown += g->n;
    if (!g->sys) {
        *app_n += g->n;
        if (g->ok) *app_ok += g->n;
        if (g->locok) *app_loc += g->n;
    }
    g->n = 0;
}

static void print_collapsed(const char *names) {
    fprintf(stderr, "  %s#-%s  [system] %s %s(CRASH_VERBOSE=1 shows all)%s\n",
            c_dim(), c_reset(), names, c_dim(), c_reset());
}

static void print_trace(uintptr_t *frames, int nframes, int sig,
                        uintptr_t fault, const char *fault_op) {
    int i, shown = 0, sys_run = 0, verbose = is_verbose();
    int app_n = 0, app_ok = 0, app_loc = 0;
    char sys_names[512] = {0};
    frame_group_t g = {0};
    if (sig)
        fprintf(stderr, "\n%sCRASH: %s%s", c_red(), sig_name(sig), c_reset());
    else
        fprintf(stderr, "\n%sTRACE:%s", c_dim(), c_reset());
    if (fault)
        fprintf(stderr, " %s 0x%llx", fault_op ? fault_op : "at",
                (unsigned long long)fault);
    if ((sig == SIGSEGV
#ifdef SIGBUS
         || sig == SIGBUS
#endif
        ) && fault < 4096)
        fprintf(stderr, " %s(likely null deref)%s", c_dim(), c_reset());
    fprintf(stderr, "\n");
    {
        /* Pending group for collapsing runs of identical frames. */
        for (i = 0; i <= nframes; i++) {
            int end = (i == nframes);
            uintptr_t raw = end ? 0 : frames[i];
            uintptr_t eff = (!end && i > 0 && raw > 0) ? raw - 1 : raw;
            char mod_path[1024] = {0};
            unsigned long long qaddr = (unsigned long long)eff;
            char func[512] = {0}, loc[1024] = {0};
            int have_mod = 0, is_sys = 0, ok = 0;
            if (!end) {
                /* Fast path: identical raw address = same call site
                 * (recursion). Skip module resolve + addr2line entirely. */
                if (g.n > 0 && sys_run == 0 &&
                    (unsigned long long)raw == g.raw) {
                    g.n++;
                    continue;
                }
                have_mod = resolve_module(eff, mod_path, sizeof(mod_path),
                                          &qaddr, &is_sys);
                if (is_sys && !verbose) {
                    const char *bn = have_mod ? file_name(mod_path) : "?";
                    flush_group(&g, &shown, &app_n, &app_ok, &app_loc);
                    if (sys_run == 0) snprintf(sys_names, sizeof(sys_names), "%s", bn);
                    else if (strlen(sys_names) + 2 + strlen(bn) < sizeof(sys_names))
                        snprintf(sys_names + strlen(sys_names),
                                 sizeof(sys_names) - strlen(sys_names), ", %s", bn);
                    sys_run++;
                    continue;
                }
                if (sys_run > 0) {
                    print_collapsed(sys_names);
                    sys_run = 0;
                    sys_names[0] = '\0';
                }
                ok = resolve_frame(have_mod ? mod_path : NULL, qaddr,
                                   (unsigned long long)raw,
                                   func, sizeof(func), loc, sizeof(loc));
            }
            if (!end && g.n > 0 && sys_run == 0 && ok && g.ok &&
                g.sys == is_sys &&
                strcmp(func, g.func) == 0 && strcmp(loc, g.loc) == 0) {
                g.n++; /* same frame repeats (recursion): just count */
                continue;
            }
            flush_group(&g, &shown, &app_n, &app_ok, &app_loc);
            if (end) break;
            g.first = shown;
            g.n = 1;
            g.ok = ok;
            g.sys = is_sys;
            g.locok = ok && loc[0] && loc[0] != '?';
            g.q = qaddr;
            g.raw = (unsigned long long)raw;
            if (ok) {
                snprintf(g.func, sizeof(g.func), "%s", func);
                snprintf(g.loc, sizeof(g.loc), "%s", loc);
            } else {
                g.func[0] = '\0';
                g.loc[0] = '\0';
            }
            if (have_mod) snprintf(g.mod, sizeof(g.mod), "%s", mod_path);
            else g.mod[0] = '\0';
        }
        if (sys_run > 0) print_collapsed(sys_names);
    }
    if (app_n > 0 && app_ok == 0)
        fprintf(stderr, "  %sNote: no symbols resolved -- is addr2line on PATH? Rebuild with -g -Og -fno-omit-frame-pointer.%s\n",
                c_dim(), c_reset());
    else if (app_n > 0 && app_loc == 0)
        fprintf(stderr, "  %sNote: functions resolved but no line info -- rebuild with -g.%s\n",
                c_dim(), c_reset());
    fflush(stderr);
}

/* Current-stack capture for normal code (abort path, smoke test).
 * Skips the capture helper and its immediate caller wrapper so #0 is
 * always user code (inner_frame / abort internals), not this helper. */
static int capture_current(uintptr_t *frames, int max) {
    int n = 0, i;
#ifdef _WIN32
    void *stack[CRASH_MAX_FRAMES];
    USHORT cap = CaptureStackBackTrace(2, CRASH_MAX_FRAMES, stack, NULL);
    for (i = 0; i < cap && n < max; i++)
        frames[n++] = (uintptr_t)stack[i];
#else
    void *stack[CRASH_MAX_FRAMES];
    int cap = backtrace(stack, CRASH_MAX_FRAMES);
    for (i = 2; i < cap && n < max; i++)
        frames[n++] = (uintptr_t)stack[i];
#endif
    return n;
}

/* Shared fatal exit: print once, restore default, exit. */
static void fatal_trace(int sig, uintptr_t fault, const char *op,
                        uintptr_t *frames, int nframes, int exit_code) {
    print_trace(frames, nframes, sig, fault, op);
    signal(sig, SIG_DFL);
    _exit(exit_code);
}

void crash_print_stacktrace(void) {
    uintptr_t frames[CRASH_MAX_FRAMES];
    int n = capture_current(frames, CRASH_MAX_FRAMES);
    print_trace(frames, n, 0, 0, NULL);
}

void crash_assert_fail(const char *cond, const char *file, int line,
                       const char *fmt, ...) {
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n%sASSERT FAILED:%s %s at %s%s:%d%s: %s\n",
            c_red(), c_reset(), cond ? cond : "?",
            "", file ? file : "?", line, "", msg);
    fflush(stderr);
    raise(SIGABRT);
    _exit(1);
}

#ifndef _WIN32
static char altstack_mem[64 * 1024];

static void linux_handler(int sig, siginfo_t *info, void *uctx) {
    uintptr_t fault = 0, ip = 0, fp = 0;
    uintptr_t frames[CRASH_MAX_FRAMES];
    int n = 0;
    if (crash_in_handler) { nested_fault_note(); _exit(127); }
    crash_in_handler = 1;
    if (info && info->si_code != SI_USER) fault = (uintptr_t)info->si_addr;
    if (uctx) {
        ucontext_t *uc = (ucontext_t *)uctx;
#if defined(__x86_64__)
        ip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
        fp = (uintptr_t)uc->uc_mcontext.gregs[REG_RBP];
#elif defined(__i386__)
        ip = (uintptr_t)uc->uc_mcontext.gregs[REG_EIP];
        fp = (uintptr_t)uc->uc_mcontext.gregs[REG_EBP];
#elif defined(__aarch64__)
        ip = (uintptr_t)uc->uc_mcontext.pc;
        fp = (uintptr_t)uc->uc_mcontext.regs[29];
#endif
    }
    if (ip && n < CRASH_MAX_FRAMES) frames[n++] = ip;
    if (fp) fp_walk(fp, frames, &n, CRASH_MAX_FRAMES);
    fatal_trace(sig, fault, "at", frames, n,
                sig == SIGABRT ? 1 : 128 + sig);
}
#else
static LONG WINAPI seh_filter(EXCEPTION_POINTERS *info) {
    unsigned long code = 0;
    uintptr_t fault = 0, ip = 0, fp = 0;
    const char *op = "at";
    uintptr_t frames[CRASH_MAX_FRAMES];
    int n = 0, sig = SIGSEGV;
    if (crash_in_handler) { nested_fault_note(); _exit(127); }
    crash_in_handler = 1;
    if (info && info->ExceptionRecord) {
        code = info->ExceptionRecord->ExceptionCode;
        if (code == EXCEPTION_ACCESS_VIOLATION &&
            info->ExceptionRecord->NumberParameters >= 2) {
            ULONG_PTR w = info->ExceptionRecord->ExceptionInformation[0];
            fault = (uintptr_t)info->ExceptionRecord->ExceptionInformation[1];
            op = (w == 0) ? "reading" : (w == 1) ? "writing" : "executing";
        }
        if (code == EXCEPTION_INT_DIVIDE_BY_ZERO) sig = SIGFPE;
        else if (code == EXCEPTION_ILLEGAL_INSTRUCTION) sig = SIGILL;
    }
    if (info && info->ContextRecord) {
#if defined(_M_X64) || defined(__x86_64__)
        ip = (uintptr_t)info->ContextRecord->Rip;
        fp = (uintptr_t)info->ContextRecord->Rbp;
#elif defined(_M_IX86) || defined(__i386__)
        ip = (uintptr_t)info->ContextRecord->Eip;
        fp = (uintptr_t)info->ContextRecord->Ebp;
#endif
    }
    if (ip && n < CRASH_MAX_FRAMES) frames[n++] = ip;
    if (fp) fp_walk(fp, frames, &n, CRASH_MAX_FRAMES);
    print_trace(frames, n, sig, fault, op);
    _exit(1);
    return EXCEPTION_EXECUTE_HANDLER;
}

static void win_abort_handler(int sig) {
    uintptr_t frames[CRASH_MAX_FRAMES];
    int n;
    if (crash_in_handler) { nested_fault_note(); _exit(127); }
    crash_in_handler = 1;
    n = capture_current(frames, CRASH_MAX_FRAMES);
    fatal_trace(sig, 0, NULL, frames, n, 1);
}
#endif

void crash_install_handlers(void) {
#ifdef _WIN32
    ULONG guarantee = 64 * 1024;
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (k32) {
        BOOL (WINAPI *set_g)(ULONG *) =
            (void *)GetProcAddress(k32, "SetThreadStackGuarantee");
        if (set_g) set_g(&guarantee);
    }
    SetUnhandledExceptionFilter(seh_filter);
    signal(SIGABRT, win_abort_handler);
#else
    stack_t ss;
    struct sigaction act;
    int sigs[] = {SIGSEGV, SIGFPE, SIGILL, SIGABRT,
#ifdef SIGBUS
        SIGBUS,
#endif
    };
    size_t i;
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = altstack_mem;
    ss.ss_size = sizeof(altstack_mem);
    ss.ss_flags = 0;
    sigaltstack(&ss, NULL);
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = linux_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND;
    for (i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
        sigaction(sigs[i], &act, NULL);
#endif
}

#endif /* CRASH_DEBUG */
