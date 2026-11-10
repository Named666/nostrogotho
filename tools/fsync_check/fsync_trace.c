/* LD_PRELOAD tracer: proves "fsync before OK" ordering for nostrogotho.
 * Logs (CLOCK_MONOTONIC ns, tid) for:
 *   W <ns> <tid> <fd> probes...   pwrite to a *-wal file (probe tags found in the bytes)
 *   S0/S1 <ns> <tid> <fd>          fdatasync/fsync start / end on a *-wal or db file
 *   O <ns> <tid> <id8> ...         socket write carrying ["OK","<id>",true
 * Output: $FSYNC_TRACE (default /tmp/fsync_trace.log). */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>

static int logfd = -1;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

static long long now_ns(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000000000LL + t.tv_nsec; }
static void emit(const char *s, size_t n) {
    if (logfd < 0) {
        const char *p = getenv("FSYNC_TRACE");
        logfd = (int) syscall(SYS_openat, AT_FDCWD, p ? p : "/tmp/fsync_trace.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    }
    if (logfd >= 0) syscall(SYS_write, logfd, s, n);
}
static int fd_kind(int fd) {   /* 1 wal, 2 main db, 0 other */
    char lp[64], path[512];
    snprintf(lp, sizeof lp, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(lp, path, sizeof path - 1);
    if (n <= 0) return 0;
    path[n] = 0;
    if (n > 4 && !strcmp(path + n - 4, "-wal")) return 1;
    if (n > 7 && !strcmp(path + n - 7, ".sqlite")) return 2;
    return 0;
}
static int is_sock(int fd) { struct stat st; return fstat(fd, &st) == 0 && S_ISSOCK(st.st_mode); }

static void scan_probes(char *out, size_t cap, size_t *len, const char *b, size_t n) {
    static const char tag[] = "durprobe-";
    for (const char *p = b; p && (size_t) (p - b) + 15 <= n; p++) {
        p = memmem(p, n - (size_t) (p - b), tag, 9);
        if (!p || (size_t) (p - b) + 15 > n) break;
        if (*len + 8 < cap) { memcpy(out + *len, " ", 1); memcpy(out + *len + 1, p + 9, 6); *len += 7; }
    }
}
static void scan_oks(char *out, size_t cap, size_t *len, const char *b, size_t n) {
    static const char tag[] = "[\"OK\",\"";
    for (const char *p = b; p && (size_t) (p - b) + 7 + 64 + 7 <= n; p++) {
        p = memmem(p, n - (size_t) (p - b), tag, 7);
        if (!p || (size_t) (p - b) + 7 + 64 + 7 > n) break;
        if (!memcmp(p + 7 + 64, "\",true", 6) && *len + 18 < cap) {
            out[(*len)++] = ' '; memcpy(out + *len, p + 7, 16); *len += 16;
        }
    }
}

#define REAL(name, ret, ...) static ret (*real_##name)(__VA_ARGS__); \
    if (!real_##name) real_##name = (ret (*)(__VA_ARGS__)) dlsym(RTLD_NEXT, #name)

ssize_t pwrite64(int fd, const void *b, size_t n, off_t off) {
    REAL(pwrite64, ssize_t, int, const void *, size_t, off_t);
    ssize_t r = real_pwrite64(fd, b, n, off);
    if (fd_kind(fd) == 1) {
        char line[65536]; size_t len = (size_t) snprintf(line, sizeof line, "W %lld %ld %d", now_ns(), syscall(SYS_gettid), fd);
        scan_probes(line, sizeof line - 2, &len, (const char *) b, n);
        line[len++] = '\n'; emit(line, len);
    }
    return r;
}
ssize_t pwrite(int fd, const void *b, size_t n, off_t off) { return pwrite64(fd, b, n, off); }

static int sync_common(int fd, int data) {
    REAL(fdatasync, int, int); REAL(fsync, int, int);
    int k = fd_kind(fd);
    char line[128]; size_t len;
    if (k) { len = (size_t) snprintf(line, sizeof line, "S0 %lld %ld %d %d\n", now_ns(), syscall(SYS_gettid), fd, k); emit(line, len); }
    int r = data ? real_fdatasync(fd) : real_fsync(fd);
    if (k) { len = (size_t) snprintf(line, sizeof line, "S1 %lld %ld %d %d %d\n", now_ns(), syscall(SYS_gettid), fd, k, r); emit(line, len); }
    return r;
}
int fdatasync(int fd) { return sync_common(fd, 1); }
int fsync(int fd) { return sync_common(fd, 0); }

static void log_sock(int fd, const struct iovec *iov, int cnt) {
    if (!is_sock(fd)) return;
    static __thread char line[1 << 20];
    size_t len = (size_t) snprintf(line, 64, "O %lld %ld", now_ns(), syscall(SYS_gettid));
    size_t l0 = len;
    for (int i = 0; i < cnt; i++) scan_oks(line, sizeof line - 2, &len, (const char *) iov[i].iov_base, iov[i].iov_len);
    if (len == l0) return;
    line[len++] = '\n'; emit(line, len);
}
/* Log before the send: the OK is leaving now; the fsync must already be done. */
ssize_t send(int fd, const void *b, size_t n, int fl) {
    REAL(send, ssize_t, int, const void *, size_t, int);
    struct iovec v = { (void *) b, n }; log_sock(fd, &v, 1);
    return real_send(fd, b, n, fl);
}
ssize_t sendmsg(int fd, const struct msghdr *m, int fl) {
    REAL(sendmsg, ssize_t, int, const struct msghdr *, int);
    log_sock(fd, m->msg_iov, (int) m->msg_iovlen);
    return real_sendmsg(fd, m, fl);
}
ssize_t writev(int fd, const struct iovec *v, int c) {
    REAL(writev, ssize_t, int, const struct iovec *, int);
    log_sock(fd, v, c);
    return real_writev(fd, v, c);
}
ssize_t write(int fd, const void *b, size_t n) {
    REAL(write, ssize_t, int, const void *, size_t);
    if (fd > 2) { struct iovec v = { (void *) b, n }; log_sock(fd, &v, 1); }
    return real_write(fd, b, n);
}
