/* storage_vfs - see storage_vfs.h. */
#include "storage_vfs.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#include "platform/ng_platform.h"

#define WAL_BUF_MAX (4u * 1024u * 1024u)

typedef struct ng_file {
    sqlite3_file base;          /* must be first: pMethods */
    sqlite3_file *real;         /* the wrapped file, allocated right after us */
    bool wal;
    unsigned char *buf;         /* pending contiguous bytes [buf_off, buf_off+len) */
    size_t len;
    sqlite3_int64 buf_off;
} ng_file_t;

static sqlite3_vfs *base_vfs;
static sqlite3_vfs shim_vfs;
static sqlite3_io_methods shim_io;

/* The one WAL file with pending bytes on this thread (or NULL). */
static NG_THREAD_LOCAL ng_file_t *pending;

/* The unix VFS masks a single write to 17 bits (seekAndWriteFd: nBuf &=
 * 0x1ffff), so larger buffers go out in chunks below that. */
#define WAL_WRITE_CHUNK 0x1f000

static int flush(ng_file_t *f) {
    int rc = SQLITE_OK;
    size_t done = 0;
    while (rc == SQLITE_OK && done < f->len) {
        size_t n = f->len - done < WAL_WRITE_CHUNK ? f->len - done : WAL_WRITE_CHUNK;
        rc = f->real->pMethods->xWrite(f->real, f->buf + done, (int) n, f->buf_off + (sqlite3_int64) done);
        done += n;
    }
    f->len = 0;
    if (pending == f) pending = NULL;
    return rc;
}

static int x_close(sqlite3_file *p) {
    ng_file_t *f = (ng_file_t *) p;
    int rc = flush(f);
    int rc2 = f->real->pMethods ? f->real->pMethods->xClose(f->real) : SQLITE_OK;
    free(f->buf); f->buf = NULL;
    return rc != SQLITE_OK ? rc : rc2;
}
static int x_read(sqlite3_file *p, void *out, int n, sqlite3_int64 off) {
    ng_file_t *f = (ng_file_t *) p;
    int rc = flush(f);
    return rc != SQLITE_OK ? rc : f->real->pMethods->xRead(f->real, out, n, off);
}
static int x_write(sqlite3_file *p, const void *data, int n, sqlite3_int64 off) {
    ng_file_t *f = (ng_file_t *) p;
    if (!f->wal || n <= 0) return f->real->pMethods->xWrite(f->real, data, n, off);
    if (f->len && off != f->buf_off + (sqlite3_int64) f->len) {      /* not an append */
        int rc = flush(f);
        if (rc != SQLITE_OK) return rc;
    }
    if (f->len + (size_t) n > WAL_BUF_MAX) {
        int rc = flush(f);
        if (rc != SQLITE_OK) return rc;
        if ((size_t) n > WAL_WRITE_CHUNK) return f->real->pMethods->xWrite(f->real, data, n, off);
    }
    if (!f->buf && !(f->buf = (unsigned char *) malloc(WAL_BUF_MAX)))
        return f->real->pMethods->xWrite(f->real, data, n, off);       /* no buffer: write through */
    if (pending && pending != f) {
        int rc = flush(pending);
        if (rc != SQLITE_OK) return rc;
    }
    if (!f->len) f->buf_off = off;
    memcpy(f->buf + f->len, data, (size_t) n);
    f->len += (size_t) n;
    pending = f;
    return SQLITE_OK;
}
static int x_truncate(sqlite3_file *p, sqlite3_int64 size) {
    ng_file_t *f = (ng_file_t *) p;
    int rc = flush(f);
    return rc != SQLITE_OK ? rc : f->real->pMethods->xTruncate(f->real, size);
}
static int x_sync(sqlite3_file *p, int flags) {
    ng_file_t *f = (ng_file_t *) p;
    int rc = flush(f);
    return rc != SQLITE_OK ? rc : f->real->pMethods->xSync(f->real, flags);
}
static int x_size(sqlite3_file *p, sqlite3_int64 *size) {
    ng_file_t *f = (ng_file_t *) p;
    int rc = flush(f);
    return rc != SQLITE_OK ? rc : f->real->pMethods->xFileSize(f->real, size);
}
static int x_lock(sqlite3_file *p, int l) { return ((ng_file_t *) p)->real->pMethods->xLock(((ng_file_t *) p)->real, l); }
static int x_unlock(sqlite3_file *p, int l) { return ((ng_file_t *) p)->real->pMethods->xUnlock(((ng_file_t *) p)->real, l); }
static int x_reserved(sqlite3_file *p, int *out) {
    ng_file_t *f = (ng_file_t *) p;
    return f->real->pMethods->xCheckReservedLock(f->real, out);
}
static int x_fcntl(sqlite3_file *p, int op, void *arg) {
    ng_file_t *f = (ng_file_t *) p;
    int rc = flush(f);
    if (rc != SQLITE_OK) return rc;
    if (op == SQLITE_FCNTL_VFSNAME) {          /* report the stack, then the base name */
        int r = f->real->pMethods->xFileControl(f->real, op, arg);
        if (r == SQLITE_OK) { char *z = sqlite3_mprintf("ngwal/%z", *(char **) arg); *(char **) arg = z; }
        return r;
    }
    return f->real->pMethods->xFileControl(f->real, op, arg);
}
static int x_sector(sqlite3_file *p) { return ((ng_file_t *) p)->real->pMethods->xSectorSize(((ng_file_t *) p)->real); }
static int x_devchar(sqlite3_file *p) {
    return ((ng_file_t *) p)->real->pMethods->xDeviceCharacteristics(((ng_file_t *) p)->real);
}
/* Methods past version 1 exist only if the real file has them. */
static bool has_v(const ng_file_t *f, int v) { return f->real->pMethods->iVersion >= v; }
static int x_shm_map(sqlite3_file *p, int pg, int sz, int ext, void volatile **pp) {
    ng_file_t *f = (ng_file_t *) p;
    return has_v(f, 2) ? f->real->pMethods->xShmMap(f->real, pg, sz, ext, pp) : SQLITE_IOERR_SHMMAP;
}
static int x_shm_lock(sqlite3_file *p, int off, int n, int flags) {
    ng_file_t *f = (ng_file_t *) p;
    return has_v(f, 2) ? f->real->pMethods->xShmLock(f->real, off, n, flags) : SQLITE_IOERR_SHMLOCK;
}
static void x_shm_barrier(sqlite3_file *p) {
    ng_file_t *f = (ng_file_t *) p;
    /* A commit is about to become visible: put this thread's frames in the
     * file first. A write error here resurfaces: the bytes are gone from
     * the buffer, so the next xSync / checkpoint read fails loudly. */
    if (pending) (void) flush(pending);
    if (has_v(f, 2)) f->real->pMethods->xShmBarrier(f->real);
}
static int x_shm_unmap(sqlite3_file *p, int del) {
    ng_file_t *f = (ng_file_t *) p;
    return has_v(f, 2) ? f->real->pMethods->xShmUnmap(f->real, del) : SQLITE_OK;
}
static int x_fetch(sqlite3_file *p, sqlite3_int64 off, int n, void **pp) {
    ng_file_t *f = (ng_file_t *) p;
    int rc = flush(f);
    if (rc != SQLITE_OK) return rc;
    if (!has_v(f, 3)) { *pp = NULL; return SQLITE_OK; }
    return f->real->pMethods->xFetch(f->real, off, n, pp);
}
static int x_unfetch(sqlite3_file *p, sqlite3_int64 off, void *ptr) {
    ng_file_t *f = (ng_file_t *) p;
    return has_v(f, 3) ? f->real->pMethods->xUnfetch(f->real, off, ptr) : SQLITE_OK;
}

static int x_open(sqlite3_vfs *vfs, sqlite3_filename name, sqlite3_file *p, int flags, int *out_flags) {
    (void) vfs;
    ng_file_t *f = (ng_file_t *) p;
    memset(f, 0, sizeof(*f));
    f->real = (sqlite3_file *) (f + 1);
    f->wal = (flags & SQLITE_OPEN_WAL) != 0;
    int rc = base_vfs->xOpen(base_vfs, name, f->real, flags, out_flags);
    if (rc != SQLITE_OK) { f->base.pMethods = NULL; return rc; }
    /* Same method set as the real file: only advertise what it has. */
    f->base.pMethods = &shim_io;
    return SQLITE_OK;
}

static int x_delete(sqlite3_vfs *v, const char *z, int sync) { (void) v; return base_vfs->xDelete(base_vfs, z, sync); }
static int x_access(sqlite3_vfs *v, const char *z, int fl, int *out) { (void) v; return base_vfs->xAccess(base_vfs, z, fl, out); }
static int x_fullpath(sqlite3_vfs *v, const char *z, int n, char *out) { (void) v; return base_vfs->xFullPathname(base_vfs, z, n, out); }
static void *x_dlopen(sqlite3_vfs *v, const char *z) { (void) v; return base_vfs->xDlOpen(base_vfs, z); }
static void x_dlerror(sqlite3_vfs *v, int n, char *z) { (void) v; base_vfs->xDlError(base_vfs, n, z); }
static void (*x_dlsym(sqlite3_vfs *v, void *h, const char *z))(void) { (void) v; return base_vfs->xDlSym(base_vfs, h, z); }
static void x_dlclose(sqlite3_vfs *v, void *h) { (void) v; base_vfs->xDlClose(base_vfs, h); }
static int x_random(sqlite3_vfs *v, int n, char *z) { (void) v; return base_vfs->xRandomness(base_vfs, n, z); }
static int x_sleep(sqlite3_vfs *v, int us) { (void) v; return base_vfs->xSleep(base_vfs, us); }
static int x_time(sqlite3_vfs *v, double *t) { (void) v; return base_vfs->xCurrentTime(base_vfs, t); }
static int x_lasterr(sqlite3_vfs *v, int n, char *z) {
    (void) v;
    return base_vfs->xGetLastError ? base_vfs->xGetLastError(base_vfs, n, z) : 0;
}
static int x_time64(sqlite3_vfs *v, sqlite3_int64 *t) { (void) v; return base_vfs->xCurrentTimeInt64(base_vfs, t); }

bool ngdb_vfs_register(void) {
    if (base_vfs) return true;
    const char *env = getenv("NG_WAL_COALESCE");
    if (env && strcmp(env, "0") == 0) return true;
    sqlite3_vfs *b = sqlite3_vfs_find(NULL);
    if (!b || b->iVersion < 2 || !b->xCurrentTimeInt64) return false;
    base_vfs = b;
    shim_io = (sqlite3_io_methods) {
        3, x_close, x_read, x_write, x_truncate, x_sync, x_size, x_lock, x_unlock, x_reserved,
        x_fcntl, x_sector, x_devchar, x_shm_map, x_shm_lock, x_shm_barrier, x_shm_unmap,
        x_fetch, x_unfetch,
    };
    shim_vfs = (sqlite3_vfs) {
        2, (int) sizeof(ng_file_t) + b->szOsFile, b->mxPathname, NULL, "ngwal", NULL,
        x_open, x_delete, x_access, x_fullpath, x_dlopen, x_dlerror, x_dlsym, x_dlclose,
        x_random, x_sleep, x_time, x_lasterr, x_time64, NULL, NULL, NULL,
    };
    if (sqlite3_vfs_register(&shim_vfs, 1) != SQLITE_OK) { base_vfs = NULL; return false; }
    return true;
}
