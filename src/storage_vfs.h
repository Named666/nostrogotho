/* storage_vfs - SQLite VFS shim that coalesces WAL frame writes.
 *
 * SQLite appends each WAL frame with two write(2) calls (24-byte header,
 * then the page), so a batch commit that dirties N pages costs 2N
 * syscalls. The shim buffers contiguous appends to a WAL file (per file
 * handle, owned by the thread that wrote them) and issues them as large
 * writes. The buffer is flushed before anything can depend on it:
 *   - xSync (FULL commits, checkpoints): flush, then the real sync;
 *   - xShmBarrier on any database file, from the owning thread: SQLite
 *     calls it between the two copies of the wal-index header it writes
 *     when a transaction commits, so no reader can see the new frames
 *     before they are in the file (this covers synchronous=NORMAL, where
 *     commits do not sync the WAL);
 *   - xRead, xTruncate, xFileSize, xFileControl, xClose on that file, a
 *     write that is not a contiguous append, a full buffer.
 * Every other file (database, journals) passes straight through.
 *
 * Thread model: a buffer is only touched by the thread that filled it
 * (SQLite connections are single-threaded here: NOMUTEX, one per thread).
 * NG_WAL_COALESCE=0 disables the shim (A/B benchmarks).
 */
#ifndef STORAGE_VFS_H_
#define STORAGE_VFS_H_

#include <stdbool.h>

/* Register the shim as the default VFS (idempotent; before any open).
 * false when the underlying default VFS is missing or registration fails. */
bool ngdb_vfs_register(void);

#endif /* STORAGE_VFS_H_ */
