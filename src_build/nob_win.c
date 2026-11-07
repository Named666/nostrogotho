#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#include "nob.h"
#include "config.h"
#include "folders.h"

/* Windows build target.
 *
 * The relay transport is ngws (src/ngws) on top of vendored uSockets, built
 * with its epoll backend. A native Windows build would need uSockets' libuv
 * backend, which is not vendored (we keep zero outside runtime deps), so this
 * target is unsupported for now. Build under WSL2 / Linux with
 * `./nob linux` (src_build/nob_linux.c). */
int main(void)
{
    nob_log(ERROR, "Windows build is not supported (ngws uses the uSockets epoll "
                   "backend). Build on Linux or WSL2: ./nob linux");
    return 1;
}
