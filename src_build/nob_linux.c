#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#include "nob.h"
#include "config.h"
#include "folders.h"
#include "nob_common.h"

/* Linux target shim. All build + supervisor logic lives in nob_common.h;
 * platform differences are the NOB_OS_* macros (non-_WIN32 branch). */

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "-module-only") == 0) return nob_build_module() ? 0 : 1;
    if (argc > 1 && strcmp(argv[1], "-hr") == 0) return nob_run_hot_supervisor(argc, argv);
    if (argc > 1 && strcmp(argv[1], "-test") == 0) return nob_build_and_run_tests();
    if (argc > 1 && strcmp(argv[1], "-asan") == 0) return nob_build_asan() ? 0 : 1;
    return nob_build_host(false) ? 0 : 1;
}
