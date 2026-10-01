/* ============================================================================
 * Hot-reload test: build a module, load it, evaluate its policy, rebuild
 * with a changed policy, reload, and verify the new policy is active.
 *
 * Each phase shells out to the system C compiler (same prerequisite as
 * nob itself) to build tests/hr_test_policy.c into a DLL/.so with a
 * different -DHR_POLICY_ALLOW flag. Loading mirrors src/nhr.c's
 * nhr_library_open() step for step -- unique-path copy (so the source
 * image is never locked while loaded), all six nhr_module_* symbols
 * resolved through the real nhr_platform_* primitives, ABI version
 * handshake -- except the copy/open/close helpers live here so the test
 * links only nhr_<platform>.c + nip_capability.c instead of half the
 * relay. Any drift from nhr_library_open() must update this mirror.
 *
 * Flow:
 *   build v1 (allow) -> load -> policy permits
 *   build v2 (deny)   -> unload v1 -> load v2 -> policy rejects
 *   build v3 (bad ABI) -> load must be refused
 *   load of a missing file must fail gracefully (no crash)
 *
 * Run: build/test_hotreload(.exe) -- exit code is the failure count.
 * Artifacts (build/hr_case_*) are removed on success AND failure.
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nhr.h"
#include "nhr_loader.h"
#include "nip_capability.h"

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

#ifdef _WIN32
#define MODULE_EXT ".dll"
#define CC_CANDIDATES_COUNT 2
static const char *cc_candidates[] = {"gcc", "cc"};
#else
#define MODULE_EXT ".so"
#define CC_CANDIDATES_COUNT 2
static const char *cc_candidates[] = {"cc", "gcc"};
#endif

static char cc_cmd[256] = {0};

/* Pick a working C compiler (nob has the same prerequisite). */
static int find_compiler(void) {
    size_t i;
    for (i = 0; i < CC_CANDIDATES_COUNT; i++) {
        char probe[300];
        snprintf(probe, sizeof(probe), "%s --version >%s 2>&1",
                 cc_candidates[i],
#ifdef _WIN32
                 "NUL"
#else
                 "/dev/null"
#endif
        );
        if (system(probe) == 0) {
            snprintf(cc_cmd, sizeof(cc_cmd), "%s", cc_candidates[i]);
            return 1;
        }
    }
    return 0;
}

/* Compile tests/hr_test_policy.c into build/<name>.<dll|so>.
 * extra_flags carries e.g. "-DHR_POLICY_ALLOW=0". Returns nonzero on ok. */
static int build_module(const char *name, const char *extra_flags) {
    char cmd[2048];
    int rc;
    snprintf(cmd, sizeof(cmd),
             "%s -std=c99 -DNHR_BUILD_MODULE -DSECP256K1_STATIC %s "
             "-Ibuild -I. -Isrc -Isrc/nips -Ithirdparty "
             "-Ithirdparty/mongoose "
#ifdef _WIN32
             "-shared -Wl,--export-all-symbols "
#else
             "-fPIC -fvisibility=hidden -shared "
#endif
             "-o build/%s%s tests/hr_test_policy.c "
             "src/nips/nip_capability.c",
             cc_cmd, extra_flags, name, MODULE_EXT);
    rc = system(cmd);
    return rc == 0;
}

/* Faithful mirror of nhr_library_open() (src/nhr.c): resolve the six ABI
 * symbols through the platform loader, then verify the ABI version. */
static int test_lib_open(const char *path, Nhr_Library *out) {
    char error[512] = {0};
    Nhr_Library candidate;
    memset(&candidate, 0, sizeof(candidate));
    if (!out || !path) return 0;

    candidate.handle = nhr_platform_open(path, error, sizeof(error));
    if (!candidate.handle) {
        printf("  (loader: %s)\n", error[0] ? error : "unknown loader error");
        memset(out, 0, sizeof(*out));
        return 0;
    }

#define HR_RESOLVE(ret, name, args)                                            \
    do {                                                                       \
        error[0] = '\0';                                                       \
        if (!nhr_platform_symbol(candidate.handle, "nhr_module_" #name,        \
                                 &candidate.api.name,                          \
                                 sizeof(candidate.api.name), error,             \
                                 sizeof(error))) {                             \
            printf("  (missing symbol nhr_module_%s: %s)\n", #name,             \
                   error[0] ? error : "not found");                            \
            nhr_platform_close(candidate.handle);                              \
            memset(out, 0, sizeof(*out));                                      \
            return 0;                                                          \
        }                                                                      \
    } while (0);
    NHR_MODULE_FUNCTIONS(HR_RESOLVE)
#undef HR_RESOLVE

    if (candidate.api.abi_version() != NHR_ABI_VERSION) {
        printf("  (ABI mismatch: module=%u host=%u)\n",
               candidate.api.abi_version(), NHR_ABI_VERSION);
        nhr_platform_close(candidate.handle);
        memset(out, 0, sizeof(*out));
        return 0;
    }
    snprintf(candidate.loaded_path, sizeof(candidate.loaded_path), "%s", path);
    *out = candidate;
    return 1;
}

/* Mirror of nhr_library_close(): unload and remove the unique copy. */
static void test_lib_close(Nhr_Library *library) {
    if (!library) return;
    if (library->handle) nhr_platform_close(library->handle);
    if (library->loaded_path[0]) remove(library->loaded_path);
    memset(library, 0, sizeof(*library));
}

static event_t dummy_event(void) {
    event_t ev;
    memset(&ev, 0, sizeof(ev));
    snprintf(ev.id, sizeof(ev.id),
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    snprintf(ev.pubkey, sizeof(ev.pubkey),
             "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    ev.kind = 1;
    return ev;
}

/* Evaluate the loaded generation's publication policy. */
static int policy_permits(Nhr_Library *lib, char *reason, size_t reason_size) {
    nip_registry_t *reg = nip_registry_create();
    event_t ev = dummy_event();
    int ok;
    if (!reg) return -1;
    lib->api.register_capabilities(reg);
    ok = nip_composition_check_publication(reg, 1, &ev, reason, reason_size);
    nip_registry_destroy(reg);
    return ok;
}

static void cleanup_artifacts(void) {
    static const char *files[] = {
        "build/hr_case_allow" MODULE_EXT,
        "build/hr_case_deny" MODULE_EXT,
        "build/hr_case_badabi" MODULE_EXT,
        "build/hr_run_v1" MODULE_EXT,
        "build/hr_run_v2" MODULE_EXT,
        "build/hr_run_v3" MODULE_EXT,
    };
    size_t i;
    for (i = 0; i < sizeof(files) / sizeof(files[0]); i++)
        remove(files[i]);
}

int main(void) {
    Nhr_Library lib;
    char reason[128];
    printf("Running hot-reload tests...\n");

    if (!find_compiler()) {
        printf("FAIL: no C compiler on PATH (tried gcc/cc) -- same "
               "prerequisite as nob itself\n");
        return 1;
    }
    printf("  compiler: %s\n", cc_cmd);
    memset(&lib, 0, sizeof(lib));

    /* --- Generation 1: allow policy --- */
    CHECK(build_module("hr_case_allow", "-DHR_POLICY_ALLOW=1"),
          "build generation 1 (allow)");
    if (g_fail) {
        cleanup_artifacts();
        printf("hotreload: %d passed, %d failed\n", g_pass, g_fail);
        return 1;
    }
    CHECK(nhr_platform_copy("build/hr_case_allow" MODULE_EXT,
                            "build/hr_run_v1" MODULE_EXT),
          "copy v1 to unique load path");
    CHECK(test_lib_open("build/hr_run_v1" MODULE_EXT, &lib),
          "load generation 1 (symbols + ABI check)");
    CHECK(lib.api.init(NULL, NULL, NULL), "gen1 init callable");
    CHECK(lib.api.pre_reload().version == NHR_STATE_VERSION,
          "gen1 pre_reload callable");
    memset(reason, 0, sizeof(reason));
    CHECK(policy_permits(&lib, reason, sizeof(reason)) == 1,
          "gen1 allow policy permits sends");

    /* --- Generation 2: deny policy, built WHILE v1 is still loaded.
     * The source image must never be locked by the running generation. --- */
    CHECK(build_module("hr_case_deny", "-DHR_POLICY_ALLOW=0"),
          "rebuild with changed policy while v1 loaded");
    test_lib_close(&lib);
    CHECK(lib.handle == NULL, "unload generation 1");
    CHECK(nhr_platform_copy("build/hr_case_deny" MODULE_EXT,
                            "build/hr_run_v2" MODULE_EXT),
          "copy v2 to unique load path");
    CHECK(test_lib_open("build/hr_run_v2" MODULE_EXT, &lib),
          "load generation 2");
    memset(reason, 0, sizeof(reason));
    CHECK(policy_permits(&lib, reason, sizeof(reason)) == 0 &&
          strstr(reason, "hr-test: deny") != NULL,
          "gen2 deny policy active after reload");
    CHECK(lib.api.shutdown != NULL, "gen2 shutdown resolvable");
    lib.api.shutdown();
    test_lib_close(&lib);

    /* --- Generation 3: wrong ABI must be refused at load. --- */
    CHECK(build_module("hr_case_badabi",
                       "-DHR_POLICY_ALLOW=1 -DHR_ABI_OVERRIDE=1"),
          "build generation 3 (bad ABI)");
    CHECK(nhr_platform_copy("build/hr_case_badabi" MODULE_EXT,
                            "build/hr_run_v3" MODULE_EXT),
          "copy v3 to unique load path");
    memset(&lib, 0, sizeof(lib));
    CHECK(!test_lib_open("build/hr_run_v3" MODULE_EXT, &lib),
          "ABI-mismatched module refused");
    CHECK(lib.handle == NULL, "refused load leaves clean state");

    /* --- Missing file must fail gracefully. --- */
    memset(&lib, 0, sizeof(lib));
    CHECK(!test_lib_open("build/hr_case_missing" MODULE_EXT, &lib),
          "missing module fails gracefully");
    test_lib_close(&lib);
    test_lib_close(NULL);

    cleanup_artifacts();
    printf("hotreload: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
