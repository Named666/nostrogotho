#ifndef NOB_COMMON_H_
#define NOB_COMMON_H_

/* Shared nob hot-reload/supervisor helpers.
 *
 * nob_win.c and nob_linux.c include this file so watch logic, NIP discovery,
 * debounce/retry, and core source lists stay identical across targets.
 * Platform files keep only: compiler flags, OS libs, .dll/.so names,
 * nhr_windows.c vs nhr_posix.c, and the supervisor loop timing.
 *
 * Drop-in NIP model: every src/nips/*.c except nip_template.c is a
 * self-registering capability provider. Adding/removing/changing a file
 * triggers a module-only rebuild; the host keeps sockets/SQLite/subs alive.
 */

#include <string.h>
#include <sys/stat.h>
#include <signal.h>

static bool nob_add_nip_sources(Cmd *cmd) {
    const char *nips_dir = SRC_FOLDER"nips/";
    File_Paths nips = {0};
    if (!read_entire_dir(nips_dir, &nips)) {
        nob_log(ERROR, "Could not list NIP sources in %s", nips_dir);
        return false;
    }
    for (size_t i = 0; i < nips.count; i++) {
        const char *name = path_name(nips.items[i]);
        size_t len = strlen(name);
        if (len < 3 || strcmp(name + len - 2, ".c") != 0 ||
            strcmp(name, "nip_template.c") == 0 ||
            strcmp(name, "nip_composition_policy.c") == 0) continue;
        nob_cmd_append(cmd, nob_temp_sprintf("%s%s", nips_dir, name));
    }
    free(nips.items);
    return true;
}

static bool nob_watched_file_changed(const char *path, struct stat *stamp) {
    struct stat current;
    if (stat(path, &current) != 0) {
        if (stamp->st_mtime != 0 || stamp->st_size != 0) {
            memset(stamp, 0, sizeof(*stamp));
            return true;
        }
        return false;
    }
    if (stamp->st_mtime != current.st_mtime || stamp->st_size != current.st_size) {
        *stamp = current;
        return true;
    }
    return false;
}

static bool nob_is_nip_build_input(const char *name) {
    size_t length = strlen(name);
    return length > 2 &&
           (strcmp(name + length - 2, ".c") == 0 ||
            strcmp(name + length - 2, ".h") == 0) &&
           strcmp(name, "nip_template.c") != 0;
}

static bool nob_read_nip_build_inputs(File_Paths *files) {
    if (!read_entire_dir(SRC_FOLDER"nips/", files)) return false;
    size_t output = 0;
    for (size_t index = 0; index < files->count; index++) {
        const char *name = path_name(files->items[index]);
        if (nob_is_nip_build_input(name)) files->items[output++] = files->items[index];
    }
    files->count = output;
    return true;
}

static bool nob_watched_inputs_changed(const char **paths, struct stat *stamps,
                                       size_t count) {
    bool changed = false;
    for (size_t index = 0; index < count; index++)
        changed |= nob_watched_file_changed(paths[index], &stamps[index]);
    return changed;
}

static volatile sig_atomic_t nob_stop_requested;

static void nob_handle_stop_signal(int signal_number) {
    (void)signal_number;
    nob_stop_requested = 1;
}

/* Platform deltas (the ONLY per-target differences). nob_win.c and
 * nob_linux.c are thin shims; all build + supervisor logic below is shared. */
#ifdef _WIN32
#define NOB_OS_MODULE_NEXT "build/nostrogotho.next.dll"
#define NOB_OS_MODULE_PUBLISHED BUILD_FOLDER"nostrogotho.dll"
#define NOB_OS_HOST_EXE BUILD_FOLDER"main.exe"
#define NOB_OS_NHR_SRC SRC_FOLDER"nhr_windows.c"
#define NOB_OS_EXTRA_DEFINES "-DSECP256K1_STATIC"
#define NOB_OS_MODULE_FLAGS "-shared", "-Wl,--export-all-symbols"
#define NOB_OS_LIBS "-lbcrypt", "-lws2_32", "-lwinpthread"
/* Stacktraces need symbols + frame pointers + CRASH_DEBUG.
 * Release omits CRASH_DEBUG (compiles to nothing). */
#define NOB_OS_DEBUG_FLAGS "-g", "-Og", "-fno-omit-frame-pointer", "-DCRASH_DEBUG"
#else
#define NOB_OS_MODULE_NEXT "build/nostrogotho.next.so"
#define NOB_OS_MODULE_PUBLISHED BUILD_FOLDER"nostrogotho.so"
#define NOB_OS_HOST_EXE BUILD_FOLDER"main"
#define NOB_OS_NHR_SRC SRC_FOLDER"nhr_posix.c"
#define NOB_OS_EXTRA_DEFINES "-D_GNU_SOURCE"
#define NOB_OS_MODULE_FLAGS "-fPIC", "-fvisibility=hidden", "-shared"
#define NOB_OS_LIBS "-lpthread", "-lm", "-ldl"
/* addr2line needs -g; FP walk needs -fno-omit-frame-pointer; dladdr needs -rdynamic. */
#define NOB_OS_DEBUG_FLAGS "-g", "-Og", "-fno-omit-frame-pointer", "-rdynamic", "-DCRASH_DEBUG"
#endif

/* Core sources shared by every artifact. Policy layer removed: relay.c owns
 * the EVENT/REQ pipeline directly (policy/ was dead code). */
#define NOB_SECP_DEFINES \
    "-DSECP256K1_STATIC", \
    "-DENABLE_MODULE_ECDH=1", "-DENABLE_MODULE_EXTRAKEYS=1", \
    "-DENABLE_MODULE_SCHNORRSIG=1", "-DENABLE_MODULE_MUSIG=1", \
    "-DENABLE_MODULE_ELLSWIFT=1", "-DENABLE_MODULE_SILENTPAYMENTS=1", \
    "-DENABLE_MODULE_RECOVERY=1", "-DECMULT_WINDOW_SIZE=15", \
    "-DCOMB_BLOCKS=43", "-DCOMB_TEETH=6"

#define NOB_THIRD_PARTY_SOURCES \
    THIRD_PARTY_FOLDER"sqlite3.c", THIRD_PARTY_FOLDER"mongoose/mongoose.c", \
    THIRD_PARTY_FOLDER"secp256k1/src/secp256k1.c", \
    THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult.c", \
    THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult_gen.c"

/* Module = capabilities + stateless helpers. Host owns relay.c/server.c
 * (event loop, dispatch), storage.c, nhr.c — never compiled into the module
 * so a reload swaps only behavior, never sockets/SQLite/subs. */
#define NOB_MODULE_SOURCES \
    SRC_FOLDER"nhr_module.c", \
    SRC_FOLDER"crypto.c", \
    SRC_FOLDER"json_util.c", SRC_FOLDER"nostrogotho.c", \
    SRC_FOLDER"log.c", \
    SRC_FOLDER"relay/connection_session.c", \
    SRC_FOLDER"relay/config.c", \
    SRC_FOLDER"subscriptions/subscription_manager.c", \
    SRC_FOLDER"protocol/protocol.c", \
    SRC_FOLDER"protocol/parser.c", \
    SRC_FOLDER"protocol/filter_builder.c", \
    SRC_FOLDER"protocol/tag_iter.c", \
    SRC_FOLDER"protocol/event_tags.c"

#define NOB_HOST_SOURCES \
    SRC_FOLDER"main.c", SRC_FOLDER"crypto.c", \
    SRC_FOLDER"crash.c", \
    SRC_FOLDER"storage.c", \
    SRC_FOLDER"nostrogotho.c", SRC_FOLDER"json_util.c", \
    SRC_FOLDER"log.c", \
    SRC_FOLDER"relay/relay.c", SRC_FOLDER"relay/connection_session.c", \
    SRC_FOLDER"relay/config.c", SRC_FOLDER"relay/config_file.c", \
    SRC_FOLDER"transport/server.c", \
    SRC_FOLDER"subscriptions/subscription_manager.c", \
    SRC_FOLDER"protocol/protocol.c", \
    SRC_FOLDER"protocol/parser.c", \
    SRC_FOLDER"protocol/filter_builder.c", \
    SRC_FOLDER"protocol/tag_iter.c", \
    SRC_FOLDER"protocol/event_tags.c"
/* NIP sources (registry + one nipXX.c per NIP) always come from the
 * nob_add_nip_sources() glob — never listed explicitly, or they link twice.
 * Exception: the hot-reload host links ONLY the registry (implementations
 * live in the DLL), so hot builds append nips/nip_capability.c explicitly. */

/* Files watched for module rebuilds: module inputs + registry.
 * NIP add/remove/change detected via directory scan in the supervisor loop. */
#define NOB_WATCH_PATHS \
    SRC_FOLDER"nhr_module.c", SRC_FOLDER"nhr.h", SRC_FOLDER"nhr_module.h", \
    SRC_FOLDER"crypto.h", SRC_FOLDER"storage.h", \
    SRC_FOLDER"json_util.c", SRC_FOLDER"json_util.h", \
    SRC_FOLDER"nostrogotho.c", SRC_FOLDER"nostrogotho.h", \
    SRC_FOLDER"relay/relay.h", SRC_FOLDER"relay/relay.c", \
    SRC_FOLDER"relay/connection_session.h", SRC_FOLDER"relay/connection_session.c", \
    SRC_FOLDER"relay/config.h", SRC_FOLDER"relay/config.c", \
    SRC_FOLDER"transport/server.h", SRC_FOLDER"transport/server.c", \
    SRC_FOLDER"subscriptions/subscription_manager.h", SRC_FOLDER"subscriptions/subscription_manager.c", \
    SRC_FOLDER"protocol/protocol.h", SRC_FOLDER"protocol/protocol.c", \
    SRC_FOLDER"protocol/parser.h", SRC_FOLDER"protocol/parser.c", \
    SRC_FOLDER"protocol/filter_builder.h", SRC_FOLDER"protocol/filter_builder.c", \
    SRC_FOLDER"protocol/tag_iter.h", SRC_FOLDER"protocol/tag_iter.c", \
    SRC_FOLDER"protocol/event_tags.h", SRC_FOLDER"protocol/event_tags.c", \
    SRC_FOLDER"nips/nip_capability.h", SRC_FOLDER"nips/nip_capability.c", \
    SRC_FOLDER"nips/nip_macros.h"

/* Build the reloadable module under a staging name, then atomically publish.
 * A failed compile never touches the last good artifact. */
static bool nob_build_module(void) {
    Cmd cmd = {0};
    nob_cc(&cmd);
    nob_cc_flags(&cmd);
    nob_cmd_append(&cmd, "-std=c99", NOB_OS_EXTRA_DEFINES, NOB_SECP_DEFINES,
                   NOB_OS_DEBUG_FLAGS,
                   "-DNHR_BUILD_MODULE", "-DNHR_DYNAMIC_MODULE",
                   NOB_OS_MODULE_FLAGS,
                   "-I"BUILD_FOLDER, "-I.", "-I"SRC_FOLDER, "-I"SRC_FOLDER"nips",
                   "-I"THIRD_PARTY_FOLDER, "-I"THIRD_PARTY_FOLDER"mongoose",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/include",
                   "-I"THIRD_PARTY_FOLDER"secp256k1",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/src",
                   "-o", NOB_OS_MODULE_NEXT,
                   NOB_MODULE_SOURCES, NOB_THIRD_PARTY_SOURCES);
    if (!nob_add_nip_sources(&cmd)) return false;
#ifdef _WIN32
    nob_cmd_append(&cmd, "-lbcrypt", "-lws2_32", "-lwinpthread");
#else
    nob_cmd_append(&cmd, "-lpthread", "-lm");
#endif
    if (!cmd_run(&cmd)) return false;
    if (!nob_rename(NOB_OS_MODULE_NEXT, NOB_OS_MODULE_PUBLISHED)) {
        nob_log(ERROR, "Could not atomically publish hot-reload module");
        return false;
    }
    return true;
}

/* Build the permanent host. Hot hosts link no NIP implementations:
 * capabilities come from the module. Monolithic hosts glob them in. */
static bool nob_build_host(bool dynamic_module) {
    Cmd cmd = {0};
    nob_cc(&cmd);
    nob_cc_flags(&cmd);
    nob_cmd_append(&cmd, "-std=c99", NOB_OS_EXTRA_DEFINES, NOB_SECP_DEFINES,
                   NOB_OS_DEBUG_FLAGS,
                   dynamic_module ? "-DNHR_DYNAMIC_MODULE" : "-DNHR_STATIC_MODULE",
                   "-I"BUILD_FOLDER, "-I.", "-I"SRC_FOLDER, "-I"SRC_FOLDER"nips",
                   "-I"THIRD_PARTY_FOLDER, "-I"THIRD_PARTY_FOLDER"mongoose",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/include",
                   "-I"THIRD_PARTY_FOLDER"secp256k1",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/src");
    nob_cc_output(&cmd, NOB_OS_HOST_EXE);
    nob_cc_inputs(&cmd, NOB_HOST_SOURCES, SRC_FOLDER"nhr.c", NOB_OS_NHR_SRC,
                  NOB_THIRD_PARTY_SOURCES);
    if (dynamic_module) {
        /* Hot-reload host: link registry + infrastructure explicitly.
         * NIP implementations live in the DLL, so we don't glob them. */
        nob_cmd_append(&cmd, SRC_FOLDER"nips/nip_capability.c",
                       SRC_FOLDER"nips/nip_composition_policy.c");
    } else {
        /* Monolithic host: glob all NIP sources including infrastructure. */
        nob_cmd_append(&cmd, SRC_FOLDER"nips/nip_composition_policy.c");
        if (!nob_add_nip_sources(&cmd)) return false;
    }
    nob_cmd_append(&cmd, NOB_OS_LIBS);
    return cmd_run(&cmd);
}

/* Phase 3: ASan+UBSan build (Linux only; not supported on MinGW).
 * Flags: -fsanitize=address,undefined -g -fno-omit-frame-pointer.
 * Plus -Wall -Wextra (via nob_cc_flags) + -fanalyzer for static analysis. */
static bool nob_build_asan(void) {
#ifdef _WIN32
    nob_log(ERROR, "ASan: -fsanitize=address,undefined not supported on MinGW; use Linux gcc");
    return false;
#else
    Cmd cmd = {0};
    nob_cc(&cmd);
    nob_cc_flags(&cmd);
    nob_cmd_append(&cmd, "-std=c99", NOB_OS_EXTRA_DEFINES, NOB_SECP_DEFINES,
                   "-g", "-Og", "-fno-omit-frame-pointer", "-rdynamic",
                   "-DCRASH_DEBUG",
                   "-DNHR_STATIC_MODULE",
                   "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                   "-fanalyzer",
                   "-I"BUILD_FOLDER, "-I.", "-I"SRC_FOLDER, "-I"SRC_FOLDER"nips",
                   "-I"THIRD_PARTY_FOLDER, "-I"THIRD_PARTY_FOLDER"mongoose",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/include",
                   "-I"THIRD_PARTY_FOLDER"secp256k1",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/src");
    nob_cc_output(&cmd, BUILD_FOLDER"main_asan");
    nob_cc_inputs(&cmd, NOB_HOST_SOURCES, SRC_FOLDER"nhr.c", NOB_OS_NHR_SRC,
                  NOB_THIRD_PARTY_SOURCES);
    nob_cmd_append(&cmd, SRC_FOLDER"nips/nip_composition_policy.c");
    if (!nob_add_nip_sources(&cmd)) return false;
    nob_cmd_append(&cmd, NOB_OS_LIBS);
    return cmd_run(&cmd);
#endif
}

static void nob_refresh_nip_stamps(File_Paths *watched_nips, struct stat **nip_stamps) {
    free(watched_nips->items);
    free(*nip_stamps);
    memset(watched_nips, 0, sizeof(*watched_nips));
    *nip_stamps = NULL;
    if (!nob_read_nip_build_inputs(watched_nips)) return;
    *nip_stamps = (struct stat *)calloc(watched_nips->count ? watched_nips->count : 1,
                                        sizeof(**nip_stamps));
    if (!*nip_stamps) return;
    for (size_t i = 0; i < watched_nips->count; i++)
        (void)stat(nob_temp_sprintf("%s%s", SRC_FOLDER"nips/",
                                    path_name(watched_nips->items[i])),
                   &(*nip_stamps)[i]);
}

/* Start (or restart) the hot-reload host child. Relay args are argv[2..]
 * (argv[0] is the supervisor binary, argv[1] is "-hr"). The child inherits
 * the supervisor's stdout/stderr, so crash stack traces printed by the
 * host appear in the same terminal as nob debug logs. */
static Nob_Proc nob_start_hot_host(int argc, char **argv) {
    Cmd cmd = {0};
    nob_cmd_append(&cmd, NOB_OS_HOST_EXE, "--hot-reload", "--module",
                   NOB_OS_MODULE_PUBLISHED);
    for (int i = 2; i < argc; i++) nob_cmd_append(&cmd, argv[i]);
    return nob_cmd_start(&cmd);
}

/* Classify a dead host: 1 = clean exit (stop supervisor), 0 = crashed and
 * successfully restarted (keep watching), -1 = stop requested or restart
 * failed (terminate supervisor with an error unless stopped).
 * The host prints its own stacktrace to stderr (inherited), so it appears
 * in the same terminal as nob logs. */
static int nob_handle_hot_host_exit(Nob_Proc *host, int status, int argc,
                                    char **argv, unsigned *crash_restarts,
                                    uint64_t *host_start_nanos) {
    if (status == 1) return 1;
    if (nob_stop_requested) return -1;
    {
        uint64_t now = nob_nanos_since_unspecified_epoch();
        if (now - *host_start_nanos > (uint64_t)10 * (uint64_t)NOB_NANOS_PER_SEC)
            *crash_restarts = 0;
        (*crash_restarts)++;
        nob_log(ERROR, "NHR: host process crashed; stack trace above (if any). Restarting (attempt %u)...",
                *crash_restarts);
        {
            unsigned wait_ms = *crash_restarts > 6 ? 3000 : 500 * *crash_restarts;
            for (unsigned waited = 0; waited < wait_ms && !nob_stop_requested; waited += 100)
                nob_sleep_ms(100);
        }
        if (nob_stop_requested) return -1;
        *host = nob_start_hot_host(argc, argv);
        if (*host == NOB_INVALID_PROC) {
            nob_log(ERROR, "NHR: could not restart host after crash");
            return -1;
        }
        *host_start_nanos = nob_nanos_since_unspecified_epoch();
        nob_log(INFO, "NHR: host restarted after crash (attempt %u)", *crash_restarts);
        return 0;
    }
}

/* Hot supervisor: build host+module, run the host, rebuild module-only on
 * source change. Relay args after `-hr` are forwarded to the host.
 * If the host crashes (non-zero exit / signal death), the supervisor logs
 * the event and restarts it instead of exiting, so a segfault in the relay
 * or in freshly reloaded module code does not kill the dev session. A
 * clean host exit (status 0) still stops the supervisor. Ctrl-C stops and
 * reaps the child. */
static int nob_run_hot_supervisor(int argc, char **argv) {
    nob_stop_requested = 0;
    signal(SIGINT, nob_handle_stop_signal);
    signal(SIGTERM, nob_handle_stop_signal);
    if (!nob_build_module()) return nob_stop_requested ? 0 : 1;
    if (nob_stop_requested) return 0;
    if (!nob_build_host(true)) return nob_stop_requested ? 0 : 1;
    if (nob_stop_requested) return 0;

    Nob_Proc host = nob_start_hot_host(argc, argv);
    if (host == NOB_INVALID_PROC) return 1;
    uint64_t host_start_nanos = nob_nanos_since_unspecified_epoch();
    unsigned crash_restarts = 0;

    File_Paths previous = {0};
    if (!nob_read_nip_build_inputs(&previous)) {
        nob_proc_terminate(host);
        return 1;
    }
    const char *watch_paths[] = { NOB_WATCH_PATHS };
    struct stat stamps[sizeof(watch_paths) / sizeof(watch_paths[0])];
    memset(stamps, 0, sizeof(stamps));
    for (size_t i = 0; i < sizeof(watch_paths) / sizeof(watch_paths[0]); i++)
        (void)stat(watch_paths[i], &stamps[i]);
    File_Paths watched_nips = {0};
    struct stat *nip_stamps = NULL;
    nob_refresh_nip_stamps(&watched_nips, &nip_stamps);
    if (!nip_stamps) {
        free(previous.items);
        free(watched_nips.items);
        nob_proc_terminate(host);
        return 1;
    }
    bool retry_build = false;
    while (!nob_stop_requested) {
        int status = nob_proc_poll(host);
        if (status != 0) {
            int action = nob_handle_hot_host_exit(&host, status, argc, argv,
                                                 &crash_restarts,
                                                 &host_start_nanos);
            if (action == 1) {
                free(previous.items); free(watched_nips.items); free(nip_stamps);
                return 0;
            }
            if (action == -1) {
                free(previous.items); free(watched_nips.items); free(nip_stamps);
                return nob_stop_requested ? 0 : 1;
            }
            continue;
        }
        File_Paths current = {0};
        if (!nob_read_nip_build_inputs(&current)) {
            free(previous.items);
            nob_proc_terminate(host);
            free(watched_nips.items); free(nip_stamps);
            return 1;
        }
        bool changed = retry_build || current.count != previous.count;
        for (size_t i = 0; !changed && i < current.count; i++) {
            bool found = false;
            for (size_t j = 0; j < previous.count; j++) {
                if (strcmp(path_name(current.items[i]), path_name(previous.items[j])) == 0) { found = true; break; }
            }
            if (!found) changed = true;
        }
        changed |= nob_watched_inputs_changed(watch_paths, stamps,
                                              sizeof(watch_paths) / sizeof(watch_paths[0]));
        if (!changed) {
            for (size_t i = 0; i < current.count; i++) {
                const char *current_name = path_name(current.items[i]);
                const char *current_path = nob_temp_sprintf("%s%s", SRC_FOLDER"nips/", current_name);
                bool found = false;
                for (size_t j = 0; j < watched_nips.count; j++) {
                    if (strcmp(current_name, path_name(watched_nips.items[j])) == 0) {
                        found = true;
                        if (nob_watched_file_changed(current_path, &nip_stamps[j])) changed = true;
                        break;
                    }
                }
                if (!found || changed) { changed = true; break; }
            }
        }
        if (changed) {
            for (int debounce = 0; debounce < 3 && !nob_stop_requested; debounce++) {
                nob_sleep_ms(100);
                bool moved = nob_watched_inputs_changed(watch_paths, stamps,
                                                        sizeof(watch_paths) / sizeof(watch_paths[0]));
                for (size_t i = 0; i < current.count && !moved; i++) {
                    const char *current_path = nob_temp_sprintf("%s%s", SRC_FOLDER"nips/",
                                                                path_name(current.items[i]));
                    for (size_t j = 0; j < watched_nips.count; j++) {
                        if (strcmp(path_name(current.items[i]), path_name(watched_nips.items[j])) == 0) {
                            moved |= nob_watched_file_changed(current_path, &nip_stamps[j]);
                            break;
                        }
                    }
                }
                if (!moved) break;
            }
            if (nob_stop_requested) { free(current.items); break; }
            if (!nob_build_module()) {
                nob_log(WARNING, "NHR: module build failed; keeping active image and retrying");
                retry_build = true;
                free(current.items);
            } else {
                free(previous.items);
                previous = current;
                nob_refresh_nip_stamps(&watched_nips, &nip_stamps);
                if (!nip_stamps) {
                    free(previous.items);
                    nob_proc_terminate(host);
                    return 1;
                }
                retry_build = false;
            }
            if (nob_stop_requested) break;
        } else free(current.items);
        for (int tick = 0; tick < (retry_build ? 10 : 4) && !nob_stop_requested; tick++) {
            status = nob_proc_poll(host);
            if (status != 0) {
                int action = nob_handle_hot_host_exit(&host, status, argc, argv,
                                                     &crash_restarts,
                                                     &host_start_nanos);
                if (action == 1) {
                    free(watched_nips.items); free(nip_stamps); free(previous.items);
                    return 0;
                }
                if (action == -1) {
                    free(watched_nips.items); free(nip_stamps); free(previous.items);
                    return nob_stop_requested ? 0 : 1;
                }
                break;
            }
            nob_sleep_ms(100);
        }
    }
    free(previous.items);
    free(watched_nips.items);
    free(nip_stamps);
    nob_log(INFO, "NHR: stopping relay child");
    return nob_proc_terminate(host) ? 0 : 1;
}

/* ============================================================================
 * Unit / integration tests (tests/test_*.c).
 *
 * Each test compiles to build/test_<name>(.exe) with the same flags the
 * relay itself uses, then runs; the target fails if any test binary
 * exits nonzero. Source lists live here (never globbed) so every test
 * links exactly what it needs:
 *   test_crypto          crypto.c + nip26 + registry + nostr/json/mongoose
 *                        + secp256k1 (signs in-test, verifies via crypto.c)
 *   test_json_fuzz       json_util + nostrogotho + mongoose (deterministic
 *                        structured fuzz, fixed seed unless argv overrides)
 *   test_nip_composition nip_capability.c only (mock conflicting policies)
 *   test_hotreload       platform loader + nip_capability.c; the test itself
 *                        compiles/lapses two module generations at runtime
 * ============================================================================ */

#ifdef _WIN32
#define NOB_TEST_EXE(name) BUILD_FOLDER name ".exe"
#define NOB_TEST_NHR_PLATFORM SRC_FOLDER"nhr_windows.c"
#else
#define NOB_TEST_EXE(name) BUILD_FOLDER name
#define NOB_TEST_NHR_PLATFORM SRC_FOLDER"nhr_posix.c"
#endif

#define NOB_TEST_INCLUDES \
    "-I"BUILD_FOLDER, "-I.", "-I"SRC_FOLDER, "-I"SRC_FOLDER"nips", \
    "-I"THIRD_PARTY_FOLDER, "-I"THIRD_PARTY_FOLDER"mongoose", \
    "-I"THIRD_PARTY_FOLDER"secp256k1/include", \
    "-I"THIRD_PARTY_FOLDER"secp256k1", \
    "-I"THIRD_PARTY_FOLDER"secp256k1/src"

#define NOB_TEST_SECP_SOURCES \
    THIRD_PARTY_FOLDER"secp256k1/src/secp256k1.c", \
    THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult.c", \
    THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult_gen.c"

static bool nob_build_one_test(const char *test_src, const char *exe,
                               const char *const *sources, size_t source_count,
                               bool need_secp) {
    Cmd cmd = {0};
    size_t i;
    nob_cc(&cmd);
    nob_cc_flags(&cmd);
    nob_cmd_append(&cmd, "-std=c99", NOB_OS_EXTRA_DEFINES, NOB_OS_DEBUG_FLAGS);
    if (need_secp) nob_cmd_append(&cmd, NOB_SECP_DEFINES);
    nob_cmd_append(&cmd, NOB_TEST_INCLUDES, "-o", exe, test_src);
    for (i = 0; i < source_count; i++) nob_cmd_append(&cmd, sources[i]);
    if (need_secp) nob_cmd_append(&cmd, NOB_TEST_SECP_SOURCES);
    nob_cmd_append(&cmd, NOB_OS_LIBS);
    return cmd_run(&cmd);
}

static bool nob_run_test_argv(const char *label, const char *const *argv,
                              size_t argc) {
    Cmd cmd = {0};
    Nob_Proc proc;
    int status;
    size_t i;
    nob_log(INFO, "TEST run: %s", label);
    /* nob_cmd_start bypasses the shell (no cmd.exe quoting pitfalls). */
    for (i = 0; i < argc; i++) nob_cmd_append(&cmd, argv[i]);
    proc = nob_cmd_start(&cmd);
    if (proc == NOB_INVALID_PROC) {
        nob_log(ERROR, "TEST could not start: %s", label);
        return false;
    }
    do {
        status = nob_proc_poll(proc);
        if (status == 0) nob_sleep_ms(50);
    } while (status == 0);
    if (status != 1) {
        nob_log(ERROR, "TEST failed: %s", label);
        return false;
    }
    return true;
}

static bool nob_run_test_exe(const char *exe) {
    return nob_run_test_argv(exe, &exe, 1);
}

/* Node.js suites (tests/*.js). node must be on PATH; dependencies are
 * installed once via npm when tests/node_modules is absent. */
static bool nob_have_node(void) {
    static const char *argv[] = {"node", "--version"};
    Cmd cmd = {0};
    Nob_Proc proc;
    int status;
    nob_cmd_append(&cmd, argv[0], argv[1]);
    proc = nob_cmd_start(&cmd);
    if (proc == NOB_INVALID_PROC) return false;
    do {
        status = nob_proc_poll(proc);
        if (status == 0) nob_sleep_ms(50);
    } while (status == 0);
    return status == 1;
}

static bool nob_ensure_node_deps(void) {
    if (file_exists("tests/node_modules/ws/package.json") > 0) return true;
    nob_log(INFO, "TEST: installing node dependencies (tests/node_modules missing)...");
    {
        /* npm ships as npm.cmd on Windows, which CreateProcess cannot run
         * directly -- go through the shell there, plain exec elsewhere. */
#ifdef _WIN32
        static const char *argv[] = {"cmd", "/c", "npm", "--prefix", "tests",
                                     "install", "--no-audit", "--no-fund"};
#else
        static const char *argv[] = {"npm", "--prefix", "tests",
                                     "install", "--no-audit", "--no-fund"};
#endif
        if (!nob_run_test_argv("npm install (tests/)", argv,
                               sizeof(argv) / sizeof(argv[0]))) {
            nob_log(ERROR, "TEST: npm install failed -- run `npm --prefix tests install` by hand");
            return false;
        }
    }
    return file_exists("tests/node_modules/ws/package.json") > 0;
}

static bool nob_run_node_tests(void) {
    static const char *scripts[] = {
        "tests/test_auth.js",
        "tests/test_nip13.js",
        "tests/test_integration.js",
        "tests/test_hotreload_integration.js",
        "tests/test_ws.js",
        "tests/test_ws2.js",
        "tests/test_hotreload_ws.js",
    };
    size_t i;
    size_t failed = 0;
    if (!nob_have_node()) {
        nob_log(ERROR, "TEST: `node` not found on PATH -- install Node 18+ to run the JS suites");
        return false;
    }
    if (!nob_ensure_node_deps()) return false;
    /* The JS suites spawn the relay themselves; make sure it exists. */
    if (file_exists(NOB_OS_HOST_EXE) <= 0) {
        nob_log(INFO, "TEST: relay binary missing, building it first...");
        if (!nob_build_host(false)) {
            nob_log(ERROR, "TEST: relay build failed");
            return false;
        }
    }
    for (i = 0; i < sizeof(scripts) / sizeof(scripts[0]); i++) {
        const char *argv[] = {"node", scripts[i]};
        if (!nob_run_test_argv(scripts[i], argv, 2)) failed++;
    }
    if (failed) {
        nob_log(ERROR, "TESTS: %lu JS suite(s) failed", (unsigned long)failed);
        return false;
    }
    return true;
}

static int nob_build_and_run_tests(void) {
    static const char *crypto_srcs[] = {
        SRC_FOLDER"crypto.c",
        SRC_FOLDER"nips/nip26.c",
        SRC_FOLDER"nips/nip_capability.c",
        SRC_FOLDER"nostrogotho.c",
        SRC_FOLDER"protocol/tag_iter.c",
        SRC_FOLDER"protocol/event_tags.c",
        SRC_FOLDER"json_util.c",
        THIRD_PARTY_FOLDER"mongoose/mongoose.c",
    };
    static const char *fuzz_srcs[] = {
        SRC_FOLDER"json_util.c",
        SRC_FOLDER"nostrogotho.c",
        THIRD_PARTY_FOLDER"mongoose/mongoose.c",
    };
    static const char *composition_srcs[] = {
        SRC_FOLDER"nips/nip_capability.c",
    };
    static const char *hotreload_srcs[] = {
        NOB_TEST_NHR_PLATFORM,
        SRC_FOLDER"nips/nip_capability.c",
    };
    static const char *crash_srcs[] = {
        SRC_FOLDER"crash.c",
    };
    static const char *sha256_srcs[] = {
        SRC_FOLDER"nips/nip26.c",
        SRC_FOLDER"nips/nip_capability.c",
        SRC_FOLDER"nostrogotho.c",
        SRC_FOLDER"protocol/tag_iter.c",
        SRC_FOLDER"protocol/event_tags.c",
        SRC_FOLDER"json_util.c",
        THIRD_PARTY_FOLDER"mongoose/mongoose.c",
    };
    static const char *storage_srcs[] = {
        SRC_FOLDER"storage.c",
        SRC_FOLDER"nostrogotho.c",
        SRC_FOLDER"log.c",
        THIRD_PARTY_FOLDER"sqlite3.c",
    };
    /* test_json_util.c needs the same objects as the fuzzer. */
    static const char *relay_srcs[] = {
        SRC_FOLDER"relay/relay.c",
        SRC_FOLDER"relay/connection_session.c",
        SRC_FOLDER"relay/config.c",
        SRC_FOLDER"relay/config_file.c",
        SRC_FOLDER"transport/server.c",
        SRC_FOLDER"subscriptions/subscription_manager.c",
        SRC_FOLDER"protocol/protocol.c",
        SRC_FOLDER"protocol/parser.c",
        SRC_FOLDER"protocol/filter_builder.c",
        SRC_FOLDER"protocol/tag_iter.c",
        SRC_FOLDER"protocol/event_tags.c",
        SRC_FOLDER"storage.c",
        SRC_FOLDER"nostrogotho.c",
        SRC_FOLDER"json_util.c",
        SRC_FOLDER"log.c",
        SRC_FOLDER"crypto.c",
        SRC_FOLDER"nhr.c",
        NOB_TEST_NHR_PLATFORM,
        SRC_FOLDER"nips/nip26.c",
        SRC_FOLDER"nips/nip_capability.c",
        SRC_FOLDER"nips/nip_composition_policy.c",
        THIRD_PARTY_FOLDER"mongoose/mongoose.c",
        THIRD_PARTY_FOLDER"sqlite3.c",
    };
    static const struct {
        const char *src;
        const char *exe;
        const char *const *deps;
        size_t ndeps;
        bool need_secp;
    } tests[] = {
        { "tests/test_crypto.c", NOB_TEST_EXE("test_crypto"),
          crypto_srcs, sizeof(crypto_srcs) / sizeof(crypto_srcs[0]), true },
        { "tests/test_json_fuzz.c", NOB_TEST_EXE("test_json_fuzz"),
          fuzz_srcs, sizeof(fuzz_srcs) / sizeof(fuzz_srcs[0]), false },
        { "tests/test_nip_composition.c", NOB_TEST_EXE("test_nip_composition"),
          composition_srcs, sizeof(composition_srcs) / sizeof(composition_srcs[0]), false },
        { "tests/test_hotreload.c", NOB_TEST_EXE("test_hotreload"),
          hotreload_srcs, sizeof(hotreload_srcs) / sizeof(hotreload_srcs[0]), false },
        /* test_sha256.c #includes src/crypto.c directly, so crypto.c itself
         * must NOT be linked (but its dependencies must). */
        { "tests/test_sha256.c", NOB_TEST_EXE("test_sha256"),
          sha256_srcs, sizeof(sha256_srcs) / sizeof(sha256_srcs[0]), true },
        { "tests/test_storage.c", NOB_TEST_EXE("test_storage"),
          storage_srcs, sizeof(storage_srcs) / sizeof(storage_srcs[0]), false },
        { "tests/test_json_util.c", NOB_TEST_EXE("test_json_util"),
          fuzz_srcs, sizeof(fuzz_srcs) / sizeof(fuzz_srcs[0]), false },
        /* test_relay.c is a boot smoke test: storage init + relay_create +
         * listen on :7457, then exit. Binds a fixed port, so stop any dev
         * relay first. */
        { "tests/test_relay.c", NOB_TEST_EXE("test_relay"),
          relay_srcs, sizeof(relay_srcs) / sizeof(relay_srcs[0]), true },
        /* test_crash.c prints a stack trace without dying; verifies the
         * crash handler installs and backtrace/CaptureStackBackTrace path
         * runs in this toolchain. */
        { "tests/test_crash.c", NOB_TEST_EXE("test_crash"),
          crash_srcs, sizeof(crash_srcs) / sizeof(crash_srcs[0]), false },
    };
    size_t i;
    size_t failed = 0;
    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        nob_log(INFO, "TEST build: %s", tests[i].src);
        if (!nob_build_one_test(tests[i].src, tests[i].exe, tests[i].deps,
                                tests[i].ndeps, tests[i].need_secp)) {
            nob_log(ERROR, "TEST build failed: %s", tests[i].src);
            failed++;
            continue;
        }
        if (!nob_run_test_exe(tests[i].exe)) failed++;
    }
    /* Node.js suites (exit codes verified the same way). */
    if (!nob_run_node_tests()) failed++;
    if (failed) {
        nob_log(ERROR, "TESTS: %lu suite(s) failed", (unsigned long)failed);
        return 1;
    }
    nob_log(INFO, "TESTS: all suites passed");
    nob_log(INFO, "NOTE: tests/hotreload_live_smoke.js is interactive (it waits "
                  "20s for a manual module rebuild) and is intentionally not "
                  "part of -test; automated live-reload is covered by "
                  "tests/test_hotreload_ws.js");
    return 0;
}

#endif /* NOB_COMMON_H_ */
