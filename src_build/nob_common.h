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
            strcmp(name, "nip_template.c") == 0) continue;
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
#else
#define NOB_OS_MODULE_NEXT "build/nostrogotho.next.so"
#define NOB_OS_MODULE_PUBLISHED BUILD_FOLDER"nostrogotho.so"
#define NOB_OS_HOST_EXE BUILD_FOLDER"main"
#define NOB_OS_NHR_SRC SRC_FOLDER"nhr_posix.c"
#define NOB_OS_EXTRA_DEFINES "-D_GNU_SOURCE"
#define NOB_OS_MODULE_FLAGS "-fPIC", "-fvisibility=hidden", "-shared"
#define NOB_OS_LIBS "-lpthread", "-lm", "-ldl"
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
    SRC_FOLDER"relay/connection_session.c", \
    SRC_FOLDER"relay/config.c", \
    SRC_FOLDER"subscriptions/subscription_manager.c", \
    SRC_FOLDER"protocol/protocol.c", \
    SRC_FOLDER"model/event_util.c", \
    SRC_FOLDER"validation/event_validation.c"

#define NOB_HOST_SOURCES \
    SRC_FOLDER"main.c", SRC_FOLDER"crypto.c", \
    SRC_FOLDER"storage.c", \
    SRC_FOLDER"nostrogotho.c", SRC_FOLDER"json_util.c", \
    SRC_FOLDER"relay/relay.c", SRC_FOLDER"relay/connection_session.c", \
    SRC_FOLDER"relay/config.c", \
    SRC_FOLDER"transport/server.c", \
    SRC_FOLDER"subscriptions/subscription_manager.c", \
    SRC_FOLDER"protocol/protocol.c", \
    SRC_FOLDER"model/event_util.c", \
    SRC_FOLDER"validation/event_validation.c"
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
    SRC_FOLDER"model/event_util.h", SRC_FOLDER"model/event_util.c", \
    SRC_FOLDER"validation/event_validation.h", SRC_FOLDER"validation/event_validation.c", \
    SRC_FOLDER"nips/nip_capability.h", SRC_FOLDER"nips/nip_capability.c"

/* Build the reloadable module under a staging name, then atomically publish.
 * A failed compile never touches the last good artifact. */
static bool nob_build_module(void) {
    Cmd cmd = {0};
    nob_cc(&cmd);
    nob_cc_flags(&cmd);
    nob_cmd_append(&cmd, "-std=c99", NOB_OS_EXTRA_DEFINES, NOB_SECP_DEFINES,
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
                   dynamic_module ? "-DNHR_DYNAMIC_MODULE" : "-DNHR_STATIC_MODULE",
                   "-I"BUILD_FOLDER, "-I.", "-I"SRC_FOLDER, "-I"SRC_FOLDER"nips",
                   "-I"THIRD_PARTY_FOLDER, "-I"THIRD_PARTY_FOLDER"mongoose",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/include",
                   "-I"THIRD_PARTY_FOLDER"secp256k1",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/src");
    nob_cc_output(&cmd, NOB_OS_HOST_EXE);
    nob_cc_inputs(&cmd, NOB_HOST_SOURCES, SRC_FOLDER"nhr.c", NOB_OS_NHR_SRC,
                  NOB_THIRD_PARTY_SOURCES);
    if (!dynamic_module && !nob_add_nip_sources(&cmd)) return false;
    nob_cmd_append(&cmd, NOB_OS_LIBS);
    return cmd_run(&cmd);
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

/* Hot supervisor: build host+module, run the host, rebuild module-only on
 * source change. Relay args after `-hr` are forwarded to the host. */
static int nob_run_hot_supervisor(int argc, char **argv) {
    nob_stop_requested = 0;
    signal(SIGINT, nob_handle_stop_signal);
    signal(SIGTERM, nob_handle_stop_signal);
    if (!nob_build_module()) return nob_stop_requested ? 0 : 1;
    if (nob_stop_requested) return 0;
    if (!nob_build_host(true)) return nob_stop_requested ? 0 : 1;
    if (nob_stop_requested) return 0;

    Cmd cmd = {0};
    nob_cmd_append(&cmd, NOB_OS_HOST_EXE, "--hot-reload", "--module",
                   NOB_OS_MODULE_PUBLISHED);
    for (int i = 2; i < argc; i++) nob_cmd_append(&cmd, argv[i]);
    Nob_Proc host = nob_cmd_start(&cmd);
    if (host == NOB_INVALID_PROC) return 1;

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
            free(previous.items); free(watched_nips.items); free(nip_stamps);
            return status == 1 ? 0 : 1;
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
                free(watched_nips.items); free(nip_stamps); free(previous.items);
                return status == 1 ? 0 : 1;
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

#endif /* NOB_COMMON_H_ */
