#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#include "nob.h"
#include "config.h"
#include "folders.h"
#include <string.h>
#include <time.h>
#include <sys/stat.h>

static bool add_nip_sources(Cmd *cmd, bool exclude_module_core) {
    const char *dir = SRC_FOLDER"nips/";
    File_Paths files = {0};
    if (!read_entire_dir(dir, &files)) {
        nob_log(ERROR, "Could not list NIP sources in %s", dir);
        return false;
    }
    for (size_t i = 0; i < files.count; i++) {
        const char *name = path_name(files.items[i]);
        size_t len = strlen(name);
        if (len < 3 || strcmp(name + len - 2, ".c") != 0 ||
            strcmp(name, "nip_template.c") == 0) continue;
        if (exclude_module_core &&
            (strcmp(name, "nip01.c") == 0 || strcmp(name, "nip_plugin.c") == 0 ||
             strcmp(name, "nip26.c") == 0 || strcmp(name, "nip42.c") == 0 ||
             strcmp(name, "nip_event.c") == 0)) continue;
        nob_cmd_append(cmd, nob_temp_sprintf("%s%s", dir, name));
    }
    free(files.items);
    return true;
}

static void append_common_flags(Cmd *cmd, bool dynamic_module) {
    nob_cmd_append(cmd, "-std=c99", "-D_GNU_SOURCE", "-DSECP256K1_STATIC",
                   "-DENABLE_MODULE_ECDH=1", "-DENABLE_MODULE_EXTRAKEYS=1",
                   "-DENABLE_MODULE_SCHNORRSIG=1", "-DENABLE_MODULE_MUSIG=1",
                   "-DENABLE_MODULE_ELLSWIFT=1", "-DENABLE_MODULE_SILENTPAYMENTS=1",
                   "-DENABLE_MODULE_RECOVERY=1", "-DECMULT_WINDOW_SIZE=15",
                   "-DCOMB_BLOCKS=43", "-DCOMB_TEETH=6",
                   dynamic_module ? "-DNHR_DYNAMIC_MODULE" : "-DNHR_STATIC_MODULE",
                   "-I"BUILD_FOLDER, "-I.", "-I"SRC_FOLDER,
                   "-I"THIRD_PARTY_FOLDER, "-I"THIRD_PARTY_FOLDER"mongoose",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/include",
                   "-I"THIRD_PARTY_FOLDER"secp256k1",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/src");
}

static bool build_module(void) {
    Cmd cmd = {0};
    nob_cc(&cmd);
    nob_cc_flags(&cmd);
    append_common_flags(&cmd, true);
    nob_cmd_append(&cmd, "-DNHR_BUILD_MODULE", "-fPIC", "-fvisibility=hidden", "-shared",
                   "-o", "build/nostrogotho.next.so",
                   SRC_FOLDER"nhr_module.c", SRC_FOLDER"nips/nip01.c",
                   SRC_FOLDER"nips/nip_plugin.c", SRC_FOLDER"nips/nip26.c",
                   SRC_FOLDER"nips/nip42.c", SRC_FOLDER"nips/nip_event.c",
                   SRC_FOLDER"json_util.c", SRC_FOLDER"nostrogotho.c",
                   THIRD_PARTY_FOLDER"mongoose/mongoose.c");
    if (!add_nip_sources(&cmd, true)) return false;
    nob_cmd_append(&cmd, "-lpthread", "-lm");
    if (!cmd_run(&cmd)) return false;
    if (!nob_rename("build/nostrogotho.next.so", BUILD_FOLDER"nostrogotho.so")) {
        if (!nob_copy_file("build/nostrogotho.next.so", BUILD_FOLDER"nostrogotho.so")) {
            nob_log(ERROR, "Could not publish hot-reload module");
            return false;
        }
        nob_delete_file("build/nostrogotho.next.so");
    }
    return true;
}

static bool build_host(bool dynamic_module) {
    Cmd cmd = {0};
    nob_cc(&cmd);
    nob_cc_flags(&cmd);
    append_common_flags(&cmd, dynamic_module);
    nob_cc_output(&cmd, BUILD_FOLDER"main");
    nob_cc_inputs(&cmd, SRC_FOLDER"main.c", SRC_FOLDER"server.c", SRC_FOLDER"crypto.c",
                  SRC_FOLDER"nhr.c", SRC_FOLDER"nhr_posix.c", SRC_FOLDER"storage.c",
                  SRC_FOLDER"nostrogotho.c", SRC_FOLDER"json_util.c",
                  THIRD_PARTY_FOLDER"sqlite3.c", THIRD_PARTY_FOLDER"mongoose/mongoose.c",
                  THIRD_PARTY_FOLDER"secp256k1/src/secp256k1.c",
                  THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult.c",
                  THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult_gen.c");
    if (!dynamic_module && !add_nip_sources(&cmd, false)) return false;
    nob_cmd_append(&cmd, "-lpthread", "-lm", "-ldl");
    return cmd_run(&cmd);
}

static bool run_hot_supervisor(int argc, char **argv) {
    int relay_start = 2;
    if (!build_module() || !build_host(true)) return false;
    Cmd run = {0};
    nob_cmd_append(&run, BUILD_FOLDER"main", "--hot-reload", "--module",
                   BUILD_FOLDER"nostrogotho.so");
    for (int i = relay_start; i < argc; i++) nob_cmd_append(&run, argv[i]);
    Nob_Proc host = nob_cmd_start(&run);
    if (host == NOB_INVALID_PROC) return false;

    File_Paths previous = {0};
    if (!read_entire_dir(SRC_FOLDER"nips/", &previous)) {
        nob_proc_terminate(host);
        return false;
    }
    const char *watched[] = {
        SRC_FOLDER"main.c", SRC_FOLDER"server.c", SRC_FOLDER"crypto.c",
        SRC_FOLDER"storage.c", SRC_FOLDER"storage.h", SRC_FOLDER"nhr_module.c",
        SRC_FOLDER"nhr.h", SRC_FOLDER"json_util.c", SRC_FOLDER"json_util.h",
        SRC_FOLDER"nostrogotho.c", SRC_FOLDER"nostrogotho.h",
        SRC_FOLDER"nips/nip01.c", SRC_FOLDER"nips/nip_plugin.c",
        SRC_FOLDER"nips/nip26.c", SRC_FOLDER"nips/nip42.c",
        SRC_FOLDER"nips/nip_event.c"
    };
    struct stat stamps[sizeof(watched) / sizeof(watched[0])];
    memset(stamps, 0, sizeof(stamps));
    for (size_t i = 0; i < sizeof(watched) / sizeof(watched[0]); i++) stat(watched[i], &stamps[i]);
    for (;;) {
        int status = nob_proc_poll(host);
        if (status != 0) {
            free(previous.items);
            return status == 1;
        }
        File_Paths current = {0};
        if (!read_entire_dir(SRC_FOLDER"nips/", &current)) {
            free(previous.items);
            nob_proc_terminate(host);
            return false;
        }
        bool changed = current.count != previous.count;
        for (size_t i = 0; !changed && i < current.count; i++) {
            bool found = false;
            for (size_t j = 0; j < previous.count; j++) {
                if (strcmp(path_name(current.items[i]), path_name(previous.items[j])) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) changed = true;
        }
        for (size_t i = 0; !changed && i < sizeof(watched) / sizeof(watched[0]); i++) {
            struct stat st;
            if (stat(watched[i], &st) == 0 &&
                (st.st_mtime != stamps[i].st_mtime || st.st_size != stamps[i].st_size)) {
                changed = true;
                stamps[i] = st;
            }
        }
        if (changed) {
            free(previous.items);
            previous = current;
            nob_sleep_ms(300);
            if (!build_module()) nob_log(WARNING, "NHR: module build failed; keeping active image");
        } else {
            free(current.items);
        }
        nob_sleep_ms(150);
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "-module-only") == 0) return build_module() ? 0 : 1;
    if (argc > 1 && strcmp(argv[1], "-hr") == 0) return run_hot_supervisor(argc, argv) ? 0 : 1;
    return build_host(false) ? 0 : 1;
}
