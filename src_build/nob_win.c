#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#include "nob.h"
#include "config.h"
#include "folders.h"
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/* ============================================================================
 * Windows build target for the nostrogotho relay.
 *
 * The NIP set is discovered automatically: every *.c in SRC_FOLDER"nips/" is a
 * self-registering plugin (see src/nips/nip_plugin.h) and is compiled into the
 * binary. Dropping a file into that folder enables a NIP; deleting a file
 * removes it — no edits to this build script or to server.c are needed.
 * ============================================================================ */

static bool add_nip_sources(Cmd *cmd, bool exclude_module_core) {
    const char *nips_dir = SRC_FOLDER"nips/";
    File_Paths nips = {0};
    if (!read_entire_dir(nips_dir, &nips)) {
        nob_log(ERROR, "Could not list NIP sources in %s", nips_dir);
        return false;
    }
    for (size_t i = 0; i < nips.count; i++) {
        const char *name = path_name(nips.items[i]);
        size_t len = strlen(name);
        if (len > 2 && strcmp(name + len - 2, ".c") == 0 &&
            strcmp(name, "nip_template.c") != 0) {
            if (exclude_module_core &&
                (strcmp(name, "nip01.c") == 0 || strcmp(name, "nip_plugin.c") == 0 ||
                 strcmp(name, "nip26.c") == 0 || strcmp(name, "nip42.c") == 0 ||
                 strcmp(name, "nip_event.c") == 0)) continue;
            nob_cmd_append(cmd, nob_temp_sprintf("%s%s", nips_dir, name));
        }
    }
    free(nips.items);
    return true;
}

static bool build_module(void) {
    Cmd cmd = {0};
    nob_cc(&cmd);
    nob_cc_flags(&cmd);
    nob_cmd_append(&cmd, "-std=c99", "-DSECP256K1_STATIC", "-DNHR_BUILD_MODULE",
                   "-DNHR_DYNAMIC_MODULE", "-shared", "-Wl,--export-all-symbols",
                   "-DENABLE_MODULE_ECDH=1", "-DENABLE_MODULE_EXTRAKEYS=1",
                   "-DENABLE_MODULE_SCHNORRSIG=1", "-DENABLE_MODULE_MUSIG=1",
                   "-DENABLE_MODULE_ELLSWIFT=1", "-DENABLE_MODULE_SILENTPAYMENTS=1",
                   "-DENABLE_MODULE_RECOVERY=1", "-DECMULT_WINDOW_SIZE=15",
                   "-DCOMB_BLOCKS=43", "-DCOMB_TEETH=6",
                   "-I"BUILD_FOLDER, "-I.", "-I"SRC_FOLDER,
                   "-I"THIRD_PARTY_FOLDER, "-I"THIRD_PARTY_FOLDER"mongoose",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/include",
                   "-I"THIRD_PARTY_FOLDER"secp256k1",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/src",
                   "-o", "build/nostrogotho.next.dll",
                   SRC_FOLDER"nhr_module.c", SRC_FOLDER"nips/nip01.c",
                   SRC_FOLDER"nips/nip_plugin.c", SRC_FOLDER"nips/nip26.c",
                   SRC_FOLDER"nips/nip42.c", SRC_FOLDER"nips/nip_event.c",
                   SRC_FOLDER"json_util.c", SRC_FOLDER"nostrogotho.c",
                   THIRD_PARTY_FOLDER"mongoose/mongoose.c");
    if (!add_nip_sources(&cmd, true)) return false;
    nob_cmd_append(&cmd, "-lbcrypt", "-lws2_32", "-lwinpthread");
    return cmd_run(&cmd) &&
           nob_rename("build/nostrogotho.next.dll", BUILD_FOLDER"nostrogotho.dll");
}

int main(int argc, char **argv)
{
    Cmd cmd = {0};
    bool hot = argc > 1 && strcmp(argv[1], "-hr") == 0;
    int relay_arg_start = hot ? 2 : 1;
    if (hot) {
        if (!build_module()) return 1;
        cmd.count = 0;
        nob_cc(&cmd);
        nob_cc_flags(&cmd);
        nob_cmd_append(&cmd, "-std=c99", "-DSECP256K1_STATIC", "-DNHR_DYNAMIC_MODULE",
                       "-DENABLE_MODULE_ECDH=1", "-DENABLE_MODULE_EXTRAKEYS=1",
                       "-DENABLE_MODULE_SCHNORRSIG=1", "-DENABLE_MODULE_MUSIG=1",
                       "-DENABLE_MODULE_ELLSWIFT=1", "-DENABLE_MODULE_SILENTPAYMENTS=1",
                       "-DENABLE_MODULE_RECOVERY=1", "-DECMULT_WINDOW_SIZE=15",
                       "-DCOMB_BLOCKS=43", "-DCOMB_TEETH=6",
                       "-I"BUILD_FOLDER, "-I.", "-I"SRC_FOLDER,
                       "-I"THIRD_PARTY_FOLDER, "-I"THIRD_PARTY_FOLDER"mongoose",
                       "-I"THIRD_PARTY_FOLDER"secp256k1/include",
                       "-I"THIRD_PARTY_FOLDER"secp256k1",
                       "-I"THIRD_PARTY_FOLDER"secp256k1/src");
        nob_cc_output(&cmd, BUILD_FOLDER"main");
        nob_cc_inputs(&cmd, SRC_FOLDER"main.c", SRC_FOLDER"server.c", SRC_FOLDER"crypto.c",
                      SRC_FOLDER"nhr.c", SRC_FOLDER"nhr_windows.c", SRC_FOLDER"storage.c",
                      SRC_FOLDER"nostrogotho.c", SRC_FOLDER"json_util.c",
                      THIRD_PARTY_FOLDER"sqlite3.c", THIRD_PARTY_FOLDER"mongoose/mongoose.c",
                      THIRD_PARTY_FOLDER"secp256k1/src/secp256k1.c",
                      THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult.c",
                      THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult_gen.c");
        nob_cmd_append(&cmd, "-lbcrypt", "-lws2_32", "-lwinpthread");
        if (!cmd_run(&cmd)) return 1;
        cmd.count = 0;
        nob_cmd_append(&cmd, BUILD_FOLDER"main.exe", "--hot-reload", "--module",
                       BUILD_FOLDER"nostrogotho.dll");
        for (int i = relay_arg_start; i < argc; i++) nob_cmd_append(&cmd, argv[i]);
        Nob_Proc host = nob_cmd_start(&cmd);
        if (host == NOB_INVALID_PROC) return 1;
        File_Paths previous = {0};
        if (!read_entire_dir(SRC_FOLDER"nips/", &previous)) {
            nob_proc_terminate(host);
            return 1;
        }
        const char *watch_paths[] = {SRC_FOLDER"nhr_module.c", SRC_FOLDER"nhr.h",
            SRC_FOLDER"storage.h", SRC_FOLDER"json_util.c", SRC_FOLDER"json_util.h",
            SRC_FOLDER"nostrogotho.c", SRC_FOLDER"nostrogotho.h",
            SRC_FOLDER"nips/nip01.c", SRC_FOLDER"nips/nip_plugin.c",
            SRC_FOLDER"nips/nip26.c", SRC_FOLDER"nips/nip42.c",
            SRC_FOLDER"nips/nip_event.c", SRC_FOLDER"nips/nip09.c",
            SRC_FOLDER"nips/nip40.c", SRC_FOLDER"nips/nip62.c",
            SRC_FOLDER"nips/nip13.c"};
        struct stat stamps[sizeof(watch_paths) / sizeof(watch_paths[0])];
        memset(stamps, 0, sizeof(stamps));
        for (size_t i = 0; i < sizeof(watch_paths) / sizeof(watch_paths[0]); i++) {
            stat(watch_paths[i], &stamps[i]);
        }
        for (;;) {
            int status = nob_proc_poll(host);
            if (status != 0) { free(previous.items); return status == 1 ? 0 : 1; }
            File_Paths current = {0};
            if (!read_entire_dir(SRC_FOLDER"nips/", &current)) {
                free(previous.items);
                nob_proc_terminate(host);
                return 1;
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
            for (size_t i = 0; !changed &&
                 i < sizeof(watch_paths) / sizeof(watch_paths[0]); i++) {
                struct stat st;
                if (stat(watch_paths[i], &st) == 0 &&
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
            } else free(current.items);
            for (int tick = 0; tick < 4; tick++) {
                status = nob_proc_poll(host);
                if (status != 0) { free(previous.items); return status == 1 ? 0 : 1; }
                nob_sleep_ms(100);
            }
        }
    }

    const char *output_path = BUILD_FOLDER"main";
    nob_cc(&cmd);
    nob_cc_flags(&cmd);
    nob_cmd_append(&cmd, "-std=c99", "-DSECP256K1_STATIC",
                   "-DENABLE_MODULE_ECDH=1", "-DENABLE_MODULE_EXTRAKEYS=1",
                   "-DENABLE_MODULE_SCHNORRSIG=1", "-DENABLE_MODULE_MUSIG=1",
                   "-DENABLE_MODULE_ELLSWIFT=1",
                   "-DENABLE_MODULE_SILENTPAYMENTS=1",
                   "-DENABLE_MODULE_RECOVERY=1", "-DECMULT_WINDOW_SIZE=15",
                   "-DCOMB_BLOCKS=43", "-DCOMB_TEETH=6",
                   "-DNHR_STATIC_MODULE",
                   "-I"BUILD_FOLDER, "-I.", "-I"SRC_FOLDER,
                   "-I"THIRD_PARTY_FOLDER,
                   "-I"THIRD_PARTY_FOLDER"mongoose",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/include",
                   "-I"THIRD_PARTY_FOLDER"secp256k1",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/src");
    nob_cc_output(&cmd, output_path);

    /* Core sources that are always required. */
    nob_cc_inputs(&cmd, SRC_FOLDER"main.c", SRC_FOLDER"server.c",
                  SRC_FOLDER"crypto.c",
                  SRC_FOLDER"nhr.c", SRC_FOLDER"nhr_windows.c",
                  SRC_FOLDER"storage.c", SRC_FOLDER"nostrogotho.c",
                  SRC_FOLDER"json_util.c", THIRD_PARTY_FOLDER"sqlite3.c",
                  THIRD_PARTY_FOLDER"mongoose/mongoose.c",
                  THIRD_PARTY_FOLDER"secp256k1/src/secp256k1.c",
                  THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult.c",
                  THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult_gen.c");

    /* NIP plugins: glob every *.c under src/nips/ so the compiled feature set
     * always matches the files present. */
    if (!add_nip_sources(&cmd, false)) return 1;

    nob_cmd_append(&cmd, "-lbcrypt", "-lws2_32", "-lwinpthread");
    if (!cmd_run(&cmd)) return 1;
    return 0;
}
