#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#include "nob.h"
#include "config.h"
#include "folders.h"
#include <string.h>

/* ============================================================================
 * Build configuration for the nostrogotho relay.
 *
 * The NIP set is discovered automatically: every *.c in SRC_FOLDER"nips/" is a
 * self-registering plugin (see src/nips/nip_plugin.h) and is compiled into the
 * binary. Dropping a file into that folder enables a NIP; deleting a file
 * removes it — no edits to this build script or to server.c are needed.
 * ============================================================================ */

int main(void)
{
    Cmd cmd = {0};
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
                  SRC_FOLDER"storage.c", SRC_FOLDER"nostrogotho.c",
                  SRC_FOLDER"json_util.c", THIRD_PARTY_FOLDER"sqlite3.c",
                  THIRD_PARTY_FOLDER"mongoose/mongoose.c",
                  THIRD_PARTY_FOLDER"secp256k1/src/secp256k1.c",
                  THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult.c",
                  THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult_gen.c");

    /* NIP plugins: glob every *.c under src/nips/ so the compiled feature set
     * always matches the files present. nip01.c is the protocol core and is
     * required for the relay to function; the rest are optional plugins. */
    const char *nips_dir = SRC_FOLDER"nips/";
    File_Paths nips = {0};
    if (!read_entire_dir(nips_dir, &nips)) {
        nob_log(ERROR, "Could not list NIP sources in %s", nips_dir);
        return 1;
    }
    for (size_t i = 0; i < nips.count; i++) {
        const char *name = path_name(nips.items[i]);
        size_t len = strlen(name);
        if (len > 2 && strcmp(name + len - 2, ".c") == 0) {
            /* read_entire_dir returns bare names; rebuild a full path. */
            nob_cmd_append(&cmd, nob_temp_sprintf("%s%s", nips_dir, name));
        }
    }
    free(nips.items);

    nob_cmd_append(&cmd, "-lbcrypt", "-lws2_32", "-lwinpthread");
    if (!cmd_run(&cmd)) return 1;
    return 0;
}