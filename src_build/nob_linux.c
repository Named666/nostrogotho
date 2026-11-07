#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#include "nob.h"
#include "config.h"
#include "folders.h"
#include <string.h>

/* ============================================================================
 * Linux build target for the nostrogotho relay.
 *
 * The NIP set is discovered automatically: every *.c in SRC_FOLDER"nips/" is a
 * self-registering plugin (see src/nips/nip_plugin.h) and is compiled into the
 * binary. Dropping a file into that folder enables a NIP; deleting a file
 * removes it — no edits to this build script or to server.c are needed.
 * ============================================================================ */

static bool append_nips(Cmd *cmd)
{
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
            nob_cmd_append(cmd, nob_temp_sprintf("%s%s", nips_dir, name));
        }
    }
    free(nips.items);
    return true;
}

static void common_flags(Cmd *cmd, const char *std)
{
    nob_cc(cmd);
    nob_cc_flags(cmd);
    nob_cmd_append(cmd, "-O2", std, "-D_GNU_SOURCE", "-DSECP256K1_STATIC",
                   "-DENABLE_MODULE_ECDH=1", "-DENABLE_MODULE_EXTRAKEYS=1",
                   "-DENABLE_MODULE_SCHNORRSIG=1", "-DENABLE_MODULE_MUSIG=1",
                   "-DENABLE_MODULE_ELLSWIFT=1",
                   "-DENABLE_MODULE_SILENTPAYMENTS=1",
                   "-DENABLE_MODULE_RECOVERY=1", "-DECMULT_WINDOW_SIZE=15",
                   "-DCOMB_BLOCKS=43", "-DCOMB_TEETH=6",
                   "-I"BUILD_FOLDER, "-I.", "-I"SRC_FOLDER,
                   "-I"THIRD_PARTY_FOLDER,
                   "-I"THIRD_PARTY_FOLDER"secp256k1/include",
                   "-I"THIRD_PARTY_FOLDER"secp256k1",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/src");
}

#define CORE_SOURCES \
    SRC_FOLDER"main.c", SRC_FOLDER"relay_core.c", SRC_FOLDER"relay_conn.c", \
    SRC_FOLDER"json_lite.c", SRC_FOLDER"crypto.c", SRC_FOLDER"storage.c", \
    SRC_FOLDER"nostrogotho.c", SRC_FOLDER"json_util.c", THIRD_PARTY_FOLDER"sqlite3.c", \
    THIRD_PARTY_FOLDER"secp256k1/src/secp256k1.c", \
    THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult.c", \
    THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult_gen.c"

#define US THIRD_PARTY_FOLDER"usockets/src/"

int main(void)
{
    Cmd cmd = {0};

    /* build/main: Mongoose backend (GPLv2/commercial), single thread. */
    common_flags(&cmd, "-std=gnu11");
    nob_cmd_append(&cmd, "-I"THIRD_PARTY_FOLDER"mongoose");
    nob_cc_output(&cmd, BUILD_FOLDER"main");
    nob_cc_inputs(&cmd, CORE_SOURCES, SRC_FOLDER"backend_mongoose.c",
                  THIRD_PARTY_FOLDER"mongoose/mongoose.c");
    if (!append_nips(&cmd)) return 1;
    nob_cmd_append(&cmd, "-lpthread", "-lm", "-ldl");
    if (!cmd_run(&cmd)) return 1;

    /* build/main_us: uSockets backend (Apache-2.0), no TLS, no mongoose. */
    common_flags(&cmd, "-std=gnu11");
    nob_cmd_append(&cmd, "-DLIBUS_NO_SSL", "-I"US);
    nob_cc_output(&cmd, BUILD_FOLDER"main_us");
    nob_cc_inputs(&cmd, CORE_SOURCES, SRC_FOLDER"backend_usockets.c", SRC_FOLDER"ws_proto.c",
                  US"bsd.c", US"context.c", US"loop.c", US"socket.c", US"udp.c",
                  US"eventing/epoll_kqueue.c");
    if (!append_nips(&cmd)) return 1;
    nob_cmd_append(&cmd, "-lpthread", "-lm", "-ldl");
    if (!cmd_run(&cmd)) return 1;
    return 0;
}
