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

/* Optimization profile: NG_OPT env (default "-O3 -march=native -flto");
 * NG_SAN=address|thread builds a sanitizer variant (-O1 -g). */
static void opt_flags(Cmd *cmd)
{
    const char *san = getenv("NG_SAN");
    if (san && *san) {
        nob_cmd_append(cmd, "-O1", "-g", "-fno-omit-frame-pointer", nob_temp_sprintf("-fsanitize=%s", san));
        return;
    }
    const char *opt = getenv("NG_OPT");
    if (!opt) opt = "-O3 -march=native -flto=auto";
    char *dup = nob_temp_strdup(opt);
    for (char *tok = strtok(dup, " "); tok; tok = strtok(NULL, " ")) nob_cmd_append(cmd, tok);
}

static void common_flags(Cmd *cmd, const char *std)
{
    nob_cc(cmd);
    nob_cc_flags(cmd);
    opt_flags(cmd);
    nob_cmd_append(cmd, std, "-D_GNU_SOURCE", "-DSECP256K1_STATIC",
                   "-DLIBUS_NO_SSL",
                   "-DENABLE_MODULE_ECDH=1", "-DENABLE_MODULE_EXTRAKEYS=1",
                   "-DENABLE_MODULE_SCHNORRSIG=1", "-DENABLE_MODULE_MUSIG=1",
                   "-DENABLE_MODULE_ELLSWIFT=1",
                   "-DENABLE_MODULE_SILENTPAYMENTS=1",
                   "-DENABLE_MODULE_RECOVERY=1", "-DECMULT_WINDOW_SIZE=15",
                   "-DCOMB_BLOCKS=43", "-DCOMB_TEETH=6",
                   "-I"BUILD_FOLDER, "-I.", "-I"SRC_FOLDER,
                   "-I"THIRD_PARTY_FOLDER,
                   "-I"THIRD_PARTY_FOLDER"usockets/src",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/include",
                   "-I"THIRD_PARTY_FOLDER"secp256k1",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/src");
}

/* NG_PGO=gen|use: profile-guided build of the ngws benchmark server.
 * gen: instrumented binary writes profiles to build/pgo (train with
 * tools/bench/pgo_train.sh build/ngws_bench_server); use: rebuild with them. */
static void pgo_flags(Cmd *cmd)
{
    const char *pgo = getenv("NG_PGO");
    if (!pgo || !*pgo) return;
    if (strcmp(pgo, "gen") == 0)
        nob_cmd_append(cmd, "-fprofile-generate", "-fprofile-update=atomic",
                       "-fprofile-dir="BUILD_FOLDER"pgo",
                       "-Wl,-u,__gcov_dump");   /* weak ref in the bench server: pull it from libgcov */
    else if (strcmp(pgo, "use") == 0)
        nob_cmd_append(cmd, "-fprofile-use", "-fprofile-partial-training", "-fprofile-correction",
                       "-fprofile-dir="BUILD_FOLDER"pgo", "-Wno-missing-profile");
}

#define US THIRD_PARTY_FOLDER"usockets/src/"
#define NGWS_SOURCES \
    SRC_FOLDER"ngws/ngws.c", SRC_FOLDER"ws_proto.c", \
    US"bsd.c", US"context.c", US"loop.c", US"socket.c", US"udp.c", US"eventing/epoll_kqueue.c"

#define CORE_SOURCES \
    SRC_FOLDER"main.c", SRC_FOLDER"relay_core.c", SRC_FOLDER"relay_conn.c", \
    SRC_FOLDER"backend_ngws.c", SRC_FOLDER"dedupe.c", \
    SRC_FOLDER"json_lite.c", SRC_FOLDER"crypto.c", SRC_FOLDER"storage.c", \
    SRC_FOLDER"nostrogotho.c", SRC_FOLDER"json_util.c", THIRD_PARTY_FOLDER"sqlite3.c", \
    SRC_FOLDER"schnorr_batch.c", /* includes the vendored secp256k1.c TU */ \
    THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult.c", \
    THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult_gen.c"

int main(void)
{
    Cmd cmd = {0};
    const char *san = getenv("NG_SAN");
    const char *suffix = san && *san ? nob_temp_sprintf("_%s", san) : "";

    /* build/main: the relay (ngws on uSockets, pure C, no TLS).
     * NG_TOOLS_ONLY=1 skips it (fast rebuilds of the bench tools). */
    const char *tools_only = getenv("NG_TOOLS_ONLY");
    if (!(tools_only && strcmp(tools_only, "1") == 0)) {
    common_flags(&cmd, "-std=gnu11");
    nob_cc_output(&cmd, nob_temp_sprintf(BUILD_FOLDER"main%s", suffix));
    nob_cc_inputs(&cmd, CORE_SOURCES, NGWS_SOURCES);
    if (!append_nips(&cmd)) return 1;
    nob_cmd_append(&cmd, "-lpthread", "-lm", "-ldl");
    if (!cmd_run(&cmd)) return 1;
    }

    /* tools: ngws benchmark server and the ngload load generator */
    common_flags(&cmd, "-std=gnu11");
    pgo_flags(&cmd);
    nob_cc_output(&cmd, nob_temp_sprintf(BUILD_FOLDER"ngws_bench_server%s", suffix));
    nob_cc_inputs(&cmd, "tools/ngws_bench_server.c", NGWS_SOURCES);
    nob_cmd_append(&cmd, "-lpthread");
    if (!cmd_run(&cmd)) return 1;

    common_flags(&cmd, "-std=gnu11");
    nob_cc_output(&cmd, nob_temp_sprintf(BUILD_FOLDER"ngload%s", suffix));
    nob_cc_inputs(&cmd, "tools/ngload.c");
    nob_cmd_append(&cmd, "-lpthread", "-lm");
    if (!cmd_run(&cmd)) return 1;
    return 0;
}
