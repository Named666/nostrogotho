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

/* Defines shared by first-party and vendored code. */
static void defines(Cmd *cmd)
{
    nob_cmd_append(cmd, "-D_GNU_SOURCE", "-DSECP256K1_STATIC",
                   "-DLIBUS_NO_SSL",
                   "-DENABLE_MODULE_ECDH=1", "-DENABLE_MODULE_EXTRAKEYS=1",
                   "-DENABLE_MODULE_SCHNORRSIG=1", "-DENABLE_MODULE_MUSIG=1",
                   "-DENABLE_MODULE_ELLSWIFT=1",
                   "-DENABLE_MODULE_SILENTPAYMENTS=1",
                   "-DENABLE_MODULE_RECOVERY=1", "-DECMULT_WINDOW_SIZE=15",
                   "-DCOMB_BLOCKS=43", "-DCOMB_TEETH=6");
}

/* First-party code: the platform contract (PLATFORM.md) is C99 + POSIX +
 * GCC/Clang builtins, built as gnu99 with the strict warning set. Vendored
 * headers come in through -isystem so their warnings are not reported as
 * ours. NG_WERROR=1 turns our warnings into errors. */
static void common_flags(Cmd *cmd)
{
    nob_cc(cmd);
    nob_cmd_append(cmd, "-std=gnu99", "-Wall", "-Wextra", "-Wpedantic", "-Wconversion",
                   "-Wshadow", "-Wstrict-prototypes", "-Wmissing-prototypes");
    const char *werror = getenv("NG_WERROR");
    if (werror && strcmp(werror, "1") == 0) nob_cmd_append(cmd, "-Werror");
    opt_flags(cmd);
    defines(cmd);
    nob_cmd_append(cmd, "-I"BUILD_FOLDER, "-I.", "-I"SRC_FOLDER,
                   "-isystem", THIRD_PARTY_FOLDER,
                   "-isystem", THIRD_PARTY_FOLDER"usockets/src",
                   "-isystem", THIRD_PARTY_FOLDER"secp256k1/include",
                   "-isystem", THIRD_PARTY_FOLDER"secp256k1",
                   "-isystem", THIRD_PARTY_FOLDER"secp256k1/src");
}

/* Vendored code (thirdparty/, see VENDOR.md): compiled to objects with its
 * own language level and the default warnings, never with ours. */
static void vendor_flags(Cmd *cmd)
{
    nob_cc(cmd);
    nob_cc_flags(cmd);
    opt_flags(cmd);
    nob_cmd_append(cmd, "-std=gnu11");
    defines(cmd);
    /* sqlite3.c: FTS5 for the NIP-50 search index (part of the vendored
     * amalgamation; off unless enabled). Inert for the other vendored TUs. */
    nob_cmd_append(cmd, "-DSQLITE_ENABLE_FTS5=1");
    nob_cmd_append(cmd, "-I"THIRD_PARTY_FOLDER, "-I"THIRD_PARTY_FOLDER"usockets/src",
                   "-I"THIRD_PARTY_FOLDER"secp256k1/include", "-I"THIRD_PARTY_FOLDER"secp256k1",
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
#define NGWS_SOURCES SRC_FOLDER"ngws/ngws.c", SRC_FOLDER"ngws/ngws_handshake.c", SRC_FOLDER"ngws/ngws_frame.c", \
                     SRC_FOLDER"ngws/ngws_send.c", SRC_FOLDER"ws_proto.c"

#define CORE_SOURCES \
    SRC_FOLDER"main.c", SRC_FOLDER"ng_config.c", SRC_FOLDER"relay_core.c", SRC_FOLDER"relay_conn.c", \
    SRC_FOLDER"backend_ngws.c", SRC_FOLDER"ngb_outbox.c", SRC_FOLDER"ngb_workers.c", \
    SRC_FOLDER"ngb_writer.c", SRC_FOLDER"relay_wire.c", SRC_FOLDER"dedupe.c", \
    SRC_FOLDER"json_lite.c", SRC_FOLDER"crypto.c", SRC_FOLDER"storage_sqlite.c", \
    SRC_FOLDER"storage_write.c", SRC_FOLDER"storage_query.c", SRC_FOLDER"storage_read.c", \
    SRC_FOLDER"storage_vfs.c", SRC_FOLDER"ratelimit.c", \
    SRC_FOLDER"nostrogotho.c", SRC_FOLDER"json_util.c", \
    SRC_FOLDER"schnorr_batch.c" /* includes the vendored secp256k1.c TU (as a system header) */

/* Vendored translation units, built once per variant into BUILD_FOLDER"obj<suffix>/". */
static const char *const US_VENDOR[] = {
    US"bsd.c", US"context.c", US"loop.c", US"socket.c", US"udp.c", US"eventing/epoll_kqueue.c",
};
static const char *const CORE_VENDOR[] = {
    THIRD_PARTY_FOLDER"sqlite3.c",
    THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult.c",
    THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult_gen.c",
};

/* Compile n vendored sources to objects under dir and append the objects
 * to out. pgo: also apply the NG_PGO flags (bench server variant). */
static bool vendor_objects(const char *dir, const char *const *srcs, size_t n, bool pgo, Cmd *out)
{
    if (!nob_mkdir_if_not_exists(dir)) return false;
    Cmd cmd = {0};
    for (size_t i = 0; i < n; i++) {
        const char *base = path_name(srcs[i]);
        const char *obj = nob_temp_sprintf("%s/%.*s.o", dir, (int) (strlen(base) - 2), base);
        cmd.count = 0;
        vendor_flags(&cmd);
        if (pgo) pgo_flags(&cmd);
        nob_cmd_append(&cmd, "-c", srcs[i], "-o", obj);
        if (!cmd_run(&cmd)) return false;
        nob_cmd_append(out, obj);
    }
    free(cmd.items);
    return true;
}

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

int main(void)
{
    Cmd cmd = {0};
    const char *san = getenv("NG_SAN");
    const char *suffix = san && *san ? nob_temp_sprintf("_%s", san) : "";
    const char *pgo = getenv("NG_PGO");
    const char *objdir = nob_temp_sprintf(BUILD_FOLDER"obj%s", suffix);
    const char *pgodir = nob_temp_sprintf(BUILD_FOLDER"obj%s_pgo%s", suffix, pgo && *pgo ? pgo : "none");

    /* build/main: the relay (ngws on uSockets, pure C, no TLS).
     * NG_TOOLS_ONLY=1 skips it (fast rebuilds of the bench tools). */
    const char *tools_only = getenv("NG_TOOLS_ONLY");
    if (!(tools_only && strcmp(tools_only, "1") == 0)) {
        common_flags(&cmd);
        nob_cc_output(&cmd, nob_temp_sprintf(BUILD_FOLDER"main%s", suffix));
        nob_cc_inputs(&cmd, CORE_SOURCES, NGWS_SOURCES);
        if (!append_nips(&cmd)) return 1;
        if (!vendor_objects(objdir, CORE_VENDOR, COUNT(CORE_VENDOR), false, &cmd)) return 1;
        if (!vendor_objects(objdir, US_VENDOR, COUNT(US_VENDOR), false, &cmd)) return 1;
        nob_cmd_append(&cmd, "-lpthread", "-lm", "-ldl");
        if (!cmd_run(&cmd)) return 1;
    }

    /* tools: ngws benchmark server and the ngload load generator */
    common_flags(&cmd);
    pgo_flags(&cmd);
    nob_cc_output(&cmd, nob_temp_sprintf(BUILD_FOLDER"ngws_bench_server%s", suffix));
    nob_cc_inputs(&cmd, "tools/ngws_bench_server.c", NGWS_SOURCES);
    if (!vendor_objects(pgodir, US_VENDOR, COUNT(US_VENDOR), true, &cmd)) return 1;
    nob_cmd_append(&cmd, "-lpthread");
    if (!cmd_run(&cmd)) return 1;

    common_flags(&cmd);
    nob_cc_output(&cmd, nob_temp_sprintf(BUILD_FOLDER"ngload%s", suffix));
    nob_cc_inputs(&cmd, "tools/ngload.c");
    nob_cmd_append(&cmd, "-lpthread", "-lm");
    if (!cmd_run(&cmd)) return 1;
    return 0;
}
