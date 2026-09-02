#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#include "nob.h"
#include "config.h"
#include "folders.h"

int main(void)
{
    Cmd cmd = {0};
#ifdef FOO
    nob_log(INFO, "FOO feature is enabled");
#endif // FOO
#ifdef BAR
    nob_log(INFO, "BAR feature is enabled");
#endif // BAR
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
    nob_cc_inputs(&cmd, SRC_FOLDER"main.c", SRC_FOLDER"server.c",
                  SRC_FOLDER"nips/nip01.c", SRC_FOLDER"nips/nip11.c",
                  SRC_FOLDER"nips/nip_event.c", SRC_FOLDER"nips/nip09.c",
                  SRC_FOLDER"nips/nip13.c", SRC_FOLDER"nips/nip16.c",
                  SRC_FOLDER"nips/nip17.c", SRC_FOLDER"nips/nip26.c",
                  SRC_FOLDER"nips/nip33.c", SRC_FOLDER"nips/nip40.c",
                  SRC_FOLDER"nips/nip42.c", SRC_FOLDER"nips/nip45.c",
                  SRC_FOLDER"nips/nip62.c", SRC_FOLDER"nips/nip67.c",
                  SRC_FOLDER"crypto.c",
                  SRC_FOLDER"storage.c", SRC_FOLDER"cagliostr.c",
                  SRC_FOLDER"json_util.c", THIRD_PARTY_FOLDER"sqlite3.c",
                  THIRD_PARTY_FOLDER"mongoose/mongoose.c",
                  THIRD_PARTY_FOLDER"secp256k1/src/secp256k1.c",
                  THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult.c",
                  THIRD_PARTY_FOLDER"secp256k1/src/precomputed_ecmult_gen.c");
    nob_cmd_append(&cmd, "-lbcrypt", "-lws2_32", "-lwinpthread");
    if (!cmd_run(&cmd)) return 1;
    return 0;
}
