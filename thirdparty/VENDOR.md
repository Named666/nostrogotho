# Vendored third-party code

Pinned to the exact commits the previous (dangling, no .gitmodules) gitlinks pointed at.

| Dir | Upstream | Commit | Version | Files kept |
|---|---|---|---|---|
| mongoose/ | https://github.com/cesanta/mongoose | 140fa6cebf412ac898327139e21909572d0ead95 (2026-09-01) | MG_VERSION 7.23 | mongoose.c, mongoose.h, LICENSE (GPLv2 / commercial dual license) |
| secp256k1/ | https://github.com/bitcoin-core/secp256k1 | a9a61831bdcd97475e200a4bdd1ebed641f7268d (2026-08-30) | master | include/, src/, COPYING (MIT) |
| sqlite3.c/.h | (already vendored) | unchanged | 3.8.7.1 | |

thirdparty/nips is still a gitlink to the NIPs spec fork (not needed to build).
