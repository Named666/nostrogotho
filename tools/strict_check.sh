#!/bin/bash
# strict_check.sh [std] : compile every first-party TU with the strict warning
# set of the platform contract (PLATFORM.md) and report warning counts.
# Vendored code (thirdparty/) is included via -isystem so only our code is
# judged. Usage: tools/strict_check.sh [gnu99]   (exit 1 if any warning)
cd "$(dirname "$0")/.."
STD=${1:-gnu99}
W="-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes -Wmissing-prototypes"
D="-D_GNU_SOURCE -DSECP256K1_STATIC -DLIBUS_NO_SSL -DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_MUSIG=1 -DENABLE_MODULE_ELLSWIFT=1 -DENABLE_MODULE_SILENTPAYMENTS=1 -DENABLE_MODULE_RECOVERY=1 -DECMULT_WINDOW_SIZE=15 -DCOMB_BLOCKS=43 -DCOMB_TEETH=6"
I="-Ibuild -I. -Isrc -isystem thirdparty -isystem thirdparty/usockets/src -isystem thirdparty/secp256k1/include -isystem thirdparty/secp256k1 -isystem thirdparty/secp256k1/src"
FILES=${FILES:-$(ls src/*.c src/ngws/*.c src/nips/*.c tools/ngload.c tools/ngws_bench_server.c tests/*.c | grep -v nip_template.c)}
OUT=${OUT:-/tmp/strict_check.log}; : > "$OUT"
for f in $FILES; do cc -std=$STD $W $D $I -O2 -fsyntax-only "$f" >>"$OUT" 2>&1; done
grep 'warning:' "$OUT" | grep -v '^[^:]*thirdparty/' > "$OUT.ours"
tot=$(wc -l < "$OUT.ours"); errs=$(grep -c 'error:' "$OUT")
echo "total warnings: $tot, errors: $errs ($STD)"
echo "-- by flag"; grep -oE '\[-W[a-z0-9=-]+\]' "$OUT.ours" | sort | uniq -c | sort -rn
echo "-- by file"; cut -d: -f1 "$OUT.ours" | sort | uniq -c | sort -rn
[ "$tot" = 0 ] && [ "$errs" = 0 ]
