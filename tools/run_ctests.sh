#!/bin/sh
# Build and run the C unit tests in tests/ (Linux). Usage: tools/run_ctests.sh
set -e
cd "$(dirname "$0")/.."
mkdir -p build/tests
F="${CT_OPT:--O1} -g -std=gnu11 -D_GNU_SOURCE -DSECP256K1_STATIC -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1 -DECMULT_WINDOW_SIZE=15 -DCOMB_BLOCKS=43 -DCOMB_TEETH=6 -I. -Isrc -Ithirdparty -Ithirdparty/secp256k1/include -Ithirdparty/secp256k1 -Ithirdparty/secp256k1/src -w"
LIB="src/json_lite.c src/json_util.c src/nostrogotho.c src/crypto.c src/relay_conn.c src/nips/*.c src/schnorr_batch.c thirdparty/secp256k1/src/precomputed_ecmult.c thirdparty/secp256k1/src/precomputed_ecmult_gen.c"
[ -f build/tests/sqlite3.o ] || cc -O2 -w -c thirdparty/sqlite3.c -o build/tests/sqlite3.o
rc=0
for t in tests/test_*.c; do
  n=$(basename "$t" .c)
  L="$LIB"
  grep -q '#include "../src/crypto.c"' "$t" && L=$(echo "$LIB" | sed 's| src/crypto.c||')
  if cc $F -o build/tests/$n "$t" $L src/storage.c src/relay_core.c src/dedupe.c build/tests/sqlite3.o -lpthread -lm -ldl 2>build/tests/$n.log; then
    if ./build/tests/$n >build/tests/$n.out 2>&1; then echo "PASS $n"; else echo "FAIL $n (see build/tests/$n.out)"; rc=1; fi
  else echo "BUILD-FAIL $n (see build/tests/$n.log)"; rc=1; fi
done
exit $rc
