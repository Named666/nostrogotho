#!/bin/bash
# Full functional suite against build/${1:-main}:
# test_core, test_ws, dedupe (both modes), config, nip13, overload (slow
# reader / budgets), RFC 6455 strict conformance and the randomized
# fragmentation/split fuzz (ngws echo server).
cd "$(dirname "$0")/.."
B=$PWD/build/${1:-main}; PY=${PY:-/workspace/ngvenv/bin/python}; rc=0
run() { echo "== $1"; shift; "$@" || { echo "!! FAILED"; rc=1; }; }
pkill -f "build/${1:-main} --port 7447" 2>/dev/null; sleep 0.3
DB=$(mktemp -u /tmp/core.XXXX.sqlite)
$B --port 7447 --db $DB >/tmp/core_relay.log 2>&1 & P=$!; sleep 1.5
run test_core env RELAY_URL=ws://127.0.0.1:7447 $PY test_core.py
run test_ws timeout 20 $PY test_ws.py
kill -INT $P; wait $P 2>/dev/null; rm -f $DB*
run dedupe env PY=$PY tools/run_dedupe_tests.sh ${1:-main}
run config env RELAY_BIN=$B $PY tests/test_config.py
run nip13 env RELAY_BIN=$B $PY test_nip13.py
run listen_backlog env RELAY_BIN=$B $PY tests/test_listen_backlog.py
[ -f tests/test_overload.py ] && run overload env RELAY_BIN=$B $PY tests/test_overload.py
run nips env RELAY_BIN=$B $PY tests/test_nips.py
run durability env RELAY_BIN=$B $PY tests/test_durability.py
SB=build/ngws_bench_server${2:-}; pkill -f "$SB 9001" 2>/dev/null
$SB 9001 2 echo >/tmp/echo.log 2>&1 & E=$!; sleep 0.5
run rfc6455 env STRICT=1 $PY tests/rfc6455_conformance.py 127.0.0.1 9001
run ws_split_fuzz timeout 120 $PY tests/ws_split_fuzz.py 9001 200 1
kill $E; wait $E 2>/dev/null
exit $rc
