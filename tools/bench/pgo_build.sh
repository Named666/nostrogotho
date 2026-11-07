#!/bin/bash
# pgo_build.sh : profile-guided build of build/ngws_bench_server (gcc).
#   1. NG_PGO=gen  instrumented build (profiles go to build/pgo)
#   2. train with pgo_train.sh (echo sizes/pipelines/conns, churn, broadcast)
#   3. NG_PGO=use  rebuild with the profile
# Run from the repo root. NG_TOOLS_ONLY=1 is used so the relay is not rebuilt.
set -e
cd "$(dirname "$0")/../.."
rm -rf build/pgo
NG_TOOLS_ONLY=1 NG_PGO=gen ./nob >/dev/null 2>&1
tools/bench/pgo_train.sh build/ngws_bench_server || true   # last wait returns the killed server status
NG_TOOLS_ONLY=1 NG_PGO=use ./nob >/dev/null 2>&1
echo "PGO build: build/ngws_bench_server ($(stat -c %s build/ngws_bench_server) bytes)"
