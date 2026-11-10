#!/bin/bash
# fanout_matrix.sh <label> <binary> <io_threads> <rates...>
# 20k idle sockets + 1k broad subscribers + 1 publisher (diagnose.py), relay on
# CPUs 0-3 with 4 workers, clients on 4-7. Prints the per-thread CPU split and
# the ngload line for each rate.
L=$1; B=$2; IO=$3; shift 3
cd "$(dirname "$0")/../.."
for r in "$@"; do
  NG_IO_THREADS=$IO NG_WORKERS=4 python3 tools/bench/diagnose.py --relay "$B" --case fanout \
    --idle ${IDLE:-20000} --rate $r --duration ${DUR:-12} --label=-$L-io$IO-r$r >/dev/null 2>&1
  python3 tools/bench/diag_summ.py tools/bench/scaling-results/diag-fanout-$L-io$IO-r$r.json 2>&1 | tail -3
done
