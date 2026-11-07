#!/bin/bash
# pgo_train.sh <instrumented ngws_bench_server> : representative echo/broadcast mix
L=$(dirname $0)/../../build/ngload
for a in "-c 100 -P 8 -m 64 echo" "-c 100 -P 8 -m 512 echo" "-c 100 -P 1 -m 16 echo" "-c 100 -P 64 -m 64 echo" "-c 20 -P 2 -m 65536 echo" "-c 2000 -P 1 -m 64 echo" "-c 100 -m 64 churn"; do
  taskset -c 0-1 $1 9001 2 echo >/dev/null 2>&1 & P=$!; sleep 0.3
  taskset -c 2-7 $L -t 6 -q -d 2 $a >/dev/null; kill $P; wait $P 2>/dev/null
done
taskset -c 0-1 $1 9001 1 broadcast >/dev/null 2>&1 & P=$!; sleep 0.3
taskset -c 2-7 $L -t 6 -q -d 2 -c 1000 -n 1 -P 4 -m 64 bcast >/dev/null; kill $P; wait $P 2>/dev/null
