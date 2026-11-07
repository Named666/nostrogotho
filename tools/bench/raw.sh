#!/bin/bash
# usage: raw.sh <label> <server cmd...>   (server gets: <port> <threads> <mode> appended)
# Server pinned to CPUs 0-3, ngload pinned to CPUs 4-7.
L=/workspace/named666/nostrogotho/build/ngload
run() { # mode srvthreads srvmode loadargs...
  local m=$1 st=$2 sm=$3; shift 3
  taskset -c 0-3 "${SRV[@]}" 9001 $st $sm >/dev/null 2>&1 & local P=$!
  sleep 0.4
  out=$(taskset -c 4-7 $L -t 4 -x $P "$@" $m 2>/dev/null)
  kill $P; wait $P 2>/dev/null
  echo "$LABEL st=$st $* :: $out"
}
LABEL=$1; shift; SRV=("$@")
for sz in 16 512 4096 65536; do run echo 4 echo -c 100 -P 8 -d 5 -m $sz; done
run echo 4 echo -c 2000 -P 1 -d 5 -m 64
run echo 1 echo -c 100 -P 8 -d 5 -m 64
run bcast 1 broadcast -c 1000 -n 1 -P 4 -d 5 -m 64
run bcast 1 broadcast -c 1000 -n 1 -R 500 -d 5 -m 64
run bcast 1 broadcast -c 10000 -n 1 -R 100 -d 5 -m 512
