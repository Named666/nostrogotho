#!/bin/bash
# matrix.sh <reps> <label=bin>...   bins take: <port> <threads> echo|broadcast
# Server pinned to CPUs ${SCPU:-0-3}, ngload to ${CCPU:-4-7} with ${CT:-4} threads.
L=/workspace/named666/nostrogotho/build/ngload
R=$1; shift
SCPU=${SCPU:-0-3}; CCPU=${CCPU:-4-7}; CT=${CT:-4}
one() { # name st srvmode ngload-args...
  local name=$1 st=${ST:-$2} sm=$3; shift 3
  for r in $(seq $R); do for lb in "${BINS[@]}"; do
    local lab=${lb%%=*} bin=${lb#*=}
    pkill -f "$bin 9001" 2>/dev/null; sleep 0.2
    taskset -c $SCPU $bin 9001 $st $sm >/dev/null 2>&1 & local P=$!; sleep 0.4
    o=$(timeout 120 taskset -c $CCPU $L -t $CT -x $P -q "$@" 2>/dev/null)
    kill $P 2>/dev/null; wait $P 2>/dev/null
    echo "$name|$lab|$(echo $o | grep -oE ' (msgs_s|MB_s|lat_us_p50|p99|p999|srv_cpu_pct|client_cpu_pct|bytes_per_conn|open)=[0-9.]+' | tr -d ' ' | tr '\n' ' ')"
  done; done
}
BINS=("$@")
CASES=${CASES:-all}
want() { [ "$CASES" = all ] || [[ " $CASES " == *" $1 "* ]]; }
if want size; then
for m in 16 64 512 4096 65536; do one "echo m=$m c=100 P8 st4" 4 echo -c 100 -P 8 -d 4 -m $m echo; done
one "echo m=1MB c=20 P2 st4" 4 echo -c 20 -P 2 -d 4 -m 1048576 echo
fi
if want pipe; then for P in 1 8 64; do one "echo m=64 c=100 P$P st4" 4 echo -c 100 -P $P -d 4 -m 64 echo; done; fi
if want conns; then
one "echo m=64 c=2k P1 st4" 4 echo -c 2000 -P 1 -d 4 -m 64 echo
one "echo m=64 c=20k P1 st4" 4 echo -c 20000 -P 1 -d 4 -i 2 -m 64 echo
one "echo m=64 c=100k P1 st4" 4 echo -c 100000 -P 1 -d 4 -i 6 -k 1024 -m 64 echo
fi
if want threads; then for st in 1 2 4; do one "echo m=64 c=500 P8 st$st" $st echo -c 500 -P 8 -d 4 -m 64 echo; done; fi
if want bcast; then
one "bcast closed c=1k P4 m=64 st1" 1 broadcast -c 1000 -n 1 -P 4 -d 4 -m 64 bcast
one "bcast 1k subs R=2000 m=64 st1" 1 broadcast -c 1000 -n 1 -R 2000 -d 4 -m 64 bcast
one "bcast 1k subs R=1000 m=512 st1" 1 broadcast -c 1000 -n 1 -R 1000 -d 4 -m 512 bcast
one "bcast 10k subs R=200 m=64 st1" 1 broadcast -c 10000 -n 1 -R 200 -d 4 -m 64 bcast
one "bcast 10k subs R=100 m=512 st1" 1 broadcast -c 10000 -n 1 -R 100 -d 4 -m 512 bcast
one "bcast 50k subs R=40 m=64 st1" 1 broadcast -c 50000 -n 1 -R 40 -d 4 -i 3 -k 1024 -m 64 bcast
fi
if want churn; then one "churn c=200 st4" 4 echo -c 200 -d 4 churn; fi
if want lat; then
one "echo fixed 100k/s c=2k m=64 st4" 4 echo -c 2000 -R 100000 -d 4 -m 64 echo
one "echo fixed 400k/s c=2k m=64 st4" 4 echo -c 2000 -R 400000 -d 4 -m 64 echo
fi
if want idle; then
one "idle 100k" 4 echo -c 100000 -d 3 -i 6 -k 1024 hold
one "idle 200k" 4 echo -c 200000 -d 3 -i 12 -k 1024 hold
fi
