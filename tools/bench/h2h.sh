#!/bin/bash
# h2h.sh reps label=bin ... : final head-to-head. Server on CPUs 0-1 (2 threads unless noted), ngload 6 threads on 2-7.
L=/workspace/named666/nostrogotho/build/ngload; R=$1; shift; BINS=("$@")
one() { local name=$1 st=$2 sm=$3; shift 3
  for r in $(seq $R); do for lb in "${BINS[@]}"; do local lab=${lb%%=*} bin=${lb#*=}
    pkill -f " 9001 " 2>/dev/null; sleep 0.3
    local sc=0-1; [ $st = 1 ] && sc=0
    taskset -c $sc $bin 9001 $st $sm >/dev/null 2>&1 & local P=$!; sleep 0.4
    o=$(timeout 120 taskset -c 2-7 $L -t 6 -x $P -q "$@" 2>/dev/null)
    kill $P 2>/dev/null; wait $P 2>/dev/null
    echo "$name|$lab|$(echo $o | grep -oE ' (open|msgs_s|MB_s|lat_us_p50|p99|srv_cpu_pct|bytes_per_conn)=[0-9.]+' | tr -d ' ' | tr '\n' ' ')"
  done; done; }
for m in 16 64 512 4096 65536 1048576; do one "echo ${m}B c100 P8 st2" 2 echo -c 100 -P 8 -d 4 -m $m echo; done
one "echo 64B c100 P8 st1" 1 echo -c 100 -P 8 -d 4 -m 64 echo
one "bcast 1k subs closed P4 64B st1" 1 broadcast -c 1000 -n 1 -P 4 -d 4 -m 64 bcast
one "bcast 1k subs R=2000 64B st1" 1 broadcast -c 1000 -n 1 -R 2000 -d 4 -m 64 bcast
one "bcast 10k subs R=200 64B st1" 1 broadcast -c 10000 -n 1 -R 200 -d 4 -m 64 bcast
one "bcast 10k subs R=100 512B st1" 1 broadcast -c 10000 -n 1 -R 100 -d 4 -m 512 bcast
one "churn c200 st2" 2 echo -c 200 -d 4 churn
one "fixed 100k/s c2k 64B st2" 2 echo -c 2000 -R 100000 -d 4 -m 64 echo
one "fixed 300k/s c2k 64B st2" 2 echo -c 2000 -R 300000 -d 4 -m 64 echo
one "idle 100k st2" 2 echo -c 100000 -d 3 -i 6 -k 1024 hold
