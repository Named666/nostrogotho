#!/bin/bash
# q.sh <reps> "<ngload args>" label=bin[:ENV=V] ...   server: 2 threads on CPUs 0-1, ngload 6 threads on 2-7
R=$1; A=$2; shift 2
for r in $(seq $R); do for lb in "$@"; do lab=${lb%%=*}; rest=${lb#*=}; bin=${rest%%:*}; envs=""; [[ $rest == *:* ]] && envs=${rest#*:}
  pkill -f "9001 2" 2>/dev/null; sleep 0.2
  env $envs taskset -c 0-1 $bin 9001 2 ${SM:-echo} >/dev/null 2>&1 & P=$!; sleep 0.4
  o=$(timeout 60 taskset -c 2-7 /workspace/named666/nostrogotho/build/ngload -t 6 -x $P -q $A 2>/dev/null); kill $P; wait $P 2>/dev/null
  echo "$lab $(echo $o | grep -oE ' (msgs_s|lat_us_p50|p99|srv_cpu_pct)=[0-9]+' | tr -d '\n')"
done; done
