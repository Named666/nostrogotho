#!/bin/bash
# ab.sh "<ngload args> <mode>" st srvmode reps bin1 bin2 ...
A=$1; ST=$2; SM=$3; R=$4; shift 4
L=/workspace/named666/nostrogotho/build/ngload
for r in $(seq $R); do for b in "$@"; do
  taskset -c 0-3 $b 9001 $ST $SM >/dev/null 2>&1 & P=$!; sleep 0.3
  o=$(taskset -c 4-7 $L -t 4 -x $P $A 2>/dev/null); kill $P; wait $P 2>/dev/null
  echo "$(basename $b) $(echo $o | grep -oE 'msgs_s=[0-9]+|p50=[0-9]+|p99=[0-9]+|srv_cpu_pct=[0-9]+' | tr '\n' ' ')"
done; done | sort | awk '{print}'
