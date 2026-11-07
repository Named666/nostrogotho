#!/bin/bash
# hold.sh conns bin...   (server 4 loops/threads, pinned 0-3)
C=$1; shift
for b in "$@"; do
  taskset -c 0-3 $b 9001 4 echo >/dev/null 2>&1 & P=$!; sleep 0.3
  o=$(taskset -c 4-7 /workspace/named666/nostrogotho/build/ngload -t 4 -x $P -c $C -d 10 -w 2 -k 512 hold 2>&1 | tail -1)
  kill $P; wait $P 2>/dev/null
  echo "$(basename $b) $o"
done
