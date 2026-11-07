#!/bin/bash
# pub.sh <bin> [conns] [pipeline]  -> nostr-pub run + per-thread CPU split
B=$1; C=${2:-64}; PL=${3:-16}
pkill -f "port 7447"; sleep 1; rm -f ${DBDIR:-/tmp}/rb.sqlite*
NG_WRITER_STATS=1 taskset -c 0-3 $B --port 7447 --db ${DBDIR:-/tmp}/rb.sqlite >/tmp/rb.log 2>&1 & P=$!; sleep 2
taskset -c 4-7 /workspace/named666/nostrogotho/build/ngload -p 7447 -c $C -t 4 -P $PL -d 6 -f /workspace/bench/${EVF:-ev1500k.txt} -x $P -q nostr-pub > /tmp/pub.out &
sleep 3; for t in /proc/$P/task/*; do echo "$(basename $t) $(awk '{print $14+$15}' $t/stat)"; done > /tmp/a; sleep 3
for t in /proc/$P/task/*; do echo "$(basename $t) $(awk '{print $14+$15}' $t/stat)"; done > /tmp/b; wait %2 2>/dev/null; sleep 1
cut -c1-330 /tmp/pub.out | tail -1
paste /tmp/a /tmp/b | awk '{printf "%d%% ", ($4-$2)/3} END{print " <- per-thread CPU (main, workers..., writer, io)"}'
kill -INT $P; sleep 2; grep writer: /tmp/rb.log
