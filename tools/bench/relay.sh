#!/bin/bash
# usage: relay.sh <relay-binary>
B=$1; L=/workspace/named666/nostrogotho/build/ngload; EV=/workspace/bench/ev400k.txt
start(){ pkill -f "port 7447"; sleep 1; rm -f /tmp/rb.sqlite*; taskset -c 0-3 $B --port 7447 --db /tmp/rb.sqlite >/tmp/rb.log 2>&1 & sleep 2; P=$!; }
start; for i in 1 2; do taskset -c 4-7 $L -p 7447 -c 64 -t 4 -P 16 -d 5 -f $EV -x $P -q nostr-pub | tail -1; done
start; taskset -c 4-7 $L -p 7447 -c 1000 -t 4 -n 4 -R 2000 -d 6 -f $EV -x $P -q nostr-fanout | tail -1
start; taskset -c 4-7 $L -p 7447 -c 5000 -t 4 -n 4 -R 500 -d 6 -f $EV -x $P -q nostr-fanout | tail -1
start; taskset -c 4-7 $L -p 7447 -c 50000 -t 4 -i 3 -d 5 -x $P -q hold | tail -1
pkill -INT -f "port 7447"
