#!/bin/bash
# Runs test_dedupe.py against build/${1:-main} with the in-flight/recent set
# enabled (default) and disabled (NG_DEDUPE_RECENT=0: exercises the per-batch
# and UNIQUE-index guards alone).
: > /tmp/dedupe_relay.log; B=build/${1:-main}; PY=${PY:-python3}; rc=0
for cfg in default 0; do
  pkill -f "$B --port 7449" 2>/dev/null; sleep 0.5
  DB=$(mktemp -u /tmp/dedupe.XXXX.sqlite)
  if [ $cfg = 0 ]; then export NG_DEDUPE_RECENT=0; else unset NG_DEDUPE_RECENT; fi
  $B --port 7449 --db $DB >>/tmp/dedupe_relay.log 2>&1 & P=$!; sleep 1.5
  echo "== dedupe set: $cfg"
  RELAY_URL=ws://127.0.0.1:7449 RELAY_DB=$DB $PY test_dedupe.py || rc=1
  kill -INT $P; wait $P 2>/dev/null; rm -f $DB*
done
exit $rc
