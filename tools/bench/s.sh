#!/bin/bash
# s.sh <reps> "<args>" labels... : q.sh then medians (msgs_s, cpu, p50, p99) per label
R=$1; A=$2; shift 2
$(dirname $0)/q.sh $R "$A" "$@" > /tmp/s.raw
for lb in "$@"; do l=${lb%%=*}
 grep "^$l " /tmp/s.raw | python3 -c '
import sys,re,statistics as st
rows=[dict((k,int(v)) for k,v in re.findall(r"(\w+)=(\d+)",ln)) for ln in sys.stdin]
def f(k):
  v=[r[k] for r in rows if k in r]; return "%s=%d[%d-%d]"%(k,st.median(v),min(v),max(v)) if v else ""
print(sys.argv[1], *[f(k) for k in ("msgs_s","srv_cpu_pct","lat_us_p50","p99")])' "$l"
done
