#!/usr/bin/env python3
"""Summarize a diagnose.py JSON: per-thread CPU% over the traffic window + traffic line."""
import json,sys,gzip,pathlib,collections
for fn in sys.argv[1:]:
    d=json.load(open(fn)); s=d['samples']; t0,t1=d['traffic_start'],d['traffic_end']
    w=[x for x in s if t0<=x['t']<=t1]
    if len(w)<2: print(fn,'no window'); continue
    a,b=w[0],w[-1]; dt=b['t']-a['t']; agg=collections.defaultdict(lambda:[0,0,0])
    for tid,tb in b['threads'].items():
        ta=a['threads'].get(tid)
        if not ta: continue
        n=tb['name'].rsplit('-',1)[0] if tb['name'].startswith(('ng-io','ng-worker')) else tb['name']
        g=agg[tb['name']]; g[0]+=100*(tb['cpu']-ta['cpu'])/dt; g[1]+=100*(tb['system']-ta['system'])/dt
    print(pathlib.Path(fn).name, 'minavail_MiB=%d'%(min(x['available_kb'] for x in s)/1024))
    print('  '+' '.join('%s=%.0f%%(sys %.0f)'%(k,v[0],v[1]) for k,v in sorted(agg.items()) if v[0]>=0.5))
    tl=pathlib.Path(fn.replace('.json','-traffic.log'))
    if tl.exists(): print('  '+tl.read_text().strip().splitlines()[-1][:400])
