import sys,re,statistics as st,collections
d=collections.OrderedDict()
for ln in open(sys.argv[1]):
    if '|' not in ln: continue
    name,lab,rest=ln.rstrip('\n').split('|',2)
    kv=dict((k,float(v)) for k,v in re.findall(r"(\w+)=([0-9.]+)",rest))
    d.setdefault(name,collections.OrderedDict()).setdefault(lab,[]).append(kv)
keys=sys.argv[2].split(',') if len(sys.argv)>2 else ['msgs_s','srv_cpu_pct','lat_us_p50','p99','bytes_per_conn','client_cpu_pct']
for name,labs in d.items():
    out=[]
    for lab,rows in labs.items():
        parts=[]
        for k in keys:
            v=[r[k] for r in rows if k in r]
            if v: parts.append("%s=%g[%g-%g]"%(k,st.median(v),min(v),max(v)))
        out.append(lab+": "+" ".join(parts))
    print(name); [print("   ",o) for o in out]
