import sys,re,statistics as st,collections as C
d=C.OrderedDict()
for ln in open(sys.argv[1]):
    p=ln.rstrip('\n').split('|')
    if len(p)<3: continue
    kv=dict((k,float(v)) for k,v in re.findall(r'(\w+)=([\d.]+)',p[2]))
    d.setdefault(p[0],{}).setdefault(p[1],[]).append(kv)
def f(rows,k,fmt):
    v=[r[k] for r in rows if k in r]
    if not v: return '-'
    return fmt(st.median(v))+' ['+fmt(min(v))+'-'+fmt(max(v))+']'
def n(x):
    return '%.2fM'%(x/1e6) if x>=1e6 else ('%.1fk'%(x/1e3) if x>=1e3 else '%.0f'%x)
for case,by in d.items():
    for lab,rows in by.items():
        key='bytes_per_conn' if case.startswith('idle') else 'msgs_s'
        print('%s | %s | %s | cpu %s | p50 %s | p99 %s | open %s'%(case,lab,f(rows,key,n),f(rows,'srv_cpu_pct',lambda x:'%.0f'%x),f(rows,'lat_us_p50',lambda x:'%.0f'%x),f(rows,'p99',lambda x:'%.0f'%x),f(rows,'open',lambda x:'%.0f'%x)))
