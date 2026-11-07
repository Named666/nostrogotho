#!/usr/bin/env python3
"""Local relay soak. Uses ngload, /proc and isolated temporary databases.
Run: python3 tools/bench/scaling.py [--steps 10000,50000,...]
No sysctl writes. Stops before <2 GiB MemAvailable; each step is a fresh relay.
"""
import argparse, json, os, pathlib, re, resource, signal, subprocess, tempfile, time
ROOT = pathlib.Path(__file__).resolve().parents[2]
ap = argparse.ArgumentParser()
ap.add_argument('--steps', default='10000,50000,100000,250000,500000,1000000')
ap.add_argument('--events', default='/workspace/bench/ev400k.txt')
ap.add_argument('--relay', default=str(ROOT/'build/main'))
ap.add_argument('--out', default=str(ROOT/'tools/bench/scaling-results'))
a = ap.parse_args(); out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
resource.setrlimit(resource.RLIMIT_NOFILE, (resource.getrlimit(resource.RLIMIT_NOFILE)[1],)*2)
children = []
HZ = os.sysconf('SC_CLK_TCK')
def kv(path):
    try:
        return {x.split()[0].rstrip(':'): int(x.split()[1]) for x in pathlib.Path(path).read_text().splitlines() if len(x.split()) >= 2 and x.split()[1].isdigit()}
    except (FileNotFoundError, ProcessLookupError): return {}
def proc(pid):
    d = kv(f'/proc/{pid}/status'); tasks = {}
    try:
        for p in pathlib.Path(f'/proc/{pid}/task').iterdir():
            s = (p/'stat').read_text(); f = s[s.rfind(')')+2:].split()
            tasks[p.name] = dict(name=(p/'comm').read_text().strip(), cpu=(int(f[11])+int(f[12]))/HZ, wchan=(p/'wchan').read_text().strip())
    except (FileNotFoundError, ProcessLookupError): pass
    return dict(rss_kb=d.get('VmRSS',0), threads=tasks)
def snap(label, pid, client=None):
    return dict(label=label, monotonic=time.monotonic(), available_kb=kv('/proc/meminfo')['MemAvailable'], relay=proc(pid), client=proc(client) if client else {}, cgroup=kv('/sys/fs/cgroup/agent/memory.stat'), sockstat=pathlib.Path('/proc/net/sockstat').read_text(), sockstat6=pathlib.Path('/proc/net/sockstat6').read_text())
def spawn(cmd, name, env=None):
    f=open(out/(name+'.log'),'w'); p=subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, env=env); f.close(); children.append(p); return p
def cleanup():
    for p in reversed(children):
        if p.poll() is None: p.send_signal(signal.SIGINT if p.args[0]=='taskset' and a.relay in p.args else signal.SIGTERM)
    for p in reversed(children):
        try: p.wait(timeout=15)
        except subprocess.TimeoutExpired: p.kill(); p.wait()
def wait_for(seconds, relay, holder=None, samples=None):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if kv('/proc/meminfo')['MemAvailable'] < 2*1024*1024: raise RuntimeError('2 GiB headroom safety stop')
        if relay.poll() is not None: raise RuntimeError('relay exited')
        if samples is not None: samples.append(snap('monitor',relay.pid,holder.pid if holder else None))
        time.sleep(min(1,max(0,deadline-time.monotonic())))
def run_wait(p, relay, holder, samples):
    while p.poll() is None:
        if p is not holder and holder.poll() is not None: raise RuntimeError('idle population expired during traffic')
        wait_for(1,relay,holder,samples)
    if p.returncode: raise RuntimeError('load generator exit '+str(p.returncode))
results=[]; previous=None
try:
    for n in map(int,a.steps.split(',')):
        if n+1024 > resource.getrlimit(resource.RLIMIT_NOFILE)[0]:
            results.append(dict(target=n,skipped='per-process fd hard limit '+str(resource.getrlimit(resource.RLIMIT_NOFILE)[0]))); continue
        avail=kv('/proc/meminfo')['MemAvailable']*1024
        if previous:
            cost=max(previous['relay_rss_bytes_per_conn']+7000, previous['host_bytes_per_conn'])
            if cost*n*1.15 > avail-2*1024**3:
                results.append(dict(target=n,skipped='projected memory exceeds 2 GiB headroom',available_bytes=avail,projected_bytes=cost*n*1.15)); continue
        samples=[]; prefix=str(n); record=dict(target=n)
        with tempfile.TemporaryDirectory(prefix='nostrogotho-soak-') as td:
            pathlib.Path(td+'/relay.conf').write_text('db_sync = full\n')
            env=os.environ.copy(); env.update(NG_IO_THREADS='2',NG_WORKERS='4',NG_WRITER_STATS='1')
            relay=spawn(['taskset','-c','0-3',a.relay,'--port','17547','--db',td+'/relay.sqlite','--config',td+'/relay.conf'], prefix+'-relay',env)
            wait_for(1,relay)
            base=snap('base',relay.pid); samples.append(base)
            hold=spawn(['taskset','-c','4-7',str(ROOT/'build/ngload_soak'),'-p','17547','-c',str(n),'-t','4','-i',str(n//15000+2),'-k','128','-w','0','-d','62','-x',str(relay.pid),'hold'],prefix+'-hold')
            deadline=time.monotonic()+90
            while 'connected ' not in (out/(prefix+'-hold.log')).read_text():
                wait_for(1,relay,hold,samples)
                if hold.poll() is not None or time.monotonic()>deadline: raise RuntimeError('holder failed to connect')
            counts=re.search(r'connected (\d+) \(failed (\d+)\)', (out/(prefix+'-hold.log')).read_text())
            if not counts or int(counts[2]) > max(100,n//100): raise RuntimeError('connection failures dominate')
            connected=snap('connected',relay.pid,hold.pid); samples.append(connected)
            print('CONNECTED',n, 'RSS MiB',connected['relay']['rss_kb']/1024, 'available MiB',connected['available_kb']/1024,flush=True)
            wait_for(30,relay,hold,samples)
            samples.append(snap('idle_end',relay.pid,hold.pid))
            subs=max(100,n//100)
            fan=spawn(['taskset','-c','4-7',str(ROOT/'build/ngload_soak'),'-p','17547','-c',str(subs+1),'-t','4','-n','1','-R','3','-w','0','-d','12','-f',a.events,'-x',str(relay.pid),'nostr-fanout'],prefix+'-fanout')
            run_wait(fan,relay,hold,samples)
            samples.append(snap('fanout_end',relay.pid,hold.pid))
            # Separate IDs from the low-rate fanout; slicing once is cheap.
            ev=pathlib.Path(td+'/pub.txt');
            with open(a.events) as f, ev.open('w') as g:
                for i,line in enumerate(f):
                    if i>=1000: g.write(line)
            pub=spawn(['taskset','-c','4-7',str(ROOT/'build/ngload_soak'),'-p','17547','-c','64','-t','4','-P','16','-w','0','-d','8','-f',str(ev),'-x',str(relay.pid),'nostr-pub'],prefix+'-publish')
            run_wait(pub,relay,hold,samples)
            samples.append(snap('publish_end',relay.pid,hold.pid))
            run_wait(hold,relay,hold,samples)
            record.update(hold=(out/(prefix+'-hold.log')).read_text(),fanout=(out/(prefix+'-fanout.log')).read_text(),publish=(out/(prefix+'-publish.log')).read_text(),samples=samples)
            record['relay_rss_bytes_per_conn']=(connected['relay']['rss_kb']-base['relay']['rss_kb'])*1024/n
            # Anonymous + kernel, not reclaimable file cache; both endpoints included.
            record['host_bytes_per_conn']=sum(connected['cgroup'].get(k,0)-base['cgroup'].get(k,0) for k in ('anon','kernel'))/n
            previous=record; results.append(record)
            relay.send_signal(signal.SIGINT)
            try: relay.wait(timeout=15)
            except subprocess.TimeoutExpired: relay.kill(); relay.wait(); record['shutdown_timeout']=True
            (out/'results.json').write_text(json.dumps(results,indent=2))
            print(record['hold'].strip(),record['fanout'].strip(),record['publish'].strip(),sep='\n',flush=True)
            wait_for_cleanup=time.monotonic()+2
            while time.monotonic()<wait_for_cleanup: time.sleep(.2)
except Exception as e:
    results.append(dict(error=str(e),partial=locals().get('record'),samples=locals().get('samples',[])))
    print('STOP',e,flush=True)
finally:
    cleanup(); (out/'results.json').write_text(json.dumps(results,indent=2))
