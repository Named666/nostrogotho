#!/usr/bin/env python3
"""Bounded high-connection diagnostics; profiling binary optional (--gprof).
Build profiling binary using scaling-results/profile-build.txt first.
"""
import argparse, collections, json, os, pathlib, signal, subprocess, tempfile, time
ROOT=pathlib.Path(__file__).resolve().parents[2]
ap=argparse.ArgumentParser(); ap.add_argument('--relay',default=str(ROOT/'build/main_soak')); ap.add_argument('--gprof',action='store_true'); ap.add_argument('--idle',type=int,default=100000); ap.add_argument('--case',choices=['fanout','publish','keepalive'],required=True); ap.add_argument('--duration',type=int,default=15); ap.add_argument('--rate',type=int,default=300); ap.add_argument('--subs',type=int,default=1000); ap.add_argument('--label',default=''); a=ap.parse_args()
out=ROOT/'tools/bench/scaling-results'; prefix=('gprof-' if a.gprof else 'diag-')+a.case+a.label; children=[]; logs=[]; samples=[]; HZ=os.sysconf('SC_CLK_TCK')
def data(path):
 try: return pathlib.Path(path).read_text()
 except (FileNotFoundError,ProcessLookupError): return ''
def mem(): return int(data('/proc/meminfo').split('MemAvailable:')[1].split()[0])
def spawn(cmd,name,td,env=None):
 f=open(out/(prefix+'-'+name+'.log'),'w'); logs.append(f); p=subprocess.Popen(cmd,cwd=td,env=env,stdout=f,stderr=subprocess.STDOUT); children.append(p); return p
start=time.monotonic()
def tick():
 if mem()<2*1024*1024: raise RuntimeError('2 GiB memory headroom stop')
 if relay.poll() is not None: raise RuntimeError('relay exited')
 tasks={}
 for p in pathlib.Path(f'/proc/{relay.pid}/task').iterdir():
  st=data(p/'stat'); f=st[st.rfind(')')+2:].split()
  if f: tasks[p.name]=dict(cpu=(int(f[11])+int(f[12]))/HZ,user=int(f[11])/HZ,system=int(f[12])/HZ,name=data(p/'comm').strip(),wchan=data(p/'wchan').strip())
 samples.append(dict(t=time.monotonic()-start,available_kb=mem(),threads=tasks,status=data(f'/proc/{relay.pid}/status'),sockstat=data('/proc/net/sockstat'),sockstat6=data('/proc/net/sockstat6')))
 time.sleep(.1)
error=None
try:
 with tempfile.TemporaryDirectory(prefix='ng-diag-') as td:
  pathlib.Path(td+'/relay.conf').write_text('db_sync = full\n')
  env=os.environ.copy(); env.setdefault('NG_IO_THREADS','2'); env.setdefault('NG_WORKERS','4'); env['NG_WRITER_STATS']='1'
  if os.environ.get('NG_DEFAULT_THREADS')=='1': env.pop('NG_IO_THREADS'); env.pop('NG_WORKERS')
  relay=spawn(['taskset','-c','0-3',a.relay,'--port','17548','--db',td+'/relay.sqlite','--config',td+'/relay.conf'],'relay',td,env)
  for _ in range(10): tick()
  holder=spawn(['taskset','-c','4-7',str(ROOT/'build/ngload_soak'),'-p','17548','-c',str(a.idle),'-i',str(a.idle//15000+2),'-k','128','-t','4','-w','0','-d',str(a.duration+8),'-x',str(relay.pid),'hold'],'hold',td)
  while 'connected ' not in data(out/(prefix+'-hold.log')):
   tick()
   if holder.poll() is not None: raise RuntimeError('holder exited')
  traffic_start=time.monotonic()-start
  if a.case!='keepalive':
   cmd=['taskset','-c','4-7',str(ROOT/'build/ngload_soak'),'-p','17548','-t','4','-w','0','-d',str(a.duration),'-f','/workspace/bench/ev400k.txt','-x',str(relay.pid)]
   if a.case=='fanout': cmd+=['-c',str(a.subs+1),'-n','1','-R',str(a.rate),'nostr-fanout']
   else: cmd+=['-c','64','-P','16','nostr-pub']
   load=spawn(cmd,'traffic',td)
   while load.poll() is None: tick()
  else:
   while holder.poll() is None: tick()
  traffic_end=time.monotonic()-start
  while holder.poll() is None: tick()
  relay.send_signal(signal.SIGINT)
  try: relay.wait(timeout=20)
  except subprocess.TimeoutExpired: raise RuntimeError('relay shutdown timeout')
  if a.gprof:
   with open(out/(prefix+'-flat.txt'),'w') as f: subprocess.run(['gprof','-b','-p',a.relay,td+'/gmon.out'],stdout=f,check=True)
except Exception as e: error=str(e)
finally:
 for p in reversed(children):
  if p.poll() is None: p.terminate()
 for p in reversed(children):
  try: p.wait(timeout=10)
  except subprocess.TimeoutExpired: p.kill(); p.wait()
 for f in logs: f.close()
 (out/(prefix+'.json')).write_text(json.dumps(dict(error=error,traffic_start=locals().get('traffic_start'),traffic_end=locals().get('traffic_end'),samples=samples),indent=2))
 print(prefix,'error=',error,flush=True)
 if error: raise SystemExit(1)
