import json,hashlib,sys,time,os
from coincurve import PrivateKey
from multiprocessing import Pool
N=int(sys.argv[1]); out=sys.argv[2]
def mk(r):
    keys=[PrivateKey(hashlib.sha256(b'k%d'%k).digest()) for k in range(64)]
    res=[]
    for i in r:
        k=keys[i%64]; pk=k.public_key_xonly.format().hex()
        ev=[0,pk,1700000000+i,1,[["t","bench"]],str(i)]
        s=json.dumps(ev,separators=(',',':'),ensure_ascii=False)
        eid=hashlib.sha256(s.encode()).digest()
        sig=k.sign_schnorr(eid)
        res.append(json.dumps(["EVENT",{"id":eid.hex(),"pubkey":pk,"created_at":ev[2],"kind":1,"tags":ev[4],"content":ev[5],"sig":sig.hex()}],separators=(',',':')))
    return res
ch=[range(a,min(a+5000,N)) for a in range(0,N,5000)]
with Pool(8) as p, open(out,'w') as f:
    for r in p.map(mk,ch): f.write('\n'.join(r)+'\n')
