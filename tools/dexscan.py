import struct,zipfile,os,re

def uleb(data,p):
 v=0
 for i in range(5):
  a=data[p];p+=1;v|=(a&0x7f)<<(7*i)
  if a<128:break
 return v,p

class Dex:
 def __init__(self,b,n):
  self.b=b;self.name=n;self.h=lambda i:struct.unpack_from('<H',b,i)[0];self.u=lambda i:struct.unpack_from('<I',b,i)[0]
  self.nstr,self.soff=self.u(0x38),self.u(0x3c)
  self.ntype,self.toff=self.u(0x40),self.u(0x44)
  self.npro,self.poff=self.u(0x48),self.u(0x4c)
  self.nfield,self.foff=self.u(0x50),self.u(0x54)
  self.nmeth,self.moff=self.u(0x58),self.u(0x5c)
  self.nclass,self.coff=self.u(0x60),self.u(0x64)
  self.strings=[]
  for i in range(self.nstr):
   p=self.u(self.soff+4*i);_,p=uleb(b,p);e=b.index(b'\0',p)
   self.strings.append(b[p:e].decode('utf8','replace'))
  self.types=[self.strings[self.u(self.toff+i*4)] for i in range(self.ntype)]
  self.protos=[]
  for i in range(self.npro):
   p=self.poff+12*i
   rtype=self.types[self.u(p+4)];po=self.u(p+8);params=[]
   if po:
    count=self.u(po);params=[self.types[self.h(po+4+2*j)] for j in range(count)]
   self.protos.append((rtype,params))
  self.methods=[]
  for i in range(self.nmeth):
   p=self.moff+i*8;cl=self.h(p);pro=self.h(p+2);name=self.u(p+4)
   self.methods.append((self.types[cl], self.strings[name],pro))
  self.class_methods={};self.locations={}
  for i in range(self.nclass):
   p=self.coff+i*32;cl=self.u(p);doff=self.u(p+24)
   if not doff:continue
   pos=doff
   n_sf,pos=uleb(b,pos);n_if,pos=uleb(b,pos);n_dm,pos=uleb(b,pos);n_vm,pos=uleb(b,pos)
   for _ in range(n_sf+n_if):
    _,pos=uleb(b,pos);_,pos=uleb(b,pos)
   mids=[]
   for k in range(2):
    mi=0
    for _ in range((n_dm,n_vm)[k]):
     diff,pos=uleb(b,pos);mi+=diff
     flag,pos=uleb(b,pos);code,pos=uleb(b,pos)
     mids.append((mi,code,flag))
     if code:self.locations[mi]=(code,self.u(code+12))
   self.class_methods[self.types[cl]]=mids
 def candidates(self,patterns):
  for cl,mids in self.class_methods.items():
   if any(re.search(p,cl,re.I) for p in patterns):
    print(self.name,cl,len(mids))
 def dump(self,cl):
  for mi,code,flag in self.class_methods.get(cl,[]):
   name=self.methods[mi][1]
   print(mi,name, self.protos[self.methods[mi][2]], ('0x%x'%code if code else ''), 'words'+str(self.u(code+12)) if code else '')

if __name__=='__main__':
 z=zipfile.ZipFile('/mnt/data/smartcamera_work/base.apk')
 for fn in sorted([k for k in z.namelist() if k.startswith('classes') and k.endswith('.dex')]):
  d=Dex(z.read(fn),fn)
  print(fn,len(d.class_methods),len(d.methods),len(d.strings))
  d.candidates([r'^Lcom/yd/saas/',r'^Lcom/mbridge/',r'^Lcom/google/android/gms/ads/',r'^Lcom/bytedance/sdk/openadsdk',r'^Lcom/unity3d/ads/',r'^Lcom/ironsource',r'^Lcom/applovin',r'^Lcom/yunyi/smartcamera'])
