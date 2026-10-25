import os,io,zipfile,struct,hashlib,sys,zlib
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding
from dexscan import Dex

def read_lp(data,p):
 n=struct.unpack_from('<I',data,p)[0]
 return data[p+4:p+4+n],p+4+n

def validate(path):
 b=path.read_bytes()
 cd=struct.unpack_from('<I',b,len(b)-22+16)[0]
 e=len(b)-22
 q=cd-24
 size2=struct.unpack_from('<Q',b,q)[0]
 assert b[q+8:q+24]==b'APK Sig Block 42'
 start=cd-8-size2
 assert struct.unpack_from('<Q',b,start)[0]==size2
 o=start+8
 size=struct.unpack_from('<Q',b,o)[0];o+=8
 aid=struct.unpack_from('<I',b,o)[0];o+=4
 assert aid==0x7109871a
 value=b[o:o+size-4]
 signer,p=read_lp(value,0)
 assert p==len(value)
 sd,p=read_lp(signer,0);sigs,p=read_lp(signer,p);pkey,p=read_lp(signer,p)
 assert p==len(signer)
 certs,pos=read_lp(sd,0);certs,pos=read_lp(sd,pos);attrib,pos=read_lp(sd,pos)
 digests,pos=read_lp(sd,0)
 d,_=read_lp(digests,0)
 algo=struct.unpack_from('<I',d,0)[0];stored,p=read_lp(d,4)
 assert algo==0x103
 signrec,p=read_lp(sigs,0)
 assert struct.unpack_from('<I',signrec,0)[0]==algo
 signature,p=read_lp(signrec,4)
 certder,_=read_lp(certs,0)
 pub=x509.load_der_x509_certificate(certder).public_key()
 assert pkey==pub.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
 pub.verify(signature,sd,padding.PKCS1v15(),hashes.SHA256())
 # independent content digest
 chunks=[]
 eocd=bytearray(b[e:]);struct.pack_into('<I',eocd,16,start)
 for buf in [b[:start],b[cd:e],eocd]:
  for i in range(0,len(buf),1024*1024):
   ch=buf[i:i+1024*1024]
   chunks.append(hashlib.sha256(b'\xa5'+struct.pack('<I',len(ch))+ch).digest())
 actual=hashlib.sha256(b'\x5a'+struct.pack('<I',len(chunks))+b''.join(chunks)).digest()
 assert actual==stored,'content digest mismatch'
 assert zipfile.is_zipfile(path)
 zz=zipfile.ZipFile(path)
 for x in zz.infolist():
  if x.filename.endswith('.so'):
   off=x.header_offset
   fnlen,extralen=struct.unpack_from('<HH',b,off+26)
   offset=off+30+fnlen+extralen
   assert offset%4096==0,(x.filename,offset%4096)
 return hashlib.sha256(certder).hexdigest(),len(zz.infolist())

z=zipfile.ZipFile('/mnt/data/YI_IoT_5.1.8_clean_arm64.apks')
for fn in ['base.apk','split_config.arm64_v8a.apk','split_config.xxhdpi.apk','split_config.en.apk']:
 p=Path('/mnt/data/smartcamera_work/mod_'+fn)
 c,n=validate(p)
 print(fn,'v2 VERIFIED',n,'entries','certificate',c[:24])
 if fn=='base.apk':
  zz=zipfile.ZipFile(p)
  for dfn in [x for x in zz.namelist() if x.endswith('.dex') and x.startswith('classes')]:
   b=zz.read(dfn)
   assert struct.unpack_from('<I',b,8)[0]==zlib.adler32(b[12:])&0xffffffff
   assert b[12:32]==hashlib.sha1(b[32:]).digest()
  print(' Dex checksums VERIFIED')
