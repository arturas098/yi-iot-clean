import os,sys,zipfile,io,hashlib,zlib,struct,datetime,json,shutil,math
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.x509.oid import NameOID
from dexscan import Dex
from pathlib import Path

ROOT=Path('/mnt/data/smartcamera_work')
ORIGINAL=list(Path('/mnt/data').glob('com.yunyi.smartcamera*.apkm'))[0]
OUT=Path('/mnt/data/YI_IoT_5.1.8_clean_arm64.apks')

def patch_dex(b,fn):
 d=Dex(b,fn); b=bytearray(b); rec=[]
 for cl,ms in d.class_methods.items():
  for mi,co,flag in ms:
   if not co:continue
   name=d.methods[mi][1];ret,params=d.protos[d.methods[mi][2]]
   app=cl.startswith('Lcom/xiaoyi/')
   yd=cl.startswith('Lcom/yd/saas/')
   googleads=cl.startswith('Lcom/google/android/gms/ads/')
   mbridge=cl.startswith('Lcom/mbridge/msdk/out/')
   doit=False
   # Entry points used by YD ad mediation incl. AdMob, Bigo, and splash/overlay ad units
   if yd and cl.startswith('Lcom/yd/saas/ydsdk/'):
    doit=(name in ('requestBanner','requestDrawVideo','requestFullVideo','requestInterstitial','requestNative','requestSpread','requestAD','requestRewardVideo','loadMixNative','show') and ret=='V')
   # Stop direct google ad requests as a secondary channel
   if googleads:
    doit |= (cl in ('Lcom/google/android/gms/ads/AdLoader;', 'Lcom/google/android/gms/ads/interstitial/InterstitialAd;','Lcom/google/android/gms/ads/admanager/AdManagerInterstitialAd;', 'Lcom/google/android/gms/ads/rewarded/RewardedAd;', 'Lcom/google/android/gms/ads/rewardedinterstitial/RewardedInterstitialAd;') and name in ('load','loadAd','loadAds') and ret=='V')
   # Mintegral direct ad SDK entrypoints
   if mbridge:
    doit |= cl in ('Lcom/mbridge/msdk/out/MBBannerView;','Lcom/mbridge/msdk/out/MBNativeAdvancedHandler;') and name in ('load','loadFromBid','loadByToken') and ret=='V'
   # First party dedicated video ad UI entry points only, not camera or playback
   if app:
    doit |= cl in ('Lcom/xiaoyi/cloud/newCloud/activity/TaskActivity;', 'Lcom/xiaoyi/cloud/newCloud/activity/ChinaPurchaseActivity;') and name in ('loadAD','loadKs','loadLr','loadWhRewardVideo','showKs','showLr','showAdVideo') and ret=='V'
    doit |= cl in ('Lcom/xiaoyi/yiplayer/ui/BallCameraPlayerFragment;','Lcom/xiaoyi/yiplayer/ui/BallPlaybackFragment;','Lcom/xiaoyi/yiplayer/ui/MultiCameraPlayerFragment;','Lcom/xiaoyi/yiplayer/ui/PlaybackChinaFragment;','Lcom/xiaoyi/yiplayer/ui/PlayerFragment;') and name=='showVideoAdFrament' and ret=='V'
   if not doit:continue
   # Short circuit method with return-void. Keep file layout unchanged.
   regs=struct.unpack_from('<H',b,co)[0]
   n=struct.unpack_from('<I',b,co+12)[0]
   if ret!='V' or n<1:continue
   struct.pack_into('<H',b,co+16,0x000e)
   rec.append({'class':cl[1:-1].replace('/','.'),'method':name,'parameter_count':len(params)})
 # DEX checksum and signature
 if rec:
  b[12:32]=hashlib.sha1(b[32:]).digest()
  struct.pack_into('<I',b,8,zlib.adler32(b[12:])&0xffffffff)
 return bytes(b),rec

def pack_apk(src,fn,path):
 rec=[]
 with zipfile.ZipFile(io.BytesIO(src)) as zi, zipfile.ZipFile(path,'w',allowZip64=True) as zo:
  zo.comment=zi.comment
  for old in zi.infolist():
   nm=old.filename
   if nm.startswith('META-INF/') or nm=='stamp-cert-sha256':continue
   data=zi.read(old)
   if fn=='base.apk' and nm.startswith('classes') and nm.endswith('.dex'):
    data,these=patch_dex(data,nm);rec+=these
   new=zipfile.ZipInfo(nm,old.date_time)
   new.compress_type=old.compress_type
   new.external_attr=old.external_attr
   new.create_system=old.create_system
   new.comment=old.comment
   new.internal_attr=old.internal_attr
   new.flag_bits=old.flag_bits
   # Keep uncompressed native .so aligned at 4096-byte pages
   if nm.endswith('.so') and new.compress_type==zipfile.ZIP_STORED:
    pos=zo.fp.tell()
    namelen=len(nm.encode('utf8'))
    pad=(-pos-30-namelen-4)%4096
    new.extra=struct.pack('<HH',0xd935,pad)+b'\0'*pad
   zo.writestr(new,data,compress_type=new.compress_type,compresslevel=6)
 return rec

def lp(data):return struct.pack('<I',len(data))+data

def digest_sections(path,cd,eo):
 # 1MB content digest chunks per APK Signature Scheme v2.
 digests=[]
 with open(path,'rb') as f:
  for start,length in [(0,cd),(cd,eo-cd)]:
   f.seek(start)
   while length:
    chunk=f.read(min(length,1024*1024));length-=len(chunk)
    digests.append(hashlib.sha256(b'\xa5'+struct.pack('<I',len(chunk))+chunk).digest())
  f.seek(eo)
  eocd=bytearray(f.read())
  if eocd[:4]!=b'PK\x05\x06':raise ValueError('EOCD not found')
  struct.pack_into('<I',eocd,16,cd)
  for k in range(0,len(eocd),1024*1024):
   chunk=eocd[k:k+1024*1024]
   digests.append(hashlib.sha256(b'\xa5'+struct.pack('<I',len(chunk))+chunk).digest())
 return hashlib.sha256(b'\x5a'+struct.pack('<I',len(digests))+b''.join(digests)).digest()

def v2_sign(path,key,cert):
 with open(path,'rb') as f:
  f.seek(-22,2);end=f.tell();eocd=f.read(22)
  assert eocd[:4]==b'PK\x05\x06' and eocd[20:22]==b'\0\0','Unexpected ZIP comment'
  cd=struct.unpack_from('<I',eocd,16)[0];assert cd<end
 dd=digest_sections(path,cd,end)
 certder=cert.public_bytes(serialization.Encoding.DER)
 pkey=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
 # RSA PKCS#1 v1.5 SHA256 algorithm 0x0103
 algo=0x0103
 signed_data=lp(lp(struct.pack('<I',algo)+lp(dd)))+lp(lp(certder))+lp(b'')
 signature=key.sign(signed_data,padding.PKCS1v15(),hashes.SHA256())
 signer=lp(signed_data)+lp(lp(struct.pack('<I',algo)+lp(signature)))+lp(pkey)
 value=lp(signer)
 pair=struct.pack('<Q',len(value)+4)+struct.pack('<I',0x7109871a)+value
 size=8+len(pair)+8+16
 block=struct.pack('<Q',size-8)+pair+struct.pack('<Q',size-8)+b'APK Sig Block 42'
 temp=path.with_suffix('.signed.tmp')
 with open(path,'rb') as inp,open(temp,'wb') as out:
  # Local file entries, signing block, central dir, adjusted EOCD
  n=cd
  while n:
   chunk=inp.read(min(n,4*1024*1024));out.write(chunk);n-=len(chunk)
  out.write(block)
  while inp.tell()<end:
   chunk=inp.read(min(end-inp.tell(),4*1024*1024));out.write(chunk)
  new_eocd=bytearray(eocd);struct.pack_into('<I',new_eocd,16,cd+len(block))
  out.write(new_eocd)
 os.replace(temp,path)
 return {'digest_sha256':dd.hex(),'block_size':len(block),'certificate_sha256':hashlib.sha256(certder).hexdigest()}

if __name__=='__main__':
 key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
 name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'YI IoT Clean Personal Build')])
 now=datetime.datetime.now(datetime.timezone.utc)
 cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=3650)).sign(key,hashes.SHA256()))
 # Store key to make future upgrades compatible; use random password in report.
 import secrets
 password=secrets.token_urlsafe(20)
 ks=ROOT/'yi_clean_update_key.p12'
 ks.write_bytes(pkcs12.serialize_key_and_certificates(b'YI Clean',key,cert,None,serialization.BestAvailableEncryption(password.encode())))
 specs=['base.apk','split_config.arm64_v8a.apk','split_config.xxhdpi.apk','split_config.en.apk']
 patch_log=[];signed=[]
 with zipfile.ZipFile(ORIGINAL) as pkg:
  for fn in specs:
   path=ROOT/('mod_'+fn)
   print('Building',fn,flush=True)
   rec=pack_apk(pkg.read(fn),fn,path)
   patch_log+=rec
   signed.append((fn,path,v2_sign(path,key,cert)))
   print(' signed',fn,path.stat().st_size,flush=True)
 with zipfile.ZipFile(OUT,'w',compression=zipfile.ZIP_STORED,allowZip64=True) as out:
  for fn,path,_ in signed:
   out.write(path,fn)
  out.writestr('meta.sai_v1.json',json.dumps({'label':'YI IoT (Clean)','package':'com.yunyi.smartcamera','version_code':3800,'version_name':'5.1.8_20261021'},ensure_ascii=False))
 report={'original':ORIGINAL.name,'output':OUT.name,'splits':[x[0] for x in signed], 'patched_methods':patch_log, 'cert_sha256':signed[0][2]['certificate_sha256'], 'key_store':'yi_clean_update_key.p12','key_password':password,'validation':'not runtime-tested'}
 (ROOT/'build_report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
 print('DONE',OUT,OUT.stat().st_size,'method_patches',len(patch_log),flush=True)
