#!/usr/bin/env python3
"""Compile an isolated DT layout experiment; leave taiyi1 kernel/rootfs intact."""
import copy,hashlib,importlib.util,io,json,os,struct,subprocess,sys,tarfile,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent
# Run from the pinned taiyi1 checkout, whose original verifier owns all identities.
spec=importlib.util.spec_from_file_location('verifier',Path('Scripts/zn-m2-nss/verify-images.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
SHA='602c19f6f4f5544052004173ce13edfdc046628d62c9b6f7aa01d7902705560f'
Q='/reserved-memory/memory@4ab00000'
def reg(addr,size):return struct.pack('>QQ',addr,size)
def digest(b):return hashlib.sha256(b).hexdigest()
def layout(nodes):
 n=copy.deepcopy(nodes)
 assert n[Q]['reg']==reg(0x4ab00000,0x5500000)
 n[Q]['reg']=reg(0x4ab00000,0x1000000)
 for name,addr in [('q6_etr',0x4bb00000),('m3_dump',0x4bc00000),('ramoops',0x4bd00000)]:
  p='/reserved-memory/'+name+'@%x'%addr;assert p not in n
  n[p]={'reg':reg(addr,0x100000),'no-map':b''}
  if name=='ramoops':n[p].update({'compatible':b'ramoops\0','record-size':struct.pack('>I',0x4000),'console-size':struct.pack('>I',0x4000)})
 return n
def dts(nodes,reservations,files=None):
 files=files or {};lines=['/dts-v1/;']
 for addr,size in reservations:lines.append('/memreserve/ 0x%x 0x%x;'%(addr,size))
 def emit(path,depth):
  pad='  '*depth;lines.append(pad+('/' if path=='/' else path.rsplit('/',1)[1])+' {')
  for key,b in nodes[path].items():
   if (path,key) in files:val='/incbin/("'+files[path,key]+'")'
   else:val='['+b.hex(' ')+']'
   lines.append(pad+'  '+key+' = '+val+';')
  for p in nodes:
   if p!='/' and (p.rsplit('/',1)[0] or '/')==path:emit(p,depth+1)
  lines.append(pad+'};')
 emit('/',0);return '\n'.join(lines)+'\n'
def run(original,out):
 original=Path(original).read_bytes();assert digest(original)==SHA,'Wrong baseline image'
 out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
 fit,root,meta=v.parse_sysupgrade(original);oldreport,kernel,dtb=v.verify_fit(fit,v.EXPECTED_KERNEL)
 old=v.FDT(dtb);expected=layout(old.nodes)
 (out/'board.dts').write_text(dts(expected,old.reservations))
 subprocess.run(['dtc','-I','dts','-O','dtb','-o',str(out/'board.dtb'),str(out/'board.dts')],check=True)
 newdt=(out/'board.dtb').read_bytes();new=v.FDT(newdt)
 assert new.nodes==expected and new.reservations==old.reservations,'Unexpected compiled DT change'
 # Validate no reservation overlaps and all original platform properties survive.
 v.verify_board_dtb(newdt)
 tree=v.FDT(fit);nodes=copy.deepcopy(tree.nodes)
 assert not tree.reservations
 nodes['/images/fdt-1']['data']=newdt
 for p,props in nodes.items():
  if p.startswith('/images/fdt-1/hash-'):
   algo=v.strings(props['algo'])[0]
   props['value']=struct.pack('>I',zlib.crc32(newdt)) if algo=='crc32' else hashlib.sha1(newdt).digest()
 (out/'kernel.gz').write_bytes(nodes['/images/kernel-1']['data'])
 files={('/images/kernel-1','data'):'kernel.gz',('/images/fdt-1','data'):'board.dtb'}
 (out/'firmware.its').write_text(dts(nodes,tree.reservations,files))
 # dtc compiles the FIT with the original timestamp and independently computed hashes.
 subprocess.run(['dtc','-I','dts','-O','dtb','-o','firmware.itb','firmware.its'],cwd=out,check=True)
 newfit=(out/'firmware.itb').read_bytes()
 report,k2,d2=v.verify_fit(newfit,v.EXPECTED_KERNEL)
 assert k2==kernel and d2==newdt and v.FDT(newfit).nodes==nodes
 archive,_=v.verify_fwtool(original);buf=io.BytesIO()
 with tarfile.open(fileobj=io.BytesIO(archive),mode='r:') as src,tarfile.open(fileobj=buf,mode='w',format=tarfile.GNU_FORMAT) as dst:
  for m in src.getmembers():
   data=src.extractfile(m).read() if m.isfile() else None
   if m.name=='sysupgrade-zn_m2/kernel':data=newfit;m.size=len(data)
   dst.addfile(m,io.BytesIO(data) if data is not None else None)
 # Keep the original metadata bytes; only recompute the CRC for the changed archive.
 assert len(meta['trailers'])==1 and meta['trailers'][0]['type']=='metadata'
 metadata=original[len(archive):-16];payload=buf.getvalue()+metadata
 result=payload+struct.pack('>IIB3xI',0x46577830,v.crc_raw(payload),1,len(metadata)+16)
 f2,r2,m2=v.parse_sysupgrade(result);assert f2==newfit and r2==root and m2['metadata']==meta['metadata']
 name='openwrt-25.12.5-nss-taiyi1-q6-19m-zn_m2-sysupgrade.bin';(out/name).write_bytes(result)
 changes={p:{k:{'before':old.nodes.get(p,{}).get(k,b'').hex(),'after':b.hex()} for k,b in props.items() if old.nodes.get(p,{}).get(k)!=b} for p,props in new.nodes.items() if old.nodes.get(p)!=props}
 manifest={'experiment':'taiyi1-q6-19m','method':'DT recompile and FIT/sysupgrade repack; not a kernel/rootfs rebuild','source_image_sha256':SHA,'output_file':name,'output_sha256':digest(result),'output_bytes':len(result),'kernel_gzip_sha256':digest(nodes['/images/kernel-1']['data']),'kernel_uncompressed_sha256':digest(kernel),'rootfs_sha256':digest(root),'rootfs_bytes':len(root),'original_dtb_sha256':digest(dtb),'new_dtb_sha256':digest(newdt),'preserved':['kernel gzip bytes','rootfs bytes','firmware identity','all other DT properties and memreserve entries','NSS/SBL/TZ/SMEM reservations','remoteproc properties'], 'reference':'VIKINGYFY/immortalwrt@0fb9b10cb9df51fb076470e1dd93d1c30dd89d83 ipq6018-nowifi.dtsi and stable device DT','changed_properties':changes,'q6_related_reserved_mib':19,'released_mib':66,'verification':report,'limits':['ZN M2 wired only','Not boot-tested by this build','Firmware UI identity remains original taiyi1 intentionally']}
 (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(out/'SHA256SUMS').write_text(digest(result)+'  '+name+'\n')
 print(json.dumps({k:manifest[k] for k in ['output_file','output_sha256','output_bytes','released_mib']}))
if __name__=='__main__':run(sys.argv[1],sys.argv[2])
