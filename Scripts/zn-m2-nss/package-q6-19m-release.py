#!/usr/bin/env python3
"""Publish the exact hardware-tested image, without rebuilding or changing it."""
import hashlib,importlib.util,json,shutil,struct,subprocess,zipfile
from pathlib import Path
ROOT=Path.cwd();TESTED=ROOT/'tested';OUT=ROOT/'release-assets'
EXPECTED='9cf9191376127c328fae14c2a5d643c63962aca13cfb6479f03d429911228450'
NAME='openwrt-25.12.5-nss-taiyi1-q6-19m-zn_m2-sysupgrade.bin'
SOURCES=ROOT/'Config/ZN-M2-NSS/releases'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(TESTED/NAME)==EXPECTED
manifest=json.loads((TESTED/'manifest.json').read_text());assert manifest['output_sha256']==EXPECTED and manifest['output_file']==NAME
report=json.loads((SOURCES/'taiyi1-q6-19m-test-results.json').read_text());assert report['image_sha256']==EXPECTED and report['status']=='passed'
spec=importlib.util.spec_from_file_location('verifier',ROOT/'Scripts/zn-m2-nss/verify-images.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
fit,root,metadata=v.parse_sysupgrade((TESTED/NAME).read_bytes());checked,kernel,dtb=v.verify_fit(fit,'6.12.94');dt=v.FDT(dtb)
assert hashlib.sha256(root).hexdigest()==manifest['rootfs_sha256']
assert hashlib.sha256(v.FDT(fit).nodes['/images/kernel-1']['data']).hexdigest()==manifest['kernel_gzip_sha256']
assert dtb==(TESTED/'board.dtb').read_bytes() and hashlib.sha256(dtb).hexdigest()==manifest['new_dtb_sha256']
for node,addr,size in [('memory@4ab00000',0x4ab00000,0x1000000),('q6_etr@4bb00000',0x4bb00000,0x100000),('m3_dump@4bc00000',0x4bc00000,0x100000),('ramoops@4bd00000',0x4bd00000,0x100000),('memory@40000000',0x40000000,0x1000000)]:
 assert dt.nodes['/reserved-memory/'+node]['reg']==struct.pack('>QQ',addr,size)
assert not OUT.exists();OUT.mkdir()
for name in [NAME,'manifest.json','board.dts','board.dtb']:shutil.copyfile(TESTED/name,OUT/name)
shutil.copyfile(SOURCES/'taiyi1-q6-19m-test-results.json',OUT/'test-results.json')
shutil.copyfile(SOURCES/'taiyi1-q6-19m-notes.txt',OUT/'release-notes.txt')
subprocess.run(['git','archive','--format=tar.gz','--output='+str(OUT/'taiyi1-q6-19m-build-sources.tar.gz'),'HEAD','Scripts/zn-m2-nss','Config/ZN-M2-NSS','.github/workflows/ZN-M2-NSS.yml','.github/workflows/Q6-19M-EXPERIMENT.yml','.github/workflows/ZN-M2-Q6-19M-RELEASE.yml'],check=True)
def sums():
 (OUT/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in sorted(OUT.iterdir()) if p.name!='SHA256SUMS'))
sums()
files=sorted(OUT.iterdir())
with zipfile.ZipFile(OUT/'ZN-M2-25.12.5-nss-taiyi1-q6-19m-20261010.zip','w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for p in files:z.write(p,p.name)
sums()
print(json.dumps({'status':'verified','firmware_sha256':EXPECTED,'assets':[{ 'name':p.name,'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(OUT.iterdir())]},indent=2))
