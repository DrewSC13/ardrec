#!/usr/bin/env python3
"""R114-F2: inspect existing F1 private receipt and P7 catalog, no root or VM I/O."""
from __future__ import annotations
import argparse,hashlib,json,os,re,secrets,stat,sys
from pathlib import Path

REPO=Path('/home/cicada/Development/GitHub/ardrec')
sys.path.insert(0,str(REPO/'src'))
from ardrec.coordination import r114_f1_real_receipt as f1
from ardrec.coordination import r114_f2_family_gap as core

F1_DIR=Path(core.F1_SESSION)
F2_DIR=Path('/home/cicada/ardrec-lab/r114-f2-family-evidence-gaps-v1')
F1_FILES=set(f1.SOURCE_FILES)|{'report.json','manifest.json'}
F2_FILES={'report.json','manifest.json'}

class Stop(RuntimeError):pass

def need(ok,msg):
    if not ok: raise Stop(msg)

def check_dir(p:Path):
    need(not p.is_symlink() and p.is_dir(),'INVALID_DIRECTORY_'+p.name)
    s=p.stat()
    need(s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o700,
         'PRIVATE_DIR_OWNER_MODE_'+p.name)

def read(p:Path,*,max_bytes=200000)->bytes:
    need(not p.is_symlink() and p.is_file(),'SOURCE_FILE_MISSING_OR_SYMLINK_'+p.name)
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and
             s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and
             0<s.st_size<=max_bytes,'PRIVATE_FILE_MODE_OR_SIZE_'+p.name)
        data=b''
        while len(data)<s.st_size:
            piece=os.read(fd,s.st_size-len(data))
            need(piece,'EARLY_EOF_'+p.name)
            data+=piece
        need(len(data)==s.st_size and os.fstat(fd).st_mtime_ns==s.st_mtime_ns,
             'SOURCE_FILE_CHANGED_DURING_READ_'+p.name)
        return data
    finally:os.close(fd)

def save(path:Path,raw:bytes):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())

def source()->tuple[dict,str,str]:
    check_dir(F1_DIR.parent); check_dir(F1_DIR)
    need({p.name for p in F1_DIR.iterdir()}==F1_FILES,
         'F1_PRIVATE_FILE_SCOPE_CHANGED')
    manifest_bytes=read(F1_DIR/'manifest.json')
    manifest_sha=core.digest(manifest_bytes)
    need(manifest_sha==core.F1_MANIFEST_PIN,'F1_MANIFEST_SHA256_DRIFT')
    m=json.loads(manifest_bytes)
    need(type(m) is dict and m.get('schema')==core.F1_MANIFEST_SCHEMA
         and m.get('source_receipt_pin')==f1.F10R_RECEIPT_SHA
         and m.get('guest_exec_count')==0 and m.get('network_probes_count')==0
         and m.get('p8')=='NO-GO'
         and m.get('new_root_calls')=='SUDO_CAT_FIXED_FILES_ONLY'
         and set(m.get('files_sha256',{}))==set(f1.SOURCE_FILES),
         'F1_MANIFEST_CONTENT_INVALID')
    upstream={key:read(F1_DIR/key) for key in f1.SOURCE_FILES}
    for k,buf in upstream.items():
        need(core.digest(buf)==m['files_sha256'][k], 'F1_SOURCE_HASH_CHANGED_'+k)
    data=read(F1_DIR/'report.json')
    report_sha=core.digest(data)
    need(report_sha==m.get('report_sha256'),'F1_REPORT_HASH_CHANGED')
    report=json.loads(data)
    need(data==f1.canonical(report),'F1_REPORT_NONCANONICAL')
    f1.verified_report(report,upstream)
    return report,manifest_sha,report_sha

def build()->int:
    need(os.geteuid()!=0,'DO_NOT_RUN_AS_ROOT')
    r,msha,rsha=source()
    report=core.make_report(r,f1_report_sha256=rsha,f1_manifest_sha256=msha)
    encoded=core.canonical(report)
    check_dir(F2_DIR.parent)
    if not F2_DIR.exists():F2_DIR.mkdir(mode=0o700)
    check_dir(F2_DIR)
    need(not any(x.name.startswith('matrix-') for x in F2_DIR.iterdir()),
         'ALREADY_GENERATED_NO_RETRY')
    folder=F2_DIR/('matrix-'+secrets.token_hex(4))
    folder.mkdir(mode=0o700)
    print('R114_F2_SESSION='+str(folder),flush=True)
    try:
        save(folder/'report.json',encoded)
        manifest={
            'schema':'ARDREC-R114-F2-PRIVATE-REPLAY-v1',
            'source_manifest_sha256':msha,
            'source_report_sha256':rsha,
            'catalog_sha256':report['source_catalog_sha256'],
            'report_sha256':core.digest(encoded),
            'network_calls':0,'root_calls':0,'new_guest_exec':0,
            'risk_recalculation':False,'p8':'NO-GO',
        }
        save(folder/'manifest.json',core.canonical(manifest))
        print('R114_F2_FAMILY_COUNT=25')
        print('R114_F2_VARIANT_PATHS=29')
        print('R114_F2_SOURCE_F1=FULL_QGA_AND_F6_REVERIFIED')
        print('R114_F2_CATALOG=PINNED_25_FAMILIES')
        print('R114_F2_A5_CASE_LINKS=0')
        print('R114_F2_A6_CONDITIONS=0')
        print('R114_F2_SMB2=NOT_VERIFIED')
        print('R114_F2_REPORT_SHA256='+core.digest(encoded))
        print('R114_F2_MANIFEST_SHA256='+core.digest(core.canonical(manifest)))
        print('R114_F2_P8=NO-GO')
    except Exception as e:
        print('R114_F2_STOP='+type(e).__name__+':'+str(e)[:140],flush=True)
        print('R114_F2_INCOMPLETE_NO_AUTORETRY='+str(folder),flush=True)
        return 23
    return 0

def replay(folder:Path)->int:
    need(os.geteuid()!=0,'DO_NOT_RUN_AS_ROOT')
    check_dir(F2_DIR.parent);check_dir(F2_DIR);check_dir(folder)
    need(folder.parent==F2_DIR and re.fullmatch('matrix-[a-f0-9]{8}',folder.name),
         'INVALID_REPLAY_SESSION')
    need({p.name for p in folder.iterdir()}==F2_FILES,
         'REPLAY_FILES_CHANGED')
    mraw=read(folder/'manifest.json'); m=json.loads(mraw)
    need(mraw==core.canonical(m),'F2_MANIFEST_NONCANONICAL')
    need(m.get('schema')=='ARDREC-R114-F2-PRIVATE-REPLAY-v1' and
         m.get('source_manifest_sha256')==core.F1_MANIFEST_PIN and
         m.get('network_calls')==0 and m.get('root_calls')==0 and
         m.get('new_guest_exec')==0 and m.get('risk_recalculation') is False and
         m.get('p8')=='NO-GO','F2_MANIFEST_INCOMPATIBLE')
    report_raw=read(folder/'report.json')
    need(core.digest(report_raw)==m.get('report_sha256'),'F2_REPORT_HASH_CHANGED')
    report=json.loads(report_raw)
    need(report_raw==core.canonical(report),'F2_REPORT_NONCANONICAL')
    r,msha,rsha=source()
    need(msha==m.get('source_manifest_sha256') and
         rsha==m.get('source_report_sha256'),'F1_INPUT_DRIFT')
    core.verify(report,r,f1_report_sha256=rsha,f1_manifest_sha256=msha)
    need(m.get('catalog_sha256')==report['source_catalog_sha256'],
         'F2_CATALOG_PIN_MISMATCH')
    print('R114_F2_REPLAY=PASS_F1_QGA_F6_P7_25_FAMILIES')
    print('R114_F2_MANIFEST_SHA256='+core.digest(mraw))
    print('R114_F2_A5_CASE_LINKS=0')
    print('R114_F2_A6=ND_ALL_25_FAMILIES')
    print('R114_F2_CONFIRMED_RISK=NO')
    print('R114_F2_NETWORK_CALLS=0')
    print('R114_F2_P8=NO-GO')
    return 0

def main():
    os.umask(0o077)
    p=argparse.ArgumentParser()
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--build',action='store_true')
    g.add_argument('--replay',type=Path)
    a=p.parse_args()
    try:return build() if a.build else replay(a.replay)
    except Exception as e:
        print('R114_F2_STOP='+type(e).__name__+':'+str(e)[:150],flush=True)
        print('R114_F2_NO_RETRY_OR_MANUAL_EDIT=TRUE',flush=True)
        return 23

if __name__=='__main__':raise SystemExit(main())
