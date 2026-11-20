#!/usr/bin/env python3
"""Read-only authentic F10R root receipt -> private R114 evidence and replay.

Only /usr/bin/sudo -n /usr/bin/cat is used against seven exact root-owned
files. No root code execution or commands in guests. One-time private capture.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, secrets, stat, subprocess, sys
from pathlib import Path

REPO=Path('/home/cicada/Development/GitHub/ardrec')
sys.path.insert(0,str(REPO/'src'))
from ardrec.coordination import r114_f1_real_receipt as c
ROOT=Path('/home/cicada/ardrec-lab/r114-f1-real-protocol-intake-v1')

class Stop(RuntimeError): pass

def need(test,msg):
    if not test:raise Stop(msg)

def private_dir(p: Path, *, must_exist=True) -> None:
    st=p.lstat() if must_exist else None
    if must_exist:
        need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and
             stat.S_IMODE(st.st_mode)==0o700 and not p.is_symlink(),
             'PRIVATE_DIRECTORY_INVALID_'+p.name)

def get_root_file(name: str) -> bytes:
    need(name in c.SOURCE_FILES,'SOURCE_NAME_NOT_ALLOWED')
    path=c.F10R_SOURCE+'/'+name
    p=subprocess.run(['/usr/bin/sudo','-n','/usr/bin/cat','--',path],
                     stdin=subprocess.DEVNULL,capture_output=True,
                     check=False,timeout=10)
    need(p.returncode==0 and len(p.stdout)<=c.MAX_BYTES and not p.stderr,
         'ROOT_READ_FAILED_'+name)
    return p.stdout

def put(p: Path, data: bytes):
    need(len(data)<=c.MAX_BYTES,'OUTPUT_TOO_LARGE')
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(data);f.flush();os.fsync(f.fileno())

def read(p: Path) -> bytes:
    need(p.parent.is_dir() and not p.is_symlink(),'FILE_LINK_INVALID_'+p.name)
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid()
             and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600
             and 0<st.st_size<=c.MAX_BYTES,'PRIVATE_FILE_INVALID_'+p.name)
        data=os.read(fd,c.MAX_BYTES+1)
        need(len(data)==st.st_size,'READ_SIZE_CHANGED_'+p.name)
        return data
    finally:os.close(fd)

def acquire():
    need(os.geteuid()!=0,'RUN_AS_NON_ROOT_USER')
    if not ROOT.exists():ROOT.mkdir(mode=0o700,parents=False)
    private_dir(ROOT)
    need(not any(x.name.startswith('intake-') for x in ROOT.iterdir()),
         'PRIOR_INTAKE_EXISTS_DO_NOT_DUPLICATE')
    folder=ROOT/('intake-'+secrets.token_hex(4))
    folder.mkdir(mode=0o700)
    print('R114_F1_SESSION='+str(folder),flush=True)
    try:
        # Check the original root receipt PIN before copying any further data.
        original=get_root_file('receipt.json')
        need(c.digest(original)==c.F10R_RECEIPT_SHA,'ROOT_RECEIPT_PIN_MISMATCH')
        raw={'receipt.json':original}
        put(folder/'receipt.json',original)
        for name in c.SOURCE_FILES[1:]:
            data=get_root_file(name)
            raw[name]=data
            put(folder/name,data)
        report=c.analyze(raw)
        encoded=c.canonical(report)
        put(folder/'report.json',encoded)
        manifest={
            'schema':'ARDREC-R114-F1-PRIVATE-INTEGRITY-v1',
            'report_sha256':c.digest(encoded),
            'files_sha256':{name:c.digest(raw[name]) for name in c.SOURCE_FILES},
            'source_receipt_pin':c.F10R_RECEIPT_SHA,
            'new_root_calls':'SUDO_CAT_FIXED_FILES_ONLY',
            'guest_exec_count':0,'network_probes_count':0,
            'p8':'NO-GO',
        }
        put(folder/'manifest.json',c.canonical(manifest))
        print('R114_F1_SOURCE_ROOT_SHA256='+c.F10R_RECEIPT_SHA)
        print('R114_F1_MANIFEST_SHA256='+c.digest(c.canonical(manifest)))
        print('R114_F1_REAL_TCP=3')
        print('R114_F1_VERIFIED_PROTOCOL_BANNERS=SSH_FTP')
        print('R114_F1_SMB2=NOT_VERIFIED')
        print('R114_F1_A6_CONDITIONS_ADMITTED=0')
        print('R114_F1_RISK_RECALCULATION=NOT_AUTHORIZED')
        print('R114_F1_P8=NO-GO')
        return 0
    except Exception as exc:
        print('R114_F1_STOP='+type(exc).__name__+':'+str(exc)[:150])
        print('R114_F1_INCOMPLETE_SESSION_PRESERVED='+str(folder))
        print('R114_F1_DO_NOT_AUTORETRY=TRUE')
        return 23

def replay(folder:Path):
    private_dir(ROOT);private_dir(folder)
    need(folder.parent==ROOT and re.fullmatch('intake-[a-f0-9]{8}',folder.name) is not None,
         'REPLAY_SOURCE_INVALID')
    expected=set(c.SOURCE_FILES)|{'manifest.json','report.json'}
    need({x.name for x in folder.iterdir()}==expected,'REPLAY_FILE_SCOPE_INVALID')
    manifest=json.loads(read(folder/'manifest.json'))
    need(manifest.get('schema')=='ARDREC-R114-F1-PRIVATE-INTEGRITY-v1'
         and manifest.get('source_receipt_pin')==c.F10R_RECEIPT_SHA
         and manifest.get('p8')=='NO-GO'
         and manifest.get('guest_exec_count')==0 and manifest.get('network_probes_count')==0
         and manifest.get('new_root_calls')=='SUDO_CAT_FIXED_FILES_ONLY'
         and set(manifest.get('files_sha256',{}))==set(c.SOURCE_FILES),
         'REPLAY_MANIFEST_INVALID')
    sources={name:read(folder/name) for name in c.SOURCE_FILES}
    for name,raw in sources.items():
        need(c.digest(raw)==manifest['files_sha256'][name],'REPLAY_SOURCE_CHANGED_'+name)
    report_raw=read(folder/'report.json')
    need(c.digest(report_raw)==manifest.get('report_sha256'), 'REPLAY_REPORT_HASH_CHANGED')
    report=json.loads(report_raw)
    c.verified_report(report,sources)
    need(report_raw==c.canonical(report),'REPORT_NON_CANONICAL')
    print('R114_F1_REPLAY=PASS_SOURCE_QGA_F6_HASHES')
    print('R114_F1_MANIFEST_SHA256='+c.digest(read(folder/'manifest.json')))
    print('R114_F1_SSH=REAL_BANNER_ONLY')
    print('R114_F1_FTP=REAL_220_GREETING_ONLY')
    print('R114_F1_SMB=TCP_ONLY_NO_SMB2_PROOF')
    print('R114_F1_A6=ND_NO_CASE_LINKAGE')
    print('R114_F1_ROOT_COMMANDS=0')
    print('R114_F1_P8=NO-GO')
    return 0

def main():
    os.umask(0o077)
    ap=argparse.ArgumentParser()
    g=ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--acquire',action='store_true')
    g.add_argument('--replay',type=Path)
    args=ap.parse_args()
    try:
        return acquire() if args.acquire else replay(args.replay)
    except Exception as e:
        print('R114_F1_STOP='+type(e).__name__+':'+str(e)[:160],flush=True)
        print('R114_F1_DO_NOT_AUTORETRY=TRUE',flush=True)
        return 23

if __name__=='__main__':raise SystemExit(main())
