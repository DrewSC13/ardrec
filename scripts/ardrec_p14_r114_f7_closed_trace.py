#!/usr/bin/env python3
"""Read-only replay of F6 A5 evidence and postboot receipt; seal A1-A10 no-go trace.

Never connects to a guest, changes policy, or admits A6. Not a protocol executor.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys

REPO=Path('/home/cicada/Development/GitHub/ardrec')
sys.path.insert(0,str(REPO/'src'))
from ardrec.coordination import r114_f7_real_nogo_trace as core

F6_SCRIPT=REPO/'scripts/ardrec_p14_r114_f6_ftp_bridge.py'
F6_SCRIPT_SHA='5231b7f3316b701787c979845f617ca7efc18b62b78626f1bcf446d3ebaad881'
BOOT_SCRIPT=Path('/home/cicada/Development/GitHub/ardrec-patches/R114_COLD_BOOT2_8pmnH9Ll/RECUPERAR_LAB_R114_F6.py')
BOOT_SCRIPT_SHA='bc8d9c10db818317293ab2e8c9df1058946c7d00eb9e38b9e3ae6c7ef458ccdc'
class Stop(ValueError):pass

def need(ok,msg):
    if not ok:raise Stop(msg)

def sha(data):return hashlib.sha256(data).hexdigest()

def private_read(p,expected_mode=0o600):
    need(p.is_file() and not p.is_symlink(),'SOURCE_NOT_REGULAR_'+p.name)
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and
             stat.S_IMODE(st.st_mode)==expected_mode and st.st_nlink==1 and
             0<st.st_size<100000,'SOURCE_MODE_OR_SIZE_'+p.name)
        b=os.read(fd,100000)
        need(len(b)==st.st_size,'SOURCE_READ_TRUNCATED_'+p.name)
        return b
    finally: os.close(fd)

def _read_script(p,expected):
    need(p.is_file() and not p.is_symlink() and sha(p.read_bytes())==expected,
         'SOURCE_SCRIPT_PIN_CHANGED_'+p.name)

def replay_script(script,args,*,env=None):
    cp=subprocess.run([sys.executable,'-I',str(script),*args],cwd=REPO,
        env=env or {**os.environ,'PYTHONNOUSERSITE':'1'},
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        timeout=40,check=False)
    need(cp.returncode==0 and 0<len(cp.stdout)<8000 and not cp.stderr,
         'SOURCE_REPLAY_FAILED_'+script.name+':'+str(cp.returncode)+':'+
         cp.stderr.decode('utf-8','replace')[:75])
    return cp.stdout

def boot_replay():
    _read_script(BOOT_SCRIPT,BOOT_SCRIPT_SHA)
    env={**os.environ,'PYTHONNOUSERSITE':'1',
         'ARDREC_RECOVERY_STAGE':str(BOOT_SCRIPT.parent),
         'ARDREC_RECOVERY_SCRIPT_SHA256':BOOT_SCRIPT_SHA}
    return replay_script(BOOT_SCRIPT,['--replay',core.BOOT_SESSION],env=env)

def f6_replay():
    _read_script(F6_SCRIPT,F6_SCRIPT_SHA)
    return replay_script(F6_SCRIPT,['--replay',core.F6_SESSION])

def read_verified_sources():
    a=f6_replay();b=boot_replay()
    f6_path=Path(core.F6_SESSION)
    boot_path=Path(core.BOOT_SESSION)
    mf=private_read(f6_path/'manifest.json')
    rp=private_read(f6_path/'report.json')
    bt=private_read(boot_path/'receipt.json')
    need(sha(mf)==core.F6_RECEIPT_MANIFEST_SHA and
         sha(bt)==core.BOOT_RECEIPT_SHA,'HISTORICAL_RECEIPT_PIN_DRIFT')
    rep=core.obj(rp)
    report=core.make_report(rep,mf,bt,a,b)
    return {'source-f6-manifest.json':mf,'source-f6-report.json':rp,
            'source-boot-receipt.json':bt,
            'f6-replay.log':a,'boot-replay.log':b,
            'report.json':core.canon(report)}

def write_once(p,v):
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(v);f.flush();os.fsync(f.fileno())

def private_dir(p,mode):
    need(p.is_dir() and not p.is_symlink(),'INVALID_DIRECTORY_'+p.name)
    st=p.stat()
    need(st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==mode,
         'BAD_DIRECTORY_MODE_'+p.name)

def create():
    sources=read_verified_sources()
    base=Path(core.OUTPUT_ROOT)
    need(not base.exists() and not base.is_symlink(), 'OUTPUT_EXISTS_DO_NOT_RETRY')
    base.mkdir(parents=True,mode=0o700,exist_ok=False)
    private_dir(base,0o700)
    sess=base/('trace-'+secrets.token_hex(4))
    sess.mkdir(mode=0o700)
    for k,v in sorted(sources.items()):write_once(sess/k,v)
    manifest={'schema':'ARDREC-R114-F7-PRIVATE-NO-GO-A1-A10-CLOSURE-v1',
              'original_f6_sha256':core.F6_RECEIPT_MANIFEST_SHA,
              'original_boot_sha256':core.BOOT_RECEIPT_SHA,
              'files_sha256':{k:sha(v) for k,v in sorted(sources.items())},
              'admitted_a6':0,'confirmed_rf':None,'p8':'NO-GO'}
    raw=core.canon(manifest)
    write_once(sess/'manifest.json',raw)
    os.chmod(sess,0o500)
    print('R114_F7_SESSION='+str(sess))
    print('R114_F7_MANIFEST_SHA256='+sha(raw))
    print('R114_F7_A1_A10=PASS_FAIL_CLOSED_TRACE_REAL_A5')
    print('R114_F7_A3=ND_FIVE_FORMAL_GUARDS')
    print('R114_F7_A6=ND_P7_DRAFT_NOT_EXECUTABLE')
    print('R114_F7_A7_A8_A9=NO_CONFIRMED_RISK_TRANSITION_OR_PUBLICATION')
    print('R114_F7_NETWORK=0\nR114_F7_P8=NO-GO')
    return 0

def replay(p):
    base=Path(core.OUTPUT_ROOT)
    private_dir(base,0o700)
    need(p.parent==base and p.name.startswith('trace-') and len(p.name)==14 and
         p.is_dir() and not p.is_symlink(),'REPLAY_BAD_PATH')
    private_dir(p,0o500)
    expected={'source-f6-manifest.json','source-f6-report.json',
              'source-boot-receipt.json','f6-replay.log','boot-replay.log',
              'report.json'}
    need({x.name for x in p.iterdir()}==expected|{'manifest.json'},
         'REPLAY_FILE_SCOPE')
    raw_m=private_read(p/'manifest.json')
    mf=core.obj(raw_m)
    need(mf.get('schema')=='ARDREC-R114-F7-PRIVATE-NO-GO-A1-A10-CLOSURE-v1' and
         mf.get('original_f6_sha256')==core.F6_RECEIPT_MANIFEST_SHA and
         mf.get('original_boot_sha256')==core.BOOT_RECEIPT_SHA and
         mf.get('admitted_a6')==0 and mf.get('confirmed_rf') is None and
         mf.get('p8')=='NO-GO' and
         set(mf.get('files_sha256',{}))==expected,'REPLAY_MANIFEST_SCOPE')
    sources={k:private_read(p/k) for k in expected}
    need(all(sha(v)==mf['files_sha256'][k] for k,v in sources.items()),
         'REPLAY_BYTE_HASH_INVALID')
    need(sources['source-f6-report.json']==core.canon(core.obj(sources['source-f6-report.json'])),
         'REPLAY_SOURCE_F6_NONCANONICAL')
    computed=core.make_report(core.obj(sources['source-f6-report.json']),
          sources['source-f6-manifest.json'], sources['source-boot-receipt.json'],
          sources['f6-replay.log'],sources['boot-replay.log'])
    need(core.canon(computed)==sources['report.json'],'REPLAY_COMPUTATION_CHANGED')
    # Independently replay original immutable sources again, without host action.
    fresh_f6=f6_replay();fresh_boot=boot_replay()
    need(core._log(fresh_f6,core.EXPECTED_REPLAY_F6,'F6') and
         core._log(fresh_boot,core.EXPECTED_REPLAY_BOOT,'BOOT') and
         sha(private_read(Path(core.F6_SESSION)/'manifest.json'))==core.F6_RECEIPT_MANIFEST_SHA and
         sha(private_read(Path(core.BOOT_SESSION)/'receipt.json'))==core.BOOT_RECEIPT_SHA,
         'REPLAY_ORIGINAL_SOURCES_CHANGED')
    print('R114_F7_REPLAY=PASS_F6_F5_F5C_F4_P7_POSTBOOT_A1_A10')
    print('R114_F7_MANIFEST_SHA256='+sha(raw_m))
    print('R114_F7_A5=REAL_FTP_T01_VERIFIED')
    print('R114_F7_A6=ND_A3_P7_NO_ADMISSION')
    print('R114_F7_RISK=UNCOMPUTED')
    print('R114_F7_ROOT_COMMANDS=0\nR114_F7_NETWORK=0\nR114_F7_P8=NO-GO')
    return 0

def main():
    os.umask(0o077)
    ap=argparse.ArgumentParser()
    g=ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--create',action='store_true')
    g.add_argument('--replay',type=Path)
    args=ap.parse_args()
    try:
        need(os.geteuid()!=0,'NO_ROOT_EXECUTION')
        return create() if args.create else replay(args.replay)
    except Exception as exc:
        print('R114_F7_STOP='+type(exc).__name__+':'+str(exc)[:170])
        print('R114_F7_NO_AUTORETRY=TRUE\nR114_F7_P8=NO-GO')
        return 23
if __name__=='__main__':raise SystemExit(main())
