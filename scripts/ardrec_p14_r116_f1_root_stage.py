#!/usr/bin/env python3
"""Optional R116-F1 root staging for DENY-only guardian; NEVER invoked by install.

Requires explicit operator action and an already signed, clean R116 source commit.
No nftables, libvirt, systemd, sockets or VM commands are executed by staging.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

REPO=Path('/home/cicada/Development/GitHub/ardrec')
ROOT=Path('/var/lib/ardrec')
DEST=ROOT/'r116-f1-five-one-deny-v1'
BRANCH='feat/p14-r116-piloto-ftp-fisico-a5-a10'
ACTIVE_BRANCH='feat/ardrec-a1-a10-cierre-integral-v1'
ACTIVE_BASE='5c7770c1548585f8eac7f50d5f68b8fb77a10614'
BASE='46dccd948d2d61c4fd777c64dafad3efa71cf035'
SOURCE={
    'root-guard.py': 'scripts/ardrec_p14_r116_f1_root_deny_guard.py',
    'manifest.json': 'lab/operational-controller/r116-f1-root-bundle.json',
}

class Stop(ValueError):pass
def need(condition,code):
    if not condition:raise Stop(code)
def sha(data):return hashlib.sha256(data).hexdigest()

def git(*args):
    p=subprocess.run(['/usr/bin/git','-c','safe.directory='+str(REPO),
                      '-C',str(REPO),*args],capture_output=True,
                     check=False,timeout=20,stdin=subprocess.DEVNULL)
    need(p.returncode==0,'GIT_COMMAND_FAILED')
    return p.stdout

def checked_source():
    need(os.geteuid()==0,'ROOT_REQUIRED')
    need(REPO.is_dir() and not REPO.is_symlink(),'REPO_INVALID')
    branch=git('branch','--show-current').strip()
    need(branch in (BRANCH.encode(),ACTIVE_BRANCH.encode()), 'BRANCH_MISMATCH')
    need(git('merge-base','--is-ancestor',BASE,'HEAD')==b'', 'ANCESTRY_INVALID')
    if branch==ACTIVE_BRANCH.encode():
        need(git('merge-base','--is-ancestor',ACTIVE_BASE,'HEAD')==b'',
             'ACTIVE_ANCESTRY_INVALID')
    need(git('status','--porcelain=v1','--untracked-files=all')==b'',
         'DIRTY_REPOSITORY')
    need(git('log','-1','--format=%G?').strip()==b'G','SOURCE_COMMIT_NOT_VERIFIED')
    git('verify-commit','HEAD')
    data={}
    for name,path in SOURCE.items():
        p=REPO/path
        need(p.is_file() and not p.is_symlink(),'SOURCE_FILE_MISSING_'+name)
        raw=p.read_bytes()
        need(0<len(raw)<524288,'SOURCE_BYTES_INVALID_'+name)
        need(git('show','HEAD:'+path)==raw,'SOURCE_NOT_COMMITTED_'+name)
        data[name]=raw
    manifest=json.loads(data['manifest.json'])
    need(manifest.get('schema')=='ARDREC-R116-F1-FIVE-ONE-DENY-GUARD-v1-root-bundle' and
         manifest.get('guard_sha256')==sha(data['root-guard.py']) and
         manifest.get('opens_ports') is False and
         manifest.get('p8')=='NO-GO' and manifest.get('window_seconds')==60,
         'SOURCE_MANIFEST_INVALID')
    return data

def stage():
    raw=checked_source()
    need(ROOT.is_dir() and not ROOT.is_symlink() and
         ROOT.stat().st_uid==0 and not (ROOT.stat().st_mode&0o022),
         'ROOT_PARENT_INVALID')
    need(not DEST.exists() and not DEST.is_symlink(), 'ALREADY_STAGED_NO_OVERWRITE')
    tmp=Path(tempfile.mkdtemp(prefix='.r116-f1-staging-',dir=ROOT))
    try:
        os.chmod(tmp,0o700)
        for name,content in raw.items():
            fd=os.open(tmp/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as h:
                h.write(content);h.flush();os.fsync(h.fileno())
        fd=os.open(tmp,os.O_DIRECTORY|os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
        os.rename(tmp,DEST)
        fd=os.open(ROOT,os.O_DIRECTORY|os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if tmp.exists():shutil.rmtree(tmp)
    print('R116_F1_ROOT_STAGE=PASS_DENY_ONLY_FILES')
    print('R116_F1_ROOT_STAGE_PATH='+str(DEST))
    print('R116_F1_ROOT_STAGE_TRAFFIC=0')
    print('R116_F1_ROOT_STAGE_VM_STARTS=0')

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    group=ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--review-source',action='store_true')
    group.add_argument('--stage-root',action='store_true')
    args=ap.parse_args()
    os.umask(0o077)
    try:
        if args.review_source:
            checked_source()
            print('R116_F1_SOURCE=VERIFIED_SIGNED_COMMIT')
        else:stage()
        return 0
    except (Stop,OSError,ValueError,subprocess.SubprocessError) as exc:
        print('R116_F1_STAGE_STOP='+type(exc).__name__+':'+str(exc)[:160])
        return 23
if __name__=='__main__':raise SystemExit(main())
