#!/usr/bin/env python3
"""Explicit R116-F3 root source staging; NEVER called by source installer.

Copies ONLY the pinned, signed Python verifier dependency closure into a
root-owned 0700 tree, with 0600 files, plus the draft catalogue. Staging
never calls nft, virsh, systemd, boot, QGA or a network socket. The authority
files must be provisioned separately by an independent operator.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

REPO=Path('/home/cicada/Development/GitHub/ardrec')
PARENT=Path('/var/lib/ardrec')
DEST=PARENT/'r116-f3-ftp-pilot-root-v1'
BRANCH='feat/p14-r116-piloto-ftp-fisico-a5-a10'
ACTIVE_BRANCH='feat/ardrec-a1-a10-cierre-integral-v1'
ACTIVE_BASE='5c7770c1548585f8eac7f50d5f68b8fb77a10614'
BASE='e193b1dcf97f72ba4245fc7dfc6d0d4b9814eecc'
LOCK=Path('lab/operational-controller/r116-f3-root-source-lock-v1.json')
SCHEMA='ARDREC-R116-F3-ROOT-FTP-PILOT-v1'
CATALOG='lab/operational-catalog-v1/catalog.json'
DOCS=['contract.json','scope-authorization.json','pilot-permit.json']

class Stop(ValueError):pass

def need(ok,code):
    if not ok:raise Stop(code)

def sha(raw):return hashlib.sha256(raw).hexdigest()
def canon(doc):return (json.dumps(doc,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode()

def git(*args):
    cmd=['/usr/bin/git','-c','safe.directory='+str(REPO),'-C',str(REPO),*args]
    p=subprocess.run(cmd,capture_output=True,check=False,stdin=subprocess.DEVNULL,
                     timeout=25,env={'LC_ALL':'C','LANG':'C','PATH':'/usr/bin:/bin'})
    need(p.returncode==0,'GIT_COMMAND_FAILED_'+args[0])
    return p.stdout

def checked():
    need(os.geteuid()==0,'ROOT_REQUIRED')
    need(REPO.is_dir() and not REPO.is_symlink(),'REPOSITORY_NOT_DIRECTORY')
    branch=git('branch','--show-current').strip()
    need(branch in (BRANCH.encode(),ACTIVE_BRANCH.encode()),'WRONG_SOURCE_BRANCH')
    need(git('status','--porcelain=v1','--untracked-files=all')==b'',
         'SOURCE_WORKTREE_NOT_CLEAN')
    need(git('merge-base','--is-ancestor',BASE,'HEAD')==b'','R116_F2_NOT_ANCESTOR')
    if branch==ACTIVE_BRANCH.encode():
        need(git('merge-base','--is-ancestor',ACTIVE_BASE,'HEAD')==b'',
             'ACTIVE_BASE_NOT_ANCESTOR')
    head=git('rev-parse','HEAD').decode('ascii').strip()
    need(re.fullmatch('[0-9a-f]{40}',head),'GIT_HEAD_INVALID')
    need(git('log','-1','--format=%G?').strip()==b'G','SOURCE_COMMIT_NOT_VERIFIED')
    git('verify-commit','HEAD')
    def commit_read(name):
        raw=git('show','HEAD:'+name)
        path=REPO/name
        need(path.is_file() and not path.is_symlink() and
             path.read_bytes()==raw,'SIGNED_SOURCE_DRIFT_'+name)
        return raw
    data=json.loads(commit_read(str(LOCK)))
    need(type(data) is dict and set(data)=={'schema','base','files','catalog_sha256',
          'root_source_only','window_seconds','p8'}, 'SOURCE_LOCK_SCHEMA')
    need(data['schema']==SCHEMA+'-source-lock' and data['base']==BASE and
         data['window_seconds']==60 and data['p8']=='NO-GO' and
         data['root_source_only'] is True and
         data['catalog_sha256']=='5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e',
         'SOURCE_LOCK_INCORRECT')
    pins=data['files']
    need(type(pins) is dict and len(pins)>=30 and
         'root-pilot.py' in pins and
         'runtime/ardrec/coordination/r116_f3_pilot_session_policy.py' in pins,
         'SOURCE_SET_INCOMPLETE')
    source={}
    for dest,digest in pins.items():
        need(type(dest) is str and re.fullmatch(
             r'(root-pilot\.py|runtime/ardrec/(?:coordination|evidence)/[a-z0-9_]+\.py)',
             dest) and type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest),
             'SOURCE_LOCK_ENTRY_INVALID')
        repo_path=('scripts/ardrec_p14_r116_f3_root_pilot.py' if dest=='root-pilot.py'
                   else 'src/'+dest.removeprefix('runtime/'))
        raw=commit_read(repo_path)
        need(0<len(raw)<524288 and sha(raw)==digest,'SIGNED_SOURCE_HASH_DRIFT_'+dest)
        source[dest]=raw
    catalog=commit_read(CATALOG)
    need(sha(catalog)==data['catalog_sha256'],'CATALOG_NOT_DRAFT_PINNED')
    # Stage helper itself must also be *exactly* the signed source.
    commit_read('scripts/ardrec_p14_r116_f3_root_stage.py')
    return head,data,source,catalog

def trusted_parent():
    for p in (Path('/'),Path('/var'),Path('/var/lib'),PARENT):
        s=p.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and
             not s.st_mode&0o022 and not p.is_symlink(), 'ROOT_PARENT_UNTRUSTED')

def exclusive(path,raw):
    need(type(raw) is bytes and 0<len(raw)<524288,'ROOT_PAYLOAD_LENGTH')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())

def stage():
    head,lock,source,catalog=checked()
    trusted_parent()
    need(not DEST.exists() and not DEST.is_symlink(),
         'STAGE_ALREADY_EXISTS_NO_OVERWRITE')
    tmp=Path(tempfile.mkdtemp(prefix='.r116-f3-stage-',dir=PARENT))
    try:
        os.chmod(tmp,0o700)
        for directory in ['runtime','runtime/ardrec','runtime/ardrec/coordination',
                          'runtime/ardrec/evidence','authority']:
            d=tmp/directory
            d.mkdir(mode=0o700)
            os.chmod(d,0o700)
        for dest,raw in source.items():exclusive(tmp/dest,raw)
        exclusive(tmp/'catalog.json',catalog)
        exclusive(tmp/'lock',b'R116_F3_ROOT_LOCK_V1\n')
        manifest={'schema':SCHEMA+'-root-bundle','head':head,'base':BASE,
                  'source_sha256':lock['files'], 'catalog_sha256':lock['catalog_sha256'],
                  'p8':'NO-GO','window_seconds':60,'authority_paths':DOCS,
                  'network_automatic':False,'a6':'ND'}
        exclusive(tmp/'manifest.json',canon(manifest))
        # Authority files intentionally do not exist after staging.
        fd=os.open(tmp,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
        os.rename(tmp,DEST)
        fd=os.open(PARENT,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if tmp.exists():shutil.rmtree(tmp)
    print('R116_F3_ROOT_STAGE=PASS_SOURCE_ONLY')
    print('R116_F3_STAGE_PATH='+str(DEST))
    print('R116_F3_STAGE_COMMIT='+head)
    print('R116_F3_ROOT_AUTHORITY=NOT_PROVISIONED')
    print('R116_F3_ROOT_WATCHDOG_ARM=NOT_EXECUTED')
    print('R116_F3_ROOT_NETWORK_CONNECTIONS=0')
    print('R116_F3_P8=NO-GO')

def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    group=ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--review-source',action='store_true')
    group.add_argument('--stage-root',action='store_true')
    args=ap.parse_args(argv)
    os.umask(0o077)
    try:
        if args.review_source:
            head,lock,source,catalog=checked()
            print('R116_F3_SIGNED_SOURCE=PASS')
            print('R116_F3_SIGNED_HEAD='+head)
            print('R116_F3_SOURCE_COUNT='+str(len(source)))
        else:stage()
        return 0
    except (Stop,ValueError,TypeError,OSError,subprocess.SubprocessError) as exc:
        print('R116_F3_STAGE_STOP='+type(exc).__name__+':'+str(exc)[:160])
        return 23

if __name__=='__main__':raise SystemExit(main())
