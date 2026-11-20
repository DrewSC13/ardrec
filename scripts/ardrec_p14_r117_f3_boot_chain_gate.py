#!/usr/bin/env python3
"""R117-F3 read-only boot-chain release audit. No VM, nft, systemd or permit issuance.

Two independent modes: --source as repository owner verifies signed HEAD,
source-release root pins and exact current branch; --root as privileged inspector
verifies the existing installed F3 manifest and determines whether its 33
runtime files require a separate authenticated migration. Neither mode boots.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True

REPO=Path('/home/cicada/Development/GitHub/ardrec')
LOCK=REPO/'lab/operational-controller/r116-f3-root-source-lock-v1.json'
ROOT=Path('/var/lib/ardrec/r116-f3-ftp-pilot-root-v1')
SHA=re.compile(r'[a-f0-9]{64}\Z')
PATH=re.compile(r'(root-pilot\.py|runtime/ardrec/(?:coordination|evidence)/[a-z0-9_]+\.py)\Z')
EXPECTED_COUNT=33
R116_F12_F7_SHA256='0a31f03d382f6fde04b93c688064f630fa0c7ab46ef45e3b40dc2d31618d59d1'

class Stop(ValueError): pass

def need(ok,reason):
    if not ok: raise Stop(reason)

def digest(b): return hashlib.sha256(b).hexdigest()

def exact_lock(obj):
    need(type(obj) is dict and type(obj.get('files')) is dict,'LOCK_SHAPE')
    need(obj.get('base')=='e193b1dcf97f72ba4245fc7dfc6d0d4b9814eecc', 'LOCK_BASE_CHANGED')
    need(obj.get('catalog_sha256')=='5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e','LOCK_CATALOG')
    files=obj['files']
    need(len(files)==EXPECTED_COUNT and 'root-pilot.py' in files,'LOCK_33_FILES')
    for path,sha in files.items():
        need(type(path) is str and PATH.fullmatch(path) and
             type(sha) is str and SHA.fullmatch(sha),'LOCK_PATH_OR_SHA')
    return files

def source_path(name,repo=REPO):
    need(type(name) is str and PATH.fullmatch(name),'SOURCE_NAME')
    return repo/('scripts/ardrec_p14_r116_f3_root_pilot.py' if name=='root-pilot.py' else
                 'src/'+name.removeprefix('runtime/'))

def check_sources(files,repo=REPO):
    need(type(files) is dict and len(files)==EXPECTED_COUNT,'SOURCE_COUNT')
    for name,expected in files.items():
        path=source_path(name,repo)
        need(path.is_file() and not path.is_symlink(),'SOURCE_MISSING_OR_SYMLINK_'+name)
        need(digest(path.read_bytes())==expected,'SOURCE_TAMPER_'+name)
    return True

def strict_root_bytes(path,*,maximum=524288):
    parent=path.parent
    ps=parent.lstat()
    need(stat.S_ISDIR(ps.st_mode) and ps.st_uid==0 and not(ps.st_mode&0o022),
         'ROOT_PARENT_UNTRUSTED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
             stat.S_IMODE(st.st_mode)==0o600 and 0<st.st_size<=maximum,
             'ROOT_FILE_UNTRUSTED')
        b=os.read(fd,maximum+1)
        need(len(b)==st.st_size,'ROOT_FILE_CHANGED')
        return b
    finally: os.close(fd)

def root_relation(old,new):
    need(type(old) is dict and type(new) is dict and set(old)==set(new),'ROOT_PIN_SET_CHANGED')
    need(old==new,'HISTORICAL_F12_ROOT_RELEASE_TAMPERED')
    return 'F12_SIGNED_UNCHANGED_R117_DISPATCH_NOT_RELEASED'

def root_audit(new):
    need(os.geteuid()==0,'ROOT_AUDIT_REQUIRES_ROOT')
    need(ROOT.is_dir() and not ROOT.is_symlink(),'ROOT_BUNDLE_NOT_STAGED')
    st=ROOT.lstat()
    need(st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700,'ROOT_BUNDLE_UNTRUSTED')
    m=json.loads(strict_root_bytes(ROOT/'manifest.json',maximum=16384))
    need(type(m) is dict and type(m.get('source_sha256')) is dict and
         m.get('schema')=='ARDREC-R116-F3-ROOT-FTP-PILOT-v1-root-bundle' and
         m.get('p8')=='NO-GO' and m.get('a6')=='ND' and
         m.get('network_automatic') is False and m.get('window_seconds')==60 and
         re.fullmatch('[0-9a-f]{40}',str(m.get('head',''))),'ROOT_MANIFEST_CHANGED')
    old=m['source_sha256']
    need(len(old)==EXPECTED_COUNT,'ROOT_STAGED_COUNT')
    relation=root_relation(old,new)
    for name,sha in old.items():
        need(PATH.fullmatch(name) and type(sha) is str and SHA.fullmatch(sha),
             'ROOT_SOURCE_NAME_OR_DIGEST')
        need(digest(strict_root_bytes(ROOT/name))==sha,'ROOT_STAGED_SOURCE_DRIFT_'+name)
    need(not (ROOT/'pilot-attempted.once').exists() and
         not (ROOT/'pilot-attempted.once').is_symlink(), 'PILOT_ALREADY_ATTEMPTED')
    need(not any(p.name.startswith('pilot-') for p in ROOT.iterdir()),'PILOT_HISTORY_REVIEW_REQUIRED')
    return relation,m['head']

def source_audit(repo=REPO):
    need(os.geteuid()!=0,'ROOT_SHELL_NOT_ALLOWED')
    from ardrec.coordination import r116_f12_controlled_boot as boot
    from ardrec.coordination import r116_f12_runner_ftp_boot as chain
    from ardrec.coordination import r117_f3_current_git_admission as admission
    try:
        head=admission.git_guard()
    except (admission.Stop,boot.Stop) as exc:
        raise Stop('R117_SOURCE_GIT_REJECTED_'+str(exc)[:80]) from exc
    need(admission.ACTIVE_BRANCH=='feat/p14-r117-piloto-real-a5-a10' and
         admission.MERGED_R116=='fdb6efa0c297ce18b28cddb9494514f51d88bdb4',
         'REBASE_ANCHOR_DRIFT')
    need(chain.f7 is boot,'CHAIN_ENGINE_SPLIT')
    need(admission.boundary()['boot_dispatcher']=='NOT_RELEASED_FOR_R117','UNAUTHORIZED_BOOT_DISPATCHER')
    lock=json.loads((repo/'lab/operational-controller/r116-f3-root-source-lock-v1.json').read_bytes())
    files=exact_lock(lock)
    check_sources(files,repo=repo)
    return head,files

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--source',action='store_true')
    group.add_argument('--root',action='store_true')
    args=parser.parse_args(argv)
    try:
        if args.source:
            head,files=source_audit()
            print('R117_F3_HEAD='+head)
            print('R117_F3_RELEASE=PASS_SIGNED_R117_BOUNDARY_R116_33_UNCHANGED')
            print('R117_F3_ROOT_REDEPLOY=NOT_EXECUTED')
        else:
            obj=json.loads(LOCK.read_bytes())
            files=exact_lock(obj)
            relation,head=root_audit(files)
            print('R117_F3_ROOT_INSTALLED_HEAD='+head)
            print('R117_F3_ROOT_SOURCE_RELATION='+relation)
            print('R117_F3_ROOT_WRITES=0')
        print('R117_F3_BOOT=NOT_EXECUTED_R117_DISPATCH_NOT_RELEASED')
        print('R117_F3_AUTHORITY=NOT_EVALUATED_NO_GRANT')
        print('R117_F3_VM_STARTS=0')
        print('R117_F3_NETWORK_CONNECTIONS=0')
        print('R117_F3_P7=DRAFT')
        print('R117_F3_A6=ND')
        print('R117_F3_P8=NO-GO')
        return 0
    except (Stop,OSError,ValueError,KeyError,TypeError) as exc:
        print('R117_F3_STOP='+type(exc).__name__+':'+str(exc)[:150])
        print('R117_F3_P8=NO-GO')
        return 23

if __name__=='__main__': raise SystemExit(main())
