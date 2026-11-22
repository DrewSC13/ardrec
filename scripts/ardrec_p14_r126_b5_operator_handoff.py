#!/usr/bin/env python3
"""R126-B5: reproducible *unapproved* root-guardian source handoff.

Does not install anything below /var or /etc, invoke sudo/systemd/nft/libvirt,
issue authority, create signing keys or dispatch FTP. An uncommitted working
branch MUST NOT be converted into a deployable root bundle. The operator's
independent signed release and root staging procedure remain separate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

SCHEMA='ARDREC-R126-B5-ROOT-OPERATOR-SOURCE-HANDOFF-v1'
REPO=Path('/home/cicada/Development/GitHub/ardrec')
PATCHES=Path('/home/cicada/Development/GitHub/ardrec-patches')
BRANCH='feat/p14-r126-r129-integrated-physical-pilot'
BASE='7c1bf90c36b17ace9b670b360b6c183770297bec'
SOURCE=Path('scripts/ardrec_p14_r126_root_session_guard.py')
PIN='4bd6e0c19f9fe30fb7c32c2688dba1f232484d5f366760ecdcc17ef4548b444a'
GUARD_PIN='c8bb29e434fcc3895ec3584e37cfd10354d2071056166d70e23526ba102e1ce7'
ROOT_SCHEMA='ARDREC-R126-B4-ROOT-DENY-SESSION-v1-root-bundle'
FILES=('root-controller.py.source-only','manifest.json.draft','review.json')
EXPECTED={
'.github/workflows/ci.yml',
'docs/development/p14-r126-r129-one-branch-integration.md',
'lab/tests/test_p14_r126_r129_integrated.py',
'lab/tests/test_p14_r126_scope_v2.py',
'lab/tests/test_p14_r126_window_v2.py',
'lab/tests/test_p14_r126_root_session_guard.py',
'lab/tests/test_p14_r126_b5_operator_handoff.py',
'scripts/ardrec_p14_r126_r129_integrated.py',
'scripts/ardrec_p14_r126_root_session_guard.py',
'scripts/ardrec_p14_r126_b5_operator_handoff.py',
'src/ardrec/coordination/r126_operational_controller.py',
'src/ardrec/coordination/r126_scope_v2.py',
'src/ardrec/coordination/r126_window_v2.py',
'src/ardrec/coordination/r127_closure_witness.py',
'src/ardrec/coordination/r128_ftp_pilot.py',
'src/ardrec/coordination/r129_a6_a10_recovery.py',
}
POLICIES=(
'/etc/ardrec/r126-ftp-t01-scope-trust-v2.json',
'/etc/ardrec/r126-ftp-t01-scope-revocation-v2.json',
'/etc/ardrec/r115-p7-pilot-trust-v1.json',
'/etc/ardrec/r115-p7-pilot-revocation-v1.json',
'/etc/ardrec/r115-p8-trust-v1.json',
'/etc/ardrec/r115-p8-revocation-v1.json',
'/etc/ardrec/r126-root-session-trust-v1.json',
'/etc/ardrec/r126-root-session-revocation-v1.json',
'/etc/ardrec/r127-root-closure-witness-v1.json',
)

class Stop(ValueError):
    """Stable refusal status; no auto-repair."""


def need(ok, code):
    if not ok:
        raise Stop(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canon(doc):
    return (json.dumps(doc,sort_keys=True,separators=(',',':'),
                       ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')


def secure_source(path):
    need(isinstance(path, Path) and path.is_absolute() and
         not any(p.is_symlink() for p in (path,*path.parents)),
         'SOURCE_SYMLINK')
    st=path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
         not(stat.S_IMODE(st.st_mode)&0o002) and 0<st.st_size<=65536,
         'SOURCE_MODE_OR_SIZE')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd)
        need((a.st_dev,a.st_ino,a.st_uid,a.st_size,a.st_nlink)==
             (st.st_dev,st.st_ino,st.st_uid,st.st_size,st.st_nlink),
             'SOURCE_RACE')
        raw=os.read(fd,65537)
        b=os.fstat(fd)
        need(len(raw)==a.st_size and
             (b.st_dev,b.st_ino,b.st_mtime_ns,b.st_size)==
             (a.st_dev,a.st_ino,a.st_mtime_ns,a.st_size),
             'SOURCE_CHANGED')
    finally:
        os.close(fd)
    need(digest(raw)==PIN,'ROOT_CONTROLLER_SOURCE_PIN_MISMATCH')
    return raw


def git(*args):
    p=subprocess.run(('/usr/bin/git',*args),cwd=REPO,stdin=subprocess.DEVNULL,
                     capture_output=True,check=False,timeout=15)
    need(p.returncode==0,'GIT_COMMAND_FAILED')
    return p.stdout


def check_git():
    need(os.geteuid()!=0,'ROOT_SHELL_FORBIDDEN')
    need(Path.cwd().resolve()==REPO and REPO.is_dir(),
         'WRONG_WORKTREE')
    need(git('rev-parse','--show-toplevel').decode().strip()==str(REPO),
         'WRONG_GIT_REPO')
    need(git('branch','--show-current').decode().strip()==BRANCH,
         'WRONG_BRANCH')
    need(git('rev-parse','HEAD').decode().strip()==BASE,
         'BASE_CHANGED')
    raw=git('status','--porcelain=v1','--untracked-files=all','-z')
    result={}
    for elem in raw.split(b'\0'):
        if not elem: continue
        need(len(elem)>=4 and elem[:2] in (b' M',b'??'),
             'UNEXPECTED_GIT_STATUS')
        try: name=elem[3:].decode('utf-8')
        except UnicodeError as exc:raise Stop('GIT_FILENAME_ENCODING') from exc
        need(name not in result,'DUPLICATE_GIT_PATH')
        result[name]=elem[:2]
    need(set(result)==EXPECTED and result.get('.github/workflows/ci.yml')==b' M' and
         all(x==b'??' for name,x in result.items() if name!='.github/workflows/ci.yml'),
         'WORKTREE_EXPECTED_SIXTEEN_FILES')
    return BASE


def metadata(path):
    try:
        st=path.lstat()
    except FileNotFoundError:
        return 'ABSENT'
    except PermissionError:
        return 'INACCESSIBLE_NOT_INFERRED'
    if path.is_symlink(): return 'UNSAFE_LINK'
    if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or
        (stat.S_IMODE(st.st_mode)&0o022)):
        return 'UNTRUSTED_METADATA'
    return 'PRESENT_METADATA_ONLY_NOT_SIGNATURE_ATTESTED'


def review():
    head=check_git()
    source=secure_source(REPO/SOURCE)
    # This is a non-authoritative, non-root inspection. Even if all paths are
    # present their signatures, freshness and revocations are NOT verified.
    policies={path:metadata(Path(path)) for path in POLICIES}
    result={'schema':SCHEMA+'-review','branch':BRANCH,
            'uncommitted_parent_head':head,
            'approved_head':None,
            'source_path':SOURCE.as_posix(),
            'root_script_sha256':digest(source),
            'installed_r116_guard_expected_sha256':GUARD_PIN,
            'source_file_count':len(EXPECTED),
            'physical_policies':policies,
            'requires_independent_signed_release':True,
            'requires_external_root_provisioning':True,
            'root_install_executed':False,
            'root_controller_executed':False,
            'traffic_admitted':False,
            'p8':'NO-GO','a6':'ND','a9':None,
            'status':'UNAPPROVED_SOURCE_REVIEW_ONLY'}
    result['sha256']=digest(canon(result))
    return result


def drafts(result,source):
    need(result['schema']==SCHEMA+'-review' and
         result['root_script_sha256']==digest(source)==PIN and
         result['status']=='UNAPPROVED_SOURCE_REVIEW_ONLY',
         'REVIEW_NOT_REPRODUCIBLE')
    manifest={'schema':ROOT_SCHEMA,'script_sha256':PIN,
              'guard_sha256':GUARD_PIN,
              'approved_head':None,'deny_only':True,
              'root_install_independent':False}
    return {
        FILES[0]:source,
        FILES[1]:canon(manifest),
        FILES[2]:canon(result),
    }


def fsync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)


def prepare(*, parent=PATCHES):
    """Store an unapproved review copy, never a root-operational bundle."""
    result=review()
    contents=drafts(result,secure_source(REPO/SOURCE))
    need(isinstance(parent, Path) and parent.is_absolute() and
         not parent.is_symlink() and parent.is_dir() and
         parent.resolve()==PATCHES and
         parent.stat().st_uid==os.geteuid(),
         'REVIEW_OUTPUT_PARENT_UNTRUSTED')
    folder=parent/('b5-source-handoff-'+result['sha256'])
    need(not folder.is_symlink(),'REVIEW_BUNDLE_SYMLINK')
    if folder.exists():
        need(folder.is_dir() and folder.stat().st_uid==os.geteuid() and
             stat.S_IMODE(folder.stat().st_mode)==0o700,
             'REVIEW_BUNDLE_FOLDER_UNSAFE')
        need({p.name for p in folder.iterdir()}==set(contents),
             'REVIEW_BUNDLE_ENTRY_DRIFT')
        for name,raw in contents.items():
            path=folder/name
            need(not path.is_symlink() and path.is_file() and
                 path.stat().st_uid==os.geteuid() and
                 stat.S_IMODE(path.stat().st_mode)==0o600 and
                 path.read_bytes()==raw,
                 'REVIEW_BUNDLE_FILE_TAMPERED')
        return folder
    folder.mkdir(mode=0o700)
    try:
        for name,raw in contents.items():
            fd=os.open(folder/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|
                       os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
            with os.fdopen(fd,'wb') as file:
                file.write(raw);file.flush();os.fsync(file.fileno())
        fsync_dir(folder)
        fsync_dir(parent)
    except Exception:
        # Never auto-delete partial evidence. Stop and require explicit review.
        raise
    return folder


def capabilities():
    return {'schema':SCHEMA+'-capabilities',
            'sha256_pinned_root_source':PIN,
            'root_guard_pin':GUARD_PIN,
            'review_uncommitted_branch_only':True,
            'unapproved_manifest_must_not_run_as_root':True,
            'operator_handoff_private_folder':True,
            'stages_root':False,'runs_root_controller':False,
            'opens_traffic':False,'issues_authorization':False,
            'p8':'NO-GO'}


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    act=ap.add_mutually_exclusive_group(required=True)
    act.add_argument('--capabilities',action='store_true')
    act.add_argument('--review',action='store_true')
    act.add_argument('--prepare',action='store_true')
    args=ap.parse_args(argv)
    try:
        if args.capabilities: output=capabilities()
        elif args.review: output=review()
        else:
            folder=prepare()
            output={'schema':SCHEMA+'-prepared',
                    'private_review_directory':str(folder),
                    'status':'UNAPPROVED_REVIEW_NOT_FOR_ROOT_INSTALL',
                    'source_only':True,'p8':'NO-GO'}
        print(canon(output).decode().strip())
        return 0
    except Exception as exc:
        print(canon({'schema':SCHEMA+'-refusal',
                     'status':'STOP_NO_ROOT_ACTION',
                     'reason':type(exc).__name__+':'+str(exc)[:150],
                     'p8':'NO-GO'}).decode().strip(),file=sys.stderr)
        return 23

if __name__=='__main__':
    raise SystemExit(main())
