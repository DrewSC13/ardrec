#!/usr/bin/env python3
"""R146 public, reproducible root-agent bootstrap handoff (NO root staging).

Only exports audited source bytes from a signed, clean HEAD into an external
private ZIP. All root-owned installation, key provenance, signed permits,
revocation and physical F8 receipts are responsibilities of a separate actor.
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
import zipfile

SCHEMA='ARDREC-R146-INDEPENDENT-ROOT-INSTALL-v1-root-bundle'
REVIEW_SCHEMA='ARDREC-R146-EXTERNAL-BOOTSTRAP-REQUEST-v1'
REPO=Path('/home/cicada/Development/GitHub/ardrec')
PATCHES=Path('/home/cicada/Development/GitHub/ardrec-patches')
BRANCH='feat/ardrec-cierre-operacional-experimental'
ANCHOR='8256c1ee7eaff0facbfc62f1f9220d139228dd89'
MAIN='95a6d57b8241101c7a8fa3aedc07fb779b088d9f'
SOURCES={
 'installer.py':'scripts/ardrec_p14_r146_root_installer.py',
 'runtime/r146_independent_install.py':'src/ardrec/coordination/r146_independent_install.py',
 'runtime/r135_root_transaction.py':'src/ardrec/coordination/r135_root_transaction.py',
 'runtime/r136_operational_semantics.py':'src/ardrec/coordination/r136_operational_semantics.py',
 'runtime/r139_independent_release_review.py':'src/ardrec/coordination/r139_independent_release_review.py',
}
ORIGIN=('https://github.com/DrewSC13/ardrec.git','git@github.com:DrewSC13/ardrec.git')

class Stop(ValueError):pass

def need(ok,reason):
    if not ok:raise Stop(reason)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def canon(doc):return (json.dumps(doc,sort_keys=True,separators=(',',':'),
                          ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')

def get_git(repo,*args):
    proc=subprocess.run(('/usr/bin/git','-C',str(repo),*args),
        check=False,capture_output=True,stdin=subprocess.DEVNULL,timeout=25,
        env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
    need(proc.returncode==0,'GIT_COMMAND_FAILED:'+','.join(args[:2]))
    return proc.stdout.decode('utf-8').rstrip('\n')

def evaluate_sources(*,head,tree,contents):
    need(type(head) is str and re.fullmatch('[a-f0-9]{40}',head) and
         type(tree) is str and re.fullmatch('[a-f0-9]{40}',tree),
         'GIT_IDENTITY_INVALID')
    need(type(contents) is dict and set(contents)==set(SOURCES) and
         all(type(v) is bytes and 0<len(v)<=250000 for v in contents.values()),
         'SOURCE_SCOPE_INVALID')
    manifest={'schema':SCHEMA,'approved_head':head,'approved_tree':tree,
              'source_only_until_independent_authority':True,
              'files':{k:sha(v) for k,v in sorted(contents.items())}}
    request={'schema':REVIEW_SCHEMA,'source_commit':head,'source_tree':tree,
       'installer_destination':'/opt/ardrec/r146-installer-v1',
       'drop_destination':'/var/lib/ardrec/r146-source-drop-v1',
       'state_destination':'/var/lib/ardrec/r146-install-state-v1',
       'b4_destination':'/var/lib/ardrec/r126-ftp-session-guard-v1',
       'b9_destination':'/var/lib/ardrec/r128-one-session-v2',
       'install_trust':'/etc/ardrec/r146-install-trust-v1.json',
       'install_revocation':'/etc/ardrec/r146-install-revocation-v1.json',
       'root_ownership_required':True,'private_file_mode':'0600',
       'private_dir_mode':'0700','signers_additional_to_operational':2,
       'signer_persons_independent_verified':False,
       'root_bootstrap_performed':False,'installation_authorized':False,
       'installed':False,'root_trust_installed':False,
       'permit_present':False,'revocation_fresh':False,
       'physical_f8_receipts_verified':False,'p8':'NO-GO',
       'a6':'ND','a9':'NOT_PUBLISHED',
       'constraints':[
        'Bootstrap only by independently authorized root administrator',
        'Never execute checkout script as root',
        'Verify B4 and B9 exact pins and historical R116 F1 F3',
        'Verify Git source and tree plus runtime bundle manifest',
        'Provision real external trust and revocation out of band',
        'Authenticate twelve operational signers plus two installer signers',
        'Reverify fresh revocation before journal B4 B9 and receipt',
        'Never infer physical 5/1 or permission to open FTP traffic',
       ]}
    return manifest,request

def checked_checkout(repo):
    need(os.geteuid()!=0,'CHECKOUT_MUST_NOT_RUN_AS_ROOT')
    need(repo.is_absolute() and repo.is_dir() and not repo.is_symlink(),
         'GIT_REPOSITORY_PATH_UNSAFE')
    need(get_git(repo,'rev-parse','--show-toplevel')==str(repo) and
         get_git(repo,'branch','--show-current')==BRANCH and
         get_git(repo,'remote','get-url','origin') in ORIGIN and
         get_git(repo,'rev-parse','main')==MAIN,'GIT_CHECKOUT_IDENTITY_INVALID')
    need(get_git(repo,'status','--porcelain=v1','--untracked-files=all')=='',
         'DIRTY_REPOSITORY')
    head=get_git(repo,'rev-parse','HEAD')
    tree=get_git(repo,'rev-parse','HEAD^{tree}')
    get_git(repo,'merge-base','--is-ancestor',ANCHOR,head)
    need(get_git(repo,'log','-1','--format=%G?')=='G',
         'GIT_SIGNED_COMMIT_REQUIRED')
    get_git(repo,'verify-commit',head)
    files={}
    for dest,src in SOURCES.items():
        p=repo/src
        need(p.is_file() and not p.is_symlink(),'SOURCE_FILE_MISSING:'+src)
        data=p.read_bytes()
        reference=subprocess.run(('/usr/bin/git','-C',str(repo),'show','HEAD:'+src),
            check=False,capture_output=True,timeout=20)
        need(reference.returncode==0 and reference.stdout==data,
             'SOURCE_NOT_EQUAL_TO_SIGNED_TREE:'+src)
        files[dest]=data
    return head,tree,files

def public_bundle(parent,head,tree,contents):
    manifest,request=evaluate_sources(head=head,tree=tree,contents=contents)
    need(parent.is_absolute() and parent.is_dir() and not parent.is_symlink(),
         'REVIEW_DIRECTORY_INVALID')
    st=parent.lstat()
    need(st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o700,
         'REVIEW_DIRECTORY_NOT_PRIVATE')
    files=dict(contents)
    files['manifest.json']=canon(manifest)
    files['REQUEST.json']=canon(request)
    files['MANIFEST.json']=canon({'schema':REVIEW_SCHEMA+'-archive',
        'files':{k:{'sha256':sha(v),'bytes':len(v)} for k,v in sorted(files.items())}})
    name='ARDREC_R146_PUBLIC_BOOTSTRAP_'+head[:12]+'.zip'
    target=parent/name
    need(not target.exists() and not target.is_symlink(), 'REVIEW_BUNDLE_ALREADY_EXISTS')
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        with os.fdopen(fd,'wb') as output:
            with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED,
                                 compresslevel=9) as zipfile_out:
                for rel,raw in sorted(files.items()):
                    info=zipfile.ZipInfo(rel,(2020,1,1,0,0,0))
                    info.compress_type=zipfile.ZIP_DEFLATED
                    info.external_attr=(0o100600<<16)
                    zipfile_out.writestr(info,raw)
            output.flush();os.fsync(output.fileno())
    except BaseException:
        raise
    return target,sha(target.read_bytes()),manifest

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--prepare-public-readonly',action='store_true',required=True)
    args=ap.parse_args()
    try:
        head,tree,files=checked_checkout(REPO)
        parent=PATCHES/'ardrec-r146-external-review'
        need(PATCHES.is_dir() and not PATCHES.is_symlink(),
             'PATCHES_PARENT_INVALID')
        if not parent.exists():
            parent.mkdir(mode=0o700)
            parent.chmod(0o700)
        target,digest,_=public_bundle(parent,head,tree,files)
        print('R146_BOOTSTRAP_REQUEST=PASS_PUBLIC_SOURCE_ONLY')
        print('R146_REVIEW_BUNDLE='+str(target))
        print('R146_REVIEW_SHA256='+digest)
        print('R146_REVIEW_HEAD='+head)
        print('R146_REVIEW_TREE='+tree)
        print('R146_ROOT_INSTALL=NO')
        print('R146_TRUST_PROVISIONED=NO')
        print('R146_VM_STARTS=0 R146_TRAFFIC=0 P8=NO-GO')
        return 0
    except (Stop,ValueError,OSError,TypeError,subprocess.SubprocessError) as exc:
        print('R146_REQUEST_STOP='+type(exc).__name__+':'+str(exc)[:180])
        return 23

if __name__=='__main__':raise SystemExit(main())
