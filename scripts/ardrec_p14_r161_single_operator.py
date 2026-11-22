#!/usr/bin/env python3
"""ARDREC single-operator development control for staged B9 only.

--prepare: self-attestation, NO VM start, root install or traffic.
--inspect: read-only B9 preflight (only when independently rooted B9 is present).
--pilot: delegates ONE attempt to the pinned B9 root executor after self-consent
         AND all original B9 signed controls approve; no alternate traffic path.
"""
from __future__ import annotations

import argparse
from datetime import datetime,timezone
import os
from pathlib import Path
import secrets
import subprocess
import sys

from ardrec.coordination import r161_single_operator as r

REPO=Path('/home/cicada/Development/GitHub/ardrec')
FOLDER=Path('/home/cicada/ardrec-lab/r161-single-operator-v1')
BASE='16a13a2b84ca6c5ba110820522146acadd856893'
TREE='7bf4da412b6ef6392b55bd5307cc4dd616863464'
BRANCH='feat/ardrec-cierre-operacional-experimental'

def git(*args):
    p=subprocess.run(('/usr/bin/git',*args),cwd=REPO,stdin=subprocess.DEVNULL,
       stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=False)
    r.need(p.returncode==0,'GIT_COMMAND_FAILED')
    return p.stdout.decode('ascii').strip()

def preflight():
    r.need(os.geteuid()!=0,'ROOT_SHELL_FORBIDDEN')
    r.need(Path.cwd()==REPO,'REPO_ROOT_REQUIRED')
    branch=git('branch','--show-current')
    r.need(branch in (BRANCH,'main'),'BRANCH_CHANGED')
    r.need(git('merge-base','--is-ancestor',BASE,'HEAD')=='','ANCESTOR_INVALID')
    if branch==BRANCH:
        r.need(git('rev-parse','main')=='95a6d57b8241101c7a8fa3aedc07fb779b088d9f','MAIN_CHANGED')
    else:
        r.need(git('rev-parse','HEAD')==git('rev-parse','main'),'MAIN_CHECKOUT_DRIFT')
    r.need(git('rev-parse',BASE+'^{tree}')==TREE,'BASE_TREE_INVALID')
    r.need(git('status','--porcelain=v1','--untracked-files=all')=='',
           'WORKTREE_DIRTY')
    p=subprocess.run(('/usr/bin/git','verify-commit','HEAD'),cwd=REPO,
        stdin=subprocess.DEVNULL,capture_output=True,timeout=15,check=False)
    r.need(p.returncode==0,'UNSIGNED_CURRENT_COMMIT')
    return git('rev-parse','HEAD'),git('rev-parse','HEAD^{tree}')

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    cmd=ap.add_mutually_exclusive_group(required=True)
    cmd.add_argument('--capabilities',action='store_true')
    cmd.add_argument('--prepare',action='store_true')
    cmd.add_argument('--inspect',action='store_true')
    cmd.add_argument('--pilot',action='store_true')
    ap.add_argument('--i-am-operator',action='store_true')
    ap.add_argument('--confirm',default='')
    ap.add_argument('--session',default='')
    args=ap.parse_args()
    if args.capabilities:
        print('R161_MODE=SELF_ATTESTED_DEV_NOT_INDEPENDENT')
        print('R161_REUSES_B9_ROOT_EXECUTOR=TRUE')
        print('R161_CAN_BOOT_VMS=FALSE')
        print('R161_CAN_INSTALL_ROOT=FALSE')
        print('R161_P8=NO-GO')
        return 0
    try:
        head,tree=preflight()
        boot_id=Path('/proc/sys/kernel/random/boot_id').read_text('ascii').strip()
        now=datetime.now(timezone.utc)
        if args.prepare:
            r.need(args.i_am_operator,'SELF_OPERATOR_ACK_REQUIRED')
            r.need(not args.session or bool(r.SESSION_RE.fullmatch(args.session)),
                   'SESSION_ARGUMENT_INVALID')
            if FOLDER.exists():
                r.safe_directory(FOLDER)
            else:
                r.need(FOLDER.parent.is_dir() and not FOLDER.parent.is_symlink(),
                       'LAB_PARENT_INVALID')
                parent_st=FOLDER.parent.lstat()
                r.need(parent_st.st_uid==os.geteuid() and
                       parent_st.st_mode & 0o077 == 0,'LAB_PARENT_NOT_PRIVATE')
                FOLDER.mkdir(mode=0o700)
                os.chmod(FOLDER,0o700)
            session=args.session or secrets.token_hex(8)
            folder=FOLDER/('session-'+session)
            folder.mkdir(mode=0o700)
            r.safe_directory(folder)
            consent=r.consent_document(head=head,tree=tree,boot_id=boot_id,
                 operator_uid=os.geteuid(),session=session,now=now)
            r.private_create(folder/'consent.json',r.canon(consent))
            print('R161_CONSENT=PASS_SELF_AUTHORIZED_DEVELOPMENT_ONLY')
            print('R161_SESSION='+session)
            print('R161_FOLDER='+str(folder))
            print('R161_ROOT_INSTALL=NO R161_VM_STARTS=0 R161_TRAFFIC=0')
            print('R161_P8=NO-GO')
            return 0
        r.need(bool(r.SESSION_RE.fullmatch(args.session)),'SESSION_ARGUMENT_REQUIRED')
        r.safe_directory(FOLDER)
        folder=FOLDER/('session-'+args.session)
        r.safe_directory(folder)
        consent_raw=r.private_read(folder/'consent.json')
        doc=r.validate_consent(r.parse(consent_raw),head=head,tree=tree,
            boot_id=boot_id,operator_uid=os.geteuid(),now=now)
        r.need(doc['session']==args.session,'SESSION_FOLDER_MISMATCH')
        if args.inspect:
            output=r.root_call('--inspect-root',timeout=20)
            r.need(output.returncode==0,'B9_ROOT_NOT_READY')
            r.validate_b9_preflight(output.stdout,
                expected_head=head,expected_session=doc['session'],now=now)
            print('R161_B9_PREFLIGHT=PASS_SIGNED_ROOT_CHECKS')
            print('R161_PILOT_NOT_EXECUTED=TRUE')
            print('R161_P8=NO-GO')
            return 0
        r.need(args.i_am_operator,'SELF_OPERATOR_ACK_REQUIRED')
        receipt=r.run_session(folder=folder,consent_raw=consent_raw,
            head=head,tree=tree,boot_id=boot_id,operator_uid=os.geteuid(),
            now=now,confirmation=args.confirm)
        print('R161_RESULT='+receipt['result'])
        print('R161_ONE_SHOT=CONSUMED')
        print('R161_RECEIPT='+str(folder/('receipt-'+doc['session']+'.json')))
        print('R161_P8=NO-GO R161_A6=ND R161_A9=NOT_PUBLISHED')
        return 0 if receipt['result']=='B9_REPORTED_CANDIDATE_WITH_DENY_RESTORED' else 23
    except (r.Stop,OSError,subprocess.TimeoutExpired,ValueError) as exc:
        print('R161_STOP='+type(exc).__name__+':'+str(exc)[:140])
        print('R161_NO_AUTO_RETRY=TRUE R161_P8=NO-GO')
        return 23

if __name__=='__main__':
    raise SystemExit(main())
