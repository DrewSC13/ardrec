#!/usr/bin/env python3
"""R55.5 offline bundle constructor. No privileged or active modes."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import stat
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r553_transition_guard as r553
from ardrec.coordination import r555_recovery_contract as r555

DEFAULT_PLAN=Path('/home/cicada/ardrec-lab/r55-transition/r552-f1-plan-20261115T152309Z-39487')
DEFAULT_HELPER=ROOT/'scripts/ardrec_p14_r555_root_recover.py'

def write_once(path,body):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(body)
        f.flush()
        os.fsync(f.fileno())

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--r552-plan',type=Path,default=DEFAULT_PLAN)
    mode=ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--verify-offline',action='store_true')
    mode.add_argument('--prepare-private-bundle',type=Path)
    a=ap.parse_args()
    try:
        src=r553.verify_private_receipt(a.r552_plan)
        helper=DEFAULT_HELPER.read_bytes()
        if DEFAULT_HELPER.is_symlink():
            raise r555.R555Error('helper_symlink_forbidden')
        blobs=r555.prepare(src,helper)
        report=r555.obligations()
        print('R555_SOURCE_R552=AUTHENTICATED')
        print('R555_BUNDLE_FILES='+str(len(blobs)))
        print('R555_RECOVERY=DENY_ONLY')
        if a.verify_offline:
            print('R555_RESULT=OFFLINE_CONTRACT_PASS')
            print('R555_ROOT_OPERATIONS=0')
        else:
            target=a.prepare_private_bundle
            if not target.is_absolute() or target.exists() or target.is_symlink():
                raise r555.R555Error('destination_must_be_new_absolute_directory')
            for p in (target,*target.parents):
                if p.is_symlink():
                    raise r555.R555Error('symlink_destination_path')
            parent=target.parent
            st=parent.stat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o700:
                raise r555.R555Error('destination_private_parent_required')
            os.umask(0o077)
            target.mkdir(mode=0o700,exist_ok=False)
            for name,body in sorted(blobs.items()):
                write_once(target/name,body)
            write_once(target/'contract.json',r555.canon(report))
            names=sorted(blobs)+['contract.json']
            write_once(target/'SHA256SUMS',(''.join(r555.sha((target/n).read_bytes())+'  '+n+'\n' for n in names)).encode('ascii'))
            print('R555_PREPARED='+str(target))
            print('R555_RESULT=PRIVATE_BUNDLE_PREPARED_NO_ROOT_INSTALL')
            print('R555_ROOT_OPERATIONS=0')
        print('R555_SYSTEM_TIMER=NOT_ARMED')
        print('R555_GUEST_TRAFFIC=0')
        print('R555_P8=NO-GO')
        return 0
    except (OSError,ValueError,RuntimeError) as exc:
        print('R555_RESULT=BLOCKED:'+type(exc).__name__+':'+str(exc)[:200])
        print('R555_P8=NO-GO')
        return 2

if __name__=='__main__':
    sys.exit(main())
