#!/usr/bin/env python3
"""Offline F8 policy generation and deterministic replay; no host commands."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO/'src'))
sys.path.insert(0,str(REPO/'scripts'))
from ardrec.coordination import r113_f8_window_policy as p
import ardrec_p14_r113_f6_bundle as f6bundle


def secure_file(path:Path):
    st=path.lstat()
    p.need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and
           st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
           0<st.st_size<524288 and not path.is_symlink(),
           'PRIVATE_FILE_INVALID_'+path.name)
    return path.read_bytes()


def check_directory(path):
    st=path.lstat()
    p.need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and
           stat.S_IMODE(st.st_mode)==0o700 and not path.is_symlink(),
           'PRIVATE_FOLDER_INVALID')


def sources():
    # Every F5 capture is rechecked by the exact installed F6 source module.
    f5=f6bundle.source()
    check_directory(p.F7E_RECEIPT.parent)
    closure=secure_file(p.F7E_RECEIPT)
    p.need(p.sha(closure)==p.F7E_MANIFEST_SHA256,'F7E_RECEIPT_HASH_CHANGED')
    return f5,closure


def put(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as output:
        output.write(raw);output.flush();os.fsync(output.fileno())


def inspect(folder):
    p.need(folder.is_absolute() and folder.parent==p.DEST and
           folder.name.startswith('plan-'),'PLAN_PATH_INVALID')
    check_directory(folder)
    got={item.name for item in folder.iterdir()}
    doc=p.f6.load_json(secure_file(folder/'manifest.json'))
    expected=set(doc['sha256'])|{'manifest.json'}
    p.need(got==expected and doc['schema']==p.SCHEMA,'PLAN_SCOPE_CHANGED')
    raw={name:secure_file(folder/name) for name in expected}
    for name,digest in doc['sha256'].items():
        p.need(p.sha(raw[name])==digest,'POLICY_FILE_HASH_CHANGED_'+name)
    recomputed=p.prepare(*sources())
    p.need(recomputed==raw,'PLAN_NOT_DETERMINISTIC')
    return raw


def create():
    os.umask(0o077)
    if not p.DEST.exists():p.DEST.mkdir(mode=0o700)
    check_directory(p.DEST)
    contents=p.prepare(*sources())
    folder=Path(tempfile.mkdtemp(prefix='plan-',dir=p.DEST))
    check_directory(folder)
    for name,raw in sorted(contents.items()):put(folder/name,raw)
    p.need(inspect(folder)==contents,'POST_CREATE_REPLAY_FAILED')
    return folder


def main():
    parser=argparse.ArgumentParser()
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan',action='store_true')
    mode.add_argument('--replay',type=Path)
    args=parser.parse_args()
    try:
        if args.plan:
            folder=create()
            print('R113_F8_POLICY_SESSION='+str(folder))
        else:
            folder=args.replay
            inspect(folder)
            print('R113_F8_POLICY_REPLAY=PASS')
        print('R113_F8_F5_CAPTURE=AUTHENTICATED')
        print('R113_F8_F7E_CLOSURE=AUTHENTICATED')
        print('R113_F8_SIX_NWFILTER_CANDIDATES=PREPARED_NOT_INSTALLED')
        print('R113_F8_NFT_POLICY=12_SCOPED_ACCEPT_PLUS_4_DENY_NOT_APPLIED')
        print('R113_F8_HOST_MUTATIONS=0')
        print('R113_F8_TRAFFIC_ADMISSION=NOT_AUTHORIZED')
        print('R113_F8_P8=NO-GO')
        return 0
    except Exception as exc:
        print('R113_F8_STOP='+type(exc).__name__+':'+str(exc)[:170])
        print('R113_F8_NO_AUTOMATIC_RETRY_OR_CLEANUP=TRUE')
        print('R113_F8_P8=NO-GO')
        return 23

if __name__=='__main__':raise SystemExit(main())
