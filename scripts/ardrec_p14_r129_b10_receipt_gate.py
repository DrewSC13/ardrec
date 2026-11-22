#!/usr/bin/env python3
"""R129 B10: audit exported B9 receipt bytes and prebound F13 journal, no A9 write.

--capabilities is always offline. --replay/--a9-barrier accept ONLY local
unprivileged private JSON files, not root-owned live source. Input copies are
never accepted as evidence of root provenance or physical attestation.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r129_b9_receipt_gate as gate

MAX=131072

class Stop(ValueError):
    pass


def read_private(path:Path, *, canonical_required=True) -> dict:
    if not isinstance(path,Path) or not path.is_absolute() or path.is_symlink():
        raise Stop('INPUT_PATH_NOT_PRIVATE_ABSOLUTE_FILE')
    st=path.lstat()
    parent=path.parent.lstat()
    if not (stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.geteuid() and
            stat.S_IMODE(parent.st_mode)==0o700 and
            not path.parent.is_symlink()):
        raise Stop('INPUT_PARENT_NOT_PRIVATE')
    if not (stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and
            st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
            0<st.st_size<=MAX):
        raise Stop('INPUT_FILE_NOT_PRIVATE')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        opened=os.fstat(fd)
        if (opened.st_dev,opened.st_ino,opened.st_uid,opened.st_size,opened.st_nlink)!=(
                st.st_dev,st.st_ino,st.st_uid,st.st_size,st.st_nlink):
            raise Stop('INPUT_FILE_REPLACED')
        raw=os.read(fd,MAX+1)
        end=os.fstat(fd)
        if len(raw)!=st.st_size or (opened.st_ino,opened.st_size,opened.st_mtime_ns)!=(
                end.st_ino,end.st_size,end.st_mtime_ns):
            raise Stop('INPUT_FILE_CHANGED_DURING_READ')
    finally:
        os.close(fd)
    if canonical_required:
        data=f1.load(raw)
        if f1.canonical(data)!=raw:raise Stop('INPUT_NOT_CANONICAL')
    else:
        def unique(pairs):
            doc={}
            for key,value in pairs:
                if key in doc:raise Stop('INPUT_DUPLICATE_KEY')
                doc[key]=value
            return doc
        data=json.loads(raw,object_pairs_hook=unique,
                        parse_constant=lambda _: (_ for _ in ()).throw(Stop('INPUT_NONFINITE')))
    if type(data) is not dict:raise Stop('INPUT_JSON_NOT_OBJECT')
    return data


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    action=p.add_mutually_exclusive_group(required=True)
    action.add_argument('--capabilities',action='store_true')
    action.add_argument('--replay',action='store_true')
    action.add_argument('--a9-barrier',action='store_true')
    for name in ('journal','handoff','intent','receipt','guest','qga'):
        p.add_argument('--'+name,type=Path)
    a=p.parse_args(argv)
    try:
        if os.geteuid()==0:raise Stop('DO_NOT_RUN_REPOSITORY_CODE_AS_ROOT')
        paths=(a.journal,a.handoff,a.intent,a.receipt,a.guest,a.qga)
        if a.capabilities:
            if any(x is not None for x in paths):raise Stop('UNEXPECTED_CAPABILITY_ARGS')
            result=gate.capabilities()
        else:
            if any(x is None for x in paths[:4]) or (a.guest is None)!=(a.qga is None):
                raise Stop('MISSING_B9_SOURCE')
            documents={name:read_private(getattr(a,name),canonical_required=name!='qga')
                      for name in ('handoff','intent','receipt')}
            if a.guest is not None:
                documents['guest']=read_private(a.guest)
                documents['qga']=read_private(a.qga,canonical_required=False)
            else:
                documents['guest']=None
                documents['qga']=None
            candidate=gate.review(journal=a.journal,**documents)
            result=(gate.a9_barrier(candidate=candidate,journal=a.journal,**documents)
                    if a.a9_barrier else candidate)
        print(f1.canonical(result).decode('ascii').strip())
        return 0
    except (Stop,gate.Stop,OSError,ValueError,KeyError,TypeError) as exc:
        print('R129_B10_STOP='+type(exc).__name__+':'+str(exc)[:160])
        print('R129_B10_P8=NO-GO')
        return 2

if __name__=='__main__':
    sys.exit(main())
