#!/usr/bin/env python3
"""ARDREC B7: A5->A10 source replay without traffic, root, or global A9 write.

Use --capabilities; or --replay --preparation PATH --unit PATH --journal PATH
[--observer-folder PATH] [--audit-root PATH].  --audit-root creates only a
private A10 candidate using R129's existing append-only storage.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import stat
import sys

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r128_r129_end_to_end as e2e
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r129_a6_a10_recovery as r129

MAX_READ = 131072


class Stop(ValueError):
    pass


def read_private(path: Path) -> dict:
    if not isinstance(path,Path) or not path.is_absolute() or path.is_symlink():
        raise Stop('PRIVATE_JSON_ABSOLUTE_REGULAR_REQUIRED')
    st=path.lstat()
    if not (stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and st.st_nlink==1 and
            (st.st_mode & 0o077)==0 and 0<st.st_size<=MAX_READ):
        raise Stop('PRIVATE_JSON_OWNER_MODE_OR_SIZE')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        after=os.fstat(fd)
        if (st.st_dev,st.st_ino,st.st_size,st.st_uid)!=(after.st_dev,after.st_ino,after.st_size,after.st_uid):
            raise Stop('PRIVATE_JSON_REPLACED')
        raw=os.read(fd,MAX_READ+1)
        if len(raw)!=st.st_size:raise Stop('PRIVATE_JSON_SHORT_READ')
        doc=f1.load(raw)
        if f1.canonical(doc)!=raw:raise Stop('PRIVATE_JSON_NONCANONICAL')
        if type(doc) is not dict:raise Stop('PRIVATE_JSON_NOT_OBJECT')
        return doc
    finally:
        os.close(fd)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    modes=p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--capabilities',action='store_true')
    modes.add_argument('--replay',action='store_true')
    modes.add_argument('--verify-a10',type=Path)
    p.add_argument('--preparation',type=Path)
    p.add_argument('--unit',type=Path)
    p.add_argument('--journal',type=Path)
    p.add_argument('--observer-folder',type=Path)
    p.add_argument('--audit-root',type=Path)
    args=p.parse_args(argv)
    try:
        if os.geteuid()==0:raise Stop('DO_NOT_RUN_AS_ROOT')
        if args.capabilities:
            if any(x is not None for x in (args.preparation,args.unit,args.journal,
                                           args.observer_folder,args.audit_root)):
                raise Stop('UNEXPECTED_CAPABILITY_ARGUMENTS')
            result=e2e.capabilities()
        elif args.verify_a10 is not None:
            if any(x is not None for x in (args.preparation,args.unit,args.journal,
                                           args.observer_folder,args.audit_root)):
                raise Stop('UNEXPECTED_VERIFY_A10_ARGUMENTS')
            result=r129.verify_private(args.verify_a10,
                    (Path(__file__).resolve().parents[1]/'lab/operational-catalog-v1/catalog.json').read_bytes())
        else:
            if any(x is None for x in (args.preparation,args.unit,args.journal)):
                raise Stop('REPLAY_INPUTS_REQUIRED')
            cat=(Path(__file__).resolve().parents[1]/'lab/operational-catalog-v1/catalog.json').read_bytes()
            preparation=read_private(args.preparation)
            unit=read_private(args.unit)
            if args.audit_root is None:
                result=e2e.reconcile(preparation=preparation,journal=args.journal,
                        declared_unit=unit,catalog_raw=cat,
                        observer_folder=args.observer_folder)
            else:
                result=e2e.persist_a10(preparation=preparation,
                        journal=args.journal,declared_unit=unit,catalog_raw=cat,
                        audit_root=args.audit_root,observer_folder=args.observer_folder)
        print(f1.canonical(result).decode('ascii').strip())
        return 0
    except (Stop,e2e.Stop,r129.Stop,ValueError,OSError,TypeError,KeyError) as exc:
        print('R128_R129_B7_STOP='+type(exc).__name__+':'+str(exc)[:180])
        print('R128_R129_B7_P8=NO-GO')
        return 2


if __name__=='__main__':sys.exit(main())
