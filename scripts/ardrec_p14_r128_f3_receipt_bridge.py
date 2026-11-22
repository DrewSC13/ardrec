#!/usr/bin/env python3
"""B8 source-pinned read-only R116-F3 receipt inspection; no dispatch."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import sys
from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r128_f3_receipt_bridge as b8


def main(argv=None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--capabilities',action='store_true')
    mode.add_argument('--fingerprint-root',action='store_true')
    mode.add_argument('--read-installed',action='store_true')
    p.add_argument('--session')
    p.add_argument('--journal',type=Path)
    a=p.parse_args(argv)
    try:
        if os.geteuid()==0:raise b8.Stop('DO_NOT_RUN_WORKTREE_CODE_AS_ROOT')
        if a.capabilities:
            if a.session is not None or a.journal is not None:
                raise b8.Stop('UNEXPECTED_CAPABILITY_ARGUMENTS')
            data=b8.capabilities()
        elif a.fingerprint_root:
            if a.session is not None or a.journal is not None:
                raise b8.Stop('UNEXPECTED_FINGERPRINT_ARGUMENTS')
            data=b8.inspect_source()
        else:
            if a.session is None or a.journal is None:
                raise b8.Stop('SESSION_AND_JOURNAL_REQUIRED')
            data=b8.read_installed(session=a.session,journal=a.journal)
        print(f1.canonical(data).decode('ascii').strip())
        return 0
    except (b8.Stop,ValueError,KeyError,TypeError,OSError) as exc:
        print('R128_B8_STOP='+type(exc).__name__+':'+str(exc)[:150])
        print('R128_B8_P8=NO-GO')
        return 2

if __name__=='__main__':sys.exit(main())
