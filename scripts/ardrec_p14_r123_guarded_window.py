#!/usr/bin/env python3
"""ARDREC R123: read-only 60s watchdog contract inspection (no root pilot)."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sys

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r122_operational_boundary as r122
from ardrec.coordination import r123_guarded_window as r123


def _unit_file(path: Path) -> dict:
    r123.need(path.is_absolute() and path.is_file() and not path.is_symlink(),
              'UNIT_FILE_UNTRUSTED')
    raw=path.read_bytes()
    r123.need(0 < len(raw) <= 16384, 'UNIT_FILE_SIZE')
    doc=f1.load(raw)
    r123.need(type(doc) is dict and f1.canonical(doc) == raw,
              'UNIT_FILE_NONCANONICAL')
    return doc


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description='R123 physical watchdog contract: SOURCE_ONLY')
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--capabilities',action='store_true')
    mode.add_argument('--inspect',action='store_true')
    parser.add_argument('--capture',type=Path)
    parser.add_argument('--journal',type=Path)
    parser.add_argument('--unit-file',type=Path)
    parser.add_argument('--head',type=str)
    parser.add_argument('--deny-target-seconds',type=int,default=45)
    parser.add_argument('--repo',type=Path,default=Path.cwd())
    args=parser.parse_args(argv)
    try:
        r123.need(os.geteuid() != 0, 'ROOT_SHELL_FORBIDDEN')
        if args.capabilities:
            r123.need(args.capture is None and args.journal is None and
                      args.unit_file is None and args.head is None and
                      args.deny_target_seconds == 45, 'UNEXPECTED_CAPABILITY_ARGS')
            print(f1.canonical(r123.capabilities()).decode().rstrip())
            return 0
        r123.need(args.inspect and args.capture is not None and
                  args.head is not None and
                  ((args.journal is None) == (args.unit_file is None)),
                  'INSPECTION_ARGUMENTS')
        catalog=(args.repo / f14.CATALOG).read_bytes()
        f14.catalog_check(catalog)
        boundary=r122.build(capture_folder=args.capture,head=args.head,
                            journal_folder=args.journal,
                            unit=(None if args.unit_file is None else
                                  _unit_file(args.unit_file)),
                            catalog_raw=catalog,
                            now=datetime.now(timezone.utc).replace(microsecond=0))
        now=datetime.now(timezone.utc).replace(microsecond=0)
        result=r123.plan(boundary=boundary,catalog_raw=catalog,now=now,
                         duration_seconds=args.deny_target_seconds)
        r123.verify_plan(result,boundary=boundary,catalog_raw=catalog)
        print('R123_SOURCE_CHAIN=VERIFIED')
        print('R123_HEAD='+result['head'])
        print('R123_HOST='+result['host_lifecycle'])
        print('R123_CASE='+str(result['case_id']))
        print('R123_GUARD='+result['root_guard_status'])
        print('R123_MAX_WINDOW_SECONDS='+str(result['max_window_seconds']))
        print('R123_DENY_TARGET_SECONDS='+str(result['deny_restore_target_seconds']))
        print('R123_PLAN_SHA256='+result['sha256'])
        print('R123_BLOCKERS='+','.join(result['blockers']))
        print('R123_PHYSICAL_ACTIONS=0')
        print('R123_A6=ND')
        print('R123_A9=NOT_PUBLISHED')
        print('R123_P8=NO-GO')
        return 0
    except (r123.Stop,r122.Stop,KeyError,TypeError,OSError,ValueError) as exc:
        print('R123_STOP='+str(exc),file=sys.stderr)
        print('R123_P8=NO-GO',file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())
