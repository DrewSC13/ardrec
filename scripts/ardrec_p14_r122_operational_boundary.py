#!/usr/bin/env python3
"""R122 read-only physical/case boundary (not a root controller)."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sys

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r122_operational_boundary as r122


def _unit_file(path: Path) -> dict:
    r122.need(path.is_absolute() and path.is_file() and not path.is_symlink(),
              'UNIT_FILE_PATH')
    raw = path.read_bytes()
    r122.need(0 < len(raw) <= 16384, 'UNIT_FILE_SIZE')
    doc = f1.load(raw)
    r122.need(type(doc) is dict and f1.canonical(doc) == raw, 'UNIT_FILE_CANONICAL')
    return doc


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='R122 physical/case preflight: no dispatch or A9')
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--capabilities', action='store_true')
    group.add_argument('--inspect', action='store_true')
    group.add_argument('--verify-report', type=Path)
    p.add_argument('--capture', type=Path, help='Existing R115-F5 private receipt folder')
    p.add_argument('--journal', type=Path, help='Optional existing F13 case folder')
    p.add_argument('--unit-file', type=Path, help='Exact rational unit for same F13 case')
    p.add_argument('--head', type=str, help='Exact git commit hash; no automatic fallback')
    p.add_argument('--audit-root', type=Path, default=r122.ROOT)
    p.add_argument('--persist', action='store_true', help='Append-only A10 audit, NOT A9')
    p.add_argument('--repo', type=Path, default=Path.cwd())
    args = p.parse_args(argv)
    try:
        r122.need(os.geteuid() != 0, 'ROOT_SHELL_FORBIDDEN')
        if args.capabilities:
            r122.need(args.capture is None and args.journal is None and
                      args.unit_file is None and args.head is None and
                      not args.persist, 'UNEXPECTED_CAPABILITIES_ARGS')
            print(f1.canonical(r122.capabilities()).decode().rstrip())
            return 0
        catalog = (args.repo / f14.CATALOG).read_bytes()
        f14.catalog_check(catalog)
        if args.verify_report is not None:
            r122.need(args.capture is None and args.journal is None and
                      args.unit_file is None and args.head is None and
                      not args.persist, 'UNEXPECTED_VERIFY_ARGS')
            report = r122.verify_persisted(args.verify_report, catalog)
            print('R122_AUDIT=REPLAY_VERIFIED')
        else:
            r122.need(args.inspect and args.capture is not None and
                      args.head is not None and
                      ((args.journal is None) == (args.unit_file is None)),
                      'INSPECTION_INPUTS')
            report = r122.build(capture_folder=args.capture,
                journal_folder=args.journal,
                unit=None if args.unit_file is None else _unit_file(args.unit_file),
                catalog_raw=catalog, head=args.head,
                now=datetime.now(timezone.utc).replace(microsecond=0))
            r122.verify(report, catalog)
            if args.persist:
                folder = r122.persist(report, catalog, root=args.audit_root)
                r122.verify_persisted(folder, catalog)
                print('R122_A10_FOLDER='+str(folder))
        print('R122_HOST='+report['host_lifecycle'])
        print('R122_CASE='+str(report['case_id']))
        print('R122_A5='+report['a5_source_status'])
        print('R122_A6='+report['a6'])
        print('R122_A7_INTERVAL='+str(report['a7_interval']))
        print('R122_A9=NOT_PUBLISHED')
        print('R122_BLOCKERS='+','.join(report['blockers']))
        print('R122_AUDIT_SHA256='+report['sha256'])
        print('R122_NETWORK_ACTIONS=0')
        print('R122_P8=NO-GO')
        return 0
    except (r122.Stop, f14.Stop, KeyError, TypeError, OSError, ValueError) as exc:
        print('R122_STOP='+str(exc), file=sys.stderr)
        print('R122_P8=NO-GO', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
