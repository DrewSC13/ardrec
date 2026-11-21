#!/usr/bin/env python3
"""R121 CLI: rebuild verified F13 candidate, exact bounded A7, durable audit.

No physical dispatcher, guest boot, firewall change or A9 generation publication.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r121_ftp_case_chain as r121


def _read_unit(path: Path):
    r121.need(isinstance(path, Path) and path.is_absolute() and not path.is_symlink(),
              'UNIT_FILE_PATH_INVALID')
    r121.need(path.is_file() and path.stat().st_size <= 4096,
              'UNIT_FILE_INVALID')
    raw = path.read_bytes()
    unit = f1.load(raw)
    r121.need(type(unit) is dict and raw == f1.canonical(unit),
              'UNIT_FILE_NOT_CANONICAL')
    return unit


def main(argv=None):
    p = argparse.ArgumentParser(description='ARDREC R121 FTP-T01 A5-A10 audit / P8 NO-GO')
    commands = p.add_mutually_exclusive_group(required=True)
    commands.add_argument('--capabilities', action='store_true')
    commands.add_argument('--build', action='store_true', help='derive conservative case without execution')
    commands.add_argument('--verify-report', type=Path, metavar='AUDIT_FOLDER')
    p.add_argument('--journal', type=Path, metavar='F13_FOLDER')
    p.add_argument('--unit-file', type=Path, metavar='EXACT_UNIT_JSON')
    p.add_argument('--persist', action='store_true', help='write private audit, NOT A9 generation')
    p.add_argument('--audit-root', type=Path, default=r121.ROOT)
    p.add_argument('--repo', type=Path, default=Path.cwd())
    args = p.parse_args(argv)
    try:
        r121.need(os.geteuid() != 0, 'ROOT_SHELL_FORBIDDEN')
        if args.capabilities:
            r121.need(args.journal is None and args.unit_file is None
                      and not args.persist, 'UNEXPECTED_CAPABILITIES_ARGS')
            print(f1.canonical(r121.capabilities()).decode().rstrip())
            return 0
        raw_catalog = (args.repo/f14.CATALOG).read_bytes()
        f14.catalog_check(raw_catalog)
        if args.verify_report is not None:
            r121.need(not args.persist and args.journal is None
                      and args.unit_file is None, 'UNEXPECTED_VERIFY_ARGS')
            report = r121.verify_persisted(args.verify_report, raw_catalog)
            print('R121_REPLAY=PASS_SOURCE_AND_EXACT_A7_A8')
            print('R121_CASE_SHA256='+report['sha256'])
            print('R121_A6=ND')
            print('R121_A9=NOT_PUBLISHED')
            print('R121_P8=NO-GO')
            return 0
        r121.need(args.build and args.journal is not None
                  and args.unit_file is not None, 'BUILD_REQUIRES_JOURNAL_AND_UNIT')
        report = r121.build(args.journal, raw_catalog, _read_unit(args.unit_file))
        r121.verify(report, raw_catalog)
        print('R121_CASE='+report['case_id'])
        print('R121_F13='+report['f14_source_status'])
        print('R121_CANDIDATE='+report['candidate_outcome'])
        print('R121_A6='+report['a6_classification'])
        print('R121_A7_INTERVAL='+report['a7_lower']+'..'+report['a7_upper'])
        print('R121_A7_CONFIRMED=ND')
        print('R121_A8='+report['a8_recommendation'])
        print('R121_A9=NOT_PUBLISHED')
        print('R121_CASE_SHA256='+report['sha256'])
        if args.persist:
            folder = r121.persist(report, raw_catalog, root=args.audit_root)
            r121.verify_persisted(folder, raw_catalog)
            print('R121_A10_AUDIT_FOLDER='+str(folder))
            print('R121_A10_REPLAY=PASS')
        print('R121_P8=NO-GO')
        return 0
    except (r121.Stop, f14.Stop, ValueError, KeyError, TypeError, OSError) as exc:
        print('R121_STOP='+str(exc), file=sys.stderr)
        print('R121_P8=NO-GO', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
