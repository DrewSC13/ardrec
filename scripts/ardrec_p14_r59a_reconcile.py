#!/usr/bin/env python3
"""R59-A: auditar fuentes verificadas SSH R58-Y y diario benigno P9/P12."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.coordination import r59a_a5_a6_provenance as a

DEFAULT_DB = Path('/home/cicada/ardrec-lab/r58y/observations.sqlite3')
DEFAULT_OUTPUT = Path('/home/cicada/ardrec-lab/r59a')


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--database', type=Path, default=DEFAULT_DB)
    p.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    p.add_argument('--journal-root', type=Path, help='P9/P12 BENIGNO preexistente, solo lectura')
    p.add_argument('--request-id', help='solicitud previa en el diario benigno')
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--texto', action='store_true')
    g.add_argument('--json', action='store_true')
    g.add_argument('--snapshot', action='store_true')
    g.add_argument('--verify', action='store_true')
    args = p.parse_args(argv)
    try:
        if Path.cwd().resolve() != ROOT:
            raise a.ReconciliationError('REPO_ROOT_REQUIRED')
        db, out = args.database.absolute(), args.output.absolute()
        journal = args.journal_root.absolute() if args.journal_root else None
        for v in (db, out, journal):
            if v is not None and (v == ROOT or ROOT in v.parents):
                raise a.ReconciliationError('PRIVATE_MATERIAL_MUST_BE_OUTSIDE_GIT')
        if (journal is None) != (args.request_id is None):
            raise a.ReconciliationError('P9_ROOT_AND_ID_REQUIRED_TOGETHER')
        doc = a.build_report(db, journal_root=journal, request_id=args.request_id)
        if args.snapshot or args.verify:
            if args.snapshot and not out.exists():
                out.mkdir(mode=0o700, parents=False)
            path = out / ('r59a-a5-a6-' + doc['sha256'] + '.json')
            if args.snapshot:
                state, path = a.save_report(out, doc)
            else:
                a.verify_saved(path,db,journal_root=journal,request_id=args.request_id)
                state='VERIFIED_REOPENED'
            print(f'R59A=PASS; REPORT={state}; OBSERVATIONS={len(doc["r58y_record_ids"])}; '
                  'A5_REAL=0; A6=ND; P8=NO-GO')
            print('R59A_REPORT_SHA256='+doc['sha256'])
            print('R59A_PRIVATE_REPORT='+str(path))
        elif args.json:
            sys.stdout.buffer.write(a.canonical(doc)+b'\n')
        else:
            print(a.format_text(doc))
        return 0
    except (ValueError,OSError,RuntimeError,TypeError,KeyError) as exc:
        print('R59A=BLOCKED:'+type(exc).__name__+':'+str(exc)[:190],file=sys.stderr)
        print('R59A_P8=NO-GO; A6=ND; NO_DISPATCH',file=sys.stderr)
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
