#!/usr/bin/env python3
"""R58-Z: sesión A10 observable recuperable a partir de R58-Y REAL."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO/'src'))
from ardrec.coordination import r58z_verified_workspace as z
from ardrec.coordination import r58z_r38_dashboard_adapter as r38_view

DEFAULT_DB = Path('/home/cicada/ardrec-lab/r58y/observations.sqlite3')
DEFAULT_OUTPUT = Path('/home/cicada/ardrec-lab/r58z')


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--database', type=Path, default=DEFAULT_DB)
    p.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--snapshot', action='store_true', help='persistir testigo documental inmutable')
    mode.add_argument('--verify', action='store_true', help='reabrir testigo e inspeccionar fuente')
    mode.add_argument('--texto', action='store_true')
    mode.add_argument('--tui', action='store_true')
    mode.add_argument('--json', action='store_true')
    p.add_argument('--service', choices=z.SERVICES, default='SSH')
    p.add_argument('--stage', choices=z.STAGES, default='A10')
    args=p.parse_args(argv)
    try:
        if Path.cwd().resolve() != REPO:
            raise z.WorkspaceError('repo_root_required')
        db=args.database.absolute()
        output=args.output.absolute()
        if db == REPO or output == REPO or REPO in db.parents or REPO in output.parents:
            raise z.WorkspaceError('all_private_material_must_be_outside_repo')
        if args.snapshot or args.verify:
            if args.snapshot and not output.exists():
                output.mkdir(mode=0o700, parents=False)
            doc=z.from_database(db)
            path=output/z._filename(doc)
            if args.snapshot:
                status,path=z.persist_snapshot(output,doc)
            else:
                z.verify_saved_against_sources(path,db)
                status='VERIFIED_REOPENED'
            print(f'R58Z=PASS; SNAPSHOT={status}; OBSERVATIONS={doc["total_observations"]}; '
                  f'A6=ND; A9=NOT_PUBLISHED; P8=NO-GO')
            print('R58Z_DOCUMENTARY_SHA256='+doc['sha256'])
            print('R58Z_PRIVATE_SNAPSHOT='+str(path))
        else:
            doc=z.from_database(db)
            index=z.SERVICES.index(args.service)
            stage=z.STAGES.index(args.stage)
            if args.tui: r38_view.run_tui(doc)
            elif args.json:
                sys.stdout.buffer.write(z.canon(doc)+b'\n')
            else:
                print('\n'.join(z.view_lines(doc,index,stage)))
        return 0
    except (ValueError,OSError,RuntimeError,KeyError,TypeError) as exc:
        print('R58Z=BLOCKED:'+type(exc).__name__+':'+str(exc)[:160],file=sys.stderr)
        print('R58Z_P8=NO-GO',file=sys.stderr)
        return 23


if __name__=='__main__':
    raise SystemExit(main())
