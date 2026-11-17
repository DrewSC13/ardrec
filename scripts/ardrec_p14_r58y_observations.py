#!/usr/bin/env python3
"""R58-Y: importar SSH historico verificado y verlo por servicio, persistente."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO/'src'))
from ardrec.coordination import r58y_observation_register as r58y


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database',type=Path,
        default=Path('/home/cicada/ardrec-lab/r58y/observations.sqlite3'))
    parser.add_argument('--init',action='store_true', help='crea registro vacio, sin observaciones ficticias')
    parser.add_argument('--import-ssh',action='store_true',
        help='verifica dos recibos privados SSH antes de registrar (sin VM)')
    parser.add_argument('--r422-result',type=Path)
    parser.add_argument('--r423-result',type=Path)
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--texto',action='store_true')
    group.add_argument('--json',action='store_true')
    group.add_argument('--tui',action='store_true')
    group.add_argument('--verify',action='store_true')
    args=parser.parse_args(argv)
    if args.init and args.import_ssh:
        parser.error('--init y --import-ssh son acciones diferentes')
    if args.import_ssh != (args.r422_result is not None and args.r423_result is not None):
        parser.error('--import-ssh exige exactamente --r422-result y --r423-result')
    if not (args.init or args.import_ssh or args.texto or args.json or args.tui or args.verify):
        parser.error('elegir --import-ssh, --texto, --json, --tui o --verify')
    try:
        if Path.cwd().resolve()!=REPO:
            raise r58y.ObservationError('repo_root_required')
        db=args.database.absolute()
        if db == REPO or REPO in db.parents:
            raise r58y.ObservationError('private_db_must_be_outside_repo')
        outcome = None
        if args.init:
            r58y.initialize_database(db)
            outcome = 'INITIALIZED_EMPTY_OR_EXISTING'
        if args.import_ssh:
            r422=args.r422_result.absolute()
            r423=args.r423_result.absolute()
            if REPO in r422.parents or REPO in r423.parents:
                raise r58y.ObservationError('private_receipts_must_be_outside_repo')
            outcome,record=r58y.import_ssh(db,r422,r423)
        rows=r58y.load_records(db,revalidate_sources=True)
        if args.tui:
            r58y.run_tui(rows)
        elif args.json:
            print(json.dumps({'schema':r58y.SCHEMA,'import_status':outcome,
                              'records':rows, 'p8_operational':'NO-GO'},
                             sort_keys=True,ensure_ascii=True,indent=2))
        elif args.texto:
            for i in range(3):
                print('\n'.join(r58y.service_rows(rows,r58y.SERVICES[i])))
                print('-'*78)
        else:
            print(f'R58Y=PASS; IMPORT={outcome or "NONE"}; RECORDS={len(rows)}; P8=NO-GO')
        return 0
    except (ValueError,OSError,sqlite3.Error,RuntimeError,KeyError,TypeError) as exc:
        print('R58Y=BLOCKED:'+type(exc).__name__+':'+str(exc)[:180],file=sys.stderr)
        print('R58Y_P8=NO-GO',file=sys.stderr)
        return 23


if __name__=='__main__':
    raise SystemExit(main())
