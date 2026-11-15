#!/usr/bin/env python3
"""R42.5: misma entrada R42.4, pero con el monitor original R38 enriquecido."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r424_evidence_tui as r424
from ardrec.coordination import r425_classic_evidence_dashboard as r425
from ardrec.coordination import r43_local_cycle as r43
from ardrec.coordination.r41_ssh_resume import canon


def main(argv=None)->int:
    parser=argparse.ArgumentParser(description='Monitor clasico R38 con SSH fisico; P8 NO-GO')
    parser.add_argument('--r422-result',type=Path,required=True)
    parser.add_argument('--r423-result',type=Path,required=True)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--texto',action='store_true',help='fotograma R38 reproducible')
    group.add_argument('--json',action='store_true',help='bundle R42.4 original intacto')
    group.add_argument('--tui',action='store_true',help='monitor R38 de tres paneles')
    parser.add_argument('--run-local-benign',action='store_true',
                        help='inicia fixture local acotado; NO una prueba de VM')
    parser.add_argument('--journal-root',type=Path,
                        help='directorio privado R43 en la misma base que R42.2/R42.3')
    parser.add_argument('--i-authorize-r43-local-benign',action='store_true',
                        help='autorizacion explicita e independiente para ejecutar fixture local')
    args=parser.parse_args(argv)
    if args.run_local_benign != args.i_authorize_r43_local_benign:
        parser.error('--run-local-benign requiere autorizacion expresa y viceversa')
    if args.run_local_benign != (args.journal_root is not None):
        parser.error('--journal-root se exige SOLO junto a --run-local-benign')
    try:
        fixture=ROOT/'lab/p14-r26-session-v1/scenario.json'
        if args.run_local_benign:
            report,bundle=r43.execute_local_cycle(
                args.r422_result,args.r423_result,fixture,args.journal_root)
        else:
            bundle=r424.build(args.r422_result,args.r423_result,fixture)
            report=r425.development_from_bundle(bundle,fixture)
        r424.verify_bundle(bundle)
        r425.validate_binding(report,bundle)
        if args.json:
            sys.stdout.buffer.write(canon(bundle)+b'\n')
        elif args.texto:
            print('\n'.join(r425.render_frame(report,bundle,width=120,height=32)))
        else:
            r425.run_tui(report,bundle)
    except (ValueError, OSError, RuntimeError) as exc:
        print('R43_STATUS=BLOCKED_DEVELOPMENT:'+type(exc).__name__+':'+str(exc)[:180],file=sys.stderr)
        print('R43_P8=NO-GO',file=sys.stderr)
        return 2
    return 0

if __name__=='__main__':
    raise SystemExit(main())
