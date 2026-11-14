#!/usr/bin/env python3
"""R27, seleccion A4 + ejecucion de fixture local A5 + soporte documental A6."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.benign_review import analyze_selection, execute_local_review
from ardrec.selection.greedy_development import canon


def main() -> int:
    a=argparse.ArgumentParser()
    mode=a.add_mutually_exclusive_group(required=True)
    mode.add_argument('--preview',action='store_true',help='No lanza procesos')
    mode.add_argument('--run-local-benign',action='store_true',help='Ejecuta solo fixture local ok')
    a.add_argument('--journal-root',type=Path,help='Directorio de recibos, nunca una VM')
    a.add_argument('--texto',action='store_true',help='Resumen legible')
    args=a.parse_args()
    if args.run_local_benign and args.journal_root is None:
        a.error('--run-local-benign requiere --journal-root')
    if args.preview and args.journal_root is not None:
        a.error('--preview no admite --journal-root')
    scenario=read_fixed_scenario(ROOT/'lab/p14-r26-session-v1/scenario.json')
    report=(execute_local_review(scenario,args.journal_root)
            if args.run_local_benign else analyze_selection(scenario))
    if args.texto:
        a4=(report['a4_confirmed'],report['a4_hypothetical'])
        print('ARDREC R27 | A4 SIMULACION | A5 SOLO LOCAL BENIGNO | A6 ND')
        print('A4 ESTADO R26: ',a4[0]['selected'],' / NO HABILITADO')
        print('A4 PROYECCION: ',a4[1]['selected'],' / NO HABILITA DESPACHO')
        if 'a5' in report:
            print('A5: ',report['a5']['state'],' INICIOS RESERVADOS=',report['a5']['start_count_reserved'])
            print('A6: ',report['a6']['classification'],report['a6']['reason'])
        print('P8: NO-GO / VM CHECKS: NO / RIESGO FINAL: ND')
    else:
        sys.stdout.buffer.write(canon(report)+b'\n')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
