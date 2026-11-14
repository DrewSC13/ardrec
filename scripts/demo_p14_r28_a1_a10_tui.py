#!/usr/bin/env python3
"""P14-R28: sesión de desarrollo A1-A10 en terminal. No toca VM."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.development_cycle import build_development_cycle,verify_development_cycle
from ardrec.coordination.terminal_view import render_text,run_tui
from ardrec.analytics.exact_preview import canonical
from ardrec.evidence.defensive_import import (
    read_observation,admit_defensive_observation)


def main() -> int:
    parser=argparse.ArgumentParser()
    m=parser.add_mutually_exclusive_group(required=True)
    m.add_argument('--preview',action='store_true',help='sin proceso local ni escritura')
    m.add_argument('--run-local-benign',action='store_true',help='solo fixture benigno local')
    parser.add_argument('--journal-root',type=Path)
    parser.add_argument('--import-defensive-receipt',type=Path)
    parser.add_argument('--import-defensive-support',type=Path)
    parser.add_argument('--as-of-utc',type=str)
    v=parser.add_mutually_exclusive_group(required=True)
    v.add_argument('--texto',action='store_true')
    v.add_argument('--json',action='store_true')
    v.add_argument('--tui',action='store_true')
    opts=parser.parse_args()
    if opts.run_local_benign and opts.journal_root is None:
        parser.error('--run-local-benign exige --journal-root')
    if opts.preview and opts.journal_root is not None:
        parser.error('--preview no permite --journal-root')
    if any(x is not None for x in (opts.import_defensive_receipt,
                                   opts.import_defensive_support,opts.as_of_utc)):
        if not all(x is not None for x in (opts.import_defensive_receipt,
                                      opts.import_defensive_support,opts.as_of_utc)):
            parser.error('la observacion exige recibo, soporte y --as-of-utc')
        imported,raw=read_observation(opts.import_defensive_receipt)
        admission=admit_defensive_observation(
            imported,raw,opts.import_defensive_support,as_of_utc=opts.as_of_utc)
    else:
        admission=None
    fixture=read_fixed_scenario(ROOT/'lab/p14-r26-session-v1/scenario.json')
    report=build_development_cycle(fixture,journal_root=opts.journal_root,
                                    run_local_benign=opts.run_local_benign,
                                    defensive_observation=admission)
    verify_development_cycle(report)
    if opts.texto:
        sys.stdout.write(render_text(report))
    elif opts.json:
        sys.stdout.buffer.write(canonical(report)+b'\n')
    else:
        run_tui(report)
    return 0

if __name__=='__main__':
    raise SystemExit(main())
