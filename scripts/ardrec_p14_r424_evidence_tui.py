#!/usr/bin/env python3
"""R42.4: TUI y texto de evidencia física autenticada + A1-A10 de desarrollo."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r424_evidence_tui as r424
from ardrec.coordination.r41_ssh_resume import canon


def main(argv=None)->int:
    p=argparse.ArgumentParser(description='Vista mixta de solo lectura; P8 NO-GO')
    p.add_argument('--r422-result',type=Path,required=True)
    p.add_argument('--r423-result',type=Path,required=True)
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--texto',action='store_true')
    g.add_argument('--json',action='store_true')
    g.add_argument('--tui',action='store_true')
    a=p.parse_args(argv)
    try:
        bundle=r424.build(a.r422_result,a.r423_result,
                          ROOT/'lab/p14-r26-session-v1/scenario.json')
        r424.verify_bundle(bundle)
        if a.texto:
            print('\n'.join(r424.lines(bundle,width=118)))
        elif a.json:
            sys.stdout.buffer.write(canon(bundle)+b'\n')
        else:
            if not (sys.stdin.isatty() and sys.stdout.isatty()):
                raise r424.EvidenceViewError('tui_requires_interactive_terminal')
            r424.run_tui(bundle)
    except (r424.EvidenceViewError, ValueError, OSError) as exc:
        print('R424_STATUS=BLOCKED_READONLY:'+type(exc).__name__+':'+str(exc)[:180],file=sys.stderr)
        print('R424_P8=NO-GO',file=sys.stderr)
        return 2
    return 0

if __name__=='__main__':
    raise SystemExit(main())
