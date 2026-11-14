#!/usr/bin/env python3
"""Demo de sesión única: A1/A2/A3 del código existente; sin VM, ni TUI viva."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.coordination.demo_session import (build_development_session,
                                               read_fixed_scenario)


def main() -> int:
    parser = argparse.ArgumentParser(description='Sesión sintética A1-A3, NO-GO')
    parser.add_argument('--texto', action='store_true',
                        help='Vista textual; no es una TUI del coordinador.')
    opts = parser.parse_args()
    fixture = ROOT / 'lab' / 'p14-r26-session-v1' / 'scenario.json'
    session = build_development_session(read_fixed_scenario(fixture))
    doc = session.document
    if opts.texto:
        print('ARDREC / SESION SINTETICA A1-A3 / NO-GO OPERACIONAL')
        print('SESION:', doc['session_id'])
        print('SHA256:', session.sha256)
        print('FUENTE:', doc['source_kind'])
        print('GEN_PUBLICADA: NO / DESPACHO: NO / RIESGO_FINAL: ND (A7 pendiente)')
        for u in doc['units']:
            print('{} | {} | A1={} ({}) | A2={} R0={} | A3={}'.format(
                u['protocol'], u['service_id'], u['a1']['status'],
                u['a1']['selected_rule'] or '-', u['a2']['initial_phase'],
                u['a2']['initial_risk'], u['a3']['table_status']))
            for c in u['a3']['controls']:
                print('   {}: {} | {}'.format(c['id'], c['truth'],
                                            ','.join(c['blockers'])))
        print('EVENTOS:', len(doc['events']), 'INTEGROS: SI')
    else:
        sys.stdout.buffer.write(session.json_bytes() + b'\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
