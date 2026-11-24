"""Entrada normal ARDREC; R69 habilita solo la sesión DEV durable explícita."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ardrec.coordination.demo_session import SessionError, read_fixed_scenario
from ardrec.coordination.durable_dev import DurableDevError, open_or_create_dev, render_dev_text, run_dev_tui
from ardrec.persistence.codec import StorageError, canonical
from ardrec.rules.kernel import A1Error
from ardrec.benign_pipeline import VerificationError, GateError


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] == 'familias':
        from ardrec.coordination.family_cli import main as family_main
        return family_main(argv[1:])
    if argv and argv[0] == 'caso':
        from ardrec.coordination.r166_case_archive_cli import main as case_main
        return case_main(argv[1:])
    if argv and argv[0] == 'live':
        from ardrec.coordination.r119_live_inspection import main as live_main
        return live_main(argv[1:])
    ap = argparse.ArgumentParser(description='ARDREC / sesion DEV durable R69')
    ap.add_argument('--durable-dev-root', type=Path, required=True,
                    help='directorio privado absoluto para sesion sintética')
    ap.add_argument('--scenario', type=Path, default=Path('lab/p14-r26-session-v1/scenario.json'))
    ap.add_argument('--shadow-cycle', action='store_true',
                    help='R71: proyeccion A4 y proceso local benigno, Rf confirmado ND')
    ap.add_argument('--shadow-journal-root', type=Path,
                    help='directorio independiente para el fixture benigno local')
    ap.add_argument('--safe-cycle', action='store_true',
                    help='R70: parada sintética DEV y generación analítica estructural 1')
    ap.add_argument('--expected-config-sha256')
    ap.add_argument('--expected-head-sha256')
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--texto', action='store_true')
    mode.add_argument('--json', action='store_true')
    mode.add_argument('--tui', action='store_true')
    args = ap.parse_args(argv)
    if args.shadow_cycle and (args.safe_cycle or args.shadow_journal_root is None):
        ap.error('--shadow-cycle requiere --shadow-journal-root y excluye --safe-cycle')
    if args.shadow_journal_root is not None and not args.shadow_cycle:
        ap.error('--shadow-journal-root solo admite --shadow-cycle')
    try:
        fixture = read_fixed_scenario(args.scenario)
        from ardrec.coordination.safe_generation import open_or_publish_safe
        archive_exists = (args.durable_dev_root / 'analytical-archive').exists()
        if args.safe_cycle and not archive_exists:
            open_or_create_dev(args.durable_dev_root, fixture,
                               expected_config_sha256=args.expected_config_sha256,
                               expected_head_sha256=args.expected_head_sha256)
        if args.shadow_cycle:
            from ardrec.coordination.shadow_cycle import run_shadow_cycle
            doc = run_shadow_cycle(args.durable_dev_root, args.shadow_journal_root,
                                   fixture, expected_head_sha256=args.expected_head_sha256)
        elif args.safe_cycle or archive_exists:
            doc = open_or_publish_safe(args.durable_dev_root, fixture,
                      publish=args.safe_cycle,
                      expected_config_sha256=args.expected_config_sha256,
                      expected_head_sha256=args.expected_head_sha256)
        else:
            doc = open_or_create_dev(args.durable_dev_root, fixture,
                      expected_config_sha256=args.expected_config_sha256,
                      expected_head_sha256=args.expected_head_sha256)
    except (DurableDevError, SessionError, StorageError, A1Error, VerificationError, GateError, ValueError, OSError, KeyError) as exc:
        print('R69_FAIL=' + getattr(exc, 'code', str(exc)), file=sys.stderr)
        return 2
    if args.json:
        sys.stdout.buffer.write(canonical(doc) + b'\n')
    elif args.tui:
        from ardrec.coordination.dashboard_tui import run_dashboard_tui
        if args.shadow_cycle:
            from ardrec.coordination.shadow_dashboard_bridge import build_shadow_dashboard
            from ardrec.coordination.safe_generation import open_or_publish_safe
            base = open_or_publish_safe(args.durable_dev_root, fixture)
            run_dashboard_tui(build_shadow_dashboard(doc, fixture, base))
        elif doc['generation'] == 1:
            from ardrec.coordination.safe_dashboard_bridge import build_safe_dashboard
            run_dashboard_tui(build_safe_dashboard(doc, fixture))
        else:
            from ardrec.coordination.durable_dashboard_bridge import build_durable_dashboard
            run_dashboard_tui(build_durable_dashboard(doc, fixture))
    else:
        if args.shadow_cycle:
            from ardrec.coordination.shadow_cycle import render_shadow_text
            sys.stdout.write(render_shadow_text(doc))
        elif doc['generation'] == 1:
            sys.stdout.write('ARDREC R70 / GEN 1 ANALITICA DEV ESTRUCTURAL\n'
                 'A3 SIN DESPACHO | A4 SIN ELEGIBLES | A5 0 INTENTOS\n'
                 'A6/A7 ND | A8 DETENER DEV | P8 NO-GO\n'
                 f"SNAPSHOT={doc['analytical_snapshot_sha256']}\n"
                 f"HEAD={doc['head_sha256']}\n")
        else:
            sys.stdout.write(render_dev_text(doc))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
