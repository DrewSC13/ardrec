"""Entrada normal ARDREC; R69 habilita solo la sesión DEV durable explícita."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ardrec.coordination.demo_session import SessionError, read_fixed_scenario
from ardrec.coordination.durable_dev import DurableDevError, open_or_create_dev, render_dev_text, run_dev_tui
from ardrec.persistence.codec import StorageError, canonical
from ardrec.rules.kernel import A1Error


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description='ARDREC / sesion DEV durable R69')
    ap.add_argument('--durable-dev-root', type=Path, required=True,
                    help='directorio privado absoluto para sesion sintética')
    ap.add_argument('--scenario', type=Path, default=Path('lab/p14-r26-session-v1/scenario.json'))
    ap.add_argument('--expected-config-sha256')
    ap.add_argument('--expected-head-sha256')
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--texto', action='store_true')
    mode.add_argument('--json', action='store_true')
    mode.add_argument('--tui', action='store_true')
    args = ap.parse_args(argv)
    try:
        fixture = read_fixed_scenario(args.scenario)
        doc = open_or_create_dev(args.durable_dev_root, fixture,
                                 expected_config_sha256=args.expected_config_sha256,
                                 expected_head_sha256=args.expected_head_sha256)
    except (DurableDevError, SessionError, StorageError, A1Error) as exc:
        print('R69_FAIL=' + getattr(exc, 'code', str(exc)), file=sys.stderr)
        return 2
    if args.json:
        sys.stdout.buffer.write(canonical(doc) + b'\n')
    elif args.tui:
        from ardrec.coordination.durable_dashboard_bridge import build_durable_dashboard
        from ardrec.coordination.dashboard_tui import run_dashboard_tui
        run_dashboard_tui(build_durable_dashboard(doc, fixture))
    else:
        sys.stdout.write(render_dev_text(doc))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
