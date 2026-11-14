#!/usr/bin/env python3
"""R36.2: htop-like terminal monitor from REAL R36 read-only evidence + DEV A1-A10.

Does not execute commands, contact networks, start VM, enable rules or run pentests.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.coordination.r36_readonly_dashboard import (  # noqa: E402
    DashboardError, load_sources, text_report, run_tui,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--r35-receipts', required=True, type=Path)
    parser.add_argument('--r36-snapshot', required=True, type=Path)
    parser.add_argument('--r361-receipts', required=True, type=Path)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--tui', action='store_true', help='interfaz curses htop-like')
    modes.add_argument('--texto', action='store_true', help='salida textual reproducible')
    modes.add_argument('--json', action='store_true', help='modelo con procedencia')
    args = parser.parse_args()
    try:
        view = load_sources(r35_dir=args.r35_receipts,
                            r36_dir=args.r36_snapshot,
                            r361_dir=args.r361_receipts)
    except (DashboardError, OSError, ValueError, TypeError, KeyError) as exc:
        print('R362_RESULT=BLOCKED_READONLY', file=sys.stderr)
        print('R362_ERROR=' + (str(exc)[:220]), file=sys.stderr)
        return 2
    if args.texto:
        sys.stdout.write(text_report(view))
    elif args.json:
        data = {k: v for k, v in view.items() if k != '_report'}
        sys.stdout.write(json.dumps(data, sort_keys=True, indent=2,
                                    ensure_ascii=True) + '\n')
    else:
        try:
            run_tui(view)
        except (DashboardError, RuntimeError) as exc:
            print('R362_TUI=UNAVAILABLE: ' + str(exc), file=sys.stderr)
            return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
