#!/usr/bin/env python3
"""R88: entrypoint de terminal, no nueva TUI ni ejecutor paralelo."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.r88_vertical import rust_deny_probe, run_vertical_once, verify_vertical


def main() -> int:
    ap = argparse.ArgumentParser(description='ARDREC R88 DEV original modules single vertical')
    cmd = ap.add_mutually_exclusive_group(required=True)
    cmd.add_argument('--run-one-local-benign', action='store_true')
    cmd.add_argument('--verify-only', action='store_true')
    cmd.add_argument('--verify-rust-only', action='store_true')
    ap.add_argument('--durable-root', type=Path)
    ap.add_argument('--benign-root', type=Path)
    ap.add_argument('--scenario', type=Path, default=ROOT/'lab/p14-r26-session-v1/scenario.json')
    ap.add_argument('--rust-probe', type=Path, required=True)
    ap.add_argument('--rust-sha256', required=True)
    ap.add_argument('--diagnostic-fixture', type=Path,
                    default=ROOT/'tests/fixtures/p8-diagnostic-v1.json')
    ap.add_argument('--expected-cycle-sha256')
    args = ap.parse_args()
    try:
        if args.verify_rust_only:
            result = rust_deny_probe(args.rust_probe, args.rust_sha256,
                                     args.diagnostic_fixture)
        else:
            if args.durable_root is None or args.benign_root is None:
                ap.error('run/verify require both absolute private roots')
            scenario = read_fixed_scenario(args.scenario)
            if args.run_one_local_benign:
                result = run_vertical_once(args.durable_root, args.benign_root,
                      scenario, args.rust_probe, args.rust_sha256, args.diagnostic_fixture)
            else:
                result = verify_vertical(args.durable_root, args.benign_root,
                      scenario, args.rust_probe, args.rust_sha256, args.diagnostic_fixture,
                      expected_sha256=args.expected_cycle_sha256)
        print(json.dumps(result, sort_keys=True, ensure_ascii=False))
        return 0
    except (ValueError, TypeError, RuntimeError, KeyError, OSError, TimeoutError) as exc:
        print('R88_STOP=' + type(exc).__name__ + ':' + str(exc)[:160], file=sys.stderr)
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
