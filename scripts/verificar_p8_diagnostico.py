"""P8-R7: cross-language comparison of 106+ untrusted synthetic JSON fixtures.

The only child process is the compiled Rust *diagnostic probe*, never a tool,
operational executor, network client or VM. No per-case execution permission.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.p8_diagnostic import evaluate_bytes, KNOWN_PROFILES


def verify(probe: Path | None):
    fixture = json.loads((ROOT / 'tests/fixtures/p8-diagnostic-v1.json').read_text())
    if fixture['schema_version'] != '1.0' or fixture['contract'] != 'P8-R7':
        raise RuntimeError('fixture schema changed')
    if len(KNOWN_PROFILES) != 29 or len(fixture['cases']) < 100:
        raise RuntimeError('profile inventory or fixture coverage changed')
    for entry in fixture['cases']:
        name = entry['name']
        raw = entry['payload'].encode('utf-8')
        expected = evaluate_bytes(raw)
        if expected['reason_code'] != entry['reason_code'] or expected['authorized'] or expected['dispatch_allowed']:
            raise RuntimeError('Python fixture failure: ' + name)
        if probe is not None:
            child = subprocess.run([str(probe)], input=raw, capture_output=True, timeout=4, check=False)
            if child.returncode != 0 or len(child.stdout) > 1024 or child.stderr:
                raise RuntimeError('Rust probe failed: ' + name)
            actual = json.loads(child.stdout)
            if actual != expected:
                raise RuntimeError(f'DIVERGENCE {name}: Python={expected}, Rust={actual}')
    return {'fixtures': len(fixture['cases']), 'profiles': len(KNOWN_PROFILES),
            'cross_language': probe is not None, 'dispatch_allowed': False,
            'status': 'PASS_P8_R7_SYNTHETIC_DIFFERENTIAL_DENY_ALL'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--probe', type=Path)
    parser.add_argument('--python-only', action='store_true')
    args = parser.parse_args()
    if args.probe is None and not args.python_only:
        raise RuntimeError('explicit --probe path or --python-only is required')
    if args.probe is not None and args.python_only:
        raise RuntimeError('choose one verification mode')
    if args.probe is not None and (not args.probe.is_file() or args.probe.is_symlink()):
        raise RuntimeError('probe is not a regular file')
    print(json.dumps(verify(args.probe), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
        print('ARDREC_P8_R7=FAIL_CLOSED: ' + str(error), file=sys.stderr)
        raise SystemExit(2)
