"""ARDREC R135/B: independent, read-only inventory of physical lab prerequisites.

No root, VM boot, network rules, signals, firewall, or time changes. A fully
matching virsh inventory never proves the 5/1 DENY topology or crash restore.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

DOMAINS = {
    'ssh': 'ardrec-r33-dev-ssh',
    'ftp': 'ardrec-r33-dev-ftp',
    'smb': 'ardrec-r33-dev-smb',
    'runner': 'ardrec-r33-dev-runner',
}
NETWORKS = {
    'ssh': 'ardrec-r33-dev-net-ssh',
    'ftp': 'ardrec-r33-dev-net-ftp',
    'smb': 'ardrec-r33-dev-net-smb',
}
BRIDGES = {'ssh': 'br33d30', 'ftp': 'br33d31', 'smb': 'br33d32'}


def probe(argv: list[str]) -> dict:
    """Read-only fixed-command capture; errors remain ND, never PASS."""
    try:
        r = subprocess.run(argv, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=8, check=False,
                           env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        return {'exit_code': r.returncode,
                'stdout': r.stdout.decode('utf-8', errors='replace')[:3000],
                'stderr': r.stderr.decode('utf-8', errors='replace')[:800]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'exit_code': None, 'stdout': '',
                'stderr': type(exc).__name__}


def collect(run=probe) -> dict:
    results = {
        'schema': 'ARDREC-R135-READONLY-PHYSICAL-READINESS-v1',
        'virsh_available': bool(shutil.which('virsh')),
        'domains': {}, 'networks': {},
        'bridges': dict(BRIDGES),
        'physical_5_1_proved': False,
        'autonomous_deny_restore_proved': False,
        'root_install_accredited': False,
        'network_enable_performed': False,
        'physical_pilot_executed': False,
        'a6': 'ND', 'p8': 'NO-GO',
        'readiness': 'NOT_ACCREDITED',
    }
    if not results['virsh_available']:
        results['blocker'] = 'VIRSH_UNAVAILABLE'
        return results
    exe = shutil.which('virsh')
    for service, domain in DOMAINS.items():
        response = run([exe, '--connect', 'qemu:///system', 'domstate', domain])
        state = response['stdout'].strip().lower() if response['exit_code'] == 0 else 'ND'
        expected_up = service in {'ssh', 'ftp', 'runner'}
        matches = (state == 'running' if expected_up else state in {'shut off', 'shutoff'})
        results['domains'][service] = {
            'name': domain, 'observed_state': state, 'pilot_expected_running': expected_up,
            'matches_pilot': matches, 'query_exit_code': response['exit_code']}
    for service, network in NETWORKS.items():
        response = run([exe, '--connect', 'qemu:///system', 'net-info', network])
        results['networks'][service] = {
            'name': network, 'query_exit_code': response['exit_code'],
            'query_succeeded': response['exit_code'] == 0}
    results['vm_pilot_alignment'] = all(
        d['matches_pilot'] for d in results['domains'].values())
    results['network_inventory_queried'] = all(
        item['query_succeeded'] for item in results['networks'].values())
    results['blocker'] = '5_1_DENY_AND_AUTONOMOUS_RESTORE_NOT_MEASURED'
    return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', action='store_true', required=True)
    args = parser.parse_args(argv)
    if os.geteuid() == 0:
        print('REFUSED: root invocation not required', file=sys.stderr)
        return 23
    report = collect()
    print(json.dumps(report, sort_keys=True, ensure_ascii=True, separators=(',', ':')))
    # ND is a truthful diagnostic, not a command failure.
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
