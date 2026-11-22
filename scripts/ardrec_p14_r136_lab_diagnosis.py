"""R136: diagnose R135 read-only VM inventory; makes no virsh calls or changes.

This is an interpretation of a captured JSON report, never a physical proof.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

EXPECTED_DOMAINS = {
    'ssh': 'running',
    'ftp': 'running',
    'runner': 'running',
    'smb': 'shut off',
}
EXPECTED_NETWORKS = ('ssh', 'ftp', 'smb')


def diagnose(report: dict) -> dict:
    if type(report) is not dict or report.get('schema') != 'ARDREC-R135-READONLY-PHYSICAL-READINESS-v1':
        raise ValueError('R135_REPORT_SCHEMA_INVALID')
    expected_keys = ('virsh_available', 'domains', 'networks', 'readiness')
    if any(key not in report for key in expected_keys):
        raise ValueError('R135_REPORT_INCOMPLETE')
    findings = []
    if not report['virsh_available']:
        findings.append({'kind': 'tool', 'service': 'virsh', 'status': 'UNAVAILABLE',
                         'expected': 'available', 'observed': 'missing'})
    domains = report['domains']
    networks = report['networks']
    if type(domains) is not dict or type(networks) is not dict:
        raise ValueError('R135_REPORT_TYPE_INVALID')
    for service, expected in EXPECTED_DOMAINS.items():
        value = domains.get(service)
        if not isinstance(value, dict):
            findings.append({'kind': 'domain', 'service': service, 'status': 'NOT_QUERIED',
                             'expected': expected, 'observed': 'ND'})
            continue
        observed = value.get('observed_state', 'ND')
        match = observed == expected or (expected == 'shut off' and observed == 'shutoff')
        if not match or value.get('query_exit_code') != 0:
            findings.append({'kind': 'domain', 'service': service, 'status': 'MISMATCH',
                             'expected': expected, 'observed': str(observed),
                             'query_exit_code': value.get('query_exit_code')})
    for service in EXPECTED_NETWORKS:
        value = networks.get(service)
        if not isinstance(value, dict) or value.get('query_exit_code') != 0:
            findings.append({'kind': 'network', 'service': service, 'status': 'NOT_VERIFIED',
                             'expected': 'virsh net-info exit 0',
                             'observed': 'ND' if not isinstance(value, dict) else str(value.get('query_exit_code'))})
    vm_aligned = all(x['kind'] != 'domain' for x in findings) and bool(report['virsh_available'])
    return {
        'schema': 'ARDREC-R136-READONLY-LAB-DIAGNOSIS-v1',
        'vm_alignment_deduced': vm_aligned,
        'reported_vm_alignment': report.get('vm_pilot_alignment', None),
        'findings': findings,
        'physical_5_1_proved': False,
        'autonomous_deny_restore_proved': False,
        'safe_to_autostart': False,
        'root_install_authorized': False,
        'a6': 'ND', 'p8': 'NO-GO',
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True)
    args = parser.parse_args(argv)
    path = Path(args.report)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        print('STOP: R135_REPORT_PATH_UNSAFE', file=sys.stderr)
        return 23
    try:
        doc = json.loads(path.read_bytes())
        result = diagnose(doc)
    except (OSError, ValueError, UnicodeError) as exc:
        print('STOP: ' + type(exc).__name__ + ':' + str(exc)[:100], file=sys.stderr)
        return 23
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
