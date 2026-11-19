"""R111-F1: reinterpret an immutable real-host R111 snapshot, not a simulated VM.

Pure code; does not contact libvirt, execute commands or confer host authority.
The original receipt remains an immutable historical record, including the
locale-dependent false warnings that this new analysis explains.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

SCHEMA = 'ardrec-r111-f1-real-host-localized-reconciliation-v1'
VM_ROLES = ('runner', 'ssh', 'ftp', 'smb')
NETWORKS = ('ssh', 'ftp', 'smb')
NET_PREFIX = 'ardrec-r33-dev-net-'
EXPECTED_RUNNER = tuple(NET_PREFIX + x for x in NETWORKS)
MAX_SOURCE_BYTES = 3_000_000


class ReconciliationError(ValueError):
    """Fail closed when a source is missing, inconsistent or overclaims authority."""


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise ReconciliationError(reason)


def canonical(data: Any) -> bytes:
    raw = json.dumps(data, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True, allow_nan=False).encode('ascii') + b'\n'
    need(len(raw) <= MAX_SOURCE_BYTES, 'DATA_TOO_LARGE')
    return raw


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def normalize_state(original: str) -> str:
    """Only exact libvirt shutoff translations count as off.

    All other states remain UNKNOWN. No active/running state is promoted to off.
    """
    if type(original) is not str:
        return 'UNKNOWN'
    return 'SHUTOFF' if original.strip().upper() in (
        'APAGADO', 'SHUT OFF', 'SHUTOFF'
    ) else 'UNKNOWN'


def network_active(raw: str) -> str:
    """Interpret net-info only if the localized field is unambiguous."""
    if type(raw) is not str:
        return 'UNKNOWN'
    found = []
    for line in raw.splitlines():
        if ':' not in line:
            continue
        label, value = (part.strip().lower() for part in line.split(':', 1))
        if label in ('active', 'activo', 'activa'):
            found.append(value)
    if len(found) != 1:
        return 'UNKNOWN'
    if found[0] in ('yes', 'sí', 'si', 'true'):
        return 'YES'
    if found[0] in ('no', 'false'):
        return 'NO'
    return 'UNKNOWN'


def build(record: dict, source_file_sha256: str, legacy_summarize) -> dict:
    """Compute new conclusions from authenticated-by-hash historical bytes.

    A SHA-256 digest establishes byte-integrity relative to the supplied receipt,
    not independent origin, physical containment or approval to change the host.
    """
    need(type(record) is dict and set(record) ==
         {'schema', 'commands', 'probes', 'summary'}, 'RECORD_SCHEMA')
    source_summary = record['summary']
    probes = record['probes']
    need(type(probes) is dict and type(source_summary) is dict,
         'RECORD_TYPES')
    need(source_summary == legacy_summarize(probes),
         'ORIGINAL_SUMMARY_NOT_REPRODUCIBLE')
    need(type(source_file_sha256) is str and len(source_file_sha256) == 64
         and all(c in '0123456789abcdef' for c in source_file_sha256),
         'SOURCE_DIGEST_INVALID')
    need(len(probes) == 29, 'SOURCE_PROBE_COUNT')
    for probe in probes.values():
        need(type(probe) is dict and type(probe.get('rc')) is int
             and probe['rc'] == 0 and probe.get('timeout') is False
             and probe.get('truncated') is False,
             'SOURCE_PROBE_UNAVAILABLE')
    need(source_summary.get('read_only') is True
         and source_summary.get('p8_operational') == 'NO-GO'
         and source_summary.get('physical_admission') == 'DENIED_F11_NOT_CHANGED'
         and source_summary.get('vm_starts') == 0
         and source_summary.get('host_policy_mutations') == 0,
         'SOURCE_FALSE_AUTHORITY')
    states = source_summary.get('domains')
    inventory = source_summary.get('domain_inventory')
    need(type(states) is dict and type(inventory) is dict
         and set(states) == set(inventory) == set(VM_ROLES),
         'DOMAIN_INVENTORY_SCHEMA')
    normalized = {role: normalize_state(states[role]) for role in VM_ROLES}
    original_findings = source_summary.get('readiness_findings')
    need(type(original_findings) is list
         and all(type(x) is str for x in original_findings),
         'FINDINGS_SCHEMA')
    remaining = set(original_findings)
    removed = []
    for role in VM_ROLES:
        flag = 'VM_' + role.upper() + '_NOT_CONFIRMED_SHUTOFF'
        if normalized[role] == 'SHUTOFF' and flag in remaining:
            remaining.remove(flag)
            removed.append(flag)
        need(type(inventory[role]) is dict
             and type(inventory[role].get('interfaces')) is list,
             'DOMAIN_INTERFACE_INVENTORY')
    runner_interfaces = inventory['runner']['interfaces']
    need(all(type(i) is dict and type(i.get('network')) is str
             for i in runner_interfaces), 'RUNNER_INTERFACE_SCHEMA')
    present_runner = tuple(i['network'] for i in runner_interfaces)
    missing_runner = [network for network in EXPECTED_RUNNER
                      if network not in present_runner]
    need(not (missing_runner and 'VM_RUNNER_NIC_TOPOLOGY_INCOMPLETE'
              not in remaining), 'RUNNER_NIC_FINDING_INCONSISTENT')
    active = {role: network_active(probes['net-'+role+'-info']['stdout'])
              for role in NETWORKS}
    report = {
        'schema': SCHEMA,
        'source_kind': 'REAL_HOST_R111_HISTORICAL_READONLY_SNAPSHOT',
        'source_snapshot_sha256': source_file_sha256,
        'source_git_main_sha': source_summary.get('source_main_sha'),
        'source_probe_count': len(probes),
        'source_original_findings': sorted(original_findings),
        'reclassified_locale_findings': sorted(removed),
        'remaining_findings': sorted(remaining),
        'domain_states_normalized': normalized,
        'all_four_domains_shutoff_at_snapshot': all(
            v == 'SHUTOFF' for v in normalized.values()),
        'runner_networks_configured': list(present_runner),
        'runner_networks_missing': missing_runner,
        'network_active_at_snapshot': active,
        'r34_nft_rule_count': source_summary.get('nft_rule_count'),
        'f11_hook_observed_sha256': source_summary.get('hook_sha256'),
        'f11_boot_unit_at_snapshot': source_summary.get('systemd', {}).get('f11-boot-unit'),
        'f11_watchdog_timer_at_snapshot': source_summary.get('systemd', {}).get('f11-watchdog-timer'),
        'snapshot_is_current_host_state': False,
        'isolation_enforcement_independently_proven': False,
        'f11_positive_admission': False,
        'host_mutations': 0,
        'vm_starts': 0,
        'protocol_connections': 0,
        'a6_classification': 'ND',
        'p8_operational': 'NO-GO',
    }
    report['sha256'] = sha(canonical(report))
    return report


def verify_report(report: dict, record: dict, source_sha: str,
                  legacy_summarize) -> bool:
    expected = build(record, source_sha, legacy_summarize)
    need(type(report) is dict and report == expected,
         'RECONCILIATION_NOT_REPRODUCIBLE')
    return True
