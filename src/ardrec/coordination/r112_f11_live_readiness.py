"""R112-F2: evaluate *measured* libvirt/F11 readiness after runner NIC update.

Never equate healthy DENY controls with permission to boot or test services.
Does not mutate host state, authenticate a guest, or accept synthetic results.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import re
from typing import Any

from ardrec.coordination import r112_runner_nic_definition as r112

SCHEMA = 'ardrec-r112-f2-physical-f11-boot-readiness-v1'
MODE = 'REAL_READONLY_F11_RECONCILIATION_DENY_PRESERVED'
ROLES = ('ssh', 'ftp', 'smb')
F11_HOOK = '8bad829fa029d78375f28f6978669721dc934481a97ee867449f45a1662dbc38'
EXTRA_UNITS = (
    'libvirtd.service',
    'ardrec-r34-boot-deny.service',
    'ardrec-r34-deny-watchdog.service',
    'ardrec-r34-deny-watchdog.timer',
)

class ReadinessError(ValueError):
    pass


def need(value: bool, code: str) -> None:
    if not value:
        raise ReadinessError(code)


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii') + b'\n'


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def systemd_properties(content: str) -> dict[str, str]:
    need(type(content) is str and len(content) <= 32768, 'UNIT_TEXT_BOUND')
    out: dict[str, str] = {}
    for line in content.splitlines():
        if not line:
            continue
        need('=' in line, 'UNIT_PROPERTY_FORMAT')
        key, value = line.split('=', 1)
        need(re.fullmatch(r'[A-Za-z][A-Za-z0-9]*', key) is not None
             and key not in out, 'UNIT_PROPERTY_DUPLICATE_OR_INVALID')
        out[key] = value
    return out


def network_active(net_info: str) -> str:
    """Explicitly recognize English and Spanish localization, no guessing."""
    need(type(net_info) is str and 0 < len(net_info) <= 16384, 'NETWORK_INFO_BOUND')
    found: list[bool] = []
    for line in net_info.splitlines():
        if ':' not in line:
            continue
        key, value = (word.strip().casefold() for word in line.split(':', 1))
        if key not in ('active', 'activo', 'activa'):
            continue
        if value in ('yes', 'sí', 'si', 'true'):
            found.append(True)
        elif value in ('no', 'false'):
            found.append(False)
        else:
            return 'UNKNOWN'
    return ('UNKNOWN' if len(found) != 1 else
            'ACTIVE' if found[0] else 'INACTIVE')


def build(snapshot: dict, unit_reports: dict, legacy,
          *, plan_sha256: str, applied_receipt_sha256: str,
          source_head: str) -> dict:
    """Fail closed on changed real topology or security barriers."""
    need(type(plan_sha256) is str and re.fullmatch(r'[a-f0-9]{64}', plan_sha256)
         and type(applied_receipt_sha256) is str
         and re.fullmatch(r'[a-f0-9]{64}', applied_receipt_sha256)
         and type(source_head) is str and re.fullmatch(r'[a-f0-9]{40}', source_head),
         'PROVENANCE_DIGEST_INVALID')
    audited = r112.audit(snapshot, legacy)
    need(audited['runner_nics'] == 3 and audited['all_shutoff'] is True,
         'RUNNER_OR_VM_STATE_DRIFT')
    need(audited['f11_hook_sha256'] == F11_HOOK
         and snapshot['summary']['physical_admission'] == 'DENIED_F11_NOT_CHANGED',
         'HOOK_NOT_DENY_ONLY')
    need(type(unit_reports) is dict and set(unit_reports) == set(EXTRA_UNITS),
         'F11_UNIT_INVENTORY')
    parsed = {}
    for unit in EXTRA_UNITS:
        response = unit_reports[unit]
        need(type(response) is dict and response.get('rc') == 0
             and response.get('timeout') is False
             and response.get('truncated') is False
             and type(response.get('stdout')) is str,
             'UNIT_INSPECTION_FAILED')
        p = systemd_properties(response['stdout'])
        need(p.get('LoadState') == 'loaded', 'UNIT_NOT_LOADED')
        parsed[unit] = p
    need(parsed['libvirtd.service'].get('ActiveState') == 'active'
         and parsed['ardrec-r34-boot-deny.service'].get('ActiveState') == 'active'
         and parsed['ardrec-r34-deny-watchdog.timer'].get('ActiveState') == 'active',
         'F11_SERVICE_OR_TIMER_NOT_ACTIVE')
    # Watchdog *service* may be inactive between timer events. Do not claim
    # continuous enforcement or first-boot attestation from timer presence.
    watchdog_state = parsed['ardrec-r34-deny-watchdog.service'].get('ActiveState')
    need(watchdog_state in ('active', 'inactive', 'failed'),
         'WATCHDOG_SERVICE_STATE_UNKNOWN')
    network_status = {}
    for role in ROLES:
        entry = snapshot['probes']['net-' + role + '-info']
        need(entry['rc'] == 0 and entry['timeout'] is False
             and entry['truncated'] is False, 'NETWORK_INFO_UNAVAILABLE')
        network_status[role] = network_active(entry['stdout'])
    # A network marked ACTIVE would demand investigation; this is not an
    # automatic privilege to test it or a blanket safety failure.
    document = {
        'schema': SCHEMA, 'mode': MODE,
        'source_local_commit': source_head,
        'r112_plan_sha256': plan_sha256,
        'r112_applied_receipt_sha256': applied_receipt_sha256,
        'physical_snapshot_sha256': sha(canonical(snapshot)),
        'systemd_readbacks_sha256': sha(canonical(unit_reports)),
        'runner_inactive_nics': 3,
        'runner_network_ids': ['ardrec-r33-dev-net-' + r for r in ROLES],
        'all_four_vms_shutoff': True,
        'network_states_observed': network_status,
        'f11_root_hook_sha256': audited['f11_hook_sha256'],
        'f11_boot_unit_active': True,
        'f11_timer_active': True,
        'f11_watchdog_service_state': watchdog_state,
        'f11_libvirtd_requires_boot_service':
           'ardrec-r34-boot-deny.service' in parsed['libvirtd.service'].get('Requires', '').split(),
        'f11_libvirtd_after_boot_service':
           'ardrec-r34-boot-deny.service' in parsed['libvirtd.service'].get('After', '').split(),
        'f11_boot_hook_denies_r33': True,
        'f11_first_boot_attested_by_this_report': False,
        'f11_independent_watchdog_attested_by_this_report': False,
        'service_ssh_checked': False, 'service_ftp_checked': False, 'service_smb_checked': False,
        'real_protocol_observations': 0,
        'operational_admission': 'BLOCKED_F11_EXPLICIT_ALLOW_NOT_IMPLEMENTED',
        'required_next_change': 'PINNED_SCOPED_TEMPORARY_BOOT_AND_LINK_POLICY_WITH_ROLLBACK',
        'a5_operational_starts': 0, 'a6_classification': 'ND',
        'a7_confirmed_rf': None, 'a9_published_generations': 0,
        'physical_changes_this_step': 0, 'vm_starts_this_step': 0,
        'operational_dispatch': False, 'p8_operational': 'NO-GO',
    }
    need(len(canonical(document)) <= 32768, 'REPORT_TOO_LARGE')
    document['sha256'] = sha(canonical(document))
    return document


def verify(report: dict, snapshot: dict, units: dict, legacy,
           *, plan_sha256: str, applied_receipt_sha256: str, source_head: str) -> bool:
    need(type(report) is dict and report == build(snapshot, units, legacy,
                plan_sha256=plan_sha256,
                applied_receipt_sha256=applied_receipt_sha256,
                source_head=source_head), 'PHYSICAL_REPLAY_MISMATCH')
    return True
