"""P14-R41.1: read-only reconciliation of an SSH VM started outside R41.

No guest command, storage read of live SSH QCOW2, packet test, or host mutation.
A host-state observation is not a proof of cause, containment or guest truth.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ardrec.coordination import r41_ssh_resume as r41
from ardrec.coordination import r365_first_boot as r365
from ardrec.coordination import r35_inactive_deployment as r35

SCHEMA = 'ardrec-p14-r411-ssh-external-start-observation-v1'
STATUS = 'EXTERNAL_SSH_RUNNING_OBSERVED_NO_GO'
FILES = frozenset({'r41_preflight.json'})
OUTPUT_NAME = 'r411_external_start.json'


class R411Error(ValueError):
    """Fail-closed observation/receipt error."""


def need(condition: bool, code: str) -> None:
    if not condition:
        raise R411Error(code)


def load_history(r41_dir: Path, r40_dir: Path, r39_dir: Path,
                 r365_preflight_dir: Path, r365_boot_dir: Path) -> dict[str, Any]:
    """Authenticate R41 preflight as history, never as a live start grant."""
    source = r41._verify_r40_source(r40_dir, r39_dir, r365_preflight_dir, r365_boot_dir)
    docs = r41.verified_directory(r41_dir, FILES)
    raw = docs['r41_preflight.json']
    report = r365.read_json(raw)
    r41.verify_report(report)
    need(report.get('mode') == 'PREFLIGHT_ONLY' and
         report.get('status') == r41.PREFLIGHT_STATUS and
         report.get('source_r40_report_sha256') == source['r40_report_sha256'] and
         report.get('source_r40_file_sha256') == source['r40_file_sha256'] and
         report.get('source_r39_report_sha256') == source['r39_report_sha256'] and
         report.get('source_r365_first_boot_report_sha256') == source['r365_first_boot_report_sha256'] and
         report.get('storage') == source['r40_storage'] and
         report.get('host_state_before') == source['r40_host_readback'] and
         report.get('vm_started_by_r41') is False and
         report.get('attempted_mutations') == [] and
         report.get('host_mutations') == [] and
         report.get('p8_operational') == 'NO-GO',
         'r41_history_source_mismatch')
    return {'source_r41_preflight_sha256': report['sha256'],
            'source_r41_preflight_file_sha256': r41.sha(raw),
            'source_r41_preflight_captured_at_utc': report['captured_at_utc'],
            'source_r40_report_sha256': source['r40_report_sha256'],
            'source_r39_report_sha256': source['r39_report_sha256'],
            'source_r365_first_boot_report_sha256': source['r365_first_boot_report_sha256'],
            'source_archive_sha256': r35.ARCHIVE_SHA256}


def _validate_running(live: dict[str, Any]) -> None:
    need(type(live) is dict and live.get('phase') == 'SSH_RUNNING' and
         live.get('active_networks') == [r365.SSH_NETWORK] and
         live.get('active_domains') == [r365.SSH_DOMAIN] and
         live.get('reserved_links') == sorted([r365.t33.NET_BRIDGE['ssh'], 'a33d30t']) and
         live.get('bridge_macs') == r35.R354_EXISTING_BRIDGE_MACS and
         live.get('deny_first_still_verified') is True,
         'ssh_running_host_scope_invalid')


def readback(host: r41.ReadOnlyHost | None = None) -> dict[str, Any]:
    """Check physical-only infrastructure; no SSH traffic or guest execution."""
    h = host if host is not None else r41.ReadOnlyHost()
    live = r365.current(h, phase='SSH_RUNNING')
    _validate_running(live)
    return live


def make_report(source: dict[str, Any], before: dict[str, Any],
                after: dict[str, Any], *, captured_at_utc: str,
                operator_acknowledged: bool) -> dict[str, Any]:
    need(operator_acknowledged is True, 'external_start_acknowledgment_required')
    need(type(source) is dict and all(r41.r40.valid_hex(source.get(k)) for k in (
        'source_r41_preflight_sha256', 'source_r41_preflight_file_sha256',
        'source_r40_report_sha256', 'source_r39_report_sha256',
        'source_r365_first_boot_report_sha256', 'source_archive_sha256')) and
        source['source_r40_report_sha256'] == r41.R40_PIN and
        source['source_archive_sha256'] == r35.ARCHIVE_SHA256,
        'source_summary_invalid')
    observed_at = r41.parse_utc(captured_at_utc)
    historical_at = r41.parse_utc(source.get('source_r41_preflight_captured_at_utc'))
    need(historical_at <= observed_at and
         (observed_at - datetime.now(timezone.utc)).total_seconds() <= 5,
         'history_after_observation_or_future')
    _validate_running(before)
    _validate_running(after)
    need(before == after, 'readback_changed_during_observation')
    doc = {'schema': SCHEMA, 'mode': 'READONLY_EXTERNAL_START_OBSERVATION',
           'status': STATUS, 'captured_at_utc': captured_at_utc,
           'source_r41_preflight_sha256': source['source_r41_preflight_sha256'],
           'source_r41_preflight_file_sha256': source['source_r41_preflight_file_sha256'],
           'source_r41_preflight_captured_at_utc': source['source_r41_preflight_captured_at_utc'],
           'source_r40_report_sha256': source['source_r40_report_sha256'],
           'source_r39_report_sha256': source['source_r39_report_sha256'],
           'source_r365_first_boot_report_sha256': source['source_r365_first_boot_report_sha256'],
           'source_archive_sha256': source['source_archive_sha256'],
           'host_readback_before': before, 'host_readback_after': after,
           'external_start_operator_acknowledged': True,
           'start_origin_independently_attested': False,
           'start_command_attributed_to_r41_executor': False,
           'r41_preflight_grants_new_permission': False,
           'active_ssh_runtime_disk_inspected': False,
           'storage_integrity_attested_while_running': False,
           'deny_policy_presence_checked': True,
           'guest_isolation_tested': False,
           'guest_identity_attested': False,
           'real_service_testing': 'NOT_EXECUTED',
           'technical_truth_accredited': False,
           'network_started_by_r411': False, 'vm_started_by_r411': False,
           'host_mutations_by_r411': [], 'automatic_rollback': False,
           'operational_dispatch': False,
           'published_generation': None, 'final_risk': None,
           'experimental_validation': 'NOT_RUN', 'p8_operational': 'NO-GO',
           'next_gate': 'SEPARATE_BOUNDED_ISOLATION_TEST_WITH_EXPLICIT_AUTHORIZATION'}
    doc['sha256'] = r41.sha(r41.canon(doc))
    verify_report(doc)
    return doc


def verify_report(doc: dict[str, Any]) -> bool:
    need(type(doc) is dict and r41.r40.valid_hex(doc.get('sha256')) and
         doc['sha256'] == r41.sha(r41.canon({k: v for k, v in doc.items() if k != 'sha256'})),
         'r411_digest_invalid')
    need(doc.get('schema') == SCHEMA and
         doc.get('mode') == 'READONLY_EXTERNAL_START_OBSERVATION' and
         doc.get('status') == STATUS and
         all(r41.r40.valid_hex(doc.get(k)) for k in (
             'source_r41_preflight_sha256', 'source_r41_preflight_file_sha256',
             'source_r40_report_sha256', 'source_r39_report_sha256',
             'source_r365_first_boot_report_sha256', 'source_archive_sha256')) and
         doc.get('source_r40_report_sha256') == r41.R40_PIN and
         doc.get('source_archive_sha256') == r35.ARCHIVE_SHA256 and
         doc.get('external_start_operator_acknowledged') is True and
         doc.get('start_origin_independently_attested') is False and
         doc.get('start_command_attributed_to_r41_executor') is False and
         doc.get('r41_preflight_grants_new_permission') is False and
         doc.get('active_ssh_runtime_disk_inspected') is False and
         doc.get('storage_integrity_attested_while_running') is False and
         doc.get('deny_policy_presence_checked') is True and
         doc.get('guest_isolation_tested') is False and
         doc.get('guest_identity_attested') is False and
         doc.get('real_service_testing') == 'NOT_EXECUTED' and
         doc.get('technical_truth_accredited') is False and
         doc.get('network_started_by_r411') is False and
         doc.get('vm_started_by_r411') is False and
         doc.get('host_mutations_by_r411') == [] and
         doc.get('automatic_rollback') is False and
         doc.get('operational_dispatch') is False and
         doc.get('published_generation') is None and
         doc.get('final_risk') is None and
         doc.get('experimental_validation') == 'NOT_RUN' and
         doc.get('p8_operational') == 'NO-GO' and
         doc.get('next_gate') == 'SEPARATE_BOUNDED_ISOLATION_TEST_WITH_EXPLICIT_AUTHORIZATION',
         'r411_false_authority_claim')
    historical_at = r41.parse_utc(doc.get('source_r41_preflight_captured_at_utc'))
    observed_at = r41.parse_utc(doc.get('captured_at_utc'))
    need(historical_at <= observed_at, 'preflight_not_before_observation')
    before, after = doc.get('host_readback_before'), doc.get('host_readback_after')
    _validate_running(before)
    _validate_running(after)
    need(before == after, 'r411_readback_drift')
    return True


def observe(*, r41_preflight_dir: Path, r40_dir: Path, r39_dir: Path,
            r365_preflight_dir: Path, r365_boot_dir: Path, receipt_dir: Path,
            operator_acknowledged: bool = False,
            host: r41.ReadOnlyHost | None = None) -> dict[str, Any]:
    need(operator_acknowledged is True, 'external_start_acknowledgment_required')
    source = load_history(r41_preflight_dir, r40_dir, r39_dir,
                          r365_preflight_dir, r365_boot_dir)
    h = host if host is not None else r41.ReadOnlyHost()
    before = readback(h)
    after = readback(h)
    doc = make_report(source, before, after,
                      captured_at_utc=r41.now_utc(),
                      operator_acknowledged=operator_acknowledged)
    r41._make_dir(receipt_dir)
    # The R41 seal verifier deliberately only accepts the R41 schema.
    # R41.1 owns its receipt and validates it against its own fixed contract.
    verify_report(doc)
    body = r41.canon(doc) + b'\n'
    sums = (r41.sha(body) + '  ' + OUTPUT_NAME + '\n').encode('ascii')
    r41._write_once(receipt_dir / OUTPUT_NAME, body)
    r41._write_once(receipt_dir / 'SHA256SUMS', sums)
    return doc
