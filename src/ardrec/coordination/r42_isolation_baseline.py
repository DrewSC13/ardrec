"""P14-R42.0: read-only SSH isolation-counter baseline.

This is NOT a test of packet isolation. It never sends packets, executes guest
commands, or modifies nftables/libvirt. A later explicitly authorized probe
must bind exact counter handles and prove packet provenance and negative paths.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from ardrec.coordination import r35_inactive_deployment as r35
from ardrec.coordination import r365_first_boot as r365
from ardrec.coordination import r411_external_ssh_observation as r411
from ardrec.coordination import r41_ssh_resume as r41
from ardrec.coordination.r36_readonly_dashboard import verified_directory

SCHEMA = 'ardrec-p14-r42-ssh-isolation-baseline-v1'
STATUS = 'SSH_DENY_COUNTER_BASELINE_ONLY_NO_GO'
R411_REPORT_PIN = '3b08bd0b91b2041a8517a1739efd21285d42e6c17f117e6a3ef9d76c65a1571b'
MAIN_PIN = '54cadf66163111842ad48a3fa13b548d18febcc5'
R411_FILES = frozenset({'r411_external_start.json'})
EXPECTED_RULES = ('input:iifname','output:oifname','forward:iifname','forward:oifname')
OUTPUT = 'r42_counter_baseline.json'

class R42Error(ValueError):
    """Fail-closed physical readback error."""


def need(condition: bool, code: str) -> None:
    if not condition:
        raise R42Error(code)


class ReadOnlyHost(r41.ReadOnlyHost):
    """Fixed readback commands; explicitly reject all inherited mutators."""
    def sudo(self, args: list[str], *, input_bytes: bytes | None = None,
             timeout: int = 30) -> bytes:
        need(input_bytes is None and args == [self.bin['nft'], '-j', '-a', 'list',
                'table', 'bridge', r35.NFT_TABLE], 'r42_sudo_write_forbidden')
        return super().sudo(args, timeout=timeout)

    def activate_ssh_network(self) -> None:
        raise R42Error('r42_activation_forbidden')

    def activate_ssh_domain(self) -> None:
        raise R42Error('r42_activation_forbidden')

    def virsh_write(self, args: list[str]) -> bytes:
        raise R42Error('r42_virsh_write_forbidden')


def load_source(r411_dir: Path, r41_dir: Path, r40_dir: Path, r39_dir: Path,
                r365_preflight_dir: Path, r365_boot_dir: Path) -> dict[str, str]:
    """Authenticate the unique observed physical receipt and its full chain."""
    docs = verified_directory(r411_dir, R411_FILES)
    raw = docs['r411_external_start.json']
    report = r365.read_json(raw)
    r411.verify_report(report)
    need(report['sha256'] == R411_REPORT_PIN, 'r411_report_pin_mismatch')
    history = r411.load_history(r41_dir, r40_dir, r39_dir,
                                 r365_preflight_dir, r365_boot_dir)
    for key in ('source_r41_preflight_sha256', 'source_r41_preflight_file_sha256',
                'source_r40_report_sha256', 'source_r39_report_sha256',
                'source_r365_first_boot_report_sha256', 'source_archive_sha256'):
        need(report.get(key) == history.get(key), 'r411_historical_chain_drift_' + key)
    need(report.get('p8_operational') == 'NO-GO' and
         report.get('guest_isolation_tested') is False and
         report.get('host_readback_after', {}).get('phase') == 'SSH_RUNNING',
         'r411_not_observation_only')
    return {'r411_report_sha256': report['sha256'],
            'r411_file_sha256': r41.sha(raw),
            'r41_report_sha256': history['source_r41_preflight_sha256']}


def parse_nft_counters(raw: bytes) -> dict[str, dict[str, int]]:
    """Use R35 strict policy validator, then extract the 4 fixed drop counters."""
    r35._verify_nft_json(raw)
    try:
        data = json.loads(raw, object_pairs_hook=r35._pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(R42Error('nonfinite_json')))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise R42Error('nft_parse_invalid') from exc
    result: dict[str, dict[str, int]] = {}
    for obj in data['nftables']:
        if type(obj) is not dict or 'rule' not in obj:
            continue
        rule = obj['rule']
        expression = rule['expr']
        kind = rule['chain'] + ':' + expression[0]['match']['left']['meta']['key']
        ctr = expression[1]['counter']
        handle = rule.get('handle')
        need(kind in EXPECTED_RULES and kind not in result and type(handle) is int and
             handle > 0 and all(type(ctr[key]) is int and ctr[key] >= 0
                                for key in ('packets','bytes')),
             'counter_identity_or_handle_invalid')
        result[kind] = {'handle': handle, 'packets': ctr['packets'], 'bytes': ctr['bytes']}
    need(set(result) == set(EXPECTED_RULES), 'counter_inventory_invalid')
    return {key: result[key] for key in EXPECTED_RULES}


def capture_counters(host: ReadOnlyHost) -> dict[str, dict[str, int]]:
    raw = host.sudo([host.bin['nft'], '-j', '-a', 'list', 'table', 'bridge', r35.NFT_TABLE])
    return parse_nft_counters(raw)


def validate_samples(before_host: dict[str, Any], after_host: dict[str, Any],
                     first: dict[str, Any], second: dict[str, Any]) -> dict[str, dict[str, int]]:
    r411._validate_running(before_host)
    r411._validate_running(after_host)
    need(before_host == after_host, 'host_readback_changed')
    need(type(first) is dict and type(second) is dict and
         set(first) == set(second) == set(EXPECTED_RULES), 'counter_keys_changed')
    delta = {}
    for key in EXPECTED_RULES:
        old, new = first[key], second[key]
        need(type(old) is dict and type(new) is dict and
             set(old) == set(new) == {'handle','packets','bytes'} and
             type(old['handle']) is int and old['handle'] > 0 and
             old['handle'] == new['handle'] and
             all(type(old[v]) is int and type(new[v]) is int and
                 0 <= old[v] <= new[v] for v in ('packets','bytes')),
             'counter_reset_or_replacement_' + key)
        delta[key] = {'packets': new['packets']-old['packets'],
                      'bytes': new['bytes']-old['bytes']}
    return delta


def make_report(source: dict[str,str], before_host: dict[str,Any],
                after_host: dict[str,Any], first: dict[str,Any], second: dict[str,Any],
                *, captured_at_utc: str) -> dict[str,Any]:
    delta = validate_samples(before_host, after_host, first, second)
    timestamp = r41.parse_utc(captured_at_utc)
    need(timestamp <= datetime.now(timezone.utc) and
         (datetime.now(timezone.utc) - timestamp).total_seconds() < 300,
         'capture_timestamp_outside_window')
    need(type(source) is dict and source.get('r411_report_sha256') == R411_REPORT_PIN and
         all(r41.r40.valid_hex(source.get(k)) for k in ('r411_file_sha256', 'r41_report_sha256')),
         'r42_source_not_pinned')
    report = {
        'schema': SCHEMA, 'status': STATUS, 'mode': 'READONLY_NFT_COUNTER_BASELINE',
        'source_main': MAIN_PIN, 'source_r411_report_sha256': source['r411_report_sha256'],
        'source_r411_file_sha256': source['r411_file_sha256'],
        'source_r41_preflight_report_sha256': source['r41_report_sha256'],
        'captured_at_utc': captured_at_utc,
        'host_readback_before': before_host, 'host_readback_after': after_host,
        'counter_snapshot_before': first, 'counter_snapshot_after': second,
        'counter_delta_unattributed': delta,
        'counter_handles_stable': True,
        'counters_prove_isolation': False,
        'counter_deltas_attributable_to_test': False,
        'active_test_performed': False,
        'packet_injection_performed': False,
        'guest_command_executed': False,
        'guest_isolation_tested': False,
        'guest_identity_attested': False,
        'network_policy_modified': False,
        'vm_started_by_r42': False,
        'host_mutations_by_r42': [],
        'real_service_testing': 'NOT_EXECUTED',
        'technical_truth_accredited': False,
        'operational_dispatch': False,
        'final_risk': None, 'published_generation': None,
        'experimental_validation': 'NOT_RUN', 'p8_operational': 'NO-GO',
        'next_gate': 'R42_SEPARATE_EXPLICIT_BOUNDED_NEGATIVE_TRAFFIC_TEST',
    }
    report['sha256'] = r41.sha(r41.canon(report))
    verify_report(report)
    return report


def verify_report(report: dict[str,Any]) -> bool:
    need(type(report) is dict and r41.r40.valid_hex(report.get('sha256')) and
         r41.sha(r41.canon({k: v for k, v in report.items() if k != 'sha256'})) == report['sha256'],
         'r42_digest_invalid')
    need(report.get('schema') == SCHEMA and report.get('status') == STATUS and
         report.get('mode') == 'READONLY_NFT_COUNTER_BASELINE' and
         report.get('source_main') == MAIN_PIN and
         report.get('source_r411_report_sha256') == R411_REPORT_PIN and
         all(r41.r40.valid_hex(report.get(k)) for k in
             ('source_r411_file_sha256','source_r41_preflight_report_sha256')) and
         report.get('counter_handles_stable') is True and
         report.get('counters_prove_isolation') is False and
         report.get('counter_deltas_attributable_to_test') is False and
         all(report.get(k) is False for k in (
             'active_test_performed','packet_injection_performed','guest_command_executed',
             'guest_isolation_tested','guest_identity_attested','network_policy_modified',
             'vm_started_by_r42','technical_truth_accredited','operational_dispatch')) and
         report.get('host_mutations_by_r42') == [] and
         report.get('real_service_testing') == 'NOT_EXECUTED' and
         report.get('final_risk') is None and report.get('published_generation') is None and
         report.get('experimental_validation') == 'NOT_RUN' and
         report.get('p8_operational') == 'NO-GO' and
         report.get('next_gate') == 'R42_SEPARATE_EXPLICIT_BOUNDED_NEGATIVE_TRAFFIC_TEST',
         'r42_false_authority')
    r41.parse_utc(report.get('captured_at_utc'))
    delta = validate_samples(report.get('host_readback_before'),
                             report.get('host_readback_after'),
                             report.get('counter_snapshot_before'),
                             report.get('counter_snapshot_after'))
    need(report.get('counter_delta_unattributed') == delta,
         'counter_delta_tampered')
    return True


def persist_private(directory: Path, report: dict[str, Any]) -> None:
    verify_report(report)
    r41._make_dir(directory)
    body = r41.canon(report) + b'\n'
    r41._write_once(directory / OUTPUT, body)
    r41._write_once(directory / 'SHA256SUMS',
                    (r41.sha(body) + '  ' + OUTPUT + '\n').encode('ascii'))


def perform(*, r411_dir: Path, r41_dir: Path, r40_dir: Path, r39_dir: Path,
            r365_preflight_dir: Path, r365_boot_dir: Path, receipt_dir: Path,
            host: ReadOnlyHost | None = None) -> dict[str,Any]:
    source = load_source(r411_dir, r41_dir, r40_dir, r39_dir,
                         r365_preflight_dir, r365_boot_dir)
    h = host if host is not None else ReadOnlyHost()
    first_host = r411.readback(h)
    first = capture_counters(h)
    second = capture_counters(h)
    second_host = r411.readback(h)
    result = make_report(source, first_host, second_host, first, second,
                         captured_at_utc=r41.now_utc())
    persist_private(receipt_dir, result)
    return result
