"""P14-R39: reconcile R36.5 receipts with an independent read-only libvirt readback.

This module has NO activation, guest, network test, packet, or remediation API.
A successful reconciliation remains P8 NO-GO and is not an isolation proof.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from ardrec.coordination import r365_first_boot as r365
from ardrec.coordination import r35_inactive_deployment as r35
from ardrec.coordination.r36_readonly_dashboard import verified_directory

SCHEMA = 'ardrec-p14-r39-ssh-postboot-reconciliation-v1'
SOURCE_FILES = frozenset({'r365_report.json', 'commands.jsonl'})
EXPECTED_ATTEMPTS = [
    'virsh net-start ' + r365.SSH_NETWORK,
    'virsh start ' + r365.SSH_DOMAIN,
]
RESULT = 'SSH_NETWORK_ACTIVE_DOMAIN_OFF_RECONCILED_NO_GO'


class R39Error(ValueError):
    """Fail-closed validation error with stable reason codes."""


def need(condition: bool, code: str) -> None:
    if not condition:
        raise R39Error(code)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canon(doc: Any) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _calls_from_ledger(raw: bytes) -> list[dict[str, Any]]:
    need(type(raw) is bytes and 0 < len(raw) <= 2_000_000, 'boot_ledger_size')
    rows = raw.splitlines()
    need(1 <= len(rows) <= 400, 'boot_ledger_lines')
    result = []
    for line in rows:
        row = r365.read_json(line)
        argv = row.get('argv')
        need(type(argv) is list and all(type(x) is str and len(x) < 512 for x in argv)
             and 1 <= len(argv) <= 15 and type(row.get('returncode')) is int,
             'boot_ledger_row_invalid')
        # R36.5 host runner never dispatches through shell.
        if argv[:3] == ['/usr/bin/sudo', '-n', '--']:
            argv = argv[3:]
        need(len(argv) > 0, 'boot_ledger_empty_command')
        verb = argv[0]
        if verb == '/usr/bin/virsh':
            need(len(argv) >= 5, 'boot_virsh_argv_invalid')
            if argv[1:3] == ['-c', 'qemu:///system']:
                need(argv[3:] in (["net-start", r365.SSH_NETWORK],
                                  ["start", r365.SSH_DOMAIN]),
                     'boot_ledger_unexpected_mutation')
                result.append({'argv': argv, 'returncode': row['returncode']})
            else:
                need(argv[1:4] == ['--readonly', '-c', 'qemu:///system'],
                     'boot_virsh_not_readonly')
                args = argv[4:]
                fixed = {
                    ('list', '--all', '--name'), ('list', '--name'),
                    ('net-list', '--all', '--name'), ('net-list', '--name'),
                }
                allow = (tuple(args) in fixed or
                         (len(args) == 2 and args[0] in ('nwfilter-dumpxml', 'net-info',
                                                          'domstate', 'dominfo') and
                          args[1] in (r365.t33.DENY_FILTER, *r35.NETWORKS, *r35.DOMAINS)) or
                         (len(args) == 3 and args[0] in ('net-dumpxml', 'dumpxml') and
                          args[1] in (*r35.NETWORKS, *r35.DOMAINS) and args[2] == '--inactive'))
                need(allow, 'boot_ledger_readonly_scope_invalid')
        elif verb in ('/usr/bin/nft', '/usr/sbin/nft'):
            need(argv[1:] == ['-j', '-a', 'list', 'table', 'bridge',
                              r365.t34.NFT_TABLE], 'boot_ledger_nft_mutation')
        elif verb in ('/usr/bin/ip', '/usr/sbin/ip'):
            need(argv[1:] == ['-j', 'link', 'show'], 'boot_ledger_ip_mutation')
        elif verb == '/usr/bin/stat':
            need(argv[1:3] == ['--printf=%F|%u|%g|%h|%a|%s|%i|%Y|%Z', '--'] and
                 len(argv) == 4, 'boot_ledger_stat_scope')
        elif verb == '/usr/bin/sha256sum':
            need(argv[1:3] == ['--binary', '--'] and len(argv) == 4,
                 'boot_ledger_sha_scope')
        elif verb == '/usr/bin/qemu-img':
            need(argv[1:5] == ['info', '--output=json', '-f', 'qcow2'] and len(argv) == 6,
                 'boot_ledger_qcow2_scope')
        else:
            raise R39Error('boot_ledger_unknown_executable')
    need([x['argv'][3:] for x in result] == [
        ['net-start', r365.SSH_NETWORK], ['start', r365.SSH_DOMAIN]],
         'boot_ledger_activation_order_invalid')
    need(all(x['returncode'] == 0 for x in result), 'boot_ledger_activation_failure')
    return result


def read_r365_chain(preflight_dir: Path, boot_dir: Path) -> dict[str, Any]:
    """Authenticate exact private file inventories and semantic first-boot linkage.

    SHA256SUMS is local integrity, NOT third-party provenance or guest verification.
    """
    boot_files = verified_directory(boot_dir, SOURCE_FILES)
    boot = r365.read_json(boot_files['r365_report.json'])
    r365.check_digest(boot, r365.SCHEMA)
    need(boot.get('mode') == 'FIRST_BOOT_AUTHORIZED' and
         boot.get('status') == 'FIRST_BOOT_DENY_POLICY_PRESENT_UNTESTED' and
         boot.get('source_main') == r365.EXPECTED_MAIN and
         boot.get('source_archive_sha256') == r35.ARCHIVE_SHA256 and
         type(boot.get('source_evidence')) is dict and
         boot.get('source_preflight_sha256') is not None and
         boot.get('storage_verified') is True and
         boot.get('host_state', {}).get('phase') == 'BEFORE' and
         boot.get('network_phase_readback', {}).get('phase') == 'NETWORK_ONLY' and
         boot.get('final_readback', {}).get('phase') == 'SSH_RUNNING' and
         boot.get('attempted_mutations') == EXPECTED_ATTEMPTS and
         boot.get('host_mutations') == EXPECTED_ATTEMPTS and
         boot.get('network_started') is True and
         boot.get('vm_started') is True and
         boot.get('guest_isolation_tested') is False and
         boot.get('real_service_testing') == 'NOT_EXECUTED' and
         boot.get('operational_dispatch') is False and
         boot.get('final_risk') is None and
         boot.get('experimental_validation') == 'NOT_RUN' and
         boot.get('p8_operational') == 'NO-GO' and
         boot.get('automatic_rollback') is False and
         boot.get('failure_code') is None,
         'first_boot_source_contract_invalid')
    preflight = r365.verify_preflight_receipt(preflight_dir, boot['source_evidence'])
    need(boot['source_preflight_sha256'] == preflight['sha256'],
         'preflight_to_boot_chain_invalid')
    _calls_from_ledger(boot_files['commands.jsonl'])
    pre_files = verified_directory(preflight_dir, SOURCE_FILES)
    return {
        'preflight_report_sha256': preflight['sha256'],
        'preflight_file_sha256': sha(pre_files['r365_report.json']),
        'first_boot_report_sha256': boot['sha256'],
        'first_boot_file_sha256': sha(boot_files['r365_report.json']),
        'first_boot_commands_sha256': sha(boot_files['commands.jsonl']),
        'source_evidence': boot['source_evidence'],
    }


class ReadOnlyHost(r365.FirstBootHost):
    """R36.5 host readback, with sudo -n ONLY for read-only virsh access.

    `sudo -v` must be authorized interactively by the operator beforehand.
    No activation API is used by this module.
    """
    def activate_ssh_network(self) -> None:
        raise R39Error('r39_mutation_forbidden')

    def activate_ssh_domain(self) -> None:
        raise R39Error('r39_mutation_forbidden')

    def virsh_ro(self, args: list[str]) -> bytes:
        need(type(args) is list, 'virsh_scope_invalid')
        fixed = {('list', '--all', '--name'), ('list', '--name'),
                 ('net-list', '--all', '--name'), ('net-list', '--name')}
        scoped = ((len(args) == 2 and args[0] == 'nwfilter-dumpxml' and
                   args[1] == r365.t33.DENY_FILTER) or
                  (len(args) == 3 and args[0] == 'net-dumpxml' and
                   args[1] in r35.NETWORKS and args[2] == '--inactive') or
                  (len(args) == 3 and args[0] == 'dumpxml' and
                   args[1] in r35.DOMAINS and args[2] == '--inactive') or
                  (len(args) == 2 and args[0] == 'net-info' and
                   args[1] in r35.NETWORKS) or
                  (len(args) == 2 and args[0] in ('dominfo', 'domstate') and
                   args[1] in r35.DOMAINS))
        need(tuple(args) in fixed or scoped, 'virsh_scope_invalid')
        return self.run([self.bin['sudo'], '-n', '--', self.bin['virsh'],
                         '--readonly', '-c', 'qemu:///system', *args])


def capture_current(host: ReadOnlyHost | None = None) -> dict[str, Any]:
    """Validate exact R36.5 NETWORK_ONLY readback against physical host.

    No guest or packet probes. Any drift raises; do not auto-repair.
    """
    h = host if host is not None else ReadOnlyHost()
    return r365.current(h, phase='NETWORK_ONLY')


def reconcile(chain: dict[str, Any], live: dict[str, Any],
              *, captured_at_utc: str) -> dict[str, Any]:
    need(type(chain) is dict and all(type(chain.get(k)) is str and
         re.fullmatch(r'[0-9a-f]{64}', chain[k]) for k in (
             'preflight_report_sha256', 'preflight_file_sha256',
             'first_boot_report_sha256', 'first_boot_file_sha256',
             'first_boot_commands_sha256')) and
         type(chain.get('source_evidence')) is dict, 'chain_summary_invalid')
    try:
        parsed = datetime.strptime(captured_at_utc, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except (ValueError, TypeError) as exc:
        raise R39Error('capture_time_invalid') from exc
    need(parsed.strftime('%Y-%m-%dT%H:%M:%SZ') == captured_at_utc,
         'capture_time_noncanonical')
    need(type(live) is dict and live.get('phase') == 'NETWORK_ONLY' and
         live.get('active_networks') == [r365.SSH_NETWORK] and
         live.get('active_domains') == [] and
         live.get('reserved_links') == [r365.t33.NET_BRIDGE['ssh']] and
         live.get('deny_first_still_verified') is True and
         live.get('bridge_macs') == r35.R354_EXISTING_BRIDGE_MACS,
         'live_state_not_network_only')
    report = {
        'schema': SCHEMA, 'mode': 'READONLY_POSTBOOT_RECONCILIATION',
        'status': RESULT,
        'source_preflight_report_sha256': chain['preflight_report_sha256'],
        'source_preflight_file_sha256': chain['preflight_file_sha256'],
        'source_first_boot_report_sha256': chain['first_boot_report_sha256'],
        'source_first_boot_file_sha256': chain['first_boot_file_sha256'],
        'source_first_boot_commands_sha256': chain['first_boot_commands_sha256'],
        'captured_at_utc': captured_at_utc,
        'host_readback': live,
        'state_transition_observed': 'BOOT_RECEIPT_SSH_RUNNING__NOW_NETWORK_ONLY',
        'shutdown_origin': 'NOT_ATTESTED',
        'local_receipt_integrity_checked': True,
        'independent_guest_provenance': False,
        'guest_isolation_tested': False,
        'real_service_testing': 'NOT_EXECUTED',
        'vm_started_by_r39': False,
        'network_started_by_r39': False,
        'host_mutations_by_r39': [],
        'operational_dispatch': False,
        'technical_truth_accredited': False,
        'final_risk': None,
        'published_generation': None,
        'p8_operational': 'NO-GO',
        'experimental_validation': 'NOT_RUN',
        'next_gate': 'R39_SEPARATE_RECOVERY_AUTHORIZATION_AND_ISOLATION_VALIDATION',
    }
    report['sha256'] = sha(canon(report))
    verify_report(report)
    return report


def verify_report(report: dict[str, Any]) -> bool:
    need(type(report) is dict and type(report.get('sha256')) is str and
         re.fullmatch(r'[0-9a-f]{64}', report['sha256']) is not None and
         sha(canon({k:v for k,v in report.items() if k != 'sha256'})) == report['sha256'],
         'reconciliation_digest_invalid')
    need(report.get('schema') == SCHEMA and
         report.get('mode') == 'READONLY_POSTBOOT_RECONCILIATION' and
         report.get('status') == RESULT and
         report.get('host_readback', {}).get('phase') == 'NETWORK_ONLY' and
         report.get('host_readback', {}).get('active_networks') == [r365.SSH_NETWORK] and
         report.get('host_readback', {}).get('active_domains') == [] and
         report.get('host_readback', {}).get('reserved_links') == [r365.t33.NET_BRIDGE['ssh']] and
         report.get('host_readback', {}).get('deny_first_still_verified') is True and
         report.get('state_transition_observed') == 'BOOT_RECEIPT_SSH_RUNNING__NOW_NETWORK_ONLY' and
         report.get('shutdown_origin') == 'NOT_ATTESTED' and
         report.get('local_receipt_integrity_checked') is True and
         report.get('independent_guest_provenance') is False and
         report.get('guest_isolation_tested') is False and
         report.get('real_service_testing') == 'NOT_EXECUTED' and
         report.get('vm_started_by_r39') is False and
         report.get('network_started_by_r39') is False and
         report.get('host_mutations_by_r39') == [] and
         report.get('operational_dispatch') is False and
         report.get('technical_truth_accredited') is False and
         report.get('final_risk') is None and
         report.get('published_generation') is None and
         report.get('p8_operational') == 'NO-GO' and
         report.get('experimental_validation') == 'NOT_RUN' and
         report.get('next_gate') == 'R39_SEPARATE_RECOVERY_AUTHORIZATION_AND_ISOLATION_VALIDATION',
         'reconciliation_false_authority')
    return True


def persist_private(directory: Path, report: dict[str, Any]) -> None:
    """Exclusive local receipt only; no mutable host or VM operations."""
    verify_report(report)
    need(isinstance(directory, Path) and directory.is_absolute() and
         not directory.exists() and not directory.is_symlink() and
         all(not p.is_symlink() for p in directory.parents), 'receipt_destination_invalid')
    parent = directory.parent
    st = parent.stat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
         stat.S_IMODE(st.st_mode) == 0o700, 'receipt_parent_not_private')
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    need(stat.S_IMODE(directory.stat().st_mode) == 0o700, 'receipt_dir_mode_invalid')
    body = canon(report) + b'\n'
    sums = sha(body).encode('ascii') + b'  r39_reconciliation.json\n'
    for name,raw in (('r39_reconciliation.json', body), ('SHA256SUMS', sums)):
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
