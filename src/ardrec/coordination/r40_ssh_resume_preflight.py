"""P14-R40: SSH postboot storage/containment READ-ONLY preflight.

No VM/network activation, no guest probes, no traffic and NO operational authority.
R36.5 preboot runtime-overlay SHA is NOT an acceptable postboot SSH oracle.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any

from ardrec.coordination import r35_inactive_deployment as r35
from ardrec.coordination import r365_first_boot as r365
from ardrec.coordination import r39_ssh_reconciliation as r39
from ardrec.coordination.r36_readonly_dashboard import verified_directory

SCHEMA = 'ardrec-p14-r40-ssh-postboot-preflight-v1'
STATUS = 'POSTBOOT_STORAGE_CONTAINMENT_CONSISTENT_NO_GO'
R39_FILES = frozenset({'r39_reconciliation.json'})
OUT_FILES = ('r40_preflight.json', 'SHA256SUMS')
HEX = re.compile(r'[0-9a-f]{64}\Z')

class R40Error(ValueError):
    """Fail-closed, reviewable preflight error."""

def need(value: bool, code: str) -> None:
    if not value:
        raise R40Error(code)

def canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def valid_hex(value: Any) -> bool:
    return type(value) is str and HEX.fullmatch(value) is not None

def verify_r39_source(r39_dir: Path, preflight_dir: Path, boot_dir: Path) -> dict[str, Any]:
    """Bind R39's receipt to the FULL R36.5 chain, rejecting any rehashed claims."""
    files = verified_directory(r39_dir, R39_FILES)
    raw = files['r39_reconciliation.json']
    report = r365.read_json(raw)
    r39.verify_report(report)
    original = r39.read_r365_chain(preflight_dir, boot_dir)
    links = {
        'source_preflight_report_sha256': 'preflight_report_sha256',
        'source_preflight_file_sha256': 'preflight_file_sha256',
        'source_first_boot_report_sha256': 'first_boot_report_sha256',
        'source_first_boot_file_sha256': 'first_boot_file_sha256',
        'source_first_boot_commands_sha256': 'first_boot_commands_sha256',
    }
    need(all(report.get(target) == original[source] for target,source in links.items()),
         'r39_to_r365_chain_drift')
    need(report.get('p8_operational') == 'NO-GO' and
         report.get('host_readback', {}).get('phase') == 'NETWORK_ONLY',
         'r39_report_not_network_only')
    return {
        'r39_report_sha256': report['sha256'],
        'r39_file_sha256': sha(raw),
        'r365_first_boot_report_sha256': original['first_boot_report_sha256'],
        'r365_preflight_report_sha256': original['preflight_report_sha256'],
        'r365_first_boot_commands_sha256': original['first_boot_commands_sha256'],
        'source_evidence': original['source_evidence'],
        'r39_host_readback': report['host_readback'],
    }

class ReadOnlyHost(r39.ReadOnlyHost):
    """Explicitly deny inherited write APIs; only R35 read-only file inspectors."""
    def activate_ssh_network(self) -> None:
        raise R40Error('activation_forbidden')
    def activate_ssh_domain(self) -> None:
        raise R40Error('activation_forbidden')
    def virsh_write(self, args: list[str]) -> bytes:
        raise R40Error('libvirt_mutation_forbidden')

def verify_storage_postboot(host: ReadOnlyHost, r32: dict[str, Any]) -> dict[str, Any]:
    """Validate 12 QCOW2 assets: frozen base/parent, and only SSH runtime mutable.

    R35 helpers inspect file metadata, SHA-256, and qemu-img info without writes.
    SSH runtime is sealed as an observation (current digest), NOT compared with
    the preboot digest. FTP/SMB/runner runtimes retain their preboot hashes.
    """
    need(type(r32) is dict and type(r32.get('roles')) is list and
         type(r32.get('new_assets')) is list and len(r32['roles']) == 4 and
         len(r32['new_assets']) == 4, 'r32_storage_inventory_invalid')
    roles = [r.get('role') if type(r) is dict else None for r in r32['roles']]
    need(len(set(roles)) == 4 and set(roles) == set(r35.t33.ROLES),
         'r32_roles_invalid')
    # Preserve R35's directory and ownership guards, without comparing the
    # changed SSH runtime image with its PREBOOT SHA (an invalid oracle).
    for folder in ('/var', '/var/lib', '/var/lib/libvirt', '/var/lib/libvirt/images'):
        s = r35._stat_command(host, folder)
        need(s['kind'] == 'directory' and s['uid'] == 0 and
             (s['mode'] & 0o022) == 0, 'storage_parent_drift')
    stage = r35._stat_command(host, r35.t33.R32_STAGE)
    need(stage['kind'] == 'directory' and stage['uid'] == 0 and
         stage['gid'] == r35.QEMU_GID and stage['mode'] == 0o750,
         'storage_stage_drift')
    assets = []
    for row, asset in zip(r32['roles'], r32['new_assets']):
        need(type(row) is dict and type(asset) is dict, 'r32_asset_type_invalid')
        role = row['role']
        base, parent, runtime = row['source_base'], row['parent_overlay'], row['new_overlay']
        virtual = row['virtual_size']
        need(asset.get('role') == role and asset.get('path') == runtime and
             asset.get('backing_filename') == parent and
             asset.get('virtual_size') == virtual and
             all(type(p) is str and p.startswith('/var/lib/libvirt/images/')
                 for p in (base,parent,runtime)) and
             len({base,parent,runtime}) == 3 and
             type(virtual) is int and virtual > 0,
             'r32_asset_binding_invalid_' + role)
        base_stat = r35._stat_command(host,base)
        parent_stat = r35._stat_command(host,parent)
        run_before = r35._stat_command(host,runtime)
        need(base_stat['kind'] == 'regular file' and base_stat['nlink'] == 1 and
             base_stat['uid'] in (0,r35.QEMU_UID) and
             (base_stat['mode'] & 0o222) == 0 and
             parent_stat['kind'] == 'regular file' and parent_stat['nlink'] == 1 and
             parent_stat['uid'] in (0,r35.QEMU_UID) and
             (parent_stat['mode'] & 0o077) == 0,
             'immutable_layer_permissions_drift_' + role)
        need(run_before['kind'] == 'regular file' and run_before['nlink'] == 1 and
             run_before['uid'] == r35.QEMU_UID and
             run_before['gid'] == r35.QEMU_GID and run_before['mode'] == 0o600,
             'runtime_overlay_permissions_drift_' + role)
        need(r35._hash_command(host,base) == row['source_base_sha256'] and
             r35._hash_command(host,parent) == row['parent_overlay_sha256'],
             'immutable_layer_digest_drift_' + role)
        r35._verify_qcow_info(r35.canon(r35._qemu_info(host,base)),
                             virtual_size=virtual, backing=None)
        r35._verify_qcow_info(r35.canon(r35._qemu_info(host,parent)),
                             virtual_size=virtual, backing=base)
        r35._verify_qcow_info(r35.canon(r35._qemu_info(host,runtime)),
                             virtual_size=virtual, backing=parent)
        digest1 = r35._hash_command(host,runtime)
        run_after = r35._stat_command(host,runtime)
        digest2 = r35._hash_command(host,runtime)
        need(run_before == run_after and digest1 == digest2 and valid_hex(digest1),
             'runtime_overlay_changed_during_read_' + role)
        if role != 'ssh':
            need(digest1 == asset['sha256'], 'other_runtime_changed_' + role)
        assets.append({'role':role, 'runtime_sha256_observed':digest1,
                       'runtime_preboot_sha256':asset['sha256'],
                       'runtime_sha256_policy':('POSTBOOT_OBSERVATION_NOT_PREBOOT_ORACLE'
                                                if role == 'ssh' else 'UNMODIFIED_PREBOOT_EXPECTED'),
                       'immutable_layers_verified':True,
                       'qcow2_structure_verified':True,
                       'runtime_observation_stable':True})
    return {'verified_roles':len(assets),'assets':assets,
            'source_images_mutated_by_r40':False,
            'ssh_runtime_preboot_hash_enforced':False,
            'non_ssh_runtime_preboot_hash_enforced':True}

def verify_live_unchanged(before: dict[str, Any], after: dict[str, Any]) -> None:
    need(before == after and type(before) is dict and
         before.get('phase') == 'NETWORK_ONLY' and
         before.get('active_networks') == [r365.SSH_NETWORK] and
         before.get('active_domains') == [] and
         before.get('reserved_links') == [r365.t33.NET_BRIDGE['ssh']] and
         before.get('deny_first_still_verified') is True,
         'physical_readback_drift_during_preflight')

def make_report(chain: dict[str, Any], before: dict[str, Any],
                after: dict[str, Any], storage: dict[str, Any],
                *, captured_at_utc: str) -> dict[str, Any]:
    verify_live_unchanged(before,after)
    need(type(chain) is dict and all(valid_hex(chain.get(k)) for k in (
         'r39_report_sha256','r39_file_sha256','r365_first_boot_report_sha256',
         'r365_preflight_report_sha256','r365_first_boot_commands_sha256')),
         'source_chain_invalid')
    need(type(storage) is dict and storage.get('verified_roles') == 4 and
         storage.get('source_images_mutated_by_r40') is False and
         storage.get('ssh_runtime_preboot_hash_enforced') is False and
         storage.get('non_ssh_runtime_preboot_hash_enforced') is True and
         type(storage.get('assets')) is list and len(storage['assets']) == 4 and
         {a.get('role') for a in storage['assets']} == set(r35.t33.ROLES) and
         all(type(a) is dict and valid_hex(a.get('runtime_sha256_observed')) and
             valid_hex(a.get('runtime_preboot_sha256')) and
             a.get('immutable_layers_verified') is True and
             a.get('qcow2_structure_verified') is True and
             a.get('runtime_observation_stable') is True and
             a.get('runtime_sha256_policy') == ('POSTBOOT_OBSERVATION_NOT_PREBOOT_ORACLE'
                    if a['role'] == 'ssh' else 'UNMODIFIED_PREBOOT_EXPECTED') and
             (a['role'] == 'ssh' or
              a['runtime_sha256_observed'] == a['runtime_preboot_sha256'])
             for a in storage['assets']), 'storage_readback_invalid')
    try:
        dt = datetime.strptime(captured_at_utc,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise R40Error('capture_time_invalid') from exc
    need(dt.strftime('%Y-%m-%dT%H:%M:%SZ') == captured_at_utc,'capture_time_noncanonical')
    report = {
        'schema':SCHEMA, 'mode':'READONLY_POSTBOOT_STORAGE_CONTAINMENT_PREFLIGHT',
        'status':STATUS, 'captured_at_utc':captured_at_utc,
        'source_r39_report_sha256':chain['r39_report_sha256'],
        'source_r39_file_sha256':chain['r39_file_sha256'],
        'source_r365_first_boot_report_sha256':chain['r365_first_boot_report_sha256'],
        'source_r365_preflight_report_sha256':chain['r365_preflight_report_sha256'],
        'source_r365_first_boot_commands_sha256':chain['r365_first_boot_commands_sha256'],
        'source_archive_sha256':r35.ARCHIVE_SHA256,
        'host_readback_before':before,'host_readback_after':after,
        'storage':storage,
        'permission_to_resume':False,
        'resumption_performed':False,'automatic_recovery':False,
        'guest_isolation_tested':False,'network_traffic_tested':False,
        'guest_os_identity_verified':False,'technical_truth_accredited':False,
        'real_service_testing':'NOT_EXECUTED','operational_dispatch':False,
        'published_generation':None,'final_risk':None,
        'p8_operational':'NO-GO','experimental_validation':'NOT_RUN',
        'next_gate':'SEPARATE_AUTHORIZED_SSH_RESUME_AND_NEGATIVE_TRAFFIC_TEST',
        'host_mutations_by_r40':[],
    }
    report['sha256']=sha(canon(report))
    verify_report(report)
    return report

def verify_report(report: dict[str, Any]) -> bool:
    need(type(report) is dict and valid_hex(report.get('sha256')) and
         sha(canon({k:v for k,v in report.items() if k!='sha256'})) == report['sha256'],
         'r40_report_digest_invalid')
    need(report.get('schema') == SCHEMA and report.get('status') == STATUS and
         report.get('mode') == 'READONLY_POSTBOOT_STORAGE_CONTAINMENT_PREFLIGHT' and
         all(valid_hex(report.get(k)) for k in (
             'source_r39_report_sha256','source_r39_file_sha256',
             'source_r365_first_boot_report_sha256',
             'source_r365_preflight_report_sha256',
             'source_r365_first_boot_commands_sha256',
             'source_archive_sha256')) and
         report['source_archive_sha256'] == r35.ARCHIVE_SHA256 and
         report.get('permission_to_resume') is False and
         report.get('resumption_performed') is False and
         report.get('automatic_recovery') is False and
         report.get('guest_isolation_tested') is False and
         report.get('network_traffic_tested') is False and
         report.get('guest_os_identity_verified') is False and
         report.get('technical_truth_accredited') is False and
         report.get('real_service_testing') == 'NOT_EXECUTED' and
         report.get('operational_dispatch') is False and
         report.get('published_generation') is None and
         report.get('final_risk') is None and
         report.get('p8_operational') == 'NO-GO' and
         report.get('experimental_validation') == 'NOT_RUN' and
         report.get('next_gate') == 'SEPARATE_AUTHORIZED_SSH_RESUME_AND_NEGATIVE_TRAFFIC_TEST' and
         report.get('host_mutations_by_r40') == [],'r40_report_false_authority')
    verify_live_unchanged(report.get('host_readback_before'),
                          report.get('host_readback_after'))
    # A tampered report with a rehashed readiness claim is still rejected.
    storage = report.get('storage')
    need(type(storage) is dict and storage.get('verified_roles') == 4 and
         storage.get('ssh_runtime_preboot_hash_enforced') is False and
         storage.get('non_ssh_runtime_preboot_hash_enforced') is True and
         storage.get('source_images_mutated_by_r40') is False and
         type(storage.get('assets')) is list and len(storage['assets']) == 4 and
         {a.get('role') for a in storage['assets']} == set(r35.t33.ROLES) and
         all(type(a) is dict and valid_hex(a.get('runtime_sha256_observed')) and
             valid_hex(a.get('runtime_preboot_sha256')) and
             a.get('immutable_layers_verified') is True and
             a.get('qcow2_structure_verified') is True and
             a.get('runtime_observation_stable') is True and
             a.get('runtime_sha256_policy') == ('POSTBOOT_OBSERVATION_NOT_PREBOOT_ORACLE'
                      if a['role'] == 'ssh' else 'UNMODIFIED_PREBOOT_EXPECTED') and
             (a['role'] == 'ssh' or
              a.get('runtime_sha256_observed') == a.get('runtime_preboot_sha256'))
             for a in storage['assets']), 'r40_report_storage_false_claim')
    return True

def persist_private(directory: Path, report: dict[str, Any]) -> None:
    verify_report(report)
    need(isinstance(directory,Path) and directory.is_absolute() and
         not directory.exists() and not directory.is_symlink() and
         all(not p.is_symlink() for p in directory.parents),'r40_receipt_destination_invalid')
    parent=directory.parent
    st=parent.stat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
         stat.S_IMODE(st.st_mode) == 0o700,'r40_parent_not_private')
    directory.mkdir(mode=0o700,parents=False,exist_ok=False)
    need(stat.S_IMODE(directory.stat().st_mode) == 0o700,'r40_receipt_dir_mode')
    body=canon(report)+b'\n'
    sums=sha(body).encode('ascii')+b'  r40_preflight.json\n'
    for name,raw in (('r40_preflight.json',body),('SHA256SUMS',sums)):
        fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())

def perform(*, source_archive: Path, r39_dir: Path,
            r365_preflight_dir: Path, r365_boot_dir: Path,
            receipt_dir: Path, host: ReadOnlyHost|None=None) -> dict[str,Any]:
    chain=verify_r39_source(r39_dir,r365_preflight_dir,r365_boot_dir)
    h=host if host is not None else ReadOnlyHost()
    before=r39.capture_current(h)
    need(before == chain['r39_host_readback'], 'host_state_drift_since_r39')
    with tempfile.TemporaryDirectory(prefix='ardrec-r40-src-') as root:
        temp=Path(root)
        temp.chmod(0o700)
        bundle=r35.verify_source_bundle(source_archive,temp)
        need(type(bundle) is dict and type(bundle.get('r32')) is dict,
             'r32_bundle_invalid')
        r35.t33.verify_r32(bundle['r32'])
        storage=verify_storage_postboot(h,bundle['r32'])
    after=r39.capture_current(h)
    report=make_report(chain,before,after,storage,
          captured_at_utc=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
    persist_private(receipt_dir,report)
    return report
