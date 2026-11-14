"""P14-R33: sealed, deterministic OFFLINE libvirt topology definitions.

No subprocess, sudo, libvirt calls, network interfaces, or VM starts.
A missing nwfilter prevents inadvertent activation before the next gate.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
import xml.etree.ElementTree as ET
from typing import Any

SCHEMA = 'ardrec-p14-r33-offline-topology-v1'
SOURCE_SCHEMA = 'ardrec-p14-r32-overlay-materialization-v1'
R32_RECEIPT_FILE_SHA256 = 'b032c35c5f9760b9b057b6bbc3e681fca82ff37532c897b37463a147b1cdaadf'
R32_STAGE = '/var/lib/libvirt/images/ardrec-dev-point4-r32'
BASE_ROOT = '/var/lib/libvirt/images/ardrec-dev-point4-v4'
PARENT_ROOT = '/var/lib/libvirt/images/ardrec-dev-point4-v6'
ROLES = ('ssh', 'ftp', 'smb', 'runner')
DENY_FILTER = 'ardrec-r33-block-until-containment'
DOMAIN_PREFIX = 'ardrec-r33-dev-'
NETWORK_PREFIX = 'ardrec-r33-dev-net-'
RESOURCE = {
    'ssh': {'vcpus': 1, 'ram_mib': 768, 'disk_gib': 8,
            'nics': [('ssh', '10.203.30.2', '52:54:00:ad:30:02', 'a33d30t')]},
    'ftp': {'vcpus': 1, 'ram_mib': 768, 'disk_gib': 8,
            'nics': [('ftp', '10.203.31.2', '52:54:00:ad:31:02', 'a33d31t')]},
    'smb': {'vcpus': 2, 'ram_mib': 1536, 'disk_gib': 12,
            'nics': [('smb', '10.203.32.2', '52:54:00:ad:32:02', 'a33d32t')]},
    'runner': {'vcpus': 2, 'ram_mib': 3072, 'disk_gib': 24,
               'nics': [('ssh', '10.203.30.1', '52:54:00:ad:30:01', 'a33d30r'),
                        ('ftp', '10.203.31.1', '52:54:00:ad:31:01', 'a33d31r'),
                        ('smb', '10.203.32.1', '52:54:00:ad:32:01', 'a33d32r')]},
}
NET_BRIDGE = {'ssh': 'br33d30', 'ftp': 'br33d31', 'smb': 'br33d32'}
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
MAX_SOURCE_BYTES = 131072


class TopologyError(ValueError):
    """Fail-closed contract failure."""


def need(condition: bool, code: str) -> None:
    if not condition:
        raise TopologyError(code)


def canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unique_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in items:
        need(key not in out, 'duplicate_json_key')
        out[key] = value
    return out


def read_r32(path: Path, expected_sha: str) -> tuple[dict[str, Any], str]:
    """Accept the one verified physical R32 receipt, never a user-selected substitute."""
    need(isinstance(path, Path) and type(expected_sha) is str and
         expected_sha == R32_RECEIPT_FILE_SHA256, 'source_hash_pin_mismatch')
    need(path.is_absolute() and path.name == 'r32_staging.json', 'source_path_invalid')
    for parent in (path, *path.parents):
        need(not parent.is_symlink(), 'source_symlink_rejected')
    st = path.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= MAX_SOURCE_BYTES and
         (st.st_mode & 0o077) == 0, 'source_type_mode_invalid')
    raw = path.read_bytes()
    need(digest(raw) == expected_sha, 'source_file_digest_mismatch')
    try:
        doc = json.loads(raw, object_pairs_hook=_unique_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(TopologyError('nonfinite_json')))
    except (ValueError, TypeError, UnicodeError) as e:
        raise TopologyError('source_json_invalid') from e
    verify_r32(doc)
    return doc, expected_sha


def _sha_value(value: Any) -> bool:
    return type(value) is str and DIGEST.fullmatch(value) is not None


def verify_r32(doc: dict[str, Any]) -> bool:
    """Verify R32's internal digest, cardinality, storage paths and NO-GO semantics."""
    need(type(doc) is dict and _sha_value(doc.get('sha256')) and
         digest(canon({k: v for k, v in doc.items() if k != 'sha256'})) == doc['sha256'],
         'r32_internal_digest_invalid')
    need(doc.get('schema') == SOURCE_SCHEMA and
         doc.get('mode') == 'EXPLICIT_STORAGE_STAGING' and
         doc.get('host') == 'Prometheus' and
         doc.get('stage_directory') == R32_STAGE and
         doc.get('stage_status') == 'FOUR_NEW_COW_OVERLAYS_VERIFIED_NOT_STARTED' and
         doc.get('new_overlays_created') == 4 and
         doc.get('storage_prepared') is True and
         doc.get('stage_directory_created') is True and
         doc.get('failure_code') is None and
         doc.get('source_images_mutated') is False and
         doc.get('p8_operational') == 'NO-GO' and
         doc.get('experimental_validation') == 'NOT_RUN' and
         doc.get('final_risk') is None and
         doc.get('published_generation') is None and
         all(doc.get(k) is False for k in ('vm_started', 'network_created',
             'guest_checked', 'operational_dispatch', 'can_restore',
             'restoration_performed', 'technical_truth_accredited')),
         'r32_false_authority_or_incomplete')
    need(_sha_value(doc.get('source_r31_file_sha256')) and
         _sha_value(doc.get('source_r31_report_sha256')) and
         type(doc.get('roles')) is list and type(doc.get('new_assets')) is list and
         len(doc['roles']) == len(doc['new_assets']) == 4,
         'r32_source_or_roles_invalid')
    need([x.get('role') for x in doc['roles']] == list(ROLES) and
         [x.get('role') for x in doc['new_assets']] == list(ROLES),
         'r32_role_identity_invalid')
    for row, item in zip(doc['roles'], doc['new_assets']):
        role = row['role']
        path = f'{R32_STAGE}/{role}-runtime.qcow2'
        parent = f'{PARENT_ROOT}/{role}-runtime.qcow2'
        base = f'{BASE_ROOT}/{role}-base.qcow2'
        size = RESOURCE[role]['disk_gib'] * 1024**3
        need(row.get('new_overlay') == path and row.get('parent_overlay') == parent and
             row.get('source_base') == base and row.get('virtual_size') == size and
             _sha_value(row.get('parent_overlay_sha256')) and
             _sha_value(row.get('source_base_sha256')) and
             item.get('path') == path and item.get('backing_filename') == parent and
             item.get('virtual_size') == size and _sha_value(item.get('sha256')),
             'r32_asset_path_or_hash_invalid')
    return True


def _stable_uuid(r32_file_sha: str, category: str, name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, 'urn:ardrec:r33:'+r32_file_sha+':'+category+':'+name))


def _xml_bytes(root: ET.Element) -> bytes:
    ET.indent(root, space='  ')
    return ET.tostring(root, encoding='utf-8', xml_declaration=True) + b'\n'


def _network_xml(r32_sha: str, role: str) -> bytes:
    need(role in NET_BRIDGE, 'unexpected_network_role')
    root = ET.Element('network', {'ipv6':'no'})
    ET.SubElement(root, 'name').text = NETWORK_PREFIX + role
    ET.SubElement(root, 'uuid').text = _stable_uuid(r32_sha, 'network', role)
    ET.SubElement(root, 'bridge', {'name': NET_BRIDGE[role], 'stp': 'off', 'delay': '0'})
    ET.SubElement(root, 'dns', {'enable': 'no'})
    return _xml_bytes(root)


def _domain_xml(r32_sha: str, role: str) -> bytes:
    cfg = RESOURCE[role]
    root = ET.Element('domain', {'type': 'kvm'})
    ET.SubElement(root, 'name').text = DOMAIN_PREFIX + role
    ET.SubElement(root, 'uuid').text = _stable_uuid(r32_sha, 'domain', role)
    for tag in ('memory','currentMemory'):
        ET.SubElement(root, tag, {'unit': 'MiB'}).text = str(cfg['ram_mib'])
    ET.SubElement(root,'vcpu',{'placement':'static'}).text = str(cfg['vcpus'])
    osel=ET.SubElement(root,'os')
    ET.SubElement(osel,'type',{'arch':'x86_64','machine':'pc-i440fx-11.1'}).text='hvm'
    ET.SubElement(osel,'boot',{'dev':'hd'})
    features=ET.SubElement(root,'features')
    ET.SubElement(features,'acpi');ET.SubElement(features,'apic')
    ET.SubElement(root,'cpu',{'mode':'host-model'})
    ET.SubElement(root,'clock',{'offset':'utc'})
    for tag in ('on_poweroff','on_reboot','on_crash'):
        ET.SubElement(root,tag).text='destroy'
    pm=ET.SubElement(root,'pm')
    ET.SubElement(pm,'suspend-to-mem',{'enabled':'no'})
    ET.SubElement(pm,'suspend-to-disk',{'enabled':'no'})
    devices=ET.SubElement(root,'devices')
    ET.SubElement(devices,'emulator').text='/usr/bin/qemu-system-x86_64'
    disk=ET.SubElement(devices,'disk',{'type':'file','device':'disk'})
    ET.SubElement(disk,'driver',{'name':'qemu','type':'qcow2','cache':'none','io':'native'})
    ET.SubElement(disk,'source',{'file':f'{R32_STAGE}/{role}-runtime.qcow2'})
    ET.SubElement(disk,'target',{'dev':'vda','bus':'virtio'})
    for segment,_ip,mac,tap in cfg['nics']:
        iface=ET.SubElement(devices,'interface',{'type':'network'})
        ET.SubElement(iface,'mac',{'address':mac})
        ET.SubElement(iface,'source',{'network':NETWORK_PREFIX+segment})
        ET.SubElement(iface,'target',{'dev':tap})
        ET.SubElement(iface,'model',{'type':'virtio'})
        # Deliberately MISSING filter definition until containment is separately authorized.
        # A premature domain start must fail if this filter is unresolved.
        ET.SubElement(iface,'filterref',{'filter':DENY_FILTER})
    ET.SubElement(devices,'controller',{'type':'virtio-serial','index':'0'})
    ch=ET.SubElement(devices,'channel',{'type':'unix'})
    ET.SubElement(ch,'target',{'type':'virtio','name':'org.qemu.guest_agent.0'})
    serial=ET.SubElement(devices,'serial',{'type':'pty'})
    ET.SubElement(serial,'target',{'port':'0'})
    vid=ET.SubElement(devices,'video')
    ET.SubElement(vid,'model',{'type':'vga','vram':'16384','heads':'1','primary':'yes'})
    ET.SubElement(devices,'memballoon',{'model':'none'})
    return _xml_bytes(root)


def _xml_inventory(file_map: dict[str,bytes]) -> list[dict[str,str]]:
    return [{'filename':name, 'sha256':digest(body)} for name,body in sorted(file_map.items())]


def render_xml(r32_sha: str) -> dict[str,bytes]:
    need(_sha_value(r32_sha), 'r32_digest_invalid')
    outputs = {f'network-{r}.xml':_network_xml(r32_sha,r) for r in NET_BRIDGE}
    outputs.update({f'domain-{r}.xml':_domain_xml(r32_sha,r) for r in ROLES})
    validate_xml(outputs)
    return outputs


def validate_xml(outputs: dict[str,bytes]) -> bool:
    need(type(outputs) is dict and len(outputs)==7, 'xml_file_count_invalid')
    need(set(outputs) == {f'network-{r}.xml' for r in NET_BRIDGE} |
         {f'domain-{r}.xml' for r in ROLES}, 'xml_filename_scope_invalid')
    observed_macs=[];observed_taps=[];observed_uuids=[]
    for role in NET_BRIDGE:
        root=ET.fromstring(outputs[f'network-{role}.xml'])
        observed_uuids.append(root.findtext('uuid'))
        need(root.tag=='network' and root.get('ipv6')=='no' and
             root.findtext('name')==NETWORK_PREFIX+role and
             root.find('bridge').get('name')==NET_BRIDGE[role] and
             root.find('dns').get('enable')=='no' and
             root.find('forward') is None and root.find('ip') is None and
             root.find('dhcp') is None, 'network_isolation_invalid')
    for role in ROLES:
        root=ET.fromstring(outputs[f'domain-{role}.xml'])
        observed_uuids.append(root.findtext('uuid'))
        disk=root.findall('devices/disk')
        ifaces=root.findall('devices/interface')
        observed_macs.extend([i.find('mac').get('address') for i in ifaces])
        observed_taps.extend([i.find('target').get('dev') for i in ifaces])
        need(root.tag=='domain' and root.get('type')=='kvm' and
             root.findtext('name')==DOMAIN_PREFIX+role and
             root.findtext('memory')==str(RESOURCE[role]['ram_mib']) and
             root.findtext('vcpu')==str(RESOURCE[role]['vcpus']) and
             len(disk)==1 and disk[0].find('source').get('file') ==
             f'{R32_STAGE}/{role}-runtime.qcow2' and
             len(ifaces)==len(RESOURCE[role]['nics']) and
             all(i.find('filterref') is not None and
                 i.find('filterref').get('filter')==DENY_FILTER for i in ifaces) and
             not root.findall('devices/graphics') and
             not root.findall('devices/hostdev') and
             not root.findall('devices/filesystem') and
             not root.findall('devices/redirdev') and
             not root.findall('devices/vsock') and
             root.find('on_reboot').text=='destroy', 'domain_safety_invalid')
        for i,(segment,_ip,mac,tap) in zip(ifaces,RESOURCE[role]['nics']):
            need(i.find('mac').get('address')==mac and
                 i.find('source').get('network')==NETWORK_PREFIX+segment and
                 i.find('target').get('dev')==tap, 'domain_nic_identity_invalid')
    need(len(set(observed_macs))==len(observed_macs) and
         len(set(observed_taps))==len(observed_taps) and
         len(set(observed_uuids))==len(observed_uuids), 'duplicate_libvirt_identity')
    return True


def make_report(source: dict[str,Any], file_sha: str, *, prepared: bool=False) -> dict[str,Any]:
    verify_r32(source)
    need(file_sha == R32_RECEIPT_FILE_SHA256, 'r32_file_pin_invalid')
    docs=render_xml(file_sha)
    report={
        'schema':SCHEMA,
        'mode':'XML_PREPARED_ONLY' if prepared else 'PLAN_ONLY',
        'source_r32_file_sha256':file_sha,
        'source_r32_report_sha256':source['sha256'],
        'files':_xml_inventory(docs),
        'network_names':[NETWORK_PREFIX+r for r in NET_BRIDGE],
        'domain_names':[DOMAIN_PREFIX+r for r in ROLES],
        'mandatory_absent_filter':DENY_FILTER,
        'topology_xml_prepared':prepared,
        'libvirt_definitions_created':False,
        'network_started':False,
        'vm_started':False,
        'host_firewall_modified':False,
        'guest_checks_executed':False,
        'operational_dispatch':False,
        'can_restore':False,
        'technical_truth_accredited':False,
        'final_risk':None,
        'published_generation':None,
        'p8_operational':'NO-GO',
        'experimental_validation':'NOT_RUN',
        'next_gate':'R34_CONTAINMENT_AND_SEPARATE_DEPLOYMENT_AUTHORIZATION',
    }
    report['sha256']=digest(canon(report))
    verify_report(report)
    return report


def verify_report(report: dict[str,Any]) -> bool:
    need(type(report) is dict and _sha_value(report.get('sha256')) and
         digest(canon({k:v for k,v in report.items() if k!='sha256'})) == report['sha256'],
         'r33_report_digest_invalid')
    need(report.get('schema')==SCHEMA and
         report.get('source_r32_file_sha256')==R32_RECEIPT_FILE_SHA256 and
         _sha_value(report.get('source_r32_report_sha256')) and
         report.get('mode') in ('PLAN_ONLY','XML_PREPARED_ONLY') and
         report.get('topology_xml_prepared') is (report['mode']=='XML_PREPARED_ONLY') and
         report.get('network_names')==[NETWORK_PREFIX+r for r in NET_BRIDGE] and
         report.get('domain_names')==[DOMAIN_PREFIX+r for r in ROLES] and
         report.get('mandatory_absent_filter')==DENY_FILTER and
         report.get('next_gate')=='R34_CONTAINMENT_AND_SEPARATE_DEPLOYMENT_AUTHORIZATION' and
         all(report.get(k) is False for k in (
             'libvirt_definitions_created','network_started','vm_started',
             'host_firewall_modified','guest_checks_executed',
             'operational_dispatch','can_restore','technical_truth_accredited')) and
         report.get('p8_operational')=='NO-GO' and
         report.get('experimental_validation')=='NOT_RUN' and
         report.get('final_risk') is None and report.get('published_generation') is None and
         report.get('files')==_xml_inventory(render_xml(R32_RECEIPT_FILE_SHA256)),
         'r33_false_claim_or_xml_drift')
    return True


def _check_private_empty_directory(directory: Path) -> None:
    need(isinstance(directory,Path) and directory.is_absolute() and directory.is_dir(),
         'receipt_directory_invalid')
    need(not any(p.is_symlink() for p in (directory,*directory.parents)),
         'receipt_parent_symlink')
    st=directory.stat()
    need(st.st_uid == os.geteuid() and (st.st_mode & 0o077) == 0 and
         list(directory.iterdir()) == [], 'receipt_directory_not_private_or_empty')


def prepare_xml(directory: Path, source: dict[str,Any], file_sha: str) -> dict[str,Any]:
    """Persist seven OFFLINE XML files and a sealed report; never overwrite or cleanup."""
    _check_private_empty_directory(directory)
    data=render_xml(file_sha)
    report=make_report(source,file_sha,prepared=True)
    names=set(data) | {'r33_topology_receipt.json'}
    need(len(names)==8 and not any((directory/n).exists() or (directory/n).is_symlink()
                              for n in names), 'xml_destination_exists')
    for name,raw in sorted(data.items()):
        _write_exclusive(directory/name, raw)
        need(digest((directory/name).read_bytes())==digest(raw), 'written_xml_digest_mismatch')
    _write_exclusive(directory/'r33_topology_receipt.json',canon(report)+b'\n')
    return report


def _write_exclusive(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
