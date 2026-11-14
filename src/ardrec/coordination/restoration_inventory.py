"""P14-R30: inventario actual de artefactos QCOW2, solo lectura.

No restaura, copia, escribe ni arranca imágenes. Los hashes de R8 son históricos:
la coincidencia de metadatos nunca certifica bytes actuales ni autorización.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Callable

from ardrec.coordination.vm_host_preflight import verify_report as verify_r29

FORMAT = 'ardrec-p14-r30-qcow2-metadata-readonly-v1'
PROFILE = 'ardrec-p14-r30-restore-assets-expected-v1'
ROLES = ('ssh', 'ftp', 'smb', 'runner')
BASE_ROOT = '/var/lib/libvirt/images/ardrec-dev-point4-v4'
RUNTIME_ROOT = '/var/lib/libvirt/images/ardrec-dev-point4-v6'
HISTORIC_BASES = {
    'ssh': ('422aa101cc26463df4a9f651f9cc66ee3d646fd79fe1615a70de26e14efe0d62', 8),
    'ftp': ('7c7992c4446c550c1b98da93ebfbe2b0d133cd14bf5eb4b7bf7818164e2cb974', 8),
    'smb': ('ffeedf326e41f4679ae8cdb7a803a25f41671eaebcd7063740f40fd4584fa475', 12),
    'runner': ('fc9244fe29917f9bbeab09604a5845506dc3ab222b5c53648b5b90b2b1bf2103', 24),
}
HASH = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
MAX_PROFILE = 32768
MAX_R29 = 131072
MAX_QEMU_OUTPUT = 65536


class RestoreInventoryError(ValueError):
    pass


def need(ok: bool, message: str) -> None:
    if not ok:
        raise RestoreInventoryError(message)


def canonical(doc: Any) -> bytes:
    try:
        return json.dumps(doc, ensure_ascii=True, sort_keys=True, allow_nan=False,
                          separators=(',', ':')).encode('ascii')
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
        raise RestoreInventoryError('canonical_invalid') from exc


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for k, v in pairs:
        need(k not in obj, 'json_duplicate_key')
        obj[k] = v
    return obj


def read_bounded(path: Path, ceiling: int) -> tuple[dict[str, Any], bytes]:
    need(isinstance(path, Path) and not path.is_symlink() and path.is_file(),
         'input_path_invalid')
    need(0 < path.stat().st_size <= ceiling, 'input_size_invalid')
    data = path.read_bytes()
    need(0 < len(data) <= ceiling, 'input_size_invalid')
    try:
        doc = json.loads(data.decode('utf-8'), object_pairs_hook=unique,
                         parse_constant=lambda _: need(False, 'json_constant_forbidden'))
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise RestoreInventoryError('input_json_invalid') from exc
    need(type(doc) is dict, 'input_root_invalid')
    return doc, data


def read_profile(path: Path) -> tuple[dict[str, Any], str]:
    doc, raw = read_bounded(path, MAX_PROFILE)
    need(set(doc) == {'schema','origin','origin_scope','host','historical_base_root',
                      'historical_runtime_root','roles','read_only','authorization_to_restore',
                      'operational_dispatch','p8_operational'}, 'profile_keys')
    need(doc['schema'] == PROFILE and
         doc['origin'] == 'lab/services-v1/procedures/activation-r8.py' and
         doc['origin_scope'] == 'HISTORICAL_RECOVERY_PIN_NOT_CURRENT_ATTESTATION' and
         doc['host'] == 'Prometheus' and doc['historical_base_root'] == BASE_ROOT and
         doc['historical_runtime_root'] == RUNTIME_ROOT and
         doc['read_only'] is True and doc['authorization_to_restore'] is False and
         doc['operational_dispatch'] is False and doc['p8_operational'] == 'NO-GO',
         'profile_claim_invalid')
    roles = doc['roles']
    need(type(roles) is list and len(roles) == 4 and
         [row.get('role') if type(row) is dict else None for row in roles] == list(ROLES),
         'profile_roles_invalid')
    for role_doc in roles:
        role = role_doc['role']
        sha, gib = HISTORIC_BASES[role]
        need(set(role_doc) == {'role','base_path','runtime_path',
                               'base_sha256_historical','virtual_size_gib'},
             'profile_role_keys')
        need(role_doc['base_path'] == BASE_ROOT+'/'+role+'-base.qcow2' and
             role_doc['runtime_path'] == RUNTIME_ROOT+'/'+role+'-runtime.qcow2' and
             role_doc['base_sha256_historical'] == sha and
             type(role_doc['virtual_size_gib']) is int and
             role_doc['virtual_size_gib'] == gib, 'profile_role_mismatch')
    return doc, hashlib.sha256(raw).hexdigest()


def read_r29(path: Path, expected_sha: str) -> tuple[dict[str, Any], str]:
    need(type(expected_sha) is str and HASH.fullmatch(expected_sha) is not None,
         'r29_sha_invalid')
    doc, raw = read_bounded(path, MAX_R29)
    digest = hashlib.sha256(raw).hexdigest()
    need(digest == expected_sha, 'r29_source_digest_mismatch')
    # R29's --json CLI emits a linked view around vm_host_preflight.
    # Authenticate both levels before treating the nested preflight as input.
    if doc.get('schema') == 'ardrec-p14-r29-linked-lab-view-v1':
        need(set(doc) == {'schema','previous_cycle_sha256',
                          'vm_host_preflight','p8_operational',
                          'guest_checks_executed','sha256'},
             'r29_linked_keys_invalid')
        need(type(doc.get('previous_cycle_sha256')) is str and
             HASH.fullmatch(doc['previous_cycle_sha256']) is not None,
             'r29_cycle_reference_invalid')
        need(doc.get('p8_operational') == 'NO-GO' and
             doc.get('guest_checks_executed') is False,
             'r29_linked_false_authority')
        need(type(doc.get('sha256')) is str and
             HASH.fullmatch(doc['sha256']) is not None and
             hashlib.sha256(canonical({k:v for k,v in doc.items()
                                       if k!='sha256'})).hexdigest()==doc['sha256'],
             'r29_linked_digest_mismatch')
        doc = doc.get('vm_host_preflight')
        need(type(doc) is dict, 'r29_nested_report_invalid')
    verify_r29(doc)
    need(doc.get('mode') == 'READONLY_LIBVIRT' and
         doc.get('host_metadata_observed') is True and
         doc.get('host') == 'Prometheus' and
         doc.get('summary') == 'NO_NAMED_ARDREC_DOMAINS_OR_NETWORKS_IN_LIBVIRT_LIST' and
         not doc.get('ardrec_networks_listed') and
         not doc.get('unrecognized_ardrec_domains') and
         all(x['state'] == 'ABSENT_FROM_LIBVIRT_LIST' for x in doc['roles']),
         'r29_host_not_clear')
    return doc, digest


def mapped(root: Path, absolute: str) -> Path:
    need(isinstance(root, Path) and root.is_absolute() and
         type(absolute) is str and absolute.startswith('/') and
         '/..' not in absolute and '//' not in absolute, 'artifact_path_invalid')
    return root / absolute.lstrip('/')


def path_metadata(root: Path, absolute: str, *, base: bool) -> dict[str, Any]:
    """No open/read/write. Check leaf and ancestors with lstat (no symlink follow)."""
    path = mapped(root, absolute)
    current = root
    for segment in path.relative_to(root).parts:
        current = current / segment
        try:
            info = current.lstat()
        except FileNotFoundError:
            return {'state': 'ABSENT', 'mode': None, 'size': None}
        except PermissionError:
            return {'state': 'ACCESS_DENIED', 'mode': None, 'size': None}
        except OSError:
            return {'state': 'STAT_FAILED', 'mode': None, 'size': None}
        if stat.S_ISLNK(info.st_mode):
            return {'state': 'SYMLINK_REJECTED', 'mode': None, 'size': None}
        if current != path and not stat.S_ISDIR(info.st_mode):
            return {'state': 'UNEXPECTED_PARENT_TYPE', 'mode': None, 'size': None}
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in (0,64055):
        return {'state': 'UNEXPECTED_LEAF_IDENTITY', 'mode': oct(mode), 'size': info.st_size}
    if base and (mode & 0o222) != 0:
        return {'state': 'BASE_NOT_READONLY', 'mode': oct(mode), 'size': info.st_size}
    if not base and (mode & 0o077) != 0:
        return {'state': 'OVERLAY_PERMISSIONS_WEAK', 'mode': oct(mode), 'size': info.st_size}
    return {'state': 'REGULAR_METADATA_ONLY', 'mode': oct(mode), 'size': info.st_size}


def qemu_info(path: Path, *, runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    argv = ['/usr/bin/qemu-img','info','--output=json','-f','qcow2',str(path)]
    try:
        completed = runner(argv, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           check=False, timeout=20, close_fds=True,
                           env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'})
    except (OSError, subprocess.TimeoutExpired):
        return {'state':'QEMU_INFO_FAILED', 'format':None, 'virtual_size':None,
                'backing_filename':None}
    if (type(completed.returncode) is not int or completed.returncode != 0 or
        type(completed.stdout) is not bytes or len(completed.stdout) > MAX_QEMU_OUTPUT):
        return {'state':'QEMU_INFO_FAILED', 'format':None, 'virtual_size':None,
                'backing_filename':None}
    try:
        data = json.loads(completed.stdout.decode('utf-8'),object_pairs_hook=unique)
    except (ValueError,UnicodeError,TypeError):
        return {'state':'QEMU_INFO_INVALID', 'format':None, 'virtual_size':None,
                'backing_filename':None}
    if type(data) is not dict:
        return {'state':'QEMU_INFO_INVALID', 'format':None, 'virtual_size':None,
                'backing_filename':None}
    return {'state':'QEMU_INFO_READONLY', 'format':data.get('format'),
            'virtual_size':data.get('virtual-size'),
            'backing_filename':data.get('backing-filename')}


def scan_assets(profile: dict[str, Any], *, root: Path = Path('/'),
                runner: Callable[..., Any] = subprocess.run,
                scan: bool = False) -> list[dict[str, Any]]:
    results=[]
    for role in profile['roles']:
        entry={'role':role['role'], 'historical_base_sha256':role['base_sha256_historical'],
               'historical_base_path':role['base_path'],
               'historical_runtime_path':role['runtime_path'],
               'base':{'state':'NOT_SCANNED','mode':None,'size':None},
               'runtime':{'state':'NOT_SCANNED','mode':None,'size':None},
               'qcow2_base_metadata':None,'qcow2_runtime_metadata':None,
               'metadata_matches_historical':False,
               'current_base_content_sha256_verified':False,
               'current_overlay_content_sha256_verified':False}
        if scan:
            b=path_metadata(root,role['base_path'],base=True)
            t=path_metadata(root,role['runtime_path'],base=False)
            entry['base'],entry['runtime']=b,t
            if b['state']=='REGULAR_METADATA_ONLY':
                entry['qcow2_base_metadata']=qemu_info(mapped(root,role['base_path']),runner=runner)
            if t['state']=='REGULAR_METADATA_ONLY':
                entry['qcow2_runtime_metadata']=qemu_info(mapped(root,role['runtime_path']),runner=runner)
            qb,qt=entry['qcow2_base_metadata'],entry['qcow2_runtime_metadata']
            if qb is not None and qt is not None:
                size=role['virtual_size_gib']*1024**3
                entry['metadata_matches_historical']=(
                    qb['state']=='QEMU_INFO_READONLY' and qt['state']=='QEMU_INFO_READONLY' and
                    qb['format']=='qcow2' and qt['format']=='qcow2' and
                    type(qb['virtual_size']) is int and qb['virtual_size']==size and
                    type(qt['virtual_size']) is int and qt['virtual_size']==size and
                    qb['backing_filename'] in (None,'') and
                    qt['backing_filename']==role['base_path'])
        results.append(entry)
    return results


def collect(profile_path: Path, r29_path: Path, r29_sha: str, *,
            scan: bool, root: Path = Path('/'),
            runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    profile, profile_sha = read_profile(profile_path)
    r29, verified_r29_sha = read_r29(r29_path,r29_sha)
    roles=scan_assets(profile,root=root,runner=runner,scan=scan)
    count=sum(x['metadata_matches_historical'] for x in roles)
    report={
        'schema':FORMAT, 'host':profile['host'], 'mode':'READONLY_QCOW2_METADATA' if scan else 'HISTORICAL_PATHS_ONLY',
        'source_r29_file_sha256':verified_r29_sha, 'source_r29_report_sha256':r29['sha256'],
        'expected_profile_sha256':profile_sha, 'roles':roles,
        'metadata_matching_roles':count,
        'summary':'FOUR_METADATA_MATCH_BUT_UNTRUSTED' if count==4 else 'CURRENT_QCOW2_ASSETS_NOT_VERIFIED',
        'r29_no_named_resources':True,
        'actual_image_content_hashes_verified':False,
        'qcow2_backing_chain_custody_verified':False,
        'vm_guest_checks_executed':False,'networks_created':False,
        'images_mutated':False,'vm_started':False,'restoration_performed':False,
        'can_restore':False,'technical_truth_accredited':False,
        'operational_dispatch':False,'p8_operational':'NO-GO',
        'published_generation':None,'final_risk':None,
        'experimental_validation':'NOT_RUN',
    }
    report['sha256']=hashlib.sha256(canonical(report)).hexdigest()
    verify_report(report)
    return report


def verify_report(report: dict[str, Any]) -> bool:
    need(type(report) is dict and type(report.get('sha256')) is str,'report_invalid')
    need(hashlib.sha256(canonical({k:v for k,v in report.items() if k!='sha256'})).hexdigest()==report['sha256'],
         'report_digest_mismatch')
    need(report.get('schema')==FORMAT and report.get('host')=='Prometheus' and
         report.get('p8_operational')=='NO-GO' and
         all(report.get(k) is False for k in (
             'actual_image_content_hashes_verified','qcow2_backing_chain_custody_verified',
             'vm_guest_checks_executed','networks_created','images_mutated','vm_started',
             'restoration_performed','can_restore','technical_truth_accredited',
             'operational_dispatch')) and
         report.get('published_generation') is None and report.get('final_risk') is None and
         report.get('experimental_validation')=='NOT_RUN' and
         report.get('r29_no_named_resources') is True and
         type(report.get('roles')) is list and len(report['roles'])==4 and
         all(type(row) is dict for row in report['roles']) and
         [row['role'] for row in report['roles']] == list(ROLES) and
         all(row.get('current_base_content_sha256_verified') is False and
             row.get('current_overlay_content_sha256_verified') is False
             for row in report['roles']) and
         type(report.get('metadata_matching_roles')) is int and
         report['metadata_matching_roles'] == sum(
             row.get('metadata_matches_historical') is True for row in report['roles']),
         'report_false_authority')
    return True
