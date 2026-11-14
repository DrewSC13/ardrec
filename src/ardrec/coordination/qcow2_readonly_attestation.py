"""P14-R31: bounded read-only audit of known local ARDREC QCOW2 assets.

This is NOT a VM launcher or an operational identity authority. Optional sudo
runs only fixed system binaries with exact pinned paths, without a shell or a
root-executed Python script. No restoration or P8 authorization is possible.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable

from ardrec.coordination.restoration_inventory import (
    BASE_ROOT, RUNTIME_ROOT, HISTORIC_BASES, ROLES,
    canonical, read_bounded, verify_report as verify_r30,
)

SCHEMA = 'ardrec-p14-r31-qcow2-readonly-attestation-v1'
DIGEST = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
FIELD_FORMAT = '%F|%u|%g|%h|%a|%s|%i|%Y|%Z'
MAX_JSON = 131072
MAX_OUTPUT = 32768
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'}


class AssetAuditError(ValueError):
    pass


def need(value: bool, reason: str) -> None:
    if not value:
        raise AssetAuditError(reason)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_r30(path: Path, expected_file_sha: str) -> tuple[dict[str, Any], str]:
    need(type(expected_file_sha) is str and DIGEST.fullmatch(expected_file_sha) is not None,
         'r30_file_sha_invalid')
    doc, raw = read_bounded(path, MAX_JSON)
    need(sha256(raw) == expected_file_sha, 'r30_file_sha_mismatch')
    verify_r30(doc)
    need(doc['mode'] == 'READONLY_QCOW2_METADATA' and
         doc['host'] == 'Prometheus' and doc['p8_operational'] == 'NO-GO' and
         doc['can_restore'] is False and
         [x['role'] for x in doc['roles']] == list(ROLES), 'r30_scope_invalid')
    for r in doc['roles']:
        role = r['role']
        need(r['historical_base_sha256'] == HISTORIC_BASES[role][0] and
             r['historical_base_path'] == f'{BASE_ROOT}/{role}-base.qcow2' and
             r['historical_runtime_path'] == f'{RUNTIME_ROOT}/{role}-runtime.qcow2',
             'r30_paths_or_pins_changed')
    return doc, expected_file_sha


def run_readonly(argv: list[str], *, runner: Callable[..., Any], timeout: int) -> bytes | None:
    need(type(argv) is list and len(argv) >= 5 and argv[:3] ==
         ['/usr/bin/sudo', '-n', '--'], 'privileged_argv_invalid')
    binary = argv[3]
    allowed_paths={file_path(role,kind) for role in ROLES for kind in ('base','overlay')}
    parent_paths={p for path in allowed_paths for p in path_parts(path)}
    if binary == '/usr/bin/stat':
        need(len(argv) == 7 and argv[4:6] == ['--printf='+FIELD_FORMAT,'--'] and
             argv[6] in parent_paths, 'privileged_stat_scope_invalid')
    elif binary == '/usr/bin/sha256sum':
        need(len(argv) == 7 and argv[4:6] == ['--binary','--'] and
             argv[6] in allowed_paths, 'privileged_sha_scope_invalid')
    elif binary == '/usr/bin/qemu-img':
        need(len(argv) == 9 and argv[4:8] ==
             ['info','--output=json','-f','qcow2'] and
             argv[8] in allowed_paths, 'privileged_qemu_scope_invalid')
    else:
        raise AssetAuditError('privileged_binary_forbidden')
    need(type(timeout) is int and 1 <= timeout <= 180, 'timeout_invalid')
    try:
        p = runner(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, timeout=timeout, check=False,
                   close_fds=True, env=ENV)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if (type(p.returncode) is not int or p.returncode != 0 or
        type(p.stdout) is not bytes or len(p.stdout) == 0 or
        len(p.stdout) > MAX_OUTPUT):
        return None
    return p.stdout


def file_path(role: str, kind: str) -> str:
    need(role in ROLES and kind in ('base', 'overlay'), 'invalid_role_or_kind')
    return (BASE_ROOT + '/' + role + '-base.qcow2' if kind == 'base'
            else RUNTIME_ROOT + '/' + role + '-runtime.qcow2')


def path_parts(path: str) -> list[str]:
    # All paths are fixed by file_path, not derived from user input.
    parts = Path(path).parts
    need(parts[0] == '/' and '..' not in parts and len(parts) == 7,
         'unsafe_asset_path')
    return ['/' + '/'.join(parts[1:i+1]) for i in range(1, len(parts))]


def stat_line(path: str, runner: Callable[..., Any]) -> dict[str, Any] | None:
    out = run_readonly(['/usr/bin/sudo','-n','--','/usr/bin/stat',
                        '--printf='+FIELD_FORMAT, '--', path], runner=runner, timeout=10)
    if out is None:
        return None
    try:
        fields = out.decode('ascii').split('|')
        need(len(fields) == 9, 'stat_fields_invalid')
        kind = fields[0]
        need(kind in ('regular file', 'directory', 'symbolic link'), 'stat_type_invalid')
        integers = [int(x, 10) for x in fields[1:4]]
        mode_str = fields[4]
        need(bool(re.fullmatch(r'[0-7]{3,4}', mode_str)), 'stat_mode_invalid')
        more = [int(x, 10) for x in fields[5:]]
        need(all(x >= 0 for x in integers + more), 'stat_number_invalid')
    except (ValueError, UnicodeError, AssetAuditError):
        return None
    return {'kind':kind,'uid':integers[0],'gid':integers[1],
            'nlink':integers[2], 'mode':int(mode_str,8), 'size':more[0],
            'inode':more[1], 'mtime':more[2], 'ctime':more[3]}


def validate_path(path: str, kind: str, runner: Callable[..., Any]) -> dict[str, Any] | None:
    steps = path_parts(path)
    for parent in steps[:-1]:
        s = stat_line(parent, runner)
        if (s is None or s['kind'] != 'directory' or s['uid'] != 0 or
            s['mode'] & 0o022):
            return None
    s = stat_line(path, runner)
    if s is None or s['kind'] != 'regular file' or s['nlink'] != 1 or s['uid'] not in (0, 64055):
        return None
    if kind == 'base' and s['mode'] & 0o222:
        return None
    if kind == 'overlay' and s['mode'] & 0o077:
        return None
    return s


def hash_file(path: str, runner: Callable[..., Any]) -> str | None:
    out = run_readonly(['/usr/bin/sudo','-n','--','/usr/bin/sha256sum',
                        '--binary','--',path], runner=runner, timeout=180)
    if out is None:
        return None
    try:
        s = out.decode('ascii').rstrip('\n')
    except UnicodeError:
        return None
    match = re.fullmatch(r'([0-9a-f]{64}) \*' + re.escape(path), s)
    return match.group(1) if match else None


def info_file(path: str, runner: Callable[..., Any]) -> dict[str, Any] | None:
    out = run_readonly(['/usr/bin/sudo','-n','--','/usr/bin/qemu-img',
                        'info','--output=json','-f','qcow2',path],runner=runner,timeout=25)
    if out is None:
        return None
    try:
        d = json.loads(out.decode('utf-8'))
    except (ValueError, UnicodeError, TypeError):
        return None
    if type(d) is not dict:
        return None
    return {'format':d.get('format'),'virtual_size':d.get('virtual-size'),
            'backing_filename':d.get('backing-filename')}


def inspect_one(role: str, kind: str, runner: Callable[..., Any]) -> dict[str, Any]:
    path = file_path(role, kind)
    out = {'path':path,'status':'NOT_VERIFIED','sha256_current':None,
           'historical_base_hash_match':False,'metadata_match':False}
    before = validate_path(path, kind, runner)
    if before is None:
        out['status'] = 'ACCESS_OR_PATH_GUARD_FAILED'
        return out
    current_sha = hash_file(path, runner)
    info = info_file(path, runner)
    after = validate_path(path, kind, runner)
    if current_sha is None or info is None or after is None or before != after:
        out['status'] = 'UNSTABLE_OR_READ_FAILED'
        return out
    expected_size = HISTORIC_BASES[role][1] * 1024**3
    expected_backing = None if kind == 'base' else file_path(role,'base')
    metadata_ok = (info['format'] == 'qcow2' and
                   type(info['virtual_size']) is int and info['virtual_size'] == expected_size and
                   info['backing_filename'] in ((None,'') if kind == 'base' else (expected_backing,)))
    out['sha256_current'] = current_sha
    out['historical_base_hash_match'] = kind == 'base' and current_sha == HISTORIC_BASES[role][0]
    out['metadata_match'] = metadata_ok
    out['status'] = ('READONLY_VERIFIED' if metadata_ok and
                     (kind == 'overlay' or out['historical_base_hash_match'])
                     else 'HASH_OR_QCOW2_METADATA_MISMATCH')
    return out


def build_report(r30: dict[str, Any], r30_file_sha: str, *,
                 mode: str, runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    need(mode in ('PLAN_ONLY','EXPLICIT_SUDO_READONLY'), 'audit_mode_invalid')
    need(r30['p8_operational']=='NO-GO' and r30['mode']=='READONLY_QCOW2_METADATA',
         'r30_mode_invalid')
    roles=[]
    for role in ROLES:
        kinds={}
        for kind in ('base','overlay'):
            kinds[kind] = (inspect_one(role, kind, runner)
                           if mode == 'EXPLICIT_SUDO_READONLY'
                           else {'path':file_path(role,kind),'status':'NOT_RUN',
                                 'sha256_current':None,'historical_base_hash_match':False,
                                 'metadata_match':False})
        roles.append({'role':role,**kinds})
    base_count=sum(x['base']['status']=='READONLY_VERIFIED' for x in roles)
    overlay_count=sum(x['overlay']['status']=='READONLY_VERIFIED' for x in roles)
    report={
        'schema':SCHEMA,'source_r30_file_sha256':r30_file_sha,
        'source_r30_report_sha256':r30['sha256'],
        'mode':mode,'roles':roles,
        'base_hashes_matching_count':base_count,
        'overlay_metadata_matching_count':overlay_count,
        'summary':('FOUR_BASES_AND_OVERLAYS_READONLY_OBSERVED_NOT_RESTORABLE'
                   if base_count==overlay_count==4
                   else 'CURRENT_ASSET_CUSTODY_INCOMPLETE'),
        'host':'Prometheus','images_mutated':False,'vm_started':False,
        'network_probe_performed':False,'restoration_performed':False,
        'operational_dispatch':False,'can_restore':False,
        'backing_chain_custody_accredited':False,'technical_truth_accredited':False,
        'final_risk':None,'published_generation':None,
        'p8_operational':'NO-GO','experimental_validation':'NOT_RUN',
    }
    report['sha256']=sha256(canonical(report))
    verify_report(report)
    return report


def verify_report(doc: dict[str, Any]) -> bool:
    need(type(doc) is dict and type(doc.get('sha256')) is str and
         DIGEST.fullmatch(doc['sha256']) is not None, 'report_invalid')
    need(sha256(canonical({k:v for k,v in doc.items() if k!='sha256'}))==doc['sha256'],
         'report_digest_invalid')
    need(doc.get('schema')==SCHEMA and doc.get('host')=='Prometheus' and
         type(doc.get('source_r30_file_sha256')) is str and
         DIGEST.fullmatch(doc['source_r30_file_sha256']) is not None and
         type(doc.get('source_r30_report_sha256')) is str and
         DIGEST.fullmatch(doc['source_r30_report_sha256']) is not None and
         doc.get('p8_operational')=='NO-GO' and
         doc.get('experimental_validation')=='NOT_RUN' and
         doc.get('final_risk') is None and doc.get('published_generation') is None and
         type(doc.get('roles')) is list and
         [x.get('role') for x in doc['roles']] == list(ROLES) and
         doc.get('mode') in ('PLAN_ONLY','EXPLICIT_SUDO_READONLY') and
         all(doc.get(k) is False for k in ('images_mutated','vm_started',
             'network_probe_performed','restoration_performed','operational_dispatch',
             'can_restore','backing_chain_custody_accredited','technical_truth_accredited')),
         'false_operational_claim')
    for r in doc['roles']:
        for kind in ('base','overlay'):
            a=r[kind]
            need(type(a) is dict and a['path']==file_path(r['role'],kind) and
                 a['status'] in ('READONLY_VERIFIED','NOT_RUN','ACCESS_OR_PATH_GUARD_FAILED',
                                 'UNSTABLE_OR_READ_FAILED','HASH_OR_QCOW2_METADATA_MISMATCH') and
                 type(a['metadata_match']) is bool and
                 type(a['historical_base_hash_match']) is bool and
                 (a['sha256_current'] is None or
                  (type(a['sha256_current']) is str and DIGEST.fullmatch(a['sha256_current']))) and
                 (kind=='base' or a['historical_base_hash_match'] is False) and
                 (a['status']!='READONLY_VERIFIED' or
                  (a['metadata_match'] and a['sha256_current'] is not None and
                   (kind=='overlay' or
                    (a['historical_base_hash_match'] and
                     a['sha256_current']==HISTORIC_BASES[r['role']][0])))) and
                 (doc['mode']!='PLAN_ONLY' or
                  (a['status']=='NOT_RUN' and a['sha256_current'] is None and
                   a['metadata_match'] is False)) and
                 (a['status']!='NOT_RUN' or a['sha256_current'] is None),
                 'asset_scope_or_claim_invalid')
    need(type(doc.get('base_hashes_matching_count')) is int and
         type(doc.get('overlay_metadata_matching_count')) is int and
         doc['base_hashes_matching_count']==sum(x['base']['status']=='READONLY_VERIFIED' for x in doc['roles']) and
         doc['overlay_metadata_matching_count']==sum(x['overlay']['status']=='READONLY_VERIFIED' for x in doc['roles']) and
         doc['summary']==('FOUR_BASES_AND_OVERLAYS_READONLY_OBSERVED_NOT_RESTORABLE'
                          if doc['base_hashes_matching_count']==doc['overlay_metadata_matching_count']==4
                          else 'CURRENT_ASSET_CUSTODY_INCOMPLETE'),
         'count_or_summary_mismatch')
    return True
