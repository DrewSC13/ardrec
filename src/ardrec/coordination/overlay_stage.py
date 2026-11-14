"""P14-R32: materialización acotada de overlays QCOW2 nuevos, sin arrancar VM.

Solo rutas constantes de laboratorio. Python corre con UID normal; sudo -n ejecuta
binarios absolutos allowlisted sin shell. El fallo conserva artefactos y NO-GO.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
from typing import Any, Callable

from ardrec.coordination.qcow2_readonly_attestation import (
    ROLES, HISTORIC_BASES, file_path, read_bounded, verify_report as verify_r31,
    canonical, stat_line, hash_file, info_file, sha256, DIGEST, ENV, FIELD_FORMAT,
)

SCHEMA = 'ardrec-p14-r32-overlay-materialization-v1'
STAGE_DIR = '/var/lib/libvirt/images/ardrec-dev-point4-r32'
POOL = '/var/lib/libvirt/images'
ALLOWED_READONLY = ('stat', 'sha256sum', 'qemu-img info')
QEMU_UID = 64055
MIN_FREE_BYTES = 40 * 1024 ** 3


class StageError(ValueError):
    pass


def need(ok: bool, code: str) -> None:
    if not ok:
        raise StageError(code)


def target_path(role: str) -> str:
    need(role in ROLES, 'invalid_role')
    return STAGE_DIR + '/' + role + '-runtime.qcow2'


def load_r31(path: Path, expected_file_sha: str) -> tuple[dict[str, Any], str]:
    need(type(expected_file_sha) is str and DIGEST.fullmatch(expected_file_sha) is not None,
         'r31_file_sha_invalid')
    doc, raw = read_bounded(path, 131072)
    need(sha256(raw) == expected_file_sha, 'r31_file_hash_mismatch')
    try:
        verify_r31(doc)
    except ValueError as e:
        raise StageError('r31_report_invalid') from e
    need(doc['host'] == 'Prometheus' and doc['mode'] == 'EXPLICIT_SUDO_READONLY' and
         doc['p8_operational'] == 'NO-GO' and doc['can_restore'] is False and
         doc['base_hashes_matching_count'] == 4 and
         doc['overlay_metadata_matching_count'] == 4 and
         doc['summary'] == 'FOUR_BASES_AND_OVERLAYS_READONLY_OBSERVED_NOT_RESTORABLE',
         'r31_not_fully_verified')
    for role, entry in zip(ROLES, doc['roles']):
        need(entry['role'] == role and entry['base']['status'] == 'READONLY_VERIFIED' and
             entry['overlay']['status'] == 'READONLY_VERIFIED' and
             entry['base']['sha256_current'] == HISTORIC_BASES[role][0] and
             entry['overlay']['sha256_current'] is not None and
             entry['overlay']['metadata_match'] is True,
             'r31_role_not_fully_verified')
    return doc, expected_file_sha


def build_plan(r31: dict[str, Any], file_sha: str) -> dict[str, Any]:
    need(r31['mode'] == 'EXPLICIT_SUDO_READONLY' and r31['base_hashes_matching_count'] == 4 and
         r31['overlay_metadata_matching_count'] == 4, 'r31_plan_scope_invalid')
    rows = []
    for entry in r31['roles']:
        role = entry['role']
        rows.append({
            'role': role,
            'parent_overlay': file_path(role, 'overlay'),
            'parent_overlay_sha256': entry['overlay']['sha256_current'],
            'source_base': file_path(role, 'base'),
            'source_base_sha256': entry['base']['sha256_current'],
            'new_overlay': target_path(role),
            'virtual_size': HISTORIC_BASES[role][1] * 1024**3,
        })
    plan = {
        'schema': SCHEMA, 'mode': 'PLAN_ONLY', 'host': 'Prometheus',
        'source_r31_file_sha256': file_sha, 'source_r31_report_sha256': r31['sha256'],
        'stage_directory': STAGE_DIR, 'roles': rows,
        'storage_prepared': False, 'new_overlays_created': 0,
        'vm_started': False, 'network_created': False, 'guest_checked': False,
        'operational_dispatch': False, 'can_restore': False, 'restoration_performed': False,
        'p8_operational': 'NO-GO', 'technical_truth_accredited': False,
        'published_generation': None, 'final_risk': None,
        'experimental_validation': 'NOT_RUN',
    }
    plan['sha256'] = sha256(canonical(plan))
    verify_plan(plan)
    return plan


def verify_plan(plan: dict[str, Any]) -> bool:
    need(type(plan) is dict and type(plan.get('sha256')) is str and
         DIGEST.fullmatch(plan['sha256']) is not None and
         sha256(canonical({k:v for k,v in plan.items() if k!='sha256'})) == plan['sha256'],
         'plan_digest_invalid')
    need(plan.get('schema') == SCHEMA and plan.get('mode') == 'PLAN_ONLY' and
         plan.get('host') == 'Prometheus' and
         type(plan.get('source_r31_file_sha256')) is str and
         DIGEST.fullmatch(plan['source_r31_file_sha256']) is not None and
         type(plan.get('source_r31_report_sha256')) is str and
         DIGEST.fullmatch(plan['source_r31_report_sha256']) is not None and
         plan.get('stage_directory') == STAGE_DIR and
         plan.get('p8_operational') == 'NO-GO' and
         plan.get('new_overlays_created') == 0 and
         plan.get('storage_prepared') is False and
         [x.get('role') for x in plan.get('roles', [])] == list(ROLES) and
         all(plan.get(k) is False for k in ('vm_started','network_created','guest_checked',
              'operational_dispatch','can_restore','restoration_performed','technical_truth_accredited')) and
         plan.get('final_risk') is None and plan.get('published_generation') is None and
         plan.get('experimental_validation') == 'NOT_RUN', 'plan_claim_invalid')
    for row in plan['roles']:
        role = row['role']
        need(row['new_overlay'] == target_path(role) and
             row['parent_overlay'] == file_path(role, 'overlay') and
             row['source_base'] == file_path(role, 'base') and
             row['source_base_sha256'] == HISTORIC_BASES[role][0] and
             row['virtual_size'] == HISTORIC_BASES[role][1] * 1024**3 and
             type(row['parent_overlay_sha256']) is str and
             DIGEST.fullmatch(row['parent_overlay_sha256']) is not None,
             'plan_path_or_role_invalid')
    return True


def run_command(args: list[str], *, runner: Callable[..., Any], timeout: int = 30,
                elevated: bool = True) -> tuple[int, bytes, bytes]:
    need(type(args) is list and len(args)>=1 and all(type(x) is str for x in args), 'argv_invalid')
    if elevated:
        need(args[:3] == ['/usr/bin/sudo', '-n', '--'], 'sudo_prefix_invalid')
        cmd = args[3:]
        stage_files = {target_path(role) for role in ROLES}
        if cmd[0] == '/usr/bin/mkdir':
            ok = cmd == ['/usr/bin/mkdir', '--mode=0750', '--', STAGE_DIR]
        elif cmd[0] == '/usr/bin/chgrp':
            ok = len(cmd) == 4 and cmd[:3] == ['/usr/bin/chgrp',str(QEMU_UID),'--'] and (cmd[3] == STAGE_DIR or cmd[3] in stage_files)
        elif cmd[0] == '/usr/bin/chown':
            ok = len(cmd)==4 and cmd[:3]==['/usr/bin/chown',str(QEMU_UID)+':'+str(QEMU_UID),'--'] and cmd[3] in stage_files
        elif cmd[0] == '/usr/bin/chmod':
            ok = len(cmd) == 4 and cmd[2] == '--' and ((cmd[1]=='0750' and cmd[3] == STAGE_DIR) or (cmd[1]=='0600' and cmd[3] in stage_files))
        elif cmd[0] == '/usr/bin/qemu-img':
            ok = len(cmd)==9 and cmd[1:7]==['create','-f','qcow2','-F','qcow2','-b'] and any(cmd[7]==file_path(role,'overlay') and cmd[8]==target_path(role) for role in ROLES)
            ok = ok or (len(cmd)==6 and cmd[1:5]==['info','--output=json','-f','qcow2'] and cmd[5] in stage_files)
        elif cmd[0] == '/usr/bin/stat':
            ok = len(cmd)==4 and cmd[1:3]==['--printf='+FIELD_FORMAT,'--'] and (cmd[3]==STAGE_DIR or cmd[3] in stage_files)
        elif cmd[0] == '/usr/bin/sha256sum':
            ok = len(cmd)==4 and cmd[1:3]==['--binary','--'] and cmd[3] in stage_files
        else:
            ok = False
        need(ok, 'privileged_argv_out_of_scope')
    else:
        cmd = args
        need(cmd[:4] == ['/usr/bin/virsh','--readonly','-c','qemu:///system'] and
             cmd[4:] in (['list','--all','--name'], ['list','--name'], ['net-list','--all','--name']),
             'virsh_scope_invalid')
    need(type(timeout) is int and 1 <= timeout <= 240, 'timeout_invalid')
    try:
        p = runner(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, check=False, timeout=timeout,
                   close_fds=True, env=ENV)
    except (OSError, subprocess.TimeoutExpired):
        raise StageError('subprocess_failed') from None
    need(type(p.returncode) is int and type(p.stdout) is bytes and type(p.stderr) is bytes and
         len(p.stdout) <= 32768 and len(p.stderr) <= 32768, 'command_output_invalid')
    return p.returncode, p.stdout, p.stderr


def sudo(argv: list[str], runner: Callable[..., Any], timeout: int = 30) -> bytes:
    rc, out, _ = run_command(['/usr/bin/sudo', '-n', '--', *argv], runner=runner, timeout=timeout)
    need(rc == 0, 'sudo_command_failed_' + Path(argv[0]).name)
    return out


def stage_stat(path: str, runner: Callable[..., Any]) -> dict[str, Any]:
    raw = sudo(['/usr/bin/stat','--printf='+FIELD_FORMAT,'--',path],runner)
    fields = raw.decode('ascii').split('|')
    need(len(fields)==9 and fields[0] in ('directory','regular file'), 'stage_stat_invalid')
    values = [int(x) for x in fields[1:4]]
    need(re.fullmatch('[0-7]{3,4}', fields[4]) is not None, 'stage_mode_invalid')
    others = [int(x) for x in fields[5:]]
    need(all(x>=0 for x in values+others), 'stage_stat_negative')
    return {'kind':fields[0],'uid':values[0],'gid':values[1],'nlink':values[2],
            'mode':int(fields[4],8),'size':others[0], 'inode':others[1],
            'mtime':others[2], 'ctime':others[3]}


def stage_hash(path: str, runner: Callable[..., Any]) -> str:
    raw = sudo(['/usr/bin/sha256sum','--binary','--',path],runner,timeout=120)
    text = raw.decode('ascii').rstrip('\n')
    m = re.fullmatch(r'([0-9a-f]{64}) \*'+re.escape(path),text)
    need(m is not None,'stage_hash_invalid')
    return m.group(1)


def stage_info(path: str, runner: Callable[..., Any]) -> dict[str,Any]:
    raw = sudo(['/usr/bin/qemu-img','info','--output=json','-f','qcow2',path],runner)
    result = json.loads(raw.decode('utf8'))
    need(type(result) is dict,'stage_qcow2_invalid')
    return result


def host_is_idle(runner: Callable[..., Any]) -> None:
    for args in (['list','--all','--name'], ['list','--name'], ['net-list','--all','--name']):
        rc, out, _ = run_command(['/usr/bin/virsh', '--readonly', '-c',
                                  'qemu:///system', *args],runner=runner,elevated=False)
        need(rc == 0, 'libvirt_readonly_unavailable')
        names = [s.strip() for s in out.decode('utf-8').splitlines() if s.strip()]
        need(not any(x.startswith('ardrec-') for x in names), 'ardrec_resource_residual')
        if args == ['list','--name']:
            need(not names, 'active_libvirt_domain')


def check_storage_parent(runner: Callable[..., Any]) -> None:
    # The same strict sudo path guardians from R31, plus an authorized libvirt pool.
    for path in ('/var', '/var/lib', '/var/lib/libvirt', POOL):
        s = stat_line(path, runner)
        need(s is not None and s['kind'] == 'directory' and s['uid'] == 0 and
             (s['mode'] & 0o022) == 0, 'untrusted_pool_parent')


def check_source_unchanged(plan: dict[str, Any], runner: Callable[..., Any]) -> None:
    for row in plan['roles']:
        for kind, path, digest in (
            ('base', row['source_base'], row['source_base_sha256']),
            ('overlay', row['parent_overlay'], row['parent_overlay_sha256']),
        ):
            parent = stat_line(str(Path(path).parent), runner)
            need(parent is not None and parent['kind']=='directory' and parent['uid']==0 and
                 (parent['mode'] & 0o022)==0, 'source_parent_permission_drift')
            s = stat_line(path, runner)
            need(s is not None and s['kind'] == 'regular file' and s['nlink'] == 1 and
                 s['uid'] in (0,QEMU_UID) and
                 (s['mode'] & (0o222 if kind == 'base' else 0o077)) == 0,
                 'source_file_permission_drift')
            need(hash_file(path, runner) == digest, 'source_digest_drift')
            info = info_file(path, runner)
            expected = (None, '') if kind == 'base' else (row['source_base'],)
            need(info is not None and info['format'] == 'qcow2' and
                 info['virtual_size'] == row['virtual_size'] and
                 info['backing_filename'] in expected, 'source_backing_drift')


def execute_staging(plan: dict[str, Any], *, runner: Callable[..., Any] = subprocess.run,
                    min_free_bytes: int = MIN_FREE_BYTES) -> dict[str, Any]:
    """Creates FOUR NEW overlays only after strict gates; no retry after partial failure.

    Any failure preserves partially materialized assets for operator forensic review.
    """
    verify_plan(plan)
    need(type(min_free_bytes) is int and min_free_bytes >= MIN_FREE_BYTES,
         'disk_reserve_must_not_be_lowered')
    result = {**{k:v for k,v in plan.items() if k != 'sha256'},
              'mode':'EXPLICIT_STORAGE_STAGING', 'stage_status':'NOT_STARTED',
              'new_overlays_created':0, 'storage_prepared':False,
              'new_assets':[], 'failure_code':None,
              'source_images_mutated':False, 'stage_directory_created':False}
    try:
        host_is_idle(runner)
        check_storage_parent(runner)
        need(shutil.disk_usage(POOL).free >= min_free_bytes, 'insufficient_free_storage')
        check_source_unchanged(plan, runner)
        # mkdir, NOT install -d: cannot touch existing stage folders. Exclusive.
        sudo(['/usr/bin/mkdir', '--mode=0750', '--', STAGE_DIR], runner)
        result['stage_directory_created'] = True
        sudo(['/usr/bin/chgrp', str(QEMU_UID), '--', STAGE_DIR], runner)
        sudo(['/usr/bin/chmod', '0750', '--', STAGE_DIR], runner)
        ds = stage_stat(STAGE_DIR, runner)
        need(ds is not None and ds['kind']=='directory' and ds['uid']==0 and
             ds['gid']==QEMU_UID and ds['mode']==0o750,
             'new_directory_verification_failed')
        for row in plan['roles']:
            new = row['new_overlay']
            parent = row['parent_overlay']
            sudo(['/usr/bin/qemu-img','create','-f','qcow2','-F','qcow2',
                  '-b',parent,new], runner, timeout=35)
            result['new_overlays_created'] += 1
            sudo(['/usr/bin/chown',str(QEMU_UID)+':'+str(QEMU_UID),'--',new], runner)
            sudo(['/usr/bin/chmod','0600','--',new], runner)
            s = stage_stat(new, runner)
            info = stage_info(new, runner)
            digest = stage_hash(new, runner)
            need(s is not None and s['kind']=='regular file' and s['uid']==QEMU_UID and
                 s['gid']==QEMU_UID and s['nlink']==1 and s['mode']==0o600 and
                 info is not None and info['format']=='qcow2' and
                 info.get('virtual-size')==row['virtual_size'] and
                 info.get('backing-filename')==parent and
                 digest is not None,
                 'new_overlay_verification_failed')
            result['new_assets'].append({'role':row['role'],'path':new,
                                         'sha256':digest, 'backing_filename':parent,
                                         'virtual_size':row['virtual_size']})
        check_source_unchanged(plan, runner)
        result['storage_prepared'] = True
        result['stage_status'] = 'FOUR_NEW_COW_OVERLAYS_VERIFIED_NOT_STARTED'
    except (StageError, OSError, ValueError) as ex:
        result['stage_status'] = 'INCOMPLETE_REVIEW_REQUIRED'
        result['failure_code'] = str(ex)[:128]
    result['sha256'] = sha256(canonical(result))
    return result


def validate_receipt_path(path: Path) -> None:
    need(isinstance(path, Path) and path.name == 'r32_staging.json' and
         path.parent.is_dir() and not path.parent.is_symlink() and
         (path.parent.stat().st_mode & 0o077) == 0 and
         not path.exists() and not path.is_symlink(), 'receipt_dir_invalid')


def write_receipt(path: Path, data: dict[str, Any]) -> Path:
    """Operator-owned private receipt, no overwrite, no symlink, no credentials."""
    validate_receipt_path(path)
    body = canonical(data)+b'\n'
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(body)
        f.flush()
        os.fsync(f.fileno())
    return path
