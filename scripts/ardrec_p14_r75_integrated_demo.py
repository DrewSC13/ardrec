#!/usr/bin/env python3
"""R75: crear/verificar una demostración sintética A1-A10 reproducible y autenticada localmente.

NO systemd, libvirt, nft, SSH/FTP/SMB, sudo, credenciales, apertura de P8 ni TUI curses.
Se invocan únicamente entradas Python locales fijadas; la verificación NO ejecuta A5.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.shadow_dashboard_bridge import build_shadow_dashboard
from ardrec.coordination.dashboard_tui import DashboardState, render_dashboard_frame, validate_dashboard_report
from ardrec.persistence.codec import canonical, digest

SCHEMA = 'ardrec-p14-r75-integrated-dev-demo-receipt-v1'
SOURCE = 'SYNTHETIC_A1_A10_NO_OPERATIONAL_AUTHORITY'
REPORTS = ('gen1.json', 'gen1_replay.json', 'shadow.json', 'shadow_replay.json',
           '54_units.json', '29_cases.json', 'r38_report.json', 'r38_pantalla.txt')
MAX_BYTES = 2_000_000

class R75Error(ValueError):
    pass

def need(condition: bool, reason: str) -> None:
    if not condition:
        raise R75Error(reason)

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def read_file(path: Path, *, max_bytes: int = MAX_BYTES) -> bytes:
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
         st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o600 and
         0 <= st.st_size <= max_bytes, 'untrusted_file_' + path.name)
    raw = path.read_bytes()
    need(len(raw) == st.st_size, 'changed_during_read_' + path.name)
    return raw

def write_file(path: Path, data: bytes) -> None:
    need(type(data) is bytes and len(data) <= MAX_BYTES, 'output_size_invalid')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())

def check_directory(root: Path, *, existing: bool) -> None:
    need(isinstance(root, Path) and root.is_absolute() and root != Path('/'), 'path_not_absolute')
    need(not any(p.is_symlink() for p in (root, *root.parents)), 'symlink_parent_forbidden')
    parent = root.parent
    ps = parent.stat()
    need(stat.S_ISDIR(ps.st_mode) and ps.st_uid == os.getuid() and
         stat.S_IMODE(ps.st_mode) == 0o700, 'private_parent_0700_required')
    if existing:
        st = root.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and
             stat.S_IMODE(st.st_mode) == 0o700, 'private_receipt_dir_required')
    else:
        need(not root.exists(), 'receipt_already_exists_no_retry')

def run_python(arguments: list[str]) -> bytes:
    # Intentional exact Python entrypoint allowlist, no shell or arbitrary command.
    base = [sys.executable, '-B']
    permitted = (['scripts/demo_p14_r21_a2_integrated_preview.py'],
                 ['scripts/ardrec_p14_r58k_unified_family_demo.py', '--synthetic-offline'])
    need(arguments[:1] == ['-m'] and arguments[1:2] == ['ardrec'] or
         arguments in permitted, 'python_command_not_permitted')
    if arguments[:2] == ['-m', 'ardrec']:
        need(all(a not in arguments for a in ('--tui', '--scenario')), 'interactive_or_external_input_forbidden')
    env = dict(os.environ)
    env['PYTHONPATH'] = str(REPO / 'src')
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    result = subprocess.run(base + arguments, cwd=REPO, env=env,
             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
             timeout=70, check=False, close_fds=True)
    need(result.returncode == 0 and len(result.stdout) <= MAX_BYTES and
         len(result.stderr) <= 4096, 'bounded_child_failed_' + str(result.returncode) +
         '_' + result.stderr.decode('utf-8', 'replace')[:130])
    return result.stdout

def validated_reports(blobs: dict[str, bytes]) -> dict[str, str]:
    need(set(blobs) == set(REPORTS), 'report_inventory_invalid')
    def j(name: str) -> dict[str, Any]:
        raw = blobs[name]
        need(len(raw) <= MAX_BYTES, 'oversized_report_' + name)
        obj = json.loads(raw)
        need(type(obj) is dict, 'report_not_object_' + name)
        return obj
    gen = j('gen1.json'); gen_again = j('gen1_replay.json')
    shadow = j('shadow.json'); shadow_again = j('shadow_replay.json')
    units = j('54_units.json'); families = j('29_cases.json')
    r38 = j('r38_report.json')
    need(blobs['gen1.json'] == blobs['gen1_replay.json'] and
         blobs['shadow.json'] == blobs['shadow_replay.json'], 'nondeterministic_replay')
    need(gen.get('generation') == 1 and gen.get('record_id') == 'DEV_TUTOR_001' and
         set(gen.get('a1_decisions', {})) == {'SSH_DEV','FTP_DEV','SMB_DEV'} and
         gen.get('a4_selected') is None and gen.get('a5_attempt_count') == 0 and
         gen.get('a5_start_count') == 0 and gen.get('a6_classification') == 'ND' and
         gen.get('a7_confirmed_rf') is None and gen.get('a8_transition') == 'DETENER' and
         gen.get('a9_structural_generation_published') is True and
         gen.get('a9_technical_evidence_published') is False and
         gen.get('physical_observation_attested') is False and
         gen.get('operational_dispatch') is False and gen.get('p8_operational') == 'NO-GO',
         'gen1_contract_invalid')
    need(shadow.get('a4_shadow_selection') == {
          'service_id':'SSH_DEV', 'case_id':'CASE_REFERENCE', 'priority':'1/4', 'precedence':10} and
         shadow.get('a4_confirmed_selection') is None and
         shadow.get('a5_local_benign_starts') == 1 and
         shadow.get('a5_local_benign_outcome') == 'BENIGN_EXIT_ZERO' and
         shadow.get('a6_classification') == 'ND' and
         shadow.get('a7_hypothetical_rf') == '5/12' and
         shadow.get('a7_confirmed_rf') is None and
         shadow.get('a8_original_stop') == 'DETENER' and
         shadow.get('a9_new_generation_published') is False and
         shadow.get('a10_dashboard') == 'R38_ORIGINAL' and
         shadow.get('r70_head_sha256') == gen.get('head_sha256') and
         shadow.get('physical_observation_attested') is False and
         shadow.get('operational_dispatch') is False and
         shadow.get('p8_operational') == 'NO-GO', 'shadow_contract_invalid')
    need(units.get('service_count') == 54 and
         units.get('protocol_counts') == {'SSH':18, 'FTP':18, 'SMB':18} and
         units.get('case_count') == 108 and units.get('control_count') == 108 and
         units.get('initial_all_prepared') is True and
         units.get('initial_all_evidence_zero') is True and
         units.get('initial_all_rf_equals_r0') is True and
         units.get('generation_published') is False and
         units.get('operational_dispatch') is False and units.get('p8_operational') == 'NO-GO',
         'synthetic_54_contract_invalid')
    need(families.get('unit_count') == 29 and
         families.get('covered_family_count') == 25 and
         families.get('count_by_service') == {'SSH_DEV':8, 'FTP_DEV':10, 'SMB_DEV':11} and
         families.get('a6_classification') == 'ND' and
         families.get('technical_truth_accredited') is False and
         families.get('confirmed_final_risk') is None and
         families.get('published_generation') is None and
         families.get('p8_operational') == 'NO-GO', 'synthetic_29_contract_invalid')
    # The view is derived exactly from the frozen gen1+shadow documents.
    fixture = read_fixed_scenario(REPO/'lab/p14-r26-session-v1/scenario.json')
    expected_view = build_shadow_dashboard(shadow, fixture, gen)
    validate_dashboard_report(expected_view)
    need(r38 == expected_view and len(r38['a10']['stages']) == 10,
         'r38_source_binding_invalid')
    expected_frame = ('\n'.join(render_dashboard_frame(
        expected_view, DashboardState(selected=4), 152, 36)) + '\n').encode('utf-8')
    need(blobs['r38_pantalla.txt'] == expected_frame, 'r38_frame_replay_mismatch')
    return {'r70_head_sha256': gen['head_sha256'],
            'r71_shadow_sha256': shadow['sha256'],
            'r38_sha256': r38['sha256']}

def report_paths(root: Path) -> dict[str, Path]:
    folder = root/'reports'
    return {name:folder/name for name in REPORTS}

def normalize_benign_sqlite_mode(root: Path) -> None:
    """Normalize sqlite's umask-dependent initial mode inside a fresh private receipt.

    SQLite may create attempts.sqlite3 as 0600 (umask 077) or 0644 (umask 022).
    The file is only ever within an owner-private 0700 directory. The creator
    converts either recognized form to exactly 0600 *before* inventory hashing;
    the verifier never changes a file or accepts a later downgrade to 0644.
    """
    folder = root / 'benign'
    ds = folder.lstat()
    need(stat.S_ISDIR(ds.st_mode) and ds.st_uid == os.getuid() and
         stat.S_IMODE(ds.st_mode) == 0o700, 'benign_directory_not_private')
    db = folder / 'attempts.sqlite3'
    fd = os.open(db, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        mode = stat.S_IMODE(st.st_mode)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
             st.st_uid == os.getuid() and 0 <= st.st_size <= MAX_BYTES and
             mode in (0o600, 0o644), 'benign_sqlite_initial_mode_invalid')
        if mode != 0o600:
            os.fchmod(fd, 0o600)
            os.fsync(fd)
    finally:
        os.close(fd)


def inventory(root: Path) -> dict[str, dict[str, int | str]]:
    results: dict[str, dict[str, int | str]] = {}
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root).as_posix()
        st = path.lstat()
        need(st.st_uid == os.getuid() and not path.is_symlink(), 'untrusted_entry_'+relative)
        if path.is_dir():
            need(stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700,
                 'directory_permissions_'+relative)
        else:
            expected_mode = (
                0o400 if (relative.startswith('session/analytical-archive/') and
                          relative.endswith('.json')) or
                         (relative.startswith('session/generational-store/') and
                          (relative.endswith('.json') or relative.endswith('/HEAD'))) else
                0o600)
            need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                 stat.S_IMODE(st.st_mode) == expected_mode and st.st_size <= MAX_BYTES,
                 'file_permissions_'+relative)
            if relative not in ('MANIFEST.json', 'SHA256SUMS'):
                results[relative] = {'sha256': sha(path.read_bytes()), 'bytes':st.st_size}
    return results

def create(root: Path) -> dict:
    check_directory(root, existing=False)
    root.mkdir(mode=0o700)
    (root/'reports').mkdir(mode=0o700)
    folder = root/'reports'
    try:
        durable = root/'session'
        benign = root/'benign'
        args = ['-m','ardrec','--durable-dev-root',str(durable)]
        write_file(folder/'gen1.json', run_python(args+['--safe-cycle','--json']))
        write_file(folder/'gen1_replay.json', run_python(args+['--json']))
        args_shadow = args + ['--shadow-cycle','--shadow-journal-root',str(benign),'--json']
        write_file(folder/'shadow.json', run_python(args_shadow))
        write_file(folder/'shadow_replay.json', run_python(args_shadow))
        write_file(folder/'54_units.json', run_python(['scripts/demo_p14_r21_a2_integrated_preview.py']))
        write_file(folder/'29_cases.json', run_python([
            'scripts/ardrec_p14_r58k_unified_family_demo.py','--synthetic-offline']))
        gen = json.loads(read_file(folder/'gen1.json'))
        shadow = json.loads(read_file(folder/'shadow.json'))
        fixture = read_fixed_scenario(REPO/'lab/p14-r26-session-v1/scenario.json')
        view = build_shadow_dashboard(shadow,fixture,gen)
        validate_dashboard_report(view)
        write_file(folder/'r38_report.json', canonical(view))
        frame = '\n'.join(render_dashboard_frame(view,DashboardState(selected=4),152,36))+'\n'
        write_file(folder/'r38_pantalla.txt',frame.encode('utf-8'))
        links = validated_reports({name:read_file(path) for name,path in report_paths(root).items()})
        normalize_benign_sqlite_mode(root)
        current = inventory(root)
        manifest = {'schema':SCHEMA, 'source_kind':SOURCE, 'p8':'NO-GO',
                    'operational_dispatch':False, 'technical_evidence_accredited':False,
                    'r70_generation':1, 'r71_benign_process_starts':1,
                    'a6':'ND','confirmed_rf':None,
                    'source_links':links, 'files':current}
        write_file(root/'MANIFEST.json', canonical(manifest))
        checks = {**current,'MANIFEST.json':{
            'sha256':sha(read_file(root/'MANIFEST.json')),
            'bytes':(root/'MANIFEST.json').stat().st_size}}
        write_file(root/'SHA256SUMS',(''.join(
            f"{v['sha256']}  {k}\n" for k,v in sorted(checks.items()))).encode('ascii'))
        return verify(root)
    except Exception:
        # Do not cleanup; failed partial receipt stays unavailable and requires review.
        raise

def verify(root: Path) -> dict:
    check_directory(root, existing=True)
    manifest = json.loads(read_file(root/'MANIFEST.json'))
    need(type(manifest) is dict and manifest.get('schema') == SCHEMA and
         manifest.get('source_kind') == SOURCE and manifest.get('p8') == 'NO-GO' and
         manifest.get('operational_dispatch') is False and
         manifest.get('technical_evidence_accredited') is False and
         manifest.get('a6') == 'ND' and manifest.get('confirmed_rf') is None and
         manifest.get('r70_generation') == 1 and
         manifest.get('r71_benign_process_starts') == 1, 'manifest_contract_invalid')
    files = manifest.get('files')
    need(type(files) is dict and type(manifest.get('source_links')) is dict,
         'manifest_files_invalid')
    need(inventory(root) == files, 'receipt_file_inventory_or_digest_drift')
    checks = read_file(root/'SHA256SUMS').decode('ascii')
    expected = {**files, 'MANIFEST.json':{'sha256': sha(read_file(root/'MANIFEST.json')),
                                      'bytes':(root/'MANIFEST.json').stat().st_size}}
    need(checks == ''.join(f"{v['sha256']}  {k}\n" for k,v in sorted(expected.items())),
         'checksums_drift')
    links = validated_reports({name:read_file(path) for name,path in report_paths(root).items()})
    need(links == manifest['source_links'], 'source_links_invalid')
    return manifest

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--create',action='store_true')
    mode.add_argument('--verify',action='store_true')
    ap.add_argument('--receipt-dir',type=Path,required=True)
    options = ap.parse_args(argv)
    try:
        need(os.geteuid() != 0 and Path.cwd().resolve() == REPO,
             'nonroot_canonical_checkout_required')
        data = create(options.receipt_dir) if options.create else verify(options.receipt_dir)
    except (R75Error, ValueError, OSError, KeyError, TypeError,
            subprocess.SubprocessError, RuntimeError) as exc:
        print('R75=BLOCKED:'+type(exc).__name__+':'+str(exc)[:180],file=sys.stderr)
        print('R75_P8=NO-GO',file=sys.stderr)
        return 23
    print('R75=PASS_'+('CREATED' if options.create else 'VERIFIED_NO_EXECUTION'))
    print('R75_54_UNITS=PASS_SYNTHETIC')
    print('R75_25_FAMILIES=PASS_SYNTHETIC')
    print('R75_A5_LOCAL_BENIGN_STARTS=1')
    print('R75_A6=ND')
    print('R75_RF_CONFIRMED=NULL')
    print('R75_GEN1_HEAD='+data['source_links']['r70_head_sha256'])
    print('R75_R38=ORIGINAL_THREE_PANELS_10_STAGES')
    print('R75_RECEIPT='+str(options.receipt_dir))
    print('R75_P8=NO-GO')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
