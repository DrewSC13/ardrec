#!/usr/bin/env python3
"""R112-F1: real runner FTP/SMB NIC definition with immutable private receipts.

Only ONE allowlisted host mutation: sudo -n virsh -c qemu:///system define <pinned XML>.
Never starts any guest or network, alters nft/F11, emits probes or dispatches A5.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

REPO = Path('/home/cicada/Development/GitHub/ardrec')
sys.path[:0] = [str(REPO/'src'), str(REPO/'scripts')]

from ardrec.coordination import r112_runner_nic_definition as core
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r111_real_reconcile as r111cli

ROOT = Path('/home/cicada/ardrec-lab/r112-real-runner-nic-v1')
BRANCH = 'feat/p14-r111-r114-real-lab'
PARENT = '41f5e1e66aa80ecfcf530dfd1916102b6bc457f0'
SOURCE_R111_SHA = 'ec6cab5569c559d274f318d0dd0c6abd3989f416a7384f84bae35129a5a04851'
FILESET = {'snapshot.json', 'before.xml', 'candidate.xml', 'plan.json', 'manifest.json'}
MAX_BYTES = 3_000_000


def need(ok: bool, code: str) -> None:
    core.need(ok, code)


def sha(raw: bytes) -> str:
    return core.sha(raw)


def private_bytes(path: Path) -> bytes:
    need(path.is_file() and not path.is_symlink(), 'PRIVATE_FILE_TYPE')
    st = path.lstat()
    need(stat.S_IMODE(st.st_mode) == 0o600 and st.st_uid == os.geteuid()
         and st.st_nlink == 1 and 0 < st.st_size <= MAX_BYTES,
         'PRIVATE_FILE_PERMISSIONS')
    return path.read_bytes()


def read_json(path: Path) -> dict:
    raw = private_bytes(path)
    data = json.loads(raw)
    need(type(data) is dict and core.canonical(data) == raw,
         'PRIVATE_JSON_NOT_CANONICAL')
    return data


def store(path: Path, raw: bytes) -> None:
    need(0 < len(raw) <= MAX_BYTES, 'OUTPUT_TOO_LARGE')
    legacy.secure_write(path, raw)


def directory(path: Path) -> None:
    legacy._private_directory(path)


def git_source(*, allow_descendant: bool = False) -> None:
    need(Path.cwd().resolve() == REPO, 'REPO_REQUIRED')
    outcome = legacy.run(('git', 'branch', '--show-current'))
    need(outcome['rc'] == 0 and outcome['stdout'].strip() == BRANCH,
         'GIT_BRANCH_DRIFT')
    if allow_descendant:
        ancestry = legacy.run(('git', 'merge-base', '--is-ancestor', PARENT, 'HEAD'))
        need(ancestry['rc'] == 0, 'GIT_R111_ANCESTRY_DRIFT')
    else:
        head = legacy.run(('git', 'rev-parse', 'HEAD'))
        need(head['rc'] == 0 and head['stdout'].strip() == PARENT,
             'GIT_SOURCE_DRIFT')


def verified_history(original: Path, reconciled: Path) -> dict:
    report, _ = r111cli.verify(reconciled, original)
    need(report['source_snapshot_sha256'] == SOURCE_R111_SHA
         and report['all_four_domains_shutoff_at_snapshot'] is True
         and report['runner_networks_missing'] == [
             'ardrec-r33-dev-net-ftp', 'ardrec-r33-dev-net-smb']
         and report['remaining_findings'] == ['VM_RUNNER_NIC_TOPOLOGY_INCOMPLETE']
         and report['p8_operational'] == 'NO-GO', 'HISTORY_NOT_AS_EXPECTED')
    return report


def capture() -> dict:
    commands = legacy.command_list()
    probes = {key: legacy.run(cmd) for key, cmd in commands.items()}
    record = {'schema': legacy.SCHEMA,
              'commands': {k:list(v) for k,v in commands.items()},
              'probes': probes,
              'summary': legacy.summarize(probes)}
    core.audit(record, legacy)
    return record


def _make_manifest(plan: dict, files: dict[str, bytes]) -> dict:
    result = {'schema': core.SCHEMA+'-private-manifest-v1',
              'plan_sha256': sha(core.canonical(plan)),
              'files': {k: sha(v) for k,v in sorted(files.items())},
              'operation': 'INACTIVE_RUNNER_XML_CHANGE_ONLY',
              'p8': 'NO-GO', 'vm_starts': 0, 'network_starts': 0,
              'f11_changed': False, 'nft_changed': False}
    result['sha256'] = sha(core.canonical(result))
    return result


def verify_plan(path: Path) -> tuple[dict, dict]:
    need(path.is_absolute() and path.parent == ROOT and path.name.startswith('plan-')
         and not path.is_symlink(), 'PLAN_PATH_INVALID')
    directory(path)
    names = {x.name for x in path.iterdir()}
    need(names in (FILESET, FILESET | {'apply.once'},
                   FILESET | {'apply.once','restore.once'}),
         'PLAN_FILE_INVENTORY')
    if 'apply.once' in names:
        need(private_bytes(path/'apply.once') == b'ATTEMPTED\n', 'APPLY_MARKER_CHANGED')
    if 'restore.once' in names:
        need(private_bytes(path/'restore.once') == b'ATTEMPTED\n', 'RESTORE_MARKER_CHANGED')
    manifest = read_json(path/'manifest.json')
    need(manifest['schema'] == core.SCHEMA+'-private-manifest-v1'
         and manifest.get('p8') == 'NO-GO'
         and manifest.get('vm_starts') == 0
         and manifest.get('f11_changed') is False
         and manifest.get('nft_changed') is False
         and manifest.get('sha256') == sha(core.canonical({k:v for k,v in manifest.items()
                                                         if k != 'sha256'})),
         'MANIFEST_INVALID')
    files = {name: private_bytes(path/name) for name in FILESET if name != 'manifest.json'}
    need({k: sha(v) for k,v in sorted(files.items())} == manifest['files'],
         'PLAN_SOURCE_HASH_DRIFT')
    plan = read_json(path/'plan.json')
    snapshot = read_json(path/'snapshot.json')
    old = files['before.xml'].decode('utf-8')
    candidate = files['candidate.xml'].decode('utf-8')
    core.validate_candidate(old, candidate)
    checked = core.audit(snapshot, legacy)
    need(checked['runner_nics'] == 1 and
         snapshot['probes']['vm-runner-inactive-xml']['stdout'] == old and
         sha(core.canonical(plan)) == manifest['plan_sha256'] and
         plan == build_plan(snapshot, old, candidate),
         'PLAN_NOT_REPRODUCIBLE')
    return plan, snapshot


def build_plan(snapshot: dict, old: str, candidate: str) -> dict:
    checked = core.audit(snapshot, legacy)
    need(checked['runner_nics'] == 1, 'RUNNER_ALREADY_CONFIGURED')
    core.validate_candidate(old, candidate)
    return {
        'schema': core.SCHEMA,
        'mode': 'REAL_HOST_INACTIVE_DOMAIN_DEFINITION_NOT_DISPATCH',
        'historical_r111_sha256': SOURCE_R111_SHA,
        'parent_commit': PARENT,
        'snapshot_sha256': sha(core.canonical(snapshot)),
        'before_xml_sha256': sha(old.encode('utf-8')),
        'candidate_xml_sha256': sha(candidate.encode('utf-8')),
        'f11_hook_sha256': core.HOST_HOOK_PIN,
        'r34_structure_sha256': checked['nft_structure_sha256'],
        'before_runner_nics': 1, 'after_runner_nics': 3,
        'other_domain_changes': 0, 'network_definitions_changed': 0,
        'vm_starts': 0, 'protocol_connections': 0,
        'f11_change_authorized': False, 'nft_change_authorized': False,
        'p8_operational': 'NO-GO',
    }


def plan(original: Path, reconciled: Path):
    git_source()
    verified_history(original, reconciled)
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory(ROOT)
    snapshot = capture()
    old = snapshot['probes']['vm-runner-inactive-xml']['stdout']
    checked = core.audit(snapshot, legacy)
    need(checked['runner_nics'] == 1, 'RUNNER_ALREADY_CONFIGURED')
    candidate = core.make_candidate(old)
    doc = build_plan(snapshot, old, candidate)
    files = {'snapshot.json': core.canonical(snapshot),
             'before.xml': old.encode('utf-8'),
             'candidate.xml': candidate.encode('utf-8'),
             'plan.json': core.canonical(doc)}
    manifest = _make_manifest(doc, files)
    root = Path(tempfile.mkdtemp(prefix='plan-', dir=ROOT))
    directory(root)
    for filename, data in files.items():
        store(root/filename, data)
    store(root/'manifest.json', core.canonical(manifest))
    verify_plan(root)
    print('R112_PLAN=READY_REAL_XML_SSH_TO_SSH_FTP_SMB')
    print('R112_PLAN_RUNNER_NICS=1_TO_3')
    print('R112_PLAN_R34_DENY=PINNED')
    print('R112_PLAN_F11_HOOK=PINNED')
    print('R112_PLAN_SHA256='+manifest['plan_sha256'])
    print('R112_PLAN_SESSION='+str(root))
    print('R112_PLAN_VM_STARTS=0')
    print('R112_PLAN_P8=NO-GO')
    return 0


def perform(plan_session: Path, *, restore: bool = False) -> int:
    """Exactly one authorized libvirt definition operation; never retry."""
    git_source(allow_descendant=restore)
    doc, old_snapshot = verify_plan(plan_session)
    marker = 'restore.once' if restore else 'apply.once'
    if restore:
        need((plan_session/'apply.once').is_file(), 'NO_APPLY_ATTEMPT')
        need((plan_session/'apply.once').read_bytes() == b'ATTEMPTED\n', 'APPLY_MARKER_DRIFT')
    # The marker is created ONLY after validating a fresh physical readback.
    current = capture()
    core.snapshot_equivalent(old_snapshot, current, legacy,
                             after_definition=restore)
    if restore:
        before = private_bytes(plan_session/'before.xml')
        expected = private_bytes(plan_session/'candidate.xml')
    else:
        before = private_bytes(plan_session/'candidate.xml')
        expected = private_bytes(plan_session/'before.xml')
    now = current['probes']['vm-runner-inactive-xml']['stdout']
    need(core.normalized_xml(now) == core.normalized_xml(expected),
         'CURRENT_DOMAIN_NOT_MATCHING_PLAN')
    directory(ROOT)
    attempt = Path(tempfile.mkdtemp(prefix='restore-' if restore else 'apply-', dir=ROOT))
    directory(attempt)
    intent = {'schema': core.SCHEMA+'-intent-v1',
              'operation': 'RESTORE' if restore else 'APPLY',
              'plan_sha256': sha(core.canonical(doc)),
              'captured_before_sha256': sha(core.canonical(current)),
              'source_xml_sha256': sha(expected),
              'target_xml_sha256': sha(before),
              'vm_starts': 0, 'host_write_operations_allowed': 1,
              'p8_operational': 'NO-GO'}
    store(attempt/'intent.json', core.canonical(intent))
    # One-way marker prevents retry after an uncertain libvirt response.
    store(plan_session/marker, b'ATTEMPTED\n')
    result = legacy.run(('sudo','-n','virsh','-c','qemu:///system','define',
                         str(plan_session/('before.xml' if restore else 'candidate.xml'))))
    # Always persist command outcome before revalidating the host.
    store(attempt/'define-result.json', core.canonical(result))
    need(result['rc'] == 0 and result['timeout'] is False
         and result['truncated'] is False, 'LIBVIRT_DEFINE_UNCERTAIN_OR_FAILED')
    after = capture()
    store(attempt/'after-snapshot.json', core.canonical(after))
    if restore:
        # Keep the same physical safety checks and require exact restoration.
        core.audit(after, legacy)
        need(core.normalized_xml(after['probes']['vm-runner-inactive-xml']['stdout']) ==
             core.normalized_xml(private_bytes(plan_session/'before.xml')),
             'RESTORE_READBACK_DIFFERENCE')
        # The restored host must match the pre-change snapshot on all
        # pinned domains, networks and safety barriers.
        core.snapshot_equivalent(old_snapshot, after, legacy, after_definition=False)
    else:
        core.snapshot_equivalent(old_snapshot, after, legacy, after_definition=True)
    receipt = {'schema': core.SCHEMA+'-physical-result-v1',
               'operation': 'RESTORE' if restore else 'APPLY',
               'plan_sha256': sha(core.canonical(doc)),
               'before_snapshot_sha256': sha(core.canonical(current)),
               'after_snapshot_sha256': sha(core.canonical(after)),
               'define_rc': 0, 'vm_starts': 0,
               'guest_evidence_observed': False,
               'physical_change': 'RUNNER_INACTIVE_XML_ONLY',
               'p8_operational': 'NO-GO'}
    store(attempt/'receipt.json', core.canonical(receipt))
    need(verify_physical(plan_session, attempt), 'PHYSICAL_REPLAY_FAILED')
    print('R112_PHYSICAL_RESULT='+('RESTORED_SSH_ONLY' if restore else 'RUNNER_INACTIVE_NICS_DEFINED'))
    print('R112_PHYSICAL_XML_SHA256='+sha(core.normalized_xml(after['probes']['vm-runner-inactive-xml']['stdout'])))
    print('R112_PHYSICAL_RECEIPT='+str(attempt))
    print('R112_PHYSICAL_RECEIPT_SHA256='+sha(core.canonical(receipt)))
    print('R112_PHYSICAL_VM_STARTS=0')
    print('R112_PHYSICAL_P8=NO-GO')
    return 0



def verify_physical(plan_session: Path, attempt: Path) -> bool:
    """Independent offline readback: no new command and no hidden mutation."""
    plan_doc, original = verify_plan(plan_session)
    need(attempt.is_absolute() and attempt.parent == ROOT
         and not attempt.is_symlink() and
         (attempt.name.startswith('apply-') or attempt.name.startswith('restore-')),
         'PHYSICAL_SESSION_PATH')
    directory(attempt)
    need({p.name for p in attempt.iterdir()} ==
         {'intent.json', 'define-result.json', 'after-snapshot.json', 'receipt.json'},
         'PHYSICAL_SESSION_FILE_INVENTORY')
    intent = read_json(attempt/'intent.json')
    execution = read_json(attempt/'define-result.json')
    after = read_json(attempt/'after-snapshot.json')
    receipt = read_json(attempt/'receipt.json')
    restore = attempt.name.startswith('restore-')
    need(intent.get('schema') == core.SCHEMA+'-intent-v1'
         and receipt.get('schema') == core.SCHEMA+'-physical-result-v1'
         and intent['operation'] == receipt['operation'] ==
             ('RESTORE' if restore else 'APPLY')
         and intent['plan_sha256'] == receipt['plan_sha256'] ==
             sha(core.canonical(plan_doc))
         and intent['host_write_operations_allowed'] == 1
         and intent['p8_operational'] == receipt['p8_operational'] == 'NO-GO'
         and intent['captured_before_sha256'] == receipt['before_snapshot_sha256']
         and receipt['define_rc'] == 0
         and receipt['vm_starts'] == 0
         and receipt['guest_evidence_observed'] is False
         and receipt['physical_change'] == 'RUNNER_INACTIVE_XML_ONLY'
         and execution['rc'] == 0 and execution['timeout'] is False
         and execution['truncated'] is False,
         'PHYSICAL_RECEIPT_SCHEMA')
    candidate = private_bytes(plan_session/'candidate.xml')
    baseline = private_bytes(plan_session/'before.xml')
    need(intent['target_xml_sha256'] == sha(baseline if restore else candidate)
         and intent['source_xml_sha256'] == sha(candidate if restore else baseline)
         and receipt['after_snapshot_sha256'] == sha(core.canonical(after)),
         'PHYSICAL_XML_OR_AFTER_HASH')
    core.audit(after, legacy)
    if restore:
        need(core.normalized_xml(after['probes']['vm-runner-inactive-xml']['stdout']) ==
             core.normalized_xml(baseline), 'RESTORE_NOT_COMPLETE')
        core.snapshot_equivalent(original, after, legacy, after_definition=False)
    else:
        core.snapshot_equivalent(original, after, legacy, after_definition=True)
    need((plan_session/('restore.once' if restore else 'apply.once')).is_file(),
         'PHYSICAL_ONCE_MARKER_MISSING')
    return True

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--plan',action='store_true')
    group.add_argument('--verify-plan',type=Path)
    group.add_argument('--apply',type=Path)
    group.add_argument('--restore',type=Path)
    group.add_argument('--verify-physical',type=Path)
    parser.add_argument('--plan-session',type=Path)
    parser.add_argument('--r111-original',type=Path)
    parser.add_argument('--r111-reconciled',type=Path)
    parser.add_argument('--i-authorize-runner-inactive-nics-only',action='store_true')
    parser.add_argument('--i-authorize-restore-runner-inactive-only',action='store_true')
    args=parser.parse_args()
    try:
        need(Path.cwd().resolve() == REPO, 'REPO_REQUIRED')
        if args.plan:
            need(args.r111_original is not None and args.r111_reconciled is not None
                 and not args.i_authorize_runner_inactive_nics_only
                 and not args.i_authorize_restore_runner_inactive_only,
                 'PLAN_ARGS')
            return plan(args.r111_original,args.r111_reconciled)
        if args.verify_plan is not None:
            doc,_=verify_plan(args.verify_plan)
            print('R112_PLAN_REPLAY=PASS')
            print('R112_PLAN_SHA256='+sha(core.canonical(doc)))
            print('R112_PLAN_P8=NO-GO')
            return 0
        if args.verify_physical is not None:
            need(args.plan_session is not None, 'VERIFY_REQUIRES_PLAN_SESSION')
            verify_physical(args.plan_session,args.verify_physical)
            print('R112_PHYSICAL_REPLAY=PASS')
            print('R112_PHYSICAL_P8=NO-GO')
            return 0
        if args.apply is not None:
            need(args.i_authorize_runner_inactive_nics_only and
                 not args.i_authorize_restore_runner_inactive_only,
                 'EXPLICIT_NIC_DEFINITION_AUTHORIZATION_REQUIRED')
            return perform(args.apply)
        need(args.restore is not None and args.i_authorize_restore_runner_inactive_only
             and not args.i_authorize_runner_inactive_nics_only,
             'EXPLICIT_RESTORE_AUTHORIZATION_REQUIRED')
        return perform(args.restore,restore=True)
    except (OSError,ValueError,KeyError,TypeError,IndexError) as exc:
        print('R112_STOP='+type(exc).__name__+':'+str(exc)[:220])
        print('R112_P8=NO-GO')
        return 23


if __name__=='__main__':
    raise SystemExit(main())
