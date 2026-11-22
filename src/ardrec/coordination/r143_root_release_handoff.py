"""R143: reproducible public source handoff for INDEPENDENT root authorization.

This module creates an unsigned, source-only review dossier from a CLEAN,
SIGNED Git commit. It contains no secret material, no permit and no power to
stage files to root. The twelve role names are tasks for independent authorities,
not twelve identities already present or verified.

The bundle's B4/B9 root sources are pinned; every review-only dependency is
also bound to the same commit/tree and checked against Git worktree bytes.
Never execute review-only modules under root: R140/R142 contain a synthetic
sandbox-only authorization callback and are not operational root authority.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import zipfile

SCHEMA = 'ARDREC-R143-INDEPENDENT-RELEASE-REQUEST-v1'
BUNDLE_SCHEMA = SCHEMA + '-bundle-v1'
BRANCH = 'feat/ardrec-cierre-operacional-experimental'
ANCHOR = 'b8e5a84cdbb35307f8fe546d848f80b7da0762a8'
ORIGIN = frozenset(('https://github.com/DrewSC13/ardrec.git',
                    'git@github.com:DrewSC13/ardrec.git'))
B4_SHA = 'f64ce5f8c31cd80f98d07f47eb99728e15e406a66b697044e3d5eefd6a3f73e8'
B9_SHA = 'c3c840f66476f3f0bbd87e48f657fdc6270e09b57b130eaf9c5b3cb68980cbd3'
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
SOURCE = {
    'operational/B4/root-controller.py': 'scripts/ardrec_p14_r130_b4_root_guard_v2.py',
    'operational/B9/root-executor.py': 'scripts/ardrec_p14_r130_b9_ftp_executor_v2.py',
    'review/r135_root_transaction.py': 'src/ardrec/coordination/r135_root_transaction.py',
    'review/r136_operational_semantics.py': 'src/ardrec/coordination/r136_operational_semantics.py',
    'review/r139_independent_release_review.py': 'src/ardrec/coordination/r139_independent_release_review.py',
    'review/r140_release_transaction_sandbox.py': 'src/ardrec/coordination/r140_release_transaction_sandbox.py',
    'review/r141_root_material_reader.py': 'src/ardrec/coordination/r141_root_material_reader.py',
    'review/r142_material_transaction_bridge.py': 'src/ardrec/coordination/r142_material_transaction_bridge.py',
}
DESTINATIONS = {
    'B4': '/var/lib/ardrec/r126-ftp-session-guard-v1',
    'B9': '/var/lib/ardrec/r128-one-session-v2',
    'agent_candidate': '/opt/ardrec/r131-installer-v1',
}
SIGNER_ROLES = (
    'root_grant', 'root_grant_revocation',
    'scope', 'scope_revocation',
    'pilot', 'pilot_revocation',
    'window', 'window_revocation',
    'traffic', 'traffic_revocation',
    'release', 'release_revocation',
)
# Never package root secrets, their public trust stores, revocations, F8
# physical receipts, approval.json, or an operational traffic permit.
EXTERNAL_MATERIALS = (
    'root-trust-and-revocation', 'scope-trust-and-revocation',
    'pilot-trust-and-revocation', 'window-trust-and-revocation',
    'traffic-trust-and-revocation', 'release-trust-and-revocation',
    'independently-signed-installation-permit-and-fresh-revocation',
    'physical-F7-F8-boot-receipts', 'root-owned-policy-provenance',
    'autonomous-DENY-physical-proof',
)

class Refusal(ValueError):
    pass


def need(check, reason):
    if not check:
        raise Refusal(reason)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(doc) -> bytes:
    return (json.dumps(doc, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def plan(*, head: str, tree: str, sources: dict[str, bytes]) -> dict:
    """Pure request, never a release or an installation authorization."""
    need(type(head) is str and HEX40.fullmatch(head) is not None, 'HEAD_INVALID')
    need(type(tree) is str and HEX40.fullmatch(tree) is not None, 'TREE_INVALID')
    need(type(sources) is dict and set(sources) == set(SOURCE),
         'SOURCE_SCOPE_INVALID')
    need(all(type(value) is bytes and 0 < len(value) <= 250000
             for value in sources.values()), 'SOURCE_BYTES_INVALID')
    need(sha(sources['operational/B4/root-controller.py']) == B4_SHA,
         'B4_SOURCE_PIN_INVALID')
    need(sha(sources['operational/B9/root-executor.py']) == B9_SHA,
         'B9_SOURCE_PIN_INVALID')
    inventory = {key: {'git_path': SOURCE[key], 'sha256': sha(value),
                       'bytes': len(value),
                       'mode': 'operational-pinned-source' if key.startswith('operational/')
                               else 'review-only-NOT-root-runtime'}
                 for key, value in sorted(sources.items())}
    result = {
        'schema': SCHEMA,
        'source_commit': head,
        'source_tree': tree,
        'branch': BRANCH,
        'repository': 'DrewSC13/ardrec',
        'git_signature_locally_verified': True,
        'git_signature_independently_attested': False,
        'source_inventory': inventory,
        'destinations': dict(DESTINATIONS),
        'required_independent_signer_roles': list(SIGNER_ROLES),
        'external_evidence_to_obtain': list(EXTERNAL_MATERIALS),
        'signer_persons_independent_verified': False,
        'trust_anchor_provenance_verified': False,
        'physical_f8_chain_verified': False,
        'root_install_permit_present': False,
        'root_install_authorized': False,
        'physical_five_one_verified': False,
        'network_traffic_authorized': False,
        'root_install_executed': False,
        'a6': 'ND', 'a9': 'NOT_PUBLISHED', 'p8': 'NO-GO',
    }
    validate_plan(result, sources)
    return result


def validate_plan(doc, sources: dict[str, bytes]):
    need(type(doc) is dict and type(sources) is dict, 'PLAN_OBJECT_INVALID')
    need(doc.get('schema') == SCHEMA, 'PLAN_SCHEMA_INVALID')
    need(type(doc.get('source_commit')) is str and
         HEX40.fullmatch(doc['source_commit']) is not None and
         type(doc.get('source_tree')) is str and
         HEX40.fullmatch(doc['source_tree']) is not None, 'GIT_IDENTITY_INVALID')
    need(set(sources) == set(SOURCE), 'INVENTORY_SCOPE_INVALID')
    need(set(doc.get('source_inventory', {})) == set(SOURCE),
         'INVENTORY_ENTRIES_INVALID')
    for name, value in sources.items():
        entry = doc['source_inventory'][name]
        need(type(entry) is dict and entry == {
            'git_path': SOURCE[name], 'sha256': sha(value), 'bytes': len(value),
            'mode': 'operational-pinned-source' if name.startswith('operational/')
                    else 'review-only-NOT-root-runtime',
        }, 'INVENTORY_ENTRY_MISMATCH:' + name)
    need(sha(sources['operational/B4/root-controller.py']) == B4_SHA and
         sha(sources['operational/B9/root-executor.py']) == B9_SHA,
         'PINNED_OPERATIONAL_BYTES_CHANGED')
    need(doc.get('destinations') == DESTINATIONS and
         doc.get('branch') == BRANCH and doc.get('repository') == 'DrewSC13/ardrec',
         'INSTALLATION_DESTINATION_OR_BRANCH_CHANGED')
    need(doc.get('required_independent_signer_roles') == list(SIGNER_ROLES) and
         doc.get('external_evidence_to_obtain') == list(EXTERNAL_MATERIALS),
         'INDEPENDENT_AUTHORITIES_SCOPE_CHANGED')
    need(doc.get('git_signature_locally_verified') is True and
         all(doc.get(k) is False for k in (
             'git_signature_independently_attested',
             'signer_persons_independent_verified', 'trust_anchor_provenance_verified',
             'physical_f8_chain_verified', 'root_install_permit_present',
             'root_install_authorized', 'physical_five_one_verified',
             'network_traffic_authorized', 'root_install_executed')) and
         doc.get('a6') == 'ND' and doc.get('a9') == 'NOT_PUBLISHED' and
         doc.get('p8') == 'NO-GO', 'UNAUTHORIZED_AUTHORITY_CLAIM')
    need(set(doc) == {
        'schema', 'source_commit', 'source_tree', 'branch', 'repository',
        'git_signature_locally_verified', 'git_signature_independently_attested',
        'source_inventory', 'destinations', 'required_independent_signer_roles',
        'external_evidence_to_obtain', 'signer_persons_independent_verified',
        'trust_anchor_provenance_verified', 'physical_f8_chain_verified',
        'root_install_permit_present', 'root_install_authorized',
        'physical_five_one_verified', 'network_traffic_authorized',
        'root_install_executed', 'a6', 'a9', 'p8'
    }, 'UNEXPECTED_PLAN_FIELDS')
    return doc


def _git(repo: Path, *args: str) -> str:
    env = os.environ.copy()
    env.update({'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C'})
    proc = subprocess.run(('git', '-C', str(repo), *args),
                          capture_output=True, stdin=subprocess.DEVNULL,
                          check=False, timeout=30, env=env)
    need(proc.returncode == 0, 'GIT_VERIFICATION_FAILED:' + ','.join(args[:3]))
    return proc.stdout.decode('utf-8').rstrip('\n')


def signed_checkout(repo: Path) -> tuple[dict, dict[str, bytes]]:
    """Create only a PUBLIC request from an exact clean signed HEAD.

    The Git signature is a local provenance observation. This function cannot
    turn a repository user's key into independent root-install authority.
    """
    need(os.geteuid() != 0, 'NONROOT_CHECKOUT_REQUIRED')
    need(isinstance(repo, Path) and repo.is_absolute() and repo.is_dir()
         and not repo.is_symlink(), 'REPO_PATH_INVALID')
    need(_git(repo, 'rev-parse', '--show-toplevel') == str(repo), 'GIT_ROOT_INVALID')
    need(_git(repo, 'branch', '--show-current') == BRANCH, 'GIT_BRANCH_INVALID')
    need(_git(repo, 'remote', 'get-url', 'origin') in ORIGIN,
         'GIT_ORIGIN_INVALID')
    need(_git(repo, 'status', '--porcelain=v1', '--untracked-files=all') == '',
         'GIT_DIRTY_REPOSITORY')
    head = _git(repo, 'rev-parse', 'HEAD')
    tree = _git(repo, 'rev-parse', 'HEAD^{tree}')
    need(_git(repo, 'merge-base', '--is-ancestor', ANCHOR, head) == '',
         'R142_NOT_ANCESTOR')
    need(_git(repo, 'log', '-1', '--format=%G?') == 'G',
         'GIT_SIGNER_NOT_TRUSTED')
    _git(repo, 'verify-commit', head)
    sources = {}
    for label, relative in SOURCE.items():
        path = repo / relative
        need(path.is_file() and not path.is_symlink(), 'SOURCE_FILE_UNSAFE:' + label)
        raw = path.read_bytes()
        body = subprocess.run(('git', '-C', str(repo), 'show', 'HEAD:' + relative),
                              capture_output=True, stdin=subprocess.DEVNULL,
                              timeout=30, check=False)
        need(body.returncode == 0 and raw == body.stdout,
             'WORKTREE_SOURCE_DIFFERS_FROM_COMMIT:' + label)
        sources[label] = raw
    return plan(head=head, tree=tree, sources=sources), sources


def create_public_bundle(*, request: dict, sources: dict[str, bytes],
                         destination: Path) -> str:
    """Write a deterministic, PUBLIC ZIP; never include root trust or permits.

    Destination parent must be a pre-existing private user-owned directory;
    target must not preexist. Exclusive creation and no external path options.
    """
    validate_plan(request, sources)
    need(os.geteuid() != 0, 'ROOT_BUNDLE_FORBIDDEN')
    need(isinstance(destination, Path) and destination.is_absolute() and
         destination.suffix == '.zip' and not destination.is_symlink() and
         not destination.exists(), 'DESTINATION_INVALID')
    parent = destination.parent
    pst = parent.lstat()
    need(stat.S_ISDIR(pst.st_mode) and pst.st_uid == os.geteuid() and
         stat.S_IMODE(pst.st_mode) == 0o700 and not parent.is_symlink(),
         'PRIVATE_PARENT_REQUIRED')
    files = dict(sources)
    files['REQUEST.json'] = canonical(request)
    manifest = {'schema': BUNDLE_SCHEMA, 'request_sha256': sha(files['REQUEST.json']),
                'sources': {k: sha(v) for k, v in sorted(sources.items())},
                'install_authorized': False, 'contains_private_keys': False,
                'contains_live_permits': False, 'p8': 'NO-GO'}
    files['MANIFEST.json'] = canonical(manifest)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            with zipfile.ZipFile(stream, mode='w', compression=zipfile.ZIP_DEFLATED,
                                 compresslevel=9) as archive:
                for name, body in sorted(files.items()):
                    info = zipfile.ZipInfo(name, (2026, 11, 22, 0, 0, 0))
                    info.external_attr = 0o100600 << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(info, body, compress_type=zipfile.ZIP_DEFLATED,
                                     compresslevel=9)
            stream.flush()
            os.fsync(stream.fileno())
        with zipfile.ZipFile(destination) as archive:
            need(set(archive.namelist()) == set(files) and archive.testzip() is None and
                 all(archive.read(name) == body for name, body in files.items()),
                 'BUNDLE_READBACK_INVALID')
        return sha(destination.read_bytes())
    except BaseException:
        # Do not blindly remove a possibly partial archive: leave it for
        # inspection and require a distinct destination for any retry.
        raise


def capabilities():
    return {
        'schema': SCHEMA + '-capabilities',
        'signed_git_source_only_handoff': True,
        'two_exact_pinned_operational_sources': True,
        'six_review_only_sources': True,
        'external_authority_material_requested': True,
        'private_credentials_collected': False,
        'independent_root_installer': False,
        'root_install_authorized': False,
        'root_install_executed': False,
        'traffic_enabled': False,
        'a6': 'ND', 'a9': 'NOT_PUBLISHED', 'p8': 'NO-GO',
    }
