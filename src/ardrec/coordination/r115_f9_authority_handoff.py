"""ARDREC R115-F9: independent-authority handoff, never issuance or execution.

This module produces an anchored, redacted inventory of the operator's pending
external approvals. Root-owned public-key pinning is reviewed read-only. Absence,
permission errors and malformed sources are kept distinct. No self-signatures,
root-file writes, guest commands, network access, boot leases or P8 dispatch.
"""
from __future__ import annotations

from datetime import datetime, timezone
import argparse
import os
from pathlib import Path

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r115_f6_signed_scope_and_activation as f6
from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_f8_runner_ftp_boot as f8

SCHEMA = 'ARDREC-R115-F9-EXTERNAL-AUTHORITY-HANDOFF-v1'
ROOT = Path('/home/cicada/ardrec-lab/r115-f9-authority-handoff-v1')
SOURCE = 'src/ardrec/coordination/r115_f9_authority_handoff.py'
SCRIPT = 'scripts/ardrec_p14_r115_f9_authority_handoff.py'
ROLES = ('ssh', 'runner', 'ftp')

class Stop(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Stop(code)


def fingerprint(raw):
    return f1.digest(raw)


def trust_report(path, loader, validator, *, role):
    """Independently provisioned policy, not a new approval path."""
    require(role in ('scope', 'boot'), 'INVALID_TRUST_ROLE')
    require(path in (f6.TRUST, f7.PERMIT_TRUST), 'UNALLOWED_ROOT_PATH')
    try:
        raw = loader(path)
    except FileNotFoundError:
        return {'status': 'ABSENT', 'reason': 'ROOT_TRUST_NOT_PROVISIONED',
                'sha256': None}
    except PermissionError:
        return {'status': 'ND', 'reason': 'ROOT_TRUST_NOT_READABLE',
                'sha256': None}
    except (OSError, ValueError, TypeError):
        return {'status': 'ND', 'reason': 'ROOT_TRUST_FILE_UNVERIFIABLE',
                'sha256': None}
    try:
        doc = f1.load(raw)
        validator(doc)
    except (f1.Rejected, f3.Stop, ValueError, TypeError, KeyError):
        return {'status': 'REJECTED', 'reason': 'ROOT_TRUST_INVALID',
                'sha256': fingerprint(raw)}
    return {'status': 'STRUCTURE_MATCH',
            'reason': 'PINNED_PUBLIC_KEYS_ONLY_NOT_CURRENT_AUTHORITY',
            'sha256': fingerprint(raw)}


def _scope_trust(doc):
    f3.trust_check(doc)


def _boot_trust(doc):
    f3.exact(doc, {'schema', 'boot_signer', 'revocation_signer'}, 'BOOT_TRUST_FIELDS')
    require(doc['schema'] == 'ARDREC-R115-F7-EXTERNAL-BOOT-TRUST-v1',
            'BOOT_TRUST_SCHEMA')
    f3.trust_check({'schema': f3.TRUST_SCHEMA,
                    'scope_signer': doc['boot_signer'],
                    'revocation_signer': doc['revocation_signer']})


def scope_review(contract, authorization, *, now, reviewer=f6.scope,
                 catalog_raw=None):
    require((contract is None) == (authorization is None),
            'PARTIAL_SCOPE_DOCUMENTS')
    if contract is None:
        return {'status': 'ND', 'reason': 'CONTRACT_AND_SIGNED_SCOPE_NOT_SUPPLIED',
                'contract_sha256': None, 'authorization_sha256': None}
    require(type(contract) is bytes and type(authorization) is bytes,
            'SCOPE_INPUT_TYPE')
    cat = catalog_raw if catalog_raw is not None else f6.CATALOG.read_bytes()
    try:
        state, reason, auth_sha = reviewer(contract, authorization,
                                          catalog_raw=cat, now=now)
    except (f6.Stop, f1.Rejected, f3.Stop, ValueError, OSError, KeyError, TypeError):
        return {'status': 'REJECTED', 'reason': 'SCOPE_VALIDATION_FAILED',
                'contract_sha256': fingerprint(contract),
                'authorization_sha256': fingerprint(authorization)}
    require(state in ('VERDADERO', 'FALSO', 'ND') and type(reason) is str,
            'INVALID_SCOPE_REVIEW')
    # CRITICAL: even a cryptographically valid scope is not a boot permit,
    # is not a current F11/R34 proof and never authorizes FTP-T01 traffic.
    return {'status': state, 'reason': reason,
            'contract_sha256': fingerprint(contract),
            'authorization_sha256': auth_sha}


def make_report(head, catalog_raw, trust_scope, trust_boot, signed_scope, *, now):
    require(type(head) is str and f1.GIT_SHA.fullmatch(head), 'BAD_SOURCE_HEAD')
    require(type(now) is datetime and now.tzinfo is not None and
            now.utcoffset() is not None, 'CLOCK_NOT_UTC_AWARE')
    cat = f1.load(catalog_raw)
    require(cat.get('status') == 'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE' and
            cat.get('execution_enabled') is False and
            cat.get('catalog_frozen') is False and
            cat.get('pilot_completed') is False, 'CATALOG_STATE_CHANGED')
    matches = [x for x in cat.get('families', [])
               if type(x) is dict and x.get('id') == 'FTP-T01']
    require(len(matches) == 1, 'FTP_T01_CATALOG_MISSING')
    require(matches[0].get('preconditions') == list(f1.GATES),
            'FTP_T01_PRECONDITION_CHANGED')
    require(type(trust_scope) is dict and type(trust_boot) is dict and
            type(signed_scope) is dict, 'INVALID_TRUST_STATUS')
    require(trust_scope.get('status') in ('ABSENT', 'ND', 'REJECTED', 'STRUCTURE_MATCH')
            and trust_boot.get('status') in ('ABSENT', 'ND', 'REJECTED', 'STRUCTURE_MATCH'),
            'INVALID_TRUST_STATE')
    require(signed_scope.get('status') in ('ND', 'FALSO', 'REJECTED', 'VERDADERO'),
            'INVALID_SCOPE_STATE')
    roles = []
    for i, role in enumerate(ROLES):
        roles.append({
            'role': role, 'vm': f7.guest(role), 'order': i + 1,
            'predecessor': None if i == 0 else ROLES[i - 1],
            'required': 'NEW_SIGNED_ROLE_PERMIT_AFTER_PHYSICAL_PLAN',
            'permit_max_seconds': f7.MAX_BOOT_PERMIT_SEC,
            'single_start_attempt': True,
            'network_traffic_authorized': False,
        })
    blockers = []
    if trust_scope['status'] != 'STRUCTURE_MATCH':
        blockers.append('INDEPENDENT_SCOPE_PUBLIC_KEY_TRUST')
    if trust_boot['status'] != 'STRUCTURE_MATCH':
        blockers.append('INDEPENDENT_BOOT_PUBLIC_KEY_TRUST')
    if signed_scope['status'] != 'VERDADERO':
        blockers.append('FRESH_SIGNED_FTP_T01_SCOPE_AND_REVOCATION')
    blockers.extend(('FRESH_INDEPENDENT_BOOT_PERMIT_PER_ROLE',
                     'F11_R34_PHYSICAL_PRE_AND_POST_ATTESTATION',
                     'CURRENT_CLIENT_AND_SERVICE_PROOF',
                     'SEPARATE_P8_TRAFFIC_WINDOW_AND_FINITE_LIMITS'))
    return {
        'schema': SCHEMA,
        'created_at': f2.iso(now),
        'repo_head': head,
        'repo_branch': f7.BRANCH,
        'family': 'FTP-T01',
        'catalog_sha256': fingerprint(catalog_raw),
        'catalog_status': cat['status'],
        'target': {'vm': 'ardrec-r33-dev-ftp', 'ip': '10.203.31.2',
                   'port': 21, 'network': 'ardrec-r33-dev-net-ftp'},
        'scope_root_paths': {'trust': str(f6.TRUST),
                             'revocation': str(f6.REVOCATION)},
        'boot_root_paths': {'trust': str(f7.PERMIT_TRUST),
                            'revocation': str(f7.PERMIT_REVOCATION)},
        'scope_trust': trust_scope,
        'boot_trust': trust_boot,
        'scope_review': signed_scope,
        'required_signer_independence': {
            'scope_and_scope_revocation': True,
            'boot_and_boot_revocation': True,
        },
        'boot_roles': roles,
        'max_static_limits': dict(f1.MAXIMUMS),
        'blockers': blockers,
        'operator_request_status': 'PREPARATION_ONLY_NOT_AN_APPROVAL',
        'boot_authority': 'ND',
        'service_ready': 'FALSO_OR_ND',
        'a3': {key: 'ND' for key in f1.GATES},
        'p7_executable': False,
        'vm_starts': 0, 'network_probes': 0,
        'a5': 'NO-GO', 'a6': 'ND', 'p8': 'NO-GO',
        'traffic_authorized': False,
    }


def source_guard():
    head = f7.git_guard(for_boot=True)
    for rel in (SOURCE, SCRIPT):
        require(f7._run(('git', 'ls-files', '--error-unmatch', rel))['rc'] == 0,
                'F9_SOURCE_NOT_COMMITTED')
        require(f7._run(('git', 'diff', '--quiet', 'HEAD', '--', rel))['rc'] == 0,
                'F9_SOURCE_DRIFT')
    for rel in ('src/ardrec/coordination/r115_f8_runner_ftp_boot.py',
                'scripts/ardrec_p14_r115_f8_runner_ftp_boot.py'):
        require(f7._run(('git', 'ls-files', '--error-unmatch', rel))['rc'] == 0,
                'F8_SOURCE_NOT_COMMITTED')
        require(f7._run(('git', 'diff', '--quiet', 'HEAD', '--', rel))['rc'] == 0,
                'F8_SOURCE_DRIFT')
    return head


def evaluate(*, contract_path=None, authorization_path=None,
             clock=f7.utcnow, source_check=source_guard,
             trust_scope_loader=f6.secure_root_file,
             trust_boot_loader=f7._secure_root):
    require((contract_path is None) == (authorization_path is None),
            'PARTIAL_SCOPE_PATHS')
    head = source_check()
    now = clock()
    source = None if contract_path is None else f2.private_read(contract_path)
    signed = None if authorization_path is None else f2.private_read(authorization_path)
    s = trust_report(f6.TRUST, trust_scope_loader, _scope_trust, role='scope')
    b = trust_report(f7.PERMIT_TRUST, trust_boot_loader, _boot_trust, role='boot')
    r = scope_review(source, signed, now=now)
    return make_report(head, f6.CATALOG.read_bytes(), s, b, r, now=now)


def persist(report, root=ROOT):
    require(os.geteuid() != 0, 'ROOT_SHELL_FORBIDDEN')
    require(type(report) is dict and report.get('schema') == SCHEMA and
            report.get('p8') == 'NO-GO' and report.get('traffic_authorized') is False,
            'UNSAFE_REPORT')
    folder = f7._create(root, 'handoff-')
    payload = f1.canonical(report)
    f2.exclusive(folder/'report.json', payload)
    f2.exclusive(folder/'manifest.json', f1.canonical({
        'schema': SCHEMA + '-manifest',
        'sha256': fingerprint(payload),
        'type': 'NON_EXECUTABLE_OPERATOR_REQUEST',
    }))
    return folder


def main(argv=None):
    parser = argparse.ArgumentParser(description='ARDREC F9 independent authorization handoff (NO-GO)')
    parser.add_argument('--prepare', action='store_true', required=True)
    parser.add_argument('--contract', type=Path)
    parser.add_argument('--authorization', type=Path)
    args = parser.parse_args(argv)
    try:
        require(os.geteuid() != 0, 'ROOT_SHELL_FORBIDDEN')
        report = evaluate(contract_path=args.contract, authorization_path=args.authorization)
        folder = persist(report)
        print('R115_F9_HANDOFF=' + str(folder))
        print('R115_F9_HEAD=' + report['repo_head'])
        print('R115_F9_SCOPE_TRUST=' + report['scope_trust']['status'])
        print('R115_F9_BOOT_TRUST=' + report['boot_trust']['status'])
        print('R115_F9_SIGNED_SCOPE=' + report['scope_review']['status'])
        print('R115_F9_BLOCKERS=' + ','.join(report['blockers']))
        print('R115_F9_A5=NO-GO')
        print('R115_F9_A6=ND')
        print('R115_F9_P8=NO-GO')
        print('R115_F9_VM_STARTS=0')
        print('R115_F9_NETWORK_PROBES=0')
        return 0
    except (Stop, f1.Rejected, f2.Stop, f3.Stop, f6.Stop, f7.Stop,
            OSError, TypeError, ValueError, KeyError) as exc:
        print('R115_F9_STOP=' + type(exc).__name__ + ':' + str(exc)[:160])
        print('R115_F9_P8=NO-GO')
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
