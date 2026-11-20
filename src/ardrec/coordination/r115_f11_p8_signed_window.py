"""R115-F11: signed, bounded P8 FTP-T01 *review* and F10 A5 candidate bridge.

Authority, revocation and budget are checked but **cannot** enable the draft P7
catalogue or release nftables. Never calls connect(), sudo, virsh, nft or
mutates guests. A valid signed P8 statement is evidence of an external request,
not proof that a physical window was applied, current A3 guards satisfied, or
A6 admitted. Physical execution needs a distinct trusted root enforcement
component and a calibrated/frozen P7 catalogue (not yet implemented).
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import os
from pathlib import Path
import stat

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r115_f6_signed_scope_and_activation as f6
from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_f9_authority_handoff as f9
from ardrec.coordination import r115_f10_ftp_a5_transport as f10

SCHEMA = 'ARDREC-R115-F11-P8-BOUNDED-SIGNED-REVIEW-v1'
WINDOW_SCHEMA = 'ARDREC-R115-F11-FTP-T01-TRAFFIC-WINDOW-v1'
REV_SCHEMA = 'ARDREC-R115-F11-P8-REVOCATION-v1'
TRUST_SCHEMA = 'ARDREC-R115-F11-P8-EXTERNAL-TRUST-v1'
WINDOW_PREFIX = b'ARDREC-R115-F11-TRAFFIC-WINDOW-v1\x00'
REV_PREFIX = b'ARDREC-R115-F11-P8-REVOCATION-v1\x00'
ROOT = Path('/home/cicada/ardrec-lab/r115-f11-p8-review-v1')
TRUST = Path('/etc/ardrec/r115-p8-trust-v1.json')
REVOCATION = Path('/etc/ardrec/r115-p8-revocation-v1.json')
SOURCE = 'src/ardrec/coordination/r115_f11_p8_signed_window.py'
SCRIPT = 'scripts/ardrec_p14_r115_f11_p8_signed_window.py'
MAX_WINDOW_SECONDS = 120
MAX_REV_AGE_SECONDS = 90
BUDGET_KEYS = {'max_connections', 'ordinary_attempts', 'additional_attempts',
               'timeout_seconds', 'max_recv_bytes', 'max_recv_calls',
               'read_size', 'max_lines', 'max_output_bytes', 'memory_mib'}
BUDGET_CAPS = {'max_connections': 1, 'ordinary_attempts': 1,
               'additional_attempts': 0, 'timeout_seconds': 10,
               'max_recv_bytes': 4096, 'max_recv_calls': 16,
               'read_size': 512, 'max_lines': 16,
               'max_output_bytes': 8192, 'memory_mib': 512}


class Stop(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Stop(reason)


def _instant(value):
    try:
        return f1._instant(value, 'F11_TIMESTAMP')
    except f1.Rejected as exc:
        raise Stop('TIMESTAMP_INVALID') from exc


def _root_file(path):
    """Root-provisioned trust and revocation ONLY; no write or self-issue."""
    need(path in (TRUST, REVOCATION), 'ROOT_FILE_NOT_ALLOWLISTED')
    for parent in (Path('/'), Path('/etc'), Path('/etc/ardrec')):
        s = parent.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not(s.st_mode & 0o022),
             'ROOT_PARENT_UNTRUSTED')
    s = path.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
         not(s.st_mode & 0o022) and 0 < s.st_size <= 8192, 'ROOT_FILE_UNTRUSTED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        actual = os.fstat(fd)
        need((actual.st_dev, actual.st_ino, actual.st_size) ==
             (s.st_dev, s.st_ino, s.st_size) and actual.st_uid == 0,
             'ROOT_FILE_RACE')
        data = os.read(fd, 8193)
        need(len(data) == s.st_size, 'ROOT_FILE_READ_SHORT')
        return data
    finally:
        os.close(fd)


def trust_check(value):
    f3.exact(value, {'schema', 'window_signer', 'revocation_signer'}, 'P8_TRUST_FIELDS')
    need(value['schema'] == TRUST_SCHEMA, 'P8_TRUST_SCHEMA')
    f3.trust_check({'schema': f3.TRUST_SCHEMA,
                    'scope_signer': value['window_signer'],
                    'revocation_signer': value['revocation_signer']})
    return value


def validate_budget(budget, contract):
    need(type(budget) is dict and set(budget) == BUDGET_KEYS, 'BUDGET_FIELDS')
    need(type(contract) is dict and type(contract.get('limits')) is dict,
         'CONTRACT_LIMITS_MISSING')
    for key, ceiling in BUDGET_CAPS.items():
        value = budget[key]
        need(type(value) is int and 0 <= value <= ceiling, 'BUDGET_INVALID_' + key)
        if key not in ('additional_attempts',):
            need(value > 0, 'BUDGET_EMPTY_' + key)
    need(budget['ordinary_attempts'] == 1 and budget['additional_attempts'] == 0 and
         budget['max_connections'] == 1, 'RETRY_OR_CONNECTION_BUDGET')
    need(budget['read_size'] <= budget['max_recv_bytes'] and
         budget['max_recv_calls'] * budget['read_size'] >= budget['max_recv_bytes'],
         'RECEIVE_BUDGET_INCONSISTENT')
    limits = contract['limits']
    for key, ckey in (('timeout_seconds', 'timeout_seconds'),
                      ('max_recv_bytes', 'transfer_bytes'),
                      ('max_output_bytes', 'output_bytes'),
                      ('memory_mib', 'memory_mib')):
        need(type(limits.get(ckey)) is int and budget[key] <= limits[ckey],
             'BUDGET_EXCEEDS_CONTRACT_' + key)
    need(budget['max_recv_calls'] <= limits['request_count'] and
         budget['ordinary_attempts'] <= limits['operation_count'],
         'REQUEST_OR_OPERATION_LIMIT')
    return budget


def signed_window_review(contract_raw, authorization_raw, window_raw, *, now,
                         loader=_root_file, catalog_raw=None):
    """Verify independent signatures & fresh revocation; documentary status only.

    Callable with injected root loader ONLY in tests or trusted internal code;
    CLI binds the actual fixed /etc/ardrec allowlist reader.
    """
    need(type(contract_raw) is bytes and type(authorization_raw) is bytes and
         type(window_raw) is bytes, 'SIGNED_INPUT_TYPE')
    need(type(now) is datetime and now.tzinfo is not None, 'CLOCK_TZ_REQUIRED')
    raw_catalog = (f6.CATALOG.read_bytes() if catalog_raw is None else catalog_raw)
    contract = f1.load(contract_raw)
    f1.validate(contract, f1.load(raw_catalog), raw_catalog)
    need(f1.digest(raw_catalog) == contract['catalog_sha256'], 'CATALOG_PIN')
    scope_state, scope_reason, _ = f6.scope(contract_raw, authorization_raw,
                                            catalog_raw=raw_catalog, now=now)
    need(scope_state == 'VERDADERO', 'SCOPE_NOT_INDEPENDENTLY_APPROVED_' + scope_state)
    trust = trust_check(f1.load(loader(TRUST)))
    revoke = f1.load(loader(REVOCATION))
    signed = f1.load(window_raw)
    f3.exact(signed, {'statement', 'signer_key_id', 'signature_b64'}, 'WINDOW_WRAPPER')
    stmt = signed['statement']
    f3.exact(stmt, {'schema', 'window_id', 'case_id', 'family_id', 'stage', 'head',
                    'catalog_sha256', 'contract_sha256', 'scope_authorization_sha256',
                    'target', 'valid_from', 'valid_until', 'action', 'budget',
                    'network_traffic_requested'}, 'WINDOW_FIELDS')
    need(stmt['schema'] == WINDOW_SCHEMA and
         type(stmt['window_id']) is str and f1.ID.fullmatch(stmt['window_id']) and
         stmt['case_id'] == contract['case_id'] and
         stmt['family_id'] == 'FTP-T01' and stmt['stage'] == 'DEV' and
         type(stmt['head']) is str and f1.GIT_SHA.fullmatch(stmt['head']) and
         stmt['catalog_sha256'] == contract['catalog_sha256'] and
         stmt['contract_sha256'] == f1.digest(contract_raw) and
         stmt['scope_authorization_sha256'] == f1.digest(authorization_raw) and
         stmt['target'] == contract['target'] and
         stmt['action'] == 'ONE_FTP_CONTROL_GREETING_READ_ONLY' and
         stmt['network_traffic_requested'] is True, 'WINDOW_SCOPE_MISMATCH')
    validate_budget(stmt['budget'], contract)
    a,b = _instant(stmt['valid_from']), _instant(stmt['valid_until'])
    need(a < b and (b-a).total_seconds() <= MAX_WINDOW_SECONDS and a <= now < b,
         'WINDOW_EXPIRED_OR_FUTURE')
    f3.verified_signature(signed, stmt, trust['window_signer'], WINDOW_PREFIX)
    f3.exact(revoke, {'statement','signer_key_id','signature_b64'}, 'REV_WRAPPER')
    state = revoke['statement']
    f3.exact(state, {'schema','window_sha256','window_id','issued_at','valid_until',
                     'revoked','reason_code'}, 'REV_FIELDS')
    need(state['schema'] == REV_SCHEMA and
         state['window_sha256'] == f1.digest(f1.canonical(signed)) and
         state['window_id'] == stmt['window_id'] and
         type(state['revoked']) is bool and
         type(state['reason_code']) is str and f1.ID.fullmatch(state['reason_code']),
         'REVOCATION_SCOPE_MISMATCH')
    f3.verified_signature(revoke, state, trust['revocation_signer'], REV_PREFIX)
    issued, until = _instant(state['issued_at']), _instant(state['valid_until'])
    need(issued <= now < until and 0 <= (now-issued).total_seconds() <= MAX_REV_AGE_SECONDS,
         'REVOCATION_NOT_CURRENT')
    if state['revoked']:
        return {'status':'FALSO','reason':'INDEPENDENT_SIGNED_REVOCATION',
                'window_sha256': f1.digest(f1.canonical(signed)),
                'budget': stmt['budget'], 'head': stmt['head']}
    return {'status':'DOCUMENT_SIGNED','reason':'DOCUMENT_ONLY_NOT_P8_RELEASE',
            'window_sha256': f1.digest(f1.canonical(signed)),
            'budget': stmt['budget'], 'head': stmt['head']}


def validate_transport_candidate(value, *, max_bytes=4096):
    """Strong F10 byte integrity check; cannot attest socket provenance/A6."""
    need(type(value) is dict and value.get('schema') == f10.SCHEMA and
         value.get('family_id') == 'FTP-T01' and
         value.get('target') == {'ip': f10.TARGET_IP, 'port': f10.TARGET_PORT},
         'F10_RESULT_SCOPE')
    need(value.get('transport') == 'TCP_IPV4_EXISTING_CONNECTION_READ_ONLY' and
         value.get('socket_opened_by_this_module') is False and
         value.get('network_connections_created_by_this_module') == 0 and
         value.get('client_bytes_transmitted_by_this_module') == 0 and
         value.get('p8_review_performed_by_this_module') is False and
         value.get('a5_physical_origin_independently_attested') is False and
         value.get('a6_classification') == 'ND', 'F10_FALSE_AUTHORITY')
    limit = value.get('limits')
    need(type(limit) is dict and set(limit) == {'timeout_seconds', 'max_bytes',
          'max_lines','read_size'}, 'F10_LIMITS')
    for key, cap in (('timeout_seconds',10),('max_bytes',4096),
                     ('max_lines',16),('read_size',512)):
        need(type(limit[key]) is int and 0 < limit[key] <= cap, 'F10_CAP_' + key)
    need(type(max_bytes) is int and 0 < max_bytes <= 4096 and
         limit['max_bytes'] <= max_bytes, 'F10_WINDOW_BYTE_LIMIT')
    count, received = value.get('recv_calls'), value.get('received_bytes')
    need(type(count) is int and count >= 0 and
         type(received) is int and 0 <= received <= limit['max_bytes'], 'F10_COUNTS')
    encoded = value.get('raw_b64')
    need(type(encoded) is str and len(encoded) <= 4*((4096+2)//3)+4,
         'F10_RAW_LENGTH')
    try:
        raw = base64.b64decode(encoded,validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Stop('F10_RAW_INVALID') from exc
    need(len(raw) == received and base64.b64encode(raw).decode('ascii') == encoded and
         f1.digest(raw) == value.get('raw_sha256'), 'F10_RAW_INTEGRITY')
    state,code = f10._line_state(raw, limit['max_lines'])
    # F10 can stop for socket/deadline reasons before the line is complete.
    if value.get('reply_status') == 'REPLY_COMPLETE':
        need(state == 'REPLY_COMPLETE' and code == value.get('ftp_reply_code'),
             'F10_REPLY_CLASS_CHANGED')
    need(value.get('greeting_220_observed') is
         (value.get('reply_status') == 'REPLY_COMPLETE' and value.get('ftp_reply_code') == 220),
         'F10_GREETING_FLAG')
    return {
        'schema': SCHEMA+'-a5-candidate',
        'family_id': 'FTP-T01', 'raw_sha256': f1.digest(raw),
        'received_bytes': len(raw), 'observed_220': value['greeting_220_observed'],
        'f10_sha256': f1.digest(f1.canonical(value)),
        'transport_origin_attested': False,
        'a5': 'PENDING_INDEPENDENT_PHYSICAL_ATTESTATION',
        'a6': 'ND', 'a7': None, 'a8': None, 'a9': None, 'a10': None,
        'p8': 'NO-GO',
    }


def policy_report(*, head, catalog_raw, handoff, window=None, candidate=None):
    """Fail-closed current-policy decision; no synthetic GO path."""
    need(type(head) is str and f1.GIT_SHA.fullmatch(head), 'HEAD_INVALID')
    cat = f1.load(catalog_raw)
    need(type(cat) is dict and type(handoff) is dict and
         handoff.get('schema') == f9.SCHEMA and handoff.get('repo_head') == head,
         'HANDOFF_OR_HEAD_CHANGED')
    need(handoff.get('catalog_sha256') == f1.digest(catalog_raw), 'CATALOG_CHANGED')
    need(type(window) in (dict,type(None)), 'WINDOW_REVIEW_TYPE')
    if window is not None:
        need(window.get('status') in ('DOCUMENT_SIGNED','FALSO','ND'),
             'WINDOW_REVIEW_VALUE')
        need(window.get('head') == head, 'WINDOW_HEAD_MISMATCH')
    blockers = []
    if not (cat.get('execution_enabled') is True and
            cat.get('catalog_frozen') is True and cat.get('pilot_completed') is True):
        blockers.append('P7_DRAFT_NOT_EXECUTABLE')
    if handoff['scope_review']['status'] != 'VERDADERO':
        blockers.append('A3_SCOPE_NOT_APPROVED')
    if handoff['scope_trust']['status'] != 'STRUCTURE_MATCH':
        blockers.append('SCOPE_TRUST_MISSING')
    if handoff['boot_trust']['status'] != 'STRUCTURE_MATCH':
        blockers.append('BOOT_TRUST_MISSING')
    if window is None or window['status'] != 'DOCUMENT_SIGNED':
        blockers.append('FRESH_SIGNED_P8_WINDOW_MISSING')
    blockers.extend(('A3_SERVICE_CLIENT_AND_DESTINATION_RUNTIME_NOT_ATTESTED',
                     'F11_R34_EFFECTIVE_P8_WINDOW_NOT_ATTESTED',
                     'P8_ROOT_EXECUTOR_NOT_IMPLEMENTED',
                     'NO_PHYSICAL_A5_PROVENANCE'))
    return {'schema':SCHEMA, 'head':head,'catalog_sha256':f1.digest(catalog_raw),
            'family':'FTP-T01', 'target':{'ip':'10.203.31.2','port':21},
            'signed_window_status': 'ND' if window is None else window['status'],
            'candidate_sha256': None if candidate is None else candidate['f10_sha256'],
            'blockers':blockers, 'p7_executable':False,
            'a3':{gate:'ND' for gate in f1.GATES},
            'p8':'NO-GO','a5':'NO-GO','a6':'ND',
            'a7':None,'a8':None,'a9':None,'a10':None,
            'network_connections':0,'guest_starts':0,
            'root_writes':0,'scope':'READONLY_POLICY_AND_CANDIDATE_ONLY'}


def review_current(*, window_path=None, contract_path=None, authorization_path=None,
                   source_check=f9.source_guard, clock=f7.utcnow):
    need((window_path is None) == (contract_path is None) ==
         (authorization_path is None), 'PARTIAL_P8_DOCUMENTS')
    head = source_check()
    now = clock()
    handoff = f9.evaluate(contract_path=contract_path,
                           authorization_path=authorization_path,
                           clock=lambda:now,source_check=lambda:head)
    review = None
    if window_path is not None:
        try:
            review = signed_window_review(f2.private_read(contract_path),
                                          f2.private_read(authorization_path),
                                          f2.private_read(window_path),now=now)
        except (FileNotFoundError,PermissionError,OSError,f1.Rejected,f3.Stop,f6.Stop,Stop):
            review = {'status':'ND','reason':'P8_DOCUMENTS_OR_ROOTS_UNVERIFIED','head':head}
    return policy_report(head=head,catalog_raw=f6.CATALOG.read_bytes(),
                         handoff=handoff, window=review)


def persist(report,root=ROOT):
    need(os.geteuid()!=0, 'ROOT_SHELL_FORBIDDEN')
    need(type(report) is dict and report.get('schema')==SCHEMA and
         report.get('p8')=='NO-GO' and report.get('network_connections')==0,
         'P8_REPORT_UNSAFE')
    folder=f7._create(root,'review-')
    payload=f1.canonical(report)
    f2.exclusive(folder/'report.json',payload)
    f2.exclusive(folder/'manifest.json',f1.canonical({
        'schema':SCHEMA+'-manifest', 'report_sha256':f1.digest(payload),
        'scope':'READONLY_NO_TRAFFIC_NO_A6'}))
    return folder


def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description='ARDREC R115-F11 P8 signed window and bounded A5 candidate (NO-GO)')
    parser.add_argument('--review',action='store_true',required=True)
    parser.add_argument('--contract',type=Path)
    parser.add_argument('--authorization',type=Path)
    parser.add_argument('--signed-window',type=Path)
    args=parser.parse_args(argv)
    try:
        report=review_current(window_path=args.signed_window,
                              contract_path=args.contract,
                              authorization_path=args.authorization)
        folder=persist(report)
        print('R115_F11_REVIEW='+str(folder))
        print('R115_F11_HEAD='+report['head'])
        print('R115_F11_P7_EXECUTABLE='+str(report['p7_executable']))
        print('R115_F11_SIGNED_WINDOW='+report['signed_window_status'])
        print('R115_F11_BLOCKERS='+','.join(report['blockers']))
        print('R115_F11_A5=NO-GO')
        print('R115_F11_A6=ND')
        print('R115_F11_P8=NO-GO')
        print('R115_F11_GUEST_STARTS=0')
        print('R115_F11_NETWORK_CONNECTIONS=0')
        return 0
    except (Stop,f1.Rejected,f2.Stop,f3.Stop,f6.Stop,f7.Stop,
            ValueError,TypeError,OSError,KeyError) as exc:
        print('R115_F11_STOP='+type(exc).__name__+':'+str(exc)[:150])
        print('R115_F11_P8=NO-GO')
        return 23


if __name__=='__main__':
    raise SystemExit(main())
