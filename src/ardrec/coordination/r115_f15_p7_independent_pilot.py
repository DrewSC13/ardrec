"""R115-F15: independently signed, narrowly-scoped P7 pilot *documentary* gate.

Breaks the P7/P8 POLICY circularity by defining a separate, short-lived pilot
request. This module CANNOT grant network access: an external trusted root
controller, live A3/F11/R34 evidence, and an individually approved pilot
session are still mandatory. No socket, guest boot, nft rule or P7 mutation.

Pilot authorizations are NOT ordinary P8 production windows and MUST NOT be
used to mark a general catalogue or any other family executable.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import stat

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r115_f6_signed_scope_and_activation as f6
from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_f11_p8_signed_window as f11
from ardrec.coordination import r115_f12_ftp_budget_preflight as f12
from ardrec.coordination import r115_f14_a5_a6_handoff as f14

SCHEMA = 'ARDREC-R115-F15-P7-INDEPENDENT-PILOT-REVIEW-v1'
REQUEST_SCHEMA = 'ARDREC-R115-F15-P7-PILOT-REQUEST-v1'
PERMIT_SCHEMA = 'ARDREC-R115-F15-FTP-T01-PILOT-PERMIT-v1'
REV_SCHEMA = 'ARDREC-R115-F15-P7-PILOT-REVOCATION-v1'
TRUST_SCHEMA = 'ARDREC-R115-F15-P7-EXTERNAL-TRUST-v1'
PERMIT_PREFIX = b'ARDREC-R115-F15-P7-PILOT-PERMIT-v1\x00'
REV_PREFIX = b'ARDREC-R115-F15-P7-PILOT-REVOCATION-v1\x00'
ROOT = Path('/home/cicada/ardrec-lab/r115-f15-p7-pilot-v1')
TRUST = Path('/etc/ardrec/r115-p7-pilot-trust-v1.json')
REVOCATION = Path('/etc/ardrec/r115-p7-pilot-revocation-v1.json')
CATALOG = Path('lab/operational-catalog-v1/catalog.json')
MAX_PILOT_SECONDS = 60
MAX_REVOCATION_AGE_SECONDS = 30
SOURCE = 'src/ardrec/coordination/r115_f15_p7_independent_pilot.py'
SCRIPT = 'scripts/ardrec_p14_r115_f15_p7_independent_pilot.py'

class Stop(ValueError):
    """Stable fail-closed validation error."""


def need(condition, code):
    if not condition:
        raise Stop(code)


def _time(value):
    try:
        return f1._instant(value, 'F15_TIMESTAMP')
    except f1.Rejected as exc:
        raise Stop('TIME_FORMAT_OR_ZONE') from exc


def _root_read(path):
    """No self-issued trust; pinned root-owned files from independent operator."""
    need(path in (TRUST, REVOCATION), 'ROOT_PATH_NOT_ALLOWLISTED')
    for parent in (Path('/'), Path('/etc'), Path('/etc/ardrec')):
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and
             not (st.st_mode & 0o022), 'ROOT_PARENT_NOT_TRUSTED')
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and
         st.st_nlink == 1 and not (st.st_mode & 0o022) and
         0 < st.st_size <= 8192, 'ROOT_FILE_UNTRUSTED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        now = os.fstat(fd)
        need((now.st_dev, now.st_ino, now.st_size, now.st_uid, now.st_nlink) ==
             (st.st_dev, st.st_ino, st.st_size, st.st_uid, st.st_nlink),
             'ROOT_FILE_RACE')
        data = os.read(fd, 8193)
        need(len(data) == st.st_size, 'ROOT_FILE_SHORT_READ')
        return data
    finally:
        os.close(fd)


def trust_check(value):
    f3.exact(value, {'schema', 'pilot_signer', 'revocation_signer'},
             'PILOT_TRUST_FIELDS')
    need(value['schema'] == TRUST_SCHEMA, 'PILOT_TRUST_SCHEMA')
    f3.trust_check({'schema': f3.TRUST_SCHEMA,
                    'scope_signer': value['pilot_signer'],
                    'revocation_signer': value['revocation_signer']})
    return value


def request(*, head, catalog_raw, contract_raw=None, profile=None):
    """Unsigned invitation for an independent human authority, never a permit."""
    need(type(head) is str and f1.GIT_SHA.fullmatch(head), 'SOURCE_HEAD_REQUIRED')
    try:
        f14.catalog_check(catalog_raw)
    except (f14.Stop,f12.Stop,f1.Rejected) as exc:
        raise Stop('DRAFT_CATALOG_PIN_OR_STRUCTURE_INVALID') from exc
    budget = profile if profile is not None else dict(f12.DRAFT_BUDGET)
    contract_sha = None
    case_id = None
    if contract_raw is not None:
        need(type(contract_raw) is bytes, 'CONTRACT_BYTES_REQUIRED')
        contract = f1.load(contract_raw)
        f1.validate(contract, f1.load(catalog_raw), catalog_raw)
        need(contract['source_commit'] == head, 'CONTRACT_HEAD_MISMATCH')
        if profile is None:
            caps=contract['limits']
            for field, contract_field in (('timeout_seconds','timeout_seconds'),
                    ('max_recv_bytes','transfer_bytes'),
                    ('max_output_bytes','output_bytes'),
                    ('memory_mib','memory_mib'),
                    ('max_recv_calls','request_count')):
                if type(caps.get(contract_field)) is int:
                    budget[field] = min(budget[field],caps[contract_field])
        budget=f12.validate_profile(budget,contract)
        contract_sha = f1.digest(contract_raw)
        case_id = contract['case_id']
    else:
        budget = f12.validate_profile(budget)
    return {
        'schema': REQUEST_SCHEMA,
        'repo_head': head,
        'family_id': 'FTP-T01',
        'stage': 'DEV',
        'target': {'ip':'10.203.31.2','port':21,
                   'vm':'ardrec-r33-dev-ftp',
                   'network':'ardrec-r33-dev-net-ftp'},
        'case_id': case_id,
        'contract_sha256': contract_sha,
        'catalog_sha256': f1.digest(catalog_raw),
        'profile': budget,
        'profile_sha256': f1.digest(f1.canonical(budget)),
        'pilot_action': 'ONE_ISOLATED_FTP_T01_CONTROL_GREETING',
        'pilot_duration_max_seconds': MAX_PILOT_SECONDS,
        'pilot_revocation_max_age_seconds': MAX_REVOCATION_AGE_SECONDS,
        'requires_independent_pilot_signer': True,
        'requires_distinct_revocation_signer': True,
        'requires_independently_approved_scope': True,
        'requires_live_boot_and_f11_r34_pre_post_proofs': True,
        'requires_separate_root_enforced_session': True,
        'pilot_exception_only': True,
        'catalogue_frozen': False,
        'catalogue_execution_enabled': False,
        'production_p8': 'NO-GO',
        'a6': 'ND',
        'authorization_issued_by_this_module': False,
    }


def signed_pilot_review(contract_raw, scope_authorization_raw, pilot_raw, *,
                        now, head, catalog_raw, loader=_root_read,
                        scope_reviewer=f6.scope):
    """Validate independent *documents*, NOT the physical P7 pilot session.

    A positive documentary review NEVER authorizes connecting a socket,
    opening a firewall, starting a VM or accepting A6. There is intentionally
    no root traffic dispatch path in this module.
    """
    need(type(now) is datetime and now.tzinfo is not None and
         now.utcoffset() is not None, 'UTC_AWARE_CLOCK_REQUIRED')
    need(type(head) is str and f1.GIT_SHA.fullmatch(head), 'HEAD_REQUIRED')
    need(type(contract_raw) is bytes and type(scope_authorization_raw) is bytes and
         type(pilot_raw) is bytes, 'SIGNED_INPUTS_REQUIRED')
    need(callable(loader) and callable(scope_reviewer), 'TRUST_READER_REQUIRED')
    draft = request(head=head, catalog_raw=catalog_raw, contract_raw=contract_raw)
    scope_state, _, auth_sha = scope_reviewer(contract_raw,
        scope_authorization_raw, catalog_raw=catalog_raw, now=now)
    need(scope_state == 'VERDADERO' and
         auth_sha == f1.digest(scope_authorization_raw),
         'SCOPE_NOT_AUTHORIZED_BY_INDEPENDENT_ROOT')
    trust = trust_check(f1.load(loader(TRUST)))
    rev = f1.load(loader(REVOCATION))
    permit = f1.load(pilot_raw)
    f3.exact(permit, {'statement','signer_key_id','signature_b64'},
             'PILOT_PERMIT_WRAPPER')
    stmt = permit['statement']
    f3.exact(stmt, {'schema','pilot_id','case_id','stage','family_id','head',
        'contract_sha256','scope_authorization_sha256','catalog_sha256','target',
        'budget','valid_from','valid_until','action',
        'pilot_only_no_production_p8'}, 'PILOT_PERMIT_FIELDS')
    contract = f1.load(contract_raw)
    need(stmt['schema'] == PERMIT_SCHEMA and
         type(stmt['pilot_id']) is str and f1.ID.fullmatch(stmt['pilot_id']) and
         stmt['case_id'] == contract['case_id'] and stmt['stage'] == 'DEV' and
         stmt['family_id'] == 'FTP-T01' and stmt['head'] == head and
         stmt['contract_sha256'] == draft['contract_sha256'] and
         stmt['scope_authorization_sha256'] == auth_sha and
         stmt['catalog_sha256'] == draft['catalog_sha256'] and
         stmt['target'] == contract['target'] and
         stmt['action'] == draft['pilot_action'] and
         stmt['pilot_only_no_production_p8'] is True,
         'PILOT_SCOPE_OR_IDENTITY_MISMATCH')
    f11.validate_budget(stmt['budget'], contract)
    # Pilot may narrow, never enlarge, prepilot budgets.
    for key, cap in draft['profile'].items():
        need(type(stmt['budget'][key]) is int and stmt['budget'][key] <= cap,
             'PILOT_BUDGET_EXCEEDS_DRAFT_' + key)
    begin, end = _time(stmt['valid_from']), _time(stmt['valid_until'])
    need(begin < end and (end-begin).total_seconds() <= MAX_PILOT_SECONDS and
         begin <= now < end, 'PILOT_NOT_IN_VALIDITY_WINDOW')
    f3.verified_signature(permit, stmt, trust['pilot_signer'], PERMIT_PREFIX)
    f3.exact(rev, {'statement','signer_key_id','signature_b64'},
             'PILOT_REVOCATION_WRAPPER')
    state = rev['statement']
    f3.exact(state, {'schema','pilot_sha256','pilot_id','issued_at',
                     'valid_until','revoked','reason_code'},
             'PILOT_REVOCATION_FIELDS')
    need(state['schema'] == REV_SCHEMA and
         state['pilot_sha256'] == f1.digest(f1.canonical(permit)) and
         state['pilot_id'] == stmt['pilot_id'] and
         type(state['revoked']) is bool and
         type(state['reason_code']) is str and
         f1.ID.fullmatch(state['reason_code']),
         'PILOT_REVOCATION_NOT_BOUND')
    f3.verified_signature(rev, state, trust['revocation_signer'], REV_PREFIX)
    issued, expires = _time(state['issued_at']), _time(state['valid_until'])
    need(issued <= now < expires and
         0 <= (now-issued).total_seconds() <= MAX_REVOCATION_AGE_SECONDS,
         'PILOT_REVOCATION_STALE')
    revoked = state['revoked']
    return {
        'schema': SCHEMA+'-signed-review',
        'pilot_sha256':f1.digest(f1.canonical(permit)),
        'scope_authorization_sha256':auth_sha,
        'contract_sha256':draft['contract_sha256'],
        'catalog_sha256':draft['catalog_sha256'],
        'head':head,'family_id':'FTP-T01',
        'budget':stmt['budget'],
        'document_status':'REVOKED' if revoked else 'DOCUMENT_SIGNED',
        'reason':'INDEPENDENT_SIGNED_REVOCATION' if revoked else
                 'ROOT_ANCHORED_DOCUMENT_NOT_PHYSICAL_SESSION',
        'physical_pilot_session_attested':False,
        'p7_pilot_completed':False,
        'p7_execution_enabled':False,
        'p8':'NO-GO','a6':'ND',
        'network_connections_by_module':0,'vm_starts_by_module':0,
        'authorized_to_connect_by_module':False,
    }


def overview(*, head, catalog_raw, contract_raw=None, authorization_raw=None,
             pilot_raw=None, now=None):
    """Current offline readout, rejecting partial documents (never auto-grants)."""
    now = datetime.now(timezone.utc) if now is None else now
    want = (contract_raw is not None, authorization_raw is not None,
            pilot_raw is not None)
    need(want in ((False,False,False),(True,True,True)),
         'PARTIAL_AUTHORIZATION_DOCUMENTS')
    document = {'status':'ND','reason':'INDEPENDENT_DOCUMENTS_MISSING'}
    if all(want):
        try:
            signed = signed_pilot_review(contract_raw,authorization_raw,
                pilot_raw, now=now, head=head, catalog_raw=catalog_raw)
            document = {'status':signed['document_status'],
                        'reason':signed['reason'],
                        'pilot_sha256':signed['pilot_sha256']}
        except (Stop,f1.Rejected,f3.Stop,f11.Stop,f12.Stop,ValueError,TypeError,
                KeyError,OSError) as exc:
            document = {'status':'REJECTED','reason':type(exc).__name__}
    req = request(head=head,catalog_raw=catalog_raw,
                  contract_raw=contract_raw if all(want) else None)
    return {
        'schema':SCHEMA+'-overview',
        'request':req,
        'pilot_documents':document,
        'blockers':([ 'INDEPENDENT_PILOT_AND_SCOPE_DOCUMENTS_MISSING'
                      if document['status']=='ND' else
                      'INDEPENDENT_PILOT_DOCUMENTS_NOT_APPROVED'
                      if document['status']!='DOCUMENT_SIGNED' else
                      'PILOT_ROOT_CONTROLLER_NOT_IMPLEMENTED' ] + [
                      'CURRENT_BOOT_CHAIN_NOT_ATTESTED',
                      'CURRENT_F11_R34_ROOT_PILOT_WINDOW_NOT_ATTESTED',
                      'CURRENT_A3_CLIENT_SERVICE_DESTINATION_NOT_ATTESTED',
                      'PHYSICAL_P7_MEASUREMENTS_NOT_COLLECTED']),
        'catalogue_status':'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE',
        'physical_pilot_authorized':False,
        'pilot_completed':False,
        'catalogue_frozen':False,
        'p7_execution_enabled':False,
        'p8':'NO-GO','a5':'NO-GO','a6':'ND',
        'a7':None,'a8':None,'a9':None,'a10':None,
        'vm_starts':0,'network_connections':0,
    }


def persist(report, *, root=ROOT):
    need(os.geteuid()!=0,'ROOT_SHELL_FORBIDDEN')
    need(type(report) is dict and report.get('schema')==SCHEMA+'-overview' and
         report.get('p8')=='NO-GO' and report.get('physical_pilot_authorized') is False,
         'UNSAFE_PILOT_REPORT')
    folder=f7._create(root,'request-')
    raw=f1.canonical(report)
    f2.exclusive(folder/'report.json',raw)
    f2.exclusive(folder/'manifest.json',f1.canonical({
        'schema':SCHEMA+'-manifest',
        'report_sha256':f1.digest(raw),
        'kind':'NON_EXECUTABLE_PILOT_AUTHORITY_HANDOFF'}))
    return folder


def capabilities():
    return {'schema':SCHEMA+'-capabilities','family_id':'FTP-T01',
            'signed_pilot_exception_review':True,
            'independent_pilot_revocation':True,
            'short_validity_max_seconds':MAX_PILOT_SECONDS,
            'root_owned_trust_only':True,
            'pilot_not_general_p8':True,
            'a5_dispatch_implemented':False,
            'opens_socket':False,'boots_guest':False,
            'changes_nftables':False,'issues_signature':False,
            'p7_pilot_completed':False,'a6':'ND','p8':'NO-GO'}
