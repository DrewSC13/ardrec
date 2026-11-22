"""R126: scope/revocation and independent-root handoff for one FTP-T01 pilot.

The signed F15 review is a DOCUMENTARY precondition. R124's DENY
readback proves containment but neither artifact authorizes networking.
No root writes, guest boots, sockets, or traffic dispatch are provided here.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
import stat
from pathlib import Path
from typing import Any

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f15_p7_independent_pilot as f15
from ardrec.coordination import r126_scope_v2 as scope_v2
from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_f11_p8_signed_window as f11
from ardrec.coordination import r124_root_deny_readback as r124
from ardrec.coordination import r125_integrated_acceptance as r125

SCHEMA = 'ARDREC-R126-FTP-T01-ROOT-HANDOFF-v1'
HEX40 = re.compile(r'[0-9a-f]{40}\Z')


class Stop(ValueError):
    """Fail closed, with stable refusal codes."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise Stop(code)


def sha(value: dict) -> str:
    return f1.digest(f1.canonical(value))


def utc(now: datetime) -> str:
    need(type(now) is datetime and now.tzinfo is not None and
         now.utcoffset() is not None and now.microsecond == 0,
         'CLOCK_UNTRUSTED')
    return now.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def review(*, head: str, now: datetime, root_report: dict,
           integrated_report: dict, documentary_review: dict | None = None,
           authorizer: str = 'MISSING') -> dict[str, Any]:
    """Bind a SOURCE_ONLY handoff to R124 and R125; never issue a root grant.

    documentary_review may ONLY be obtained from signed_documents() in live
    operation. Supplying an arbitrary dict cannot ever set allow_dispatch.
    """
    need(type(head) is str and HEX40.fullmatch(head) is not None, 'HEAD_INVALID')
    timestamp = utc(now)
    need(type(root_report) is dict and type(integrated_report) is dict,
         'SOURCE_REPORTS_REQUIRED')
    try:
        host = r125.root_check(root_report, head=head)
    except (r125.Stop, ValueError, KeyError, TypeError) as exc:
        raise Stop('R124_ROOT_READBACK_REJECTED') from exc
    need(integrated_report.get('schema') == r125.SCHEMA and
         integrated_report.get('head') == head and
         integrated_report.get('root_readback_sha256') == root_report['sha256'] and
         integrated_report.get('p8') == 'NO-GO' and
         integrated_report.get('physical_60s_closure_attested') is False and
         integrated_report.get('a6') == 'ND' and
         integrated_report.get('a9_global_generation') is None and
         integrated_report.get('sha256') == sha({k:v for k,v in integrated_report.items()
                                                  if k!='sha256'}),
         'R125_INTEGRITY_OR_STATUS_INVALID')
    review_status = 'DOCUMENTS_NOT_PRESENT'
    if documentary_review is not None:
        need(type(documentary_review) is dict and
             documentary_review.get('schema') == f15.SCHEMA+'-signed-review' and
             documentary_review.get('head') == head and
             documentary_review.get('family_id') == 'FTP-T01' and
             documentary_review.get('p8') == 'NO-GO' and
             documentary_review.get('physical_pilot_session_attested') is False and
             documentary_review.get('authorized_to_connect_by_module') is False and
             documentary_review.get('document_status') in ('DOCUMENT_SIGNED','REVOKED'),
             'F15_DOCUMENTARY_REVIEW_INVALID')
        review_status = documentary_review['document_status']
    need(authorizer == 'MISSING', 'CANNOT_SELF_ISSUE_ROOT_AUTHORITY')
    blockers = ['INDEPENDENT_ROOT_ENFORCED_PILOT_GRANT_NOT_PRESENT',
                'NO_SESSION_TIMER_ARMED_FOR_THIS_CASE',
                'P7_DRAFT_PILOT_ONLY',
                'NO_PHYSICAL_DISPATCH_AUTHORIZATION']
    if review_status != 'DOCUMENT_SIGNED':
        blockers.append('SIGNED_PILOT_OR_CURRENT_REVOCATION_MISSING')
    if host['status'] != 'FIVE_ONE_DENY_MATCH':
        blockers.append('FIVE_ONE_FTP_DENY_NOT_OBSERVED')
    if host['session_timer_state'] != 'active':
        blockers.append('SESSION_45S_AUTONOMOUS_TIMER_NOT_ACTIVE')
    result = {
        'schema': SCHEMA, 'head':head,'evaluated_at_utc':timestamp,
        'family_id':'FTP-T01','root_readback_sha256':root_report['sha256'],
        'r125_sha256':integrated_report['sha256'],
        'document_status':review_status,
        'documentary_review_sha256':None if documentary_review is None else sha(documentary_review),
        'root_deny_state':host['status'],
        'root_session_timer':host['session_timer_state'],
        'one_shot_attempt_consumed':host['session_marker_consumed'],
        'root_enforced_grant_verified':False,
        'dispatch':False,'network_connections':0,'vm_starts':0,
        'a6':'ND','a9':None,'p7':'DRAFT','p8':'NO-GO',
        'blockers':sorted(blockers),
    }
    result['sha256'] = sha(result)
    return result


def signed_documents(*, contract_raw: bytes, authorization_raw: bytes,
                     pilot_raw: bytes, catalog_raw: bytes, head: str,
                     now: datetime) -> dict:
    """Invoke F15's actual signed+revocation review and root-owned trust.

    It is critical NOT to inject a test loader in the live path.
    """
    try:
        scope_v2.root_role_separation()
        return f15.signed_pilot_review(contract_raw, authorization_raw,
                                       pilot_raw, now=now, head=head,
                                       catalog_raw=catalog_raw,
                                       scope_reviewer=scope_v2.for_head(head))
    except (f15.Stop, ValueError, TypeError, OSError, KeyError) as exc:
        raise Stop('CURRENT_SIGNED_PILOT_REJECTED') from exc




def unsigned_pilot_request(*, head: str, catalog_raw: bytes,
                           contract_raw: bytes) -> dict:
    """Generate only the unsigned F15 operator request; never an authority.

    Strictly binds the supplied contract to the checked-out commit. An
    unsigned request from an unmerged source branch is NOT executable and
    must be reissued if the approved source commit changes.
    """
    need(type(head) is str and HEX40.fullmatch(head) is not None,
         'UNSIGNED_REQUEST_HEAD_INVALID')
    need(type(contract_raw) is bytes, 'UNSIGNED_CONTRACT_REQUIRED')
    need(type(catalog_raw) is bytes, 'UNSIGNED_CATALOG_REQUIRED')
    try:
        request = f15.request(head=head, catalog_raw=catalog_raw,
                              contract_raw=contract_raw)
    except (f15.Stop, f1.Rejected, ValueError, TypeError, KeyError) as exc:
        raise Stop('UNSIGNED_PILOT_REQUEST_INVALID') from exc
    need(request.get('authorization_issued_by_this_module') is False and
         request.get('production_p8') == 'NO-GO' and
         request.get('catalogue_execution_enabled') is False and
         request.get('case_id') is not None and
         request.get('contract_sha256') == f1.digest(contract_raw) and
         request.get('repo_head') == head,
         'UNSIGNED_REQUEST_AUTHORITY_PROMOTION')
    return request


def root_document_metadata() -> dict:
    """Inspect fixed trust/revocation file *metadata*, not their contents.

    Nothing here authenticates a signature, non-revocation or permission.
    Even root-owned files marked present are only DOCUMENTARY prerequisites.
    """
    targets = {
        'f15_pilot_trust': f15.TRUST,
        'f15_pilot_revocation': f15.REVOCATION,
        'f7_boot_trust': f7.PERMIT_TRUST,
        'f7_boot_revocation': f7.PERMIT_REVOCATION,
        'f11_traffic_trust': f11.TRUST,
        'f11_traffic_revocation': f11.REVOCATION,
        'r127_root_closure_witness_trust': Path('/etc/ardrec/r127-root-closure-witness-v1.json'),
    }
    out = {}
    for name, path in targets.items():
        try:
            info=path.lstat()
        except FileNotFoundError:
            status='NOT_PROVISIONED'
        except PermissionError:
            status='NOT_ACCESSIBLE_CANNOT_INFER'
        except OSError:
            status='UNREADABLE_CANNOT_INFER'
        else:
            status=('ROOT_OWNED_FILE_NOT_CRYPTO_VERIFIED'
                    if stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                       info.st_nlink == 1 and not(info.st_mode & 0o022) and
                       0 < info.st_size <= 8192
                    else 'UNTRUSTED_FILE_METADATA')
        out[name]={'path':str(path),'status':status}
    return {'schema':SCHEMA+'-root-document-metadata',
            'files':out,'signature_verified':False,
            'revocation_verified':False,
            'root_operational_grant':False,'p8':'NO-GO'}


def verify(report: dict, *, root_report: dict,
           integrated_report: dict, documentary_review: dict | None = None) -> bool:
    need(type(report) is dict and type(report.get('evaluated_at_utc')) is str,
         'REPORT_SCHEMA')
    try:
        now=datetime.strptime(report['evaluated_at_utc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        expected=review(head=report['head'],now=now,root_report=root_report,
                        integrated_report=integrated_report,
                        documentary_review=documentary_review)
    except (ValueError, TypeError, KeyError, OverflowError) as exc:
        raise Stop('HANDOFF_REPLAY_REJECTED') from exc
    need(report == expected, 'HANDOFF_TAMPERED')
    return True


def capabilities() -> dict:
    return {'schema':SCHEMA+'-capabilities','f15_crypto_and_revocation_reuse':True,
            'r124_deny_and_r125_case_bound':True,
            'independent_root_permit_issued_here':False,
            'opens_socket':False,'boots_vm':False,'arms_timer':False,
            'p8':'NO-GO','a6':'ND','a9':None}
