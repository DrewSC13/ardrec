"""ARDREC R126-B3: authenticate a one-shot FTP-T01 traffic-window *document*.

Reuses F11's schemas, signature domains, exact budget and root policy pins,
while using the current-source R126 Scope V2 instead of legacy F6's fixed
historical HEAD.  Neither a signed window nor this review grants P8/traffic.
A separate root controller, exact session binding and independent watchdog
must be proven before operational use.  Runtime uses pinned /etc/ardrec only.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r115_f11_p8_signed_window as f11
from ardrec.coordination import r115_f15_p7_independent_pilot as f15
from ardrec.coordination import r126_scope_v2 as scope_v2

SCHEMA = 'ARDREC-R126-FTP-T01-CURRENT-SOURCE-WINDOW-v2'
WINDOW_MAX_SECONDS = 60
REVOCATION_MAX_AGE_SECONDS = 30

class Stop(ValueError):
    """Fail closed; a rejected document never authorizes a connection."""


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise Stop(reason)


def _canonical(raw: bytes) -> dict:
    need(type(raw) is bytes, 'DOCUMENT_BYTES_REQUIRED')
    value = f1.load(raw)
    need(f1.canonical(value) == raw, 'NON_CANONICAL_DOCUMENT')
    return value


def _now(value: datetime) -> datetime:
    need(type(value) is datetime and value.tzinfo is not None and
         value.utcoffset() is not None and value.microsecond == 0,
         'CLOCK_NOT_TRUSTED')
    return value.astimezone(timezone.utc)


def _separate(scope: dict, pilot: dict, traffic: dict) -> None:
    """Six different public keys AND role IDs; no aliasing across roles."""
    try:
        f3.trust_check(scope)
        f15.trust_check(pilot)
        f11.trust_check(traffic)
        entries = (scope['scope_signer'], scope['revocation_signer'],
                   pilot['pilot_signer'], pilot['revocation_signer'],
                   traffic['window_signer'], traffic['revocation_signer'])
        keys = [f1.digest(e['public_key_pem'].encode('ascii')) for e in entries]
        ids = [e['key_id'] for e in entries]
    except (KeyError, TypeError, AttributeError, UnicodeError,
            f3.Stop, f15.Stop, f11.Stop) as exc:
        raise Stop('SIGNER_TRUST_INVALID') from exc
    need(len(set(keys)) == len(set(ids)) == 6,
         'SCOPE_PILOT_TRAFFIC_SIGNERS_NOT_INDEPENDENT')


def root_signer_separation() -> bool:
    """Production path: read root-owned, allowlisted trust from /etc/ardrec."""
    _separate(_canonical(scope_v2._root_file(scope_v2.TRUST)),
              _canonical(f15._root_read(f15.TRUST)),
              _canonical(f11._root_file(f11.TRUST)))
    return True


def review_documents(*, contract_raw: bytes, authorization_raw: bytes,
                     pilot_raw: bytes, window_raw: bytes, catalog_raw: bytes,
                     expected_head: str, now: datetime,
                     scope_reviewer: Callable | None = None,
                     pilot_reviewer: Callable | None = None,
                     trust_loader: Callable | None = None) -> dict:
    """Unit-testable review. Injected readers are forbidden on live CLI path.

    Revocation is authenticated and fresh. All documentary results are blocked
    from root and network actions. An independent session-specific root permit
    must bind the pilot and window hashes before any physical transition.
    """
    at = _now(now)
    need(type(expected_head) is str and f1.GIT_SHA.fullmatch(expected_head),
         'HEAD_INVALID')
    need(all(type(raw) is bytes for raw in (contract_raw, authorization_raw,
             pilot_raw, window_raw, catalog_raw)), 'DOC_INPUT_TYPE')
    scope_reviewer = scope_reviewer or scope_v2.for_head(expected_head)
    pilot_reviewer = pilot_reviewer or f15.signed_pilot_review
    trust_loader = trust_loader or f11._root_file
    need(callable(scope_reviewer) and callable(pilot_reviewer) and
         callable(trust_loader), 'REVIEW_DEPENDENCY_INVALID')
    try:
        contract = _canonical(contract_raw)
        authorization = _canonical(authorization_raw)
        pilot = _canonical(pilot_raw)
        window = _canonical(window_raw)
        f1.validate(contract, f1.load(catalog_raw), catalog_raw)
    except (f1.Rejected, ValueError, TypeError, KeyError) as exc:
        raise Stop('CONTRACT_OR_DOCUMENT_INVALID') from exc
    need(contract['source_commit'] == expected_head, 'CONTRACT_HEAD_MISMATCH')
    scope_state, _, scope_sha = scope_reviewer(contract_raw,
                     authorization_raw, catalog_raw=catalog_raw, now=at)
    need(scope_state == 'VERDADERO' and scope_sha == f1.digest(authorization_raw),
         'CURRENT_SCOPE_NOT_SIGNED_AND_FRESH')
    try:
        pilot_review = pilot_reviewer(contract_raw, authorization_raw, pilot_raw,
                                     now=at, head=expected_head,
                                     catalog_raw=catalog_raw,
                                     scope_reviewer=scope_reviewer)
    except (f15.Stop, TypeError, ValueError, OSError) as exc:
        raise Stop('INDEPENDENT_PILOT_DOCUMENT_REJECTED') from exc
    need(type(pilot_review) is dict and
         pilot_review.get('document_status') == 'DOCUMENT_SIGNED' and
         pilot_review.get('head') == expected_head and
         pilot_review.get('scope_authorization_sha256') == scope_sha and
         pilot_review.get('pilot_sha256') == f1.digest(f1.canonical(pilot)),
         'PILOT_NOT_CURRENTLY_SIGNED')
    try:
        trust = f11.trust_check(_canonical(trust_loader(f11.TRUST)))
        revoked = _canonical(trust_loader(f11.REVOCATION))
        f3.exact(window, {'statement','signer_key_id','signature_b64'},
                 'WINDOW_ENVELOPE_FIELDS')
        stmt = window['statement']
        f3.exact(stmt, {'schema','window_id','case_id','family_id','stage','head',
                'catalog_sha256','contract_sha256','scope_authorization_sha256',
                'target','valid_from','valid_until','action','budget',
                'network_traffic_requested'}, 'WINDOW_STATEMENT_FIELDS')
    except (Stop, f1.Rejected, f11.Stop, f3.Stop, OSError, TypeError, KeyError) as exc:
        raise Stop('WINDOW_ROOT_TRUST_OR_STRUCTURE_INVALID') from exc
    need(stmt['schema'] == f11.WINDOW_SCHEMA and
         type(stmt['window_id']) is str and f1.ID.fullmatch(stmt['window_id']) and
         stmt['case_id'] == contract['case_id'] and stmt['family_id'] == 'FTP-T01' and
         stmt['stage'] == 'DEV' and stmt['head'] == expected_head and
         stmt['catalog_sha256'] == f1.digest(catalog_raw) and
         stmt['contract_sha256'] == f1.digest(contract_raw) and
         stmt['scope_authorization_sha256'] == scope_sha and
         stmt['target'] == contract['target'] and
         stmt['action'] == 'ONE_FTP_CONTROL_GREETING_READ_ONLY' and
         stmt['network_traffic_requested'] is True,
         'WINDOW_WRONG_CASE_HEAD_OR_TARGET')
    try:
        budget = f11.validate_budget(stmt['budget'], contract)
    except (f11.Stop, TypeError, ValueError, KeyError) as exc:
        raise Stop('WINDOW_BUDGET_INVALID') from exc
    need(type(pilot_review.get('budget')) is dict and
         set(pilot_review['budget']) == set(budget) and
         all(type(pilot_review['budget'][k]) is int and
             budget[k] <= pilot_review['budget'][k] for k in budget),
         'WINDOW_EXPANDS_PILOT_BUDGET')
    try:
        start = f1._instant(stmt['valid_from'], 'WINDOW_FROM')
        end = f1._instant(stmt['valid_until'], 'WINDOW_UNTIL')
        f3.verified_signature(window, stmt, trust['window_signer'],
                              f11.WINDOW_PREFIX)
        f3.exact(revoked, {'statement','signer_key_id','signature_b64'},
                 'WINDOW_REVOCATION_ENVELOPE')
        state = revoked['statement']
        f3.exact(state, {'schema','window_sha256','window_id','issued_at',
                  'valid_until','revoked','reason_code'},
                 'WINDOW_REVOCATION_FIELDS')
        need(state['schema'] == f11.REV_SCHEMA and
             state['window_sha256'] == f1.digest(f1.canonical(window)) and
             state['window_id'] == stmt['window_id'] and
             type(state['revoked']) is bool and
             type(state['reason_code']) is str and
             f1.ID.fullmatch(state['reason_code']),
             'WINDOW_REVOCATION_NOT_BOUND')
        f3.verified_signature(revoked, state, trust['revocation_signer'],
                              f11.REV_PREFIX)
        issued = f1._instant(state['issued_at'], 'REVOCATION_ISSUED')
        expires = f1._instant(state['valid_until'], 'REVOCATION_UNTIL')
    except (Stop, f1.Rejected, f3.Stop, TypeError, ValueError, KeyError) as exc:
        if isinstance(exc, Stop): raise
        raise Stop('WINDOW_SIGNATURE_OR_REVOCATION_INVALID') from exc
    need(start < end and (end-start).total_seconds() <= WINDOW_MAX_SECONDS and
         start <= at < end, 'WINDOW_EXPIRED_OR_TOO_LONG')
    need(issued <= at < expires and
         0 <= (at-issued).total_seconds() <= REVOCATION_MAX_AGE_SECONDS and
         expires > issued, 'WINDOW_REVOCATION_NOT_FRESH')
    status = 'REVOKED' if state['revoked'] else 'DOCUMENT_SIGNED'
    result = {
        'schema':SCHEMA+'-review', 'head':expected_head,
        'case_id':contract['case_id'], 'family_id':'FTP-T01',
        'scope_authorization_sha256':scope_sha,
        'pilot_sha256':pilot_review['pilot_sha256'],
        'window_sha256':f1.digest(f1.canonical(window)),
        'window_revocation_sha256':f1.digest(f1.canonical(revoked)),
        'document_status':status, 'budget':budget.copy(),
        'root_controller_grant_attested':False,
        'session_specific_permit_bound':False,
        'independent_60s_watchdog_attested':False,
        'dispatch':False,'physical_action_count':0,
        'a6':'ND','a9':None,'p8':'NO-GO',
    }
    result['sha256']=f1.digest(f1.canonical(result))
    return result


def review_current(*, contract_raw: bytes, authorization_raw: bytes,
                   pilot_raw: bytes, window_raw: bytes, catalog_raw: bytes,
                   expected_head: str, now: datetime) -> dict:
    """Only production entry point: no ability to supply caller-owned trust."""
    root_signer_separation()
    return review_documents(contract_raw=contract_raw,
        authorization_raw=authorization_raw, pilot_raw=pilot_raw,
        window_raw=window_raw, catalog_raw=catalog_raw,
        expected_head=expected_head, now=now)


def capabilities() -> dict:
    return {'schema':SCHEMA+'-capabilities',
            'reuses_f11_exact_window_signature_domain':True,
            'scope_v2_current_source_required':True,
            'f15_independent_pilot_required':True,
            'six_separate_authority_signers_required':True,
            'maximum_window_seconds':WINDOW_MAX_SECONDS,
            'maximum_revocation_age_seconds':REVOCATION_MAX_AGE_SECONDS,
            'independent_root_controller_grant':False,
            'physical_window_opened':False,
            'p8':'NO-GO','a6':'ND','a9':None}
