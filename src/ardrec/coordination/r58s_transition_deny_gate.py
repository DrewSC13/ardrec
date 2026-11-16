"""R58-S: durable, deny-only assessment of R58-R state proposals.

The signed actor, independently attested authorization and durable state
commit are NOT present in R58-R. This module makes that missing boundary
machine-verifiable. It never approves, commits, dispatches or publishes.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.coordination.r58r_durable_transition_proposal import (
    _read_private, _root, build_proposal, verify_persisted_proposal,
)

SCHEMA = 'ardrec-r58s-a3-a4-deny-only-transition-gate-v1'
BASE = '7a891cc01d1d9b95ad21087e472eb80eb1227045'
MAX_CASES = 54
MAX_RECEIPT_BYTES = 131072
IDENTITY = ('service_id','session_id','derived_case_id','assessment_index')
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
SESSION = re.compile(r'[A-Za-z0-9_:-]{1,80}\Z', re.ASCII)
GATE_KEYS = frozenset((
    'schema','source_base_commit','mode','session_id',
    'r58r_proposal_sha256','r58q_trace_sha256','source_catalog_sha256',
    'source_thesis_sha256','case_count','family_count',
    'current_prepared_count','hypothetical_pending_count',
    'request_count','logical_candidates_count','not_eligible_count',
    'denials_by_reason','cases','all_requests_denied','independent_authority_attested',
    'signed_approval_attested','transition_commit_attested',
    'confirmed_pending_case_count','transitions_applied',
    'state_machine_mutated','technical_truth_accredited','a6_classification',
    'confirmed_final_risk','published_generation','operational_dispatch',
    'p8_operational','sha256',
))
CASE_KEYS = frozenset((
    *IDENTITY,'family_id','variant','case_id_a7','control_id_a3',
    'current_phase','counterfactual_phase','a3_guard_truth',
    'a3_blockers','logical_candidate','request_status','deny_reason',
    'independent_authority_attested','signed_approval_attested',
    'transition_commit_attested','review_outcome','state_committed',
))


class TransitionGateError(ValueError):
    """Integrity or authority barrier failure; never retry as an approval."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise TransitionGateError(code)


def _sha(value: Any) -> str:
    need(type(value) is str and HEX.fullmatch(value) is not None,
         'DIGEST_NOT_SHA256')
    return value


def _case_identity(row: dict[str, Any]) -> tuple[str, str, str, int]:
    return tuple(row[key] for key in IDENTITY)


def _name(session_id: str) -> str:
    need(type(session_id) is str and SESSION.fullmatch(session_id) is not None,
         'SESSION_ID_UNSAFE')
    token = hashlib.sha256(b'ARDREC-R58S-DENY-GATE-V1\x00' +
                           session_id.encode('ascii')).hexdigest()
    return 'r58s_' + token + '.json'


def build_deny_gate(proposal_root: Path, trace: dict[str, Any],
                    scenario: dict[str, Any], review: dict[str, Any],
                    a3_report: dict[str, Any]) -> dict[str, Any]:
    """Verify persisted R58-R source, then assess each case fail-closed.

    A logical A3/A4 candidate is a *request for review*, never consent.
    All approvals are intentionally unavailable until a separate, attested
    authorization and transition-commit protocol has been designed.
    """
    source = verify_persisted_proposal(proposal_root, trace, scenario,
                                       review, a3_report)
    proposal = build_proposal(trace, scenario, review, a3_report)
    need(type(source) is dict and
         source.get('verification') == 'PASS_DECLARED_LOCAL_PROPOSAL_NO_TRANSITION' and
         source.get('receipt_sha256') == proposal.get('sha256') and
         source.get('transitions_applied') == 0 and
         source.get('state_machine_mutated') is False and
         source.get('operational_dispatch') is False and
         source.get('p8_operational') == 'NO-GO',
         'SOURCE_NOT_VERIFIED_DECLARED_ONLY')
    need(type(proposal) is dict and
         proposal.get('schema') == 'ardrec-r58r-immutable-declared-transition-proposal-v1' and
         proposal.get('mode') == 'IMMUTABLE_LOCAL_PROPOSAL_NOT_MACHINE_STATE' and
         proposal.get('session_id') == trace.get('session_id') and
         type(proposal.get('cases')) is list and
         type(proposal.get('case_count')) is int and
         0 < proposal['case_count'] <= MAX_CASES and
         len(proposal['cases']) == proposal['case_count'] and
         type(proposal.get('family_count')) is int and
         0 < proposal['family_count'] <= 25,
         'PROPOSAL_STRUCTURE_INVALID')
    need(digest({k:v for k,v in proposal.items() if k != 'sha256'}) ==
         proposal['sha256'], 'PROPOSAL_DIGEST_MISMATCH')
    for field in ('sha256','r58q_trace_sha256','source_catalog_sha256',
                  'source_thesis_sha256'):
        _sha(proposal[field])
    need(proposal['r58q_trace_sha256'] == trace['sha256'] and
         proposal['source_catalog_sha256'] == review['source_catalog_sha256'] and
         proposal['source_thesis_sha256'] == review['source_thesis_sha256'] and
         proposal['current_prepared_count'] == proposal['case_count'] and
         proposal['a4_current_eligible_count'] == 0 and
         proposal['current_selected_case'] is None and
         proposal['counterfactual_pending_count'] ==
             proposal['a4_counterfactual_eligible_count'] and
         proposal['transitions_applied'] == 0 and
         proposal['confirmed_pending_case_count'] == 0 and
         proposal['technical_truth_accredited'] is False and
         proposal['applied_state_transition'] is None and
         proposal['published_generation'] is None and
         proposal['operational_dispatch'] is False and
         proposal['p8_operational'] == 'NO-GO',
         'PROPOSAL_FALSE_AUTHORITY')

    cases = []
    seen = set()
    decisions = Counter()
    for item in proposal['cases']:
        need(type(item) is dict and
             item['current_phase'] == 'PREPARADO' and
             item['counterfactual_phase'] in ('PREPARADO','PENDIENTE') and
             item['transition_authorized'] is False and
             type(item['a3_blockers']) is list and
             'AUTORIDAD_OPERACIONAL_NO_ACREDITADA' in item['a3_blockers'],
             'CASE_UNVERIFIED_GUARD_OR_AUTHORITY')
        k = _case_identity(item)
        need(k not in seen, 'DUPLICATE_CASE_IDENTITY')
        seen.add(k)
        logical = item['counterfactual_phase'] == 'PENDIENTE'
        need((item['decision'] == 'HYPOTHETICAL_PENDING_NO_AUTHORITY')
             if logical else
             (item['decision'] == 'STAY_PREPARED_NOT_APPLIED'),
             'CASE_PROPOSAL_INCONSISTENT')
        need(not logical or (
            item['a3_guard_truth'] == 'VERDADERO' and
            set(item['a3_blockers']) == {'AUTORIDAD_OPERACIONAL_NO_ACREDITADA'}),
            'CASE_PENDING_WITHOUT_CLEAN_A3')
        reason = ('INDEPENDENT_APPROVAL_AND_COMMIT_NOT_ATTESTED' if logical
                  else 'CASE_NOT_A3_LOGICALLY_ELIGIBLE')
        decisions[reason] += 1
        row = {
            **{field: item[field] for field in IDENTITY},
            'family_id': item['family_id'], 'variant': item['variant'],
            'case_id_a7': item['case_id_a7'],
            'control_id_a3': item['control_id_a3'],
            'current_phase': 'PREPARADO',
            'counterfactual_phase': item['counterfactual_phase'],
            'a3_guard_truth': item['a3_guard_truth'],
            'a3_blockers': sorted(item['a3_blockers']),
            'logical_candidate': logical,
            'request_status': ('UNATTESTED_LOGICAL_CANDIDATE' if logical
                               else 'NOT_LOGICALLY_ELIGIBLE'),
            'deny_reason': reason,
            'independent_authority_attested': False,
            'signed_approval_attested': False,
            'transition_commit_attested': False,
            'review_outcome': 'DENIED',
            'state_committed': None,
        }
        need(set(row) == CASE_KEYS, 'GATE_CASE_SCHEMA')
        cases.append(row)
    cases.sort(key=_case_identity)
    logical_count = sum(row['logical_candidate'] for row in cases)
    need(logical_count == proposal['counterfactual_pending_count'] and
         sum(decisions.values()) == len(cases),
         'GATE_CASE_COUNTS_INVALID')
    report = {
        'schema': SCHEMA,
        'source_base_commit': BASE,
        'mode': 'DECLARED_DOCUMENTARY_DENIAL_NO_STATE_COMMIT',
        'session_id': proposal['session_id'],
        'r58r_proposal_sha256': proposal['sha256'],
        'r58q_trace_sha256': trace['sha256'],
        'source_catalog_sha256': proposal['source_catalog_sha256'],
        'source_thesis_sha256': proposal['source_thesis_sha256'],
        'case_count': len(cases),
        'family_count': proposal['family_count'],
        'current_prepared_count': len(cases),
        'hypothetical_pending_count': logical_count,
        'request_count': logical_count,
        'logical_candidates_count': logical_count,
        'not_eligible_count': len(cases) - logical_count,
        'denials_by_reason': {k: decisions[k] for k in sorted(decisions)},
        'cases': cases,
        'all_requests_denied': True,
        'independent_authority_attested': False,
        'signed_approval_attested': False,
        'transition_commit_attested': False,
        'confirmed_pending_case_count': 0,
        'transitions_applied': 0,
        'state_machine_mutated': False,
        'technical_truth_accredited': False,
        'a6_classification': 'ND',
        'confirmed_final_risk': None,
        'published_generation': None,
        'operational_dispatch': False,
        'p8_operational': 'NO-GO',
    }
    need(len(canonical(report)) < MAX_RECEIPT_BYTES - 100,
         'GATE_RECEIPT_TOO_LARGE')
    report['sha256'] = digest(report)
    need(set(report) == GATE_KEYS, 'GATE_REPORT_SCHEMA')
    return report


def verify_deny_gate(gate: dict[str, Any], proposal_root: Path,
                     trace: dict[str, Any], scenario: dict[str, Any],
                     review: dict[str, Any], a3_report: dict[str, Any]) -> bool:
    need(type(gate) is dict and set(gate) == GATE_KEYS and
         type(gate.get('sha256')) is str and
         HEX.fullmatch(gate['sha256']) is not None,
         'GATE_SCHEMA')
    need(digest({k:v for k,v in gate.items() if k != 'sha256'}) ==
         gate['sha256'], 'GATE_DIGEST_MISMATCH')
    expected = build_deny_gate(proposal_root, trace, scenario, review, a3_report)
    need(canonical(gate) == canonical(expected),
         'GATE_SOURCE_OR_DECISION_TAMPERED')
    return True


def persist_deny_gate(root: Path, proposal_root: Path,
                      trace: dict[str, Any], scenario: dict[str, Any],
                      review: dict[str, Any], a3_report: dict[str, Any]) -> dict[str, Any]:
    """Write exactly one private, immutable, deny-only gate per session."""
    dest = _root(root)
    source_dir = _root(proposal_root)
    need(not os.path.samefile(dest, source_dir), 'GATE_ROOT_MUST_BE_SEPARATE')
    gate = build_deny_gate(proposal_root, trace, scenario, review, a3_report)
    verify_deny_gate(gate, proposal_root, trace, scenario, review, a3_report)
    target = dest / _name(gate['session_id'])
    need(not target.is_symlink(), 'GATE_SYMLINK_REFUSED')
    raw = canonical(gate) + b'\n'
    action = 'REPLAY_IDENTICAL'
    if not target.exists():
        try:
            fd = os.open(target,
                         os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                         getattr(os, 'O_NOFOLLOW', 0) |
                         getattr(os, 'O_CLOEXEC', 0), 0o600)
        except FileExistsError:
            pass
        else:
            action = 'CREATED'
            with os.fdopen(fd, 'wb') as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            dfd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
    need(_read_private(target) == raw, 'GATE_REPLAY_CONFLICT_OR_TAMPER')
    return {
        'persist_status': action, 'receipt_sha256': gate['sha256'],
        'filename': target.name, 'transitions_applied': 0,
        'state_machine_mutated': False, 'p8_operational': 'NO-GO',
    }


def verify_persisted_deny_gate(root: Path, proposal_root: Path,
                               trace: dict[str, Any], scenario: dict[str, Any],
                               review: dict[str, Any],
                               a3_report: dict[str, Any]) -> dict[str, Any]:
    dest = _root(root)
    source_dir = _root(proposal_root)
    need(not os.path.samefile(dest, source_dir), 'GATE_ROOT_MUST_BE_SEPARATE')
    target = dest / _name(trace['session_id'])
    raw = _read_private(target)
    try:
        saved = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise TransitionGateError('GATE_JSON_INVALID') from exc
    verify_deny_gate(saved, proposal_root, trace, scenario, review, a3_report)
    need(raw == canonical(saved) + b'\n', 'GATE_NOT_CANONICAL')
    return {
        'verification': 'PASS_DOCUMENTARY_DENIAL_ONLY_NO_TRANSITION',
        'receipt_sha256': saved['sha256'],
        'case_count': saved['case_count'],
        'denied_request_count': saved['request_count'],
        'transitions_applied': 0,
        'state_machine_mutated': False,
        'operational_dispatch': False,
        'p8_operational': 'NO-GO',
    }


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        need(key not in result, 'DUPLICATE_GATE_JSON_KEY')
        result[key] = value
    return result
