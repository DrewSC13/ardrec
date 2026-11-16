"""R58-R: immutable *proposal* receipt for R58-Q; never a state transition.

Uses the genuine A3/A4 counterfactual report, not inferred authorization.
Writes only an explicitly supplied private local receipt directory. Never
writes a service state, runs A5, touches a VM or publishes an A9 generation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.coordination.r58q_transition_guard_bridge import (
    verify_a3_a4_transition_audit,
)

SCHEMA = 'ardrec-r58r-immutable-declared-transition-proposal-v1'
BASE = '5bb8ce2c3e31de3c74d71e126b8ea556e86805b5'
MAX_CASES = 54
MAX_BYTES = 131072
SESSION = re.compile(r'[A-Za-z0-9_:-]{1,80}\Z', re.ASCII)
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
IDENTITY = ('service_id', 'session_id', 'derived_case_id', 'assessment_index')
AUTHORITY_BLOCKER = 'AUTORIDAD_OPERACIONAL_NO_ACREDITADA'
RECEIPT_FIELDS = frozenset((
    'schema', 'mode', 'source_base_commit', 'session_id',
    'r58q_trace_sha256', 'r58p_a3_projection_sha256', 'r58l_review_sha256',
    'source_catalog_sha256', 'source_thesis_sha256',
    'source_transition_context_sha256', 'case_count', 'family_count',
    'current_prepared_count', 'counterfactual_pending_count',
    'a4_current_eligible_count', 'a4_counterfactual_eligible_count',
    'current_selected_case', 'counterfactual_selected_case',
    'cases', 'receipt_semantics', 'transitions_applied',
    'confirmed_pending_case_count', 'technical_truth_accredited',
    'confirmed_final_risk', 'applied_state_transition',
    'published_generation', 'operational_dispatch', 'p8_operational', 'sha256',
))
CASE_FIELDS = frozenset((
    *IDENTITY, 'family_id', 'variant', 'case_id_a7', 'control_id_a3',
    'a3_guard_truth', 'a3_blockers', 'current_phase',
    'counterfactual_phase', 'decision', 'transition_authorized',
))


class ProposalError(ValueError):
    """Fail-closed on uncertain, forged, or mutable transition proposals."""


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise ProposalError(reason)


def _key(row: dict[str, Any]) -> tuple[str, str, str, int]:
    return tuple(row[k] for k in IDENTITY)


def _sha(value: str) -> str:
    need(type(value) is str and HEX.fullmatch(value) is not None,
         'SOURCE_SHA256_INVALID')
    return value


def _record_name(session_id: str) -> str:
    need(type(session_id) is str and SESSION.fullmatch(session_id) is not None,
         'SESSION_ID_UNSAFE')
    return 'r58r_' + hashlib.sha256(
        b'ARDREC-R58R-ONE-PROPOSAL-PER-SESSION-V1\x00' +
        session_id.encode('ascii')
    ).hexdigest() + '.json'


def _root(path: Path) -> Path:
    need(isinstance(path, Path) and path.is_absolute() and
         not path.is_symlink() and path.is_dir() and
         path.resolve() == path, 'RECEIPT_ROOT_NOT_SAFE_ABSOLUTE_DIRECTORY')
    meta = path.stat()
    need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid() and
         (stat.S_IMODE(meta.st_mode) & 0o077) == 0,
         'RECEIPT_ROOT_OWNER_OR_MODE')
    return path


def _read_private(path: Path) -> bytes:
    """Read immutable receipt with no-follow fd and pre/post fstat checks."""
    need(not path.is_symlink(), 'RECEIPT_SYMLINK_REFUSED')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ProposalError('RECEIPT_NOT_READABLE') from exc
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
             before.st_nlink == 1 and (stat.S_IMODE(before.st_mode) & 0o077) == 0 and
             0 < before.st_size <= MAX_BYTES, 'RECEIPT_FILE_MODE_OR_SIZE')
        chunks = []
        remaining = before.st_size + 1
        while remaining:
            block = os.read(fd, remaining)
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b''.join(chunks)
        after = os.fstat(fd)
        need(len(data) == before.st_size and
             (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) ==
             (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns),
             'RECEIPT_CHANGED_ON_READ')
        return data
    finally:
        os.close(fd)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out = {}
    for k, value in pairs:
        need(k not in out, 'DUPLICATE_RECEIPT_KEY')
        out[k] = value
    return out


def build_proposal(trace: dict[str, Any], scenario: dict[str, Any],
                   review: dict[str, Any], a3_report: dict[str, Any]) -> dict[str, Any]:
    """Recompute R58-Q before recording a non-operational state proposal."""
    verify_a3_a4_transition_audit(trace, scenario, review, a3_report)
    need(type(trace) is dict and
         trace.get('schema') == 'ardrec-r58q-prepared-pending-a3-a4-counterfactual-v1' and
         trace.get('mode') == 'DUAL_A4_RANKING_NO_STATE_CHANGE' and
         trace.get('session_id') == scenario.get('session_id') and
         SESSION.fullmatch(trace['session_id']) is not None,
         'SOURCE_TRACE_OR_SESSION_INVALID')
    _sha(trace['sha256'])
    need(digest({k:v for k,v in trace.items() if k != 'sha256'}) == trace['sha256'],
         'TRACE_NOT_SELF_CONSISTENT')
    for field in ('source_catalog_sha256', 'source_thesis_sha256',
                  'r58l_review_sha256', 'r58p_a3_projection_sha256',
                  'transition_context_sha256'):
        _sha(trace[field])
    need(trace['r58l_review_sha256'] == review['sha256'] and
         trace['r58p_a3_projection_sha256'] == a3_report['sha256'] and
         trace['source_catalog_sha256'] == review['source_catalog_sha256'] and
         trace['source_thesis_sha256'] == review['source_thesis_sha256'],
         'TRACE_SOURCE_BINDING_INVALID')
    need(type(trace['unit_count']) is int and
         0 < trace['unit_count'] <= MAX_CASES and
         type(trace['family_count']) is int and
         0 < trace['family_count'] <= 25 and
         type(trace['control_cases']) is list and
         len(trace['control_cases']) == trace['unit_count'],
         'CASE_COUNT_OR_COVERAGE_INVALID')
    before = trace['a4_actual_prepared_selection']
    hypothetical = trace['a4_counterfactual_pending_selection']
    need(before['eligible_count'] == 0 and before['selected'] is None and
         before['operational_dispatch'] is False and
         before['selection_is_operational'] is False and
         hypothetical['operational_dispatch'] is False and
         hypothetical['selection_is_operational'] is False and
         hypothetical['p8_operational'] == 'NO-GO',
         'A4_CURRENT_OR_COUNTERFACTUAL_AUTHORITY')
    need(trace['prepared_to_pending_transitions_applied'] == 0 and
         trace['confirmed_pending_case_count'] == 0 and
         trace['a3_to_a4_operational_authority_attested'] is False and
         trace['a5_operational_attempts_started'] == 0 and
         trace['a6_classification'] == 'ND' and
         trace['technical_truth_accredited'] is False and
         trace['confirmed_final_risk'] is None and
         trace['applied_state_transition'] is None and
         trace['published_generation'] is None and
         trace['vm_checks_executed'] is False and
         trace['operational_dispatch'] is False and
         trace['p8_operational'] == 'NO-GO',
         'TRACE_FALSE_OPERATIONAL_AUTHORITY')
    cases = []
    keys = set()
    pending = 0
    for source in trace['control_cases']:
        need(type(source) is dict and
             source['a3_phase_confirmed_by_fixture'] == 'PREPARADO' and
             type(source['a3_blockers']) is list and
             AUTHORITY_BLOCKER in source['a3_blockers'] and
             source['confirmed_transition'] is None and
             source['current_confirmed_phase_change'] is False and
             source['case_authority_attested'] is False and
             type(source['logical_pending_counterfactual']) is bool and
             source['counterfactual_phase'] in ('PREPARADO','PENDIENTE'),
             'CASE_FALSE_STATE_OR_AUTHORITY')
        logical = source['logical_pending_counterfactual']
        need((source['counterfactual_phase'] == 'PENDIENTE') is logical,
             'CASE_COUNTERFACTUAL_PHASE_DISAGREEMENT')
        need(logical is False or (
            source['a3_guard_truth'] == 'VERDADERO' and
            source['a3_table_status'] == 'VERDADERO' and
            set(source['a3_blockers']) == {AUTHORITY_BLOCKER} and
            source['a4_applicable_simulated'] is True),
             'CASE_PENDING_WITHOUT_CLEAN_A3')
        k = _key(source)
        need(k not in keys, 'DUPLICATE_CASE_IDENTITY')
        keys.add(k)
        pending += int(logical)
        row = {
            **{field: source[field] for field in IDENTITY},
            'family_id': source['family_id'],
            'variant': source['variant'],
            'case_id_a7': source['case_id_a7'],
            'control_id_a3': source['control_id_a3'],
            'a3_guard_truth': source['a3_guard_truth'],
            'a3_blockers': sorted(source['a3_blockers']),
            'current_phase': 'PREPARADO',
            'counterfactual_phase': source['counterfactual_phase'],
            'decision': ('HYPOTHETICAL_PENDING_NO_AUTHORITY' if logical
                         else 'STAY_PREPARED_NOT_APPLIED'),
            'transition_authorized': False,
        }
        need(set(row) == CASE_FIELDS, 'CASE_RECEIPT_FIELDS')
        cases.append(row)
    cases.sort(key=_key)
    need(pending == trace['hypothetical_phase_counts']['PENDIENTE'] ==
         hypothetical['eligible_count'] and
         trace['hypothetical_phase_counts']['PREPARADO'] + pending == len(cases),
         'COUNTERFACTUAL_AGGREGATE_INVALID')
    doc = {
        'schema': SCHEMA,
        'mode': 'IMMUTABLE_LOCAL_PROPOSAL_NOT_MACHINE_STATE',
        'source_base_commit': BASE,
        'session_id': trace['session_id'],
        'r58q_trace_sha256': trace['sha256'],
        'r58p_a3_projection_sha256': trace['r58p_a3_projection_sha256'],
        'r58l_review_sha256': trace['r58l_review_sha256'],
        'source_catalog_sha256': trace['source_catalog_sha256'],
        'source_thesis_sha256': trace['source_thesis_sha256'],
        'source_transition_context_sha256': trace['transition_context_sha256'],
        'case_count': len(cases),
        'family_count': trace['family_count'],
        'current_prepared_count': len(cases),
        'counterfactual_pending_count': pending,
        'a4_current_eligible_count': 0,
        'a4_counterfactual_eligible_count': hypothetical['eligible_count'],
        'current_selected_case': None,
        'counterfactual_selected_case': hypothetical['selected'],
        'cases': cases,
        'receipt_semantics': 'DECLARED_ONLY_REPLAY_ONCE_PER_SESSION_NO_TRANSITION',
        'transitions_applied': 0,
        'confirmed_pending_case_count': 0,
        'technical_truth_accredited': False,
        'confirmed_final_risk': None,
        'applied_state_transition': None,
        'published_generation': None,
        'operational_dispatch': False,
        'p8_operational': 'NO-GO',
    }
    need(len(canonical(doc)) < MAX_BYTES - 100, 'PROPOSAL_TOO_LARGE')
    doc['sha256'] = digest(doc)
    need(set(doc) == RECEIPT_FIELDS, 'PROPOSAL_FIELDS')
    return doc


def verify_proposal(document: dict[str, Any], trace: dict[str, Any],
                    scenario: dict[str, Any], review: dict[str, Any],
                    a3_report: dict[str, Any]) -> bool:
    need(type(document) is dict and set(document) == RECEIPT_FIELDS and
         type(document['sha256']) is str and HEX.fullmatch(document['sha256']) is not None,
         'PROPOSAL_SCHEMA')
    expected = build_proposal(trace, scenario, review, a3_report)
    need(canonical(document) == canonical(expected), 'PROPOSAL_SOURCE_OR_AUTHORITY_TAMPER')
    return True


def persist_proposal(root: Path, trace: dict[str, Any], scenario: dict[str, Any],
                     review: dict[str, Any], a3_report: dict[str, Any]) -> dict[str, Any]:
    """One immutable local proposal per session; no overwrite or retry override."""
    directory = _root(root)
    proposal = build_proposal(trace, scenario, review, a3_report)
    verify_proposal(proposal, trace, scenario, review, a3_report)
    path = directory / _record_name(proposal['session_id'])
    raw = canonical(proposal) + b'\n'
    need(not path.is_symlink(), 'RECEIPT_SYMLINK_REFUSED')
    action = 'REPLAY_IDENTICAL'
    if not path.exists():
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                         getattr(os, 'O_NOFOLLOW', 0) |
                         getattr(os, 'O_CLOEXEC', 0), 0o600)
        except FileExistsError:
            pass  # Another writer won; verify the exact bytes, fail if changed.
        else:
            action = 'CREATED'
            with os.fdopen(fd, 'wb') as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
    need(_read_private(path) == raw, 'RECEIPT_REPLAY_CONFLICT_OR_TAMPER')
    verify_proposal(proposal, trace, scenario, review, a3_report)
    return {'persist_status': action, 'receipt_sha256': proposal['sha256'],
            'receipt_filename': path.name, 'transitions_applied': 0,
            'state_machine_mutated': False,
            'operational_dispatch': False, 'p8_operational': 'NO-GO'}


def verify_persisted_proposal(root: Path, trace: dict[str, Any],
                              scenario: dict[str, Any], review: dict[str, Any],
                              a3_report: dict[str, Any]) -> dict[str, Any]:
    directory = _root(root)
    path = directory / _record_name(trace['session_id'])
    data = _read_private(path)
    try:
        saved = json.loads(data, object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProposalError('PROPOSAL_JSON_INVALID') from exc
    verify_proposal(saved, trace, scenario, review, a3_report)
    need(data == canonical(saved) + b'\n', 'RECEIPT_NOT_CANONICAL')
    return {'verification': 'PASS_DECLARED_LOCAL_PROPOSAL_NO_TRANSITION',
            'receipt_filename': path.name,
            'receipt_sha256': saved['sha256'],
            'current_prepared_count': saved['current_prepared_count'],
            'counterfactual_pending_count': saved['counterfactual_pending_count'],
            'transitions_applied': 0, 'state_machine_mutated': False,
            'technical_truth_accredited': False,
            'operational_dispatch': False, 'p8_operational': 'NO-GO'}
