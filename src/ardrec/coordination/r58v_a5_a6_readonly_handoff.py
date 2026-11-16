"""R58-V: verified R58-T/U sandbox snapshot -> A5/A6 *read-only* handoff.

No A5 submission/reservation/start, no A6 evidence accreditation, no operational
transition, no Rf computation, no A9 publication. The *only* optional write is
an immutable report in a separately supplied private development directory.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any
from urllib.parse import quote

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.coordination import r58t_counterfactual_state_store as t
from ardrec.coordination import r58u_counterfactual_pause_recovery as u
from ardrec.coordination.r58r_durable_transition_proposal import _root, _read_private

SCHEMA = 'ardrec-r58v-sandbox-a5-a6-readonly-handoff-v1'
BASE = '1316c13b05583096f7b04486257f6e7861535d31'
MODE = 'OFFLINE_HANDOFF_NO_ATTEMPT_NO_EVIDENCE'
MAX_CASES = 54
MAX_BYTES = 131072
SESSION = re.compile(r'[A-Za-z0-9_:-]{1,80}\Z', re.ASCII)
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
CASE = re.compile(r'CASE_[0-9A-F]{48}\Z', re.ASCII)
PHASES = ('PREPARADO', 'PENDIENTE', 'PAUSADO', 'DETENIDO')
FIELDS = frozenset((
    'schema', 'source_base_commit', 'mode', 'session_id', 'case_count',
    'family_count', 'source_r58s_deny_sha256', 'source_r58t_t1_head_sha256',
    'source_r58u_overlay_head_sha256', 'source_catalog_sha256',
    'source_thesis_sha256', 'source_t1_event_count', 'source_overlay_event_count',
    'simulated_phase_counts', 'model_a5_review_candidate_count', 'cases',
    'all_source_requests_denied', 'a5_status', 'a5_intents_submitted',
    'a5_attempts_reserved', 'a5_attempts_started', 'a5_local_fixture_starts',
    'a6_classification', 'a6_accredited_evidence_count',
    'technical_truth_accredited', 'confirmed_final_risk',
    'operational_transitions_applied', 'operational_state_mutated',
    'operational_dispatch', 'published_generation', 'p8_operational', 'sha256',
))
CASE_FIELDS = frozenset((
    'case_key', 'service_id', 'session_id', 'derived_case_id',
    'assessment_index', 'family_id', 'case_id_a7', 'logical_candidate',
    'deny_reason', 'initial_model_phase', 'current_model_phase',
    'model_revision', 'model_a5_disposition', 'a5_intent_submitted',
    'a5_start_count', 'a6_classification', 'evidence_accredited',
))


class HandoffError(ValueError):
    """Source ambiguity, tampering or non-declared authority is always denied."""


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise HandoffError(reason)


def _sha(value: Any) -> str:
    need(type(value) is str and HEX.fullmatch(value) is not None,
         'SOURCE_DIGEST_NOT_SHA256')
    return value


def _record_path(root: Path, session_id: str) -> Path:
    _root(root)
    need(type(session_id) is str and SESSION.fullmatch(session_id) is not None,
         'SESSION_ID_INVALID')
    name = hashlib.sha256(b'ARDREC-R58V-ONE-READONLY-HANDOFF\0' +
                          session_id.encode('ascii')).hexdigest()
    return root / ('r58v_' + name + '.json')


def _rows_read_only(path: Path) -> tuple[list[tuple[Any, ...]], tuple[int, int, int, int]]:
    """Never open the R58-U SQLite database in write mode."""
    need(not path.is_symlink() and path.is_file(), 'OVERLAY_PATH_NOT_SAFE')
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
         before.st_nlink == 1 and (stat.S_IMODE(before.st_mode) & 0o077) == 0 and
         0 < before.st_size <= u.MAX_BYTES, 'OVERLAY_OWNER_MODE_SIZE')
    fingerprint = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    db_uri = 'file:' + quote(str(path), safe='/') + '?mode=ro'
    connection = sqlite3.connect(db_uri, uri=True, timeout=5)
    try:
        connection.execute('PRAGMA query_only=ON')
        rows = connection.execute(
            'SELECT case_key,case_id,initial_phase,phase,revision '
            'FROM cases ORDER BY case_key').fetchall()
    finally:
        connection.close()
    after = path.stat()
    need(fingerprint == (after.st_dev, after.st_ino, after.st_size,
                         after.st_mtime_ns), 'OVERLAY_CHANGED_DURING_READ')
    return rows, fingerprint


def build_handoff(overlay_root: Path, simulator_root: Path,
                  gate_root: Path, proposal_root: Path,
                  trace: dict[str, Any], scenario: dict[str, Any],
                  review: dict[str, Any], a3_report: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct the sandbox state; emit facts about a *non-executed* A5/A6."""
    roots = [_root(p) for p in (overlay_root, simulator_root,
                                 gate_root, proposal_root)]
    need(len({(p.stat().st_dev, p.stat().st_ino) for p in roots}) == 4,
         'FOUR_SOURCE_ROOTS_NOT_DISTINCT')
    gate, t1_status, initial, path = u._context(
        overlay_root, simulator_root, gate_root, proposal_root,
        trace, scenario, review, a3_report)
    overlay = u.inspect_overlay(overlay_root, simulator_root, gate_root,
                                proposal_root, trace, scenario, review, a3_report)
    rows, _ = _rows_read_only(path)
    second_overlay = u.inspect_overlay(overlay_root, simulator_root, gate_root,
                                       proposal_root, trace, scenario, review, a3_report)
    second_t1 = t.inspect_simulator(simulator_root, gate_root, proposal_root,
                                    trace, scenario, review, a3_report)
    need(overlay == second_overlay and t1_status == second_t1,
         'SOURCE_SNAPSHOT_DRIFT')
    need(type(gate) is dict and gate.get('all_requests_denied') is True and
         gate.get('operational_dispatch') is False and
         gate.get('a6_classification') == 'ND' and
         gate.get('state_machine_mutated') is False and
         gate.get('p8_operational') == 'NO-GO', 'SOURCE_GATE_NOT_DENY_ONLY')
    need(type(overlay) is dict and
         overlay.get('schema') == u.SCHEMA and
         overlay.get('mode') == u.MODE and
         overlay.get('case_count') == gate.get('case_count') and
         overlay.get('source_gate_sha256') == gate.get('sha256') and
         overlay.get('source_t1_head_sha256') == t1_status.get('last_event_sha256') and
         overlay.get('operational_transitions_applied') == 0 and
         overlay.get('operational_state_mutated') is False and
         overlay.get('operational_dispatch') is False and
         overlay.get('a6_classification') == 'ND' and
         overlay.get('confirmed_final_risk') is None and
         overlay.get('published_generation') is None and
         overlay.get('p8_operational') == 'NO-GO',
         'OVERLAY_FALSE_AUTHORITY_OR_SOURCE')
    need(type(gate.get('case_count')) is int and
         0 < gate['case_count'] <= MAX_CASES and
         type(gate.get('family_count')) is int and
         0 < gate['family_count'] <= 25 and
         len(rows) == len(initial) == gate['case_count'] and
         set(overlay['simulated_phase_counts']) == set(PHASES),
         'CASE_COUNTS_OR_PHASES_INVALID')
    expected = {(key, cid): phase for key, cid, phase in initial}
    need(len(expected) == len(initial), 'SOURCE_CASE_IDS_NOT_BIJECTIVE')
    by_key = {t._key(item): item for item in gate['cases']}
    need(len(by_key) == len(initial), 'SOURCE_GATE_CASES_NOT_UNIQUE')
    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for key, cid, initial_phase, phase, revision in rows:
        need((key, cid) in expected and expected[(key, cid)] == initial_phase and
             key in by_key and by_key[key]['case_id_a7'] == cid and
             type(cid) is str and CASE.fullmatch(cid) is not None and
             type(revision) is int and 0 <= revision <= u.MAX_EVENTS_PER_CASE and
             phase in PHASES and
             (phase != 'PREPARADO' or revision == 0) and
             (phase not in ('PAUSADO','DETENIDO') or revision > 0),
             'CASE_REPLAY_IDENTITY_OR_STATE_INVALID')
        source = by_key[key]
        need(source['review_outcome'] == 'DENIED' and
             source['state_committed'] is None and
             source['independent_authority_attested'] is False and
             source['signed_approval_attested'] is False and
             source['transition_commit_attested'] is False and
             source['a3_guard_truth'] in ('VERDADERO','FALSO','ND'),
             'CASE_SOURCE_NOT_DENIED')
        logical = source['logical_candidate']
        need(type(logical) is bool and
             (not (phase in ('PENDIENTE','PAUSADO') and not logical)),
             'MODEL_PHASE_CONTRADICTS_LOGICAL_CANDIDATE')
        reason = ('MODEL_PENDING_REVIEW_ONLY_NO_DISPATCH'
                  if phase == 'PENDIENTE' else
                  'MODEL_PAUSED_NO_ATTEMPT' if phase == 'PAUSADO' else
                  'MODEL_TERMINAL_NO_ATTEMPT' if phase == 'DETENIDO' else
                  'MODEL_PREPARED_NO_ATTEMPT')
        item = {
            'case_key': key,
            **{name: source[name] for name in t.ID_FIELDS},
            'family_id': source['family_id'],
            'case_id_a7': cid,
            'logical_candidate': logical,
            'deny_reason': source['deny_reason'],
            'initial_model_phase': initial_phase,
            'current_model_phase': phase,
            'model_revision': revision,
            'model_a5_disposition': reason,
            'a5_intent_submitted': False,
            'a5_start_count': 0,
            'a6_classification': 'ND',
            'evidence_accredited': False,
        }
        need(set(item) == CASE_FIELDS, 'CASE_HANDOFF_SCHEMA')
        cases.append(item)
        counts[phase] += 1
    need(dict(counts) == {name: overlay['simulated_phase_counts'][name]
                          for name in PHASES if overlay['simulated_phase_counts'][name] != 0} and
         sum(counts.values()) == gate['case_count'], 'SOURCE_PHASE_COUNTS_MISMATCH')
    cases.sort(key=lambda value: value['case_key'])
    document = {
        'schema': SCHEMA,
        'source_base_commit': BASE,
        'mode': MODE,
        'session_id': gate['session_id'],
        'case_count': len(cases),
        'family_count': gate['family_count'],
        'source_r58s_deny_sha256': _sha(gate['sha256']),
        'source_r58t_t1_head_sha256': _sha(t1_status['last_event_sha256']),
        'source_r58u_overlay_head_sha256': _sha(overlay['last_event_sha256']),
        'source_catalog_sha256': _sha(review['source_catalog_sha256']),
        'source_thesis_sha256': _sha(review['source_thesis_sha256']),
        'source_t1_event_count': t1_status['simulated_t1_count'],
        'source_overlay_event_count': overlay['simulated_event_count'],
        'simulated_phase_counts': {phase: counts[phase] for phase in PHASES},
        'model_a5_review_candidate_count': counts['PENDIENTE'],
        'cases': cases,
        'all_source_requests_denied': True,
        'a5_status': 'NOT_SUBMITTED_NO_START',
        'a5_intents_submitted': 0,
        'a5_attempts_reserved': 0,
        'a5_attempts_started': 0,
        'a5_local_fixture_starts': 0,
        'a6_classification': 'ND',
        'a6_accredited_evidence_count': 0,
        'technical_truth_accredited': False,
        'confirmed_final_risk': None,
        'operational_transitions_applied': 0,
        'operational_state_mutated': False,
        'operational_dispatch': False,
        'published_generation': None,
        'p8_operational': 'NO-GO',
    }
    need(len(canonical(document)) < MAX_BYTES - 100, 'HANDOFF_TOO_LARGE')
    document['sha256'] = digest(document)
    need(set(document) == FIELDS, 'HANDOFF_DOCUMENT_FIELDS')
    return document


def verify_handoff(report: dict[str, Any], *args: Any) -> bool:
    need(type(report) is dict and set(report) == FIELDS and
         type(report.get('sha256')) is str and
         HEX.fullmatch(report['sha256']) is not None and
         digest({k: v for k, v in report.items() if k != 'sha256'}) == report['sha256'],
         'HANDOFF_SCHEMA_OR_DIGEST_INVALID')
    expected = build_handoff(*args)
    need(canonical(report) == canonical(expected), 'HANDOFF_SOURCE_CHANGED_OR_TAMPERED')
    return True


def persist_handoff(root: Path, *args: Any) -> dict[str, Any]:
    directory = _root(root)
    # No sharing source dirs: even a trusted caller cannot write into a source root.
    need(len(args) == 8 and all(isinstance(p, Path) for p in args[:4]) and
         all(not os.path.samefile(directory, _root(p)) for p in args[:4]),
         'HANDOFF_ROOT_MUST_DIFFER_FROM_SOURCES')
    report = build_handoff(*args)
    target = _record_path(directory, report['session_id'])
    need(not target.is_symlink(), 'HANDOFF_SYMLINK_REFUSED')
    data = canonical(report) + b'\n'
    action = 'REPLAY_IDENTICAL'
    if not target.exists():
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os,'O_NOFOLLOW',0) |
                         getattr(os,'O_CLOEXEC',0), 0o600)
        except FileExistsError:
            pass
        else:
            action = 'CREATED'
            with os.fdopen(fd, 'wb') as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            fd_root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(fd_root)
            finally: os.close(fd_root)
    need(_read_private(target) == data, 'HANDOFF_REPLAY_CONFLICT_OR_TAMPER')
    return {'persist_status': action, 'receipt_sha256': report['sha256'],
            'model_a5_review_candidate_count':report['model_a5_review_candidate_count'],
            'a5_attempts_started': 0, 'operational_dispatch':False, 'p8_operational':'NO-GO'}


def verify_persisted_handoff(root: Path, *args: Any) -> dict[str, Any]:
    directory = _root(root)
    need(len(args) == 8 and all(isinstance(p,Path) for p in args[:4]) and
         all(not os.path.samefile(directory, _root(p)) for p in args[:4]),
         'HANDOFF_ROOT_MUST_DIFFER_FROM_SOURCES')
    report = build_handoff(*args)
    target = _record_path(directory, report['session_id'])
    raw = _read_private(target)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise HandoffError('HANDOFF_RECEIPT_INVALID_JSON') from exc
    verify_handoff(value, *args)
    need(raw == canonical(value) + b'\n', 'HANDOFF_RECEIPT_NOT_CANONICAL')
    return {'verification':'PASS_READONLY_MODEL_HANDOFF_NO_A5_OR_A6',
            'receipt_sha256':value['sha256'],
            'case_count':value['case_count'],
            'model_a5_review_candidate_count':value['model_a5_review_candidate_count'],
            'a5_attempts_started':0, 'a6_classification':'ND',
            'operational_dispatch':False, 'p8_operational':'NO-GO'}


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out = {}
    for key, value in pairs:
        need(key not in out, 'DUPLICATE_HANDOFF_JSON_KEY')
        out[key] = value
    return out
