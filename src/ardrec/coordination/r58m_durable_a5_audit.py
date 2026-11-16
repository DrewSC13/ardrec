"""R58-M: READ-ONLY audit of pre-existing P9-P12 benign attempt journal.

No A5 reservation, acceptance, start, retry, recover, guest I/O or journal write.
A P9 request id cannot prove a binding to an R58-L SSH/FTP/SMB case:
that identity is absent from the durable P9 schema. The join is DECLARED ONLY.
"""
from __future__ import annotations

import hashlib
from contextlib import closing
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any
from urllib.parse import quote

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.coordination.r58l_a4_a5_family_review import verify_a4_a5_review

SCHEMA = 'ardrec-r58m-readonly-durable-a5-fixture-audit-v1'
JOURNAL_SCHEMA = 'ardrec-p9-p12-benign-pipeline-v1'
MAX_DB_BYTES = 8 * 1024 * 1024
MAX_EVENTS = 8
MAX_OUTPUT_BYTES = 65536
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
RID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z', re.ASCII)
ALLOWED_FIXTURES = frozenset(('ok', 'nonzero', 'noisy', 'slow'))
STATES = frozenset(('RESERVED', 'ACCEPTED', 'START_INTENT',
                    'RECOVERY_UNCERTAIN', 'RECORDED_LIMITED'))
OUTCOMES = frozenset(('BENIGN_EXIT_ZERO', 'BENIGN_EXIT_NONZERO',
                      'CAPTURE_INCOMPLETE', 'DEADLINE'))


class DurableAuditError(ValueError):
    """Conservative denial of unsupported, mutable, or ambiguous receipts."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise DurableAuditError(code)


def _canonical_p9(obj: Any) -> bytes:
    # Exact P9-P12 canonicalization, NOT the A6 canonical JSON routine.
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _object_unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        need(key not in out, 'DUPLICATE_JSON_KEY')
        out[key] = value
    return out


def _json(raw: str) -> dict[str, Any]:
    need(type(raw) is str and len(raw) <= 524288, 'JSON_SIZE_OR_TYPE')
    try:
        obj = json.loads(raw, object_pairs_hook=_object_unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DurableAuditError('JOURNAL_JSON_INVALID') from exc
    need(type(obj) is dict, 'JOURNAL_JSON_OBJECT_REQUIRED')
    return obj


def _file_bytes(path: Path, maximum: int) -> bytes:
    need(not path.is_symlink() and path.is_file(), 'MISSING_OR_SYMLINKED_FILE')
    size = path.stat().st_size
    need(0 <= size <= maximum, 'FILE_SIZE_LIMIT')
    data = path.read_bytes()
    need(len(data) == size, 'FILE_CHANGED_DURING_READ')
    return data


def _safe_root(root: Path) -> tuple[Path, Path, Path]:
    need(isinstance(root, Path) and root.is_absolute(), 'ROOT_MUST_BE_ABSOLUTE_PATH')
    need(root.is_dir() and not root.is_symlink() and
         (root.stat().st_mode & 0o022) == 0, 'UNSAFE_JOURNAL_ROOT')
    artifacts = root / 'artifacts'
    need(artifacts.is_dir() and not artifacts.is_symlink() and
         (artifacts.stat().st_mode & 0o022) == 0, 'UNSAFE_ARTIFACTS_ROOT')
    db = root / 'attempts.sqlite3'
    need(not db.is_symlink() and db.is_file() and
         stat.S_ISREG(db.stat().st_mode), 'UNSAFE_DATABASE')
    # immutable=1 provides no-write access without creating -shm; it does NOT
    # read WAL data. Refuse WAL/SHM sidecars rather than silently omit commits.
    for suffix in ('-wal', '-shm', '-journal'):
        need(not Path(str(db) + suffix).exists() and
             not Path(str(db) + suffix).is_symlink(),
             'LIVE_OR_UNCHECKPOINTED_JOURNAL_REFUSED')
    return root, artifacts, db


def _actions_coherent(state: str, starts: int, actions: list[str]) -> None:
    need(actions and actions[0] == 'RESERVED', 'NO_RESERVATION_EVENT')
    need(type(starts) is int and starts in (0, 1), 'START_BUDGET_INVALID')
    if state == 'RESERVED':
        need(actions == ['RESERVED'] and starts == 0, 'RESERVED_LIFECYCLE')
        return
    need(len(actions) >= 2 and actions[1] == 'ACCEPTED',
         'ACCEPTANCE_EVENT_MISSING')
    if state == 'ACCEPTED':
        need(actions == ['RESERVED', 'ACCEPTED'] and starts == 0,
             'ACCEPTED_LIFECYCLE')
        return
    need(len(actions) >= 3 and actions[2] == 'START_INTENT' and starts == 1,
         'START_INTENT_NOT_DURABLE')
    remainder = actions[3:]
    if remainder and remainder[0] == 'LEADER_OBSERVED':
        remainder = remainder[1:]
    tail = {'START_INTENT': [], 'RECOVERY_UNCERTAIN': ['RECOVERY_UNCERTAIN'],
            'RECORDED_LIMITED': ['RECORDED_LIMITED']}[state]
    need(remainder == tail, 'LIFECYCLE_ORDER_OR_TERMINAL_MISMATCH')


def _verify_artifacts(root: Path, rid: str, result: dict[str, Any]) -> None:
    need(result.get('schema') == JOURNAL_SCHEMA and
         result.get('p8_operational') == 'NO-GO' and
         result.get('outcome') in OUTCOMES and
         result.get('global_tree_cleanup_proven') is False and
         result.get('cleanup_scope') == 'OWNED_LEADER_ONLY_NO_DESCENDANT_CERTIFICATION',
         'BENIGN_RESULT_AUTHORITY_OR_SCHEMA')
    artifacts = result.get('artifacts')
    need(type(artifacts) is dict and set(artifacts) == {'stdout', 'stderr'},
         'ARTIFACT_MANIFEST_SCHEMA')
    slug = _sha(rid.encode('utf-8'))
    for channel in ('stdout', 'stderr'):
        info = artifacts[channel]
        need(type(info) is dict and set(info) == {'name', 'sha256', 'bytes'},
             'ARTIFACT_ENTRY_SCHEMA')
        need(info['name'] == f'{slug}.{channel}' and
             type(info['sha256']) is str and HEX.fullmatch(info['sha256']) is not None and
             type(info['bytes']) is int and 0 <= info['bytes'] <= MAX_OUTPUT_BYTES,
             'ARTIFACT_ENTRY_INVALID')
        data = _file_bytes(root / 'artifacts' / info['name'], MAX_OUTPUT_BYTES)
        need(len(data) == info['bytes'] and _sha(data) == info['sha256'],
             'ARTIFACT_INTEGRITY_MISMATCH')


def audit_benign_journal(root: Path, rid: str) -> dict[str, Any]:
    """Read an already closed P9 journal; never instantiate the benign pipeline or write."""
    need(type(rid) is str and RID.fullmatch(rid) is not None,
         'REQUEST_ID_INVALID')
    root, _, dbpath = _safe_root(root)
    db_before = _file_bytes(dbpath, MAX_DB_BYTES)
    # URI percent-encoding prevents query-string injection by path components.
    uri = 'file:' + quote(str(dbpath), safe='/') + '?mode=ro&immutable=1'
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=1.0)) as db:
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA query_only=ON')
            db.execute('PRAGMA trusted_schema=OFF')
            row = db.execute('SELECT * FROM attempts WHERE id=?', (rid,)).fetchone()
            need(row is not None, 'REQUEST_NOT_IN_JOURNAL')
            events = db.execute(
                'SELECT seq,action,payload_json,previous_sha256,entry_sha256 '
                'FROM events WHERE request_id=? ORDER BY seq', (rid,)).fetchall()
    except sqlite3.Error as exc:
        raise DurableAuditError('DATABASE_READ_OR_SCHEMA_ERROR') from exc
    need(_file_bytes(dbpath, MAX_DB_BYTES) == db_before,
         'DATABASE_CHANGED_DURING_AUDIT')
    row = dict(row)
    state = row.get('state')
    starts = row.get('start_count')
    need(type(state) is str and state in STATES, 'UNSUPPORTED_JOURNAL_STATE')
    fixture = row.get('fixture')
    need(type(fixture) is str and fixture in ALLOWED_FIXTURES,
         'NON_BENIGN_OR_SYSTEMD_FIXTURE_REFUSED')
    need(row.get('id') == rid and
         type(row.get('fingerprint')) is str and
         HEX.fullmatch(row['fingerprint']) is not None,
         'REQUEST_FINGERPRINT_INVALID')
    need(type(row.get('deadline_ms')) is int and
         100 <= row['deadline_ms'] <= 3000 and
         type(row.get('output_cap')) is int and
         128 <= row['output_cap'] <= MAX_OUTPUT_BYTES,
         'FIXTURE_BUDGET_INVALID')
    spec = {'schema': JOURNAL_SCHEMA, 'fixture': fixture,
            'deadline_ms': row['deadline_ms'], 'output_cap': row['output_cap'],
            'p8_operational': 'NO-GO'}
    need(row['fingerprint'] == _sha(_canonical_p9(spec)),
         'REQUEST_SPEC_FINGERPRINT_MISMATCH')
    need(0 < len(events) <= MAX_EVENTS, 'EVENT_COUNT_INVALID')
    previous = '0' * 64
    actions = []
    payloads = []
    last_seq = 0
    for event in events:
        seq, action = event['seq'], event['action']
        need(type(seq) is int and seq > last_seq, 'EVENT_SEQUENCE_INVALID')
        last_seq = seq
        need(type(action) is str, 'EVENT_ACTION_INVALID')
        payload = _json(event['payload_json'])
        expected = _sha(_canonical_p9({'id': rid, 'action': action,
                                       'payload': payload, 'previous': previous}))
        need(event['previous_sha256'] == previous and
             event['entry_sha256'] == expected, 'EVENT_CHAIN_MISMATCH')
        previous = expected
        actions.append(action)
        payloads.append(payload)
    need(payloads[0] == {'fingerprint': row['fingerprint'], **spec},
         'INITIAL_EVENT_SPEC_MISMATCH')
    if len(actions) > 1:
        need(payloads[1] == {'fingerprint': row['fingerprint'],
                             'profile': 'FIXTURE_ONLY', 'p8': 'NO-GO'},
             'ACCEPTANCE_SPEC_MISMATCH')
    if len(actions) > 2:
        need(payloads[2] == {'prior': 'ACCEPTED', 'start_count': 1},
             'START_EVENT_SCHEMA')
    _actions_coherent(state, starts, actions)
    result = None
    if state == 'RECORDED_LIMITED':
        result = _json(row.get('result_json'))
        _verify_artifacts(root, rid, result)
        need(payloads[-1].get('result_sha256') == _sha(_canonical_p9(result)) and
             payloads[-1].get('outcome') == result['outcome'] and
             payloads[-1].get('cleanup_scope') == result['cleanup_scope'],
             'RESULT_EVENT_MISMATCH')
    else:
        need(row.get('result_json') is None, 'NONTERMINAL_RESULT_INJECTION')
    if state == 'RECOVERY_UNCERTAIN':
        need(type(payloads[-1].get('reason')) is str and
             payloads[-1]['reason'] != '', 'RECOVERY_REASON_MISSING')
    if 'LEADER_OBSERVED' in actions:
        idx = actions.index('LEADER_OBSERVED')
        need(type(payloads[idx].get('pid')) is int and
             payloads[idx]['pid'] > 0, 'LEADER_EVENT_INVALID')
    return {'schema': SCHEMA, 'source': 'P9_P12_EXISTING_SQLITE_READ_ONLY',
            'journal_file_sha256': _sha(db_before), 'request_id': rid,
            'request_fingerprint': row['fingerprint'],
            'local_fixture_name': fixture, 'journal_state': state,
            'local_fixture_start_intent_count': starts,
            'event_count': len(actions), 'event_head_sha256': previous,
            'result_outcome': None if result is None else result['outcome'],
            'recorded_artifacts_integrity_checked': state == 'RECORDED_LIMITED',
            'local_receipt_chain_self_consistent': True,
            'independent_origin_attested': False,
            'case_identity_stored_in_journal': False,
            'ordinary_retry_allowed': False,
            'operational_dispatch': False, 'p8_operational': 'NO-GO'}


def build_durable_a5_link(review: dict[str, Any], journal_root: Path,
                          request_id: str) -> dict[str, Any]:
    """Documentary link by matching declared RID; NEVER assert case provenance."""
    verify_a4_a5_review(review)
    need(review.get('p8_operational') == 'NO-GO' and
         review.get('a6_classification') == 'ND' and
         review.get('technical_truth_accredited') is False and
         review.get('operational_dispatch') is False and
         review.get('confirmed_final_risk') is None and
         review.get('published_generation') is None,
         'PARENT_REPORT_AUTHORITY')
    intent = review.get('attempt_intent')
    need(type(intent) is dict and intent.get('attempt_id') == request_id and
         intent.get('action') == 'SYNTHETIC_REVIEW_ONLY',
         'DECLARED_REQUEST_BINDING_INVALID')
    selected = review.get('a4_selected_identity')
    need(type(selected) is dict and all(intent.get(k) == selected.get(k)
         for k in ('service_id','session_id','derived_case_id','assessment_index')),
         'A4_SELECTED_CASE_BINDING_MISMATCH')
    need(review['a5']['actual_attempts_started'] == 0 and
         review['a5']['actual_attempt_reservations'] == 0 and
         review['a5']['real_attempt_budget_attested'] is False,
         'R58L_ATTEMPT_AUTHORITY')
    audit = audit_benign_journal(journal_root, request_id)
    doc = {'schema': SCHEMA,
           'mode': 'VERIFIED_LOCAL_BENIGN_RECEIPT_UNACCREDITED_CASE_LINK',
           'r58l_review_sha256': review['sha256'],
           'declared_case_identity': {k: selected[k] for k in (
               'service_id','session_id','derived_case_id','assessment_index')},
           'declared_request_id': request_id,
           'durable_a5': audit,
           'journal_integrity_verified_for_local_fixture': True,
           'case_identity_binding_accredited': False,
           'actual_operational_attempts_started': 0,
           'a5_disposition': 'BLOCKED_NO_NEW_ATTEMPT_FROM_READONLY_AUDIT',
           'a6_classification': 'ND', 'technical_truth_accredited': False,
           'confirmed_final_risk': None,
           'applied_state_transition': None,
           'published_generation': None,
           'operational_dispatch': False,
           'host_mutations_by_audit': 0,
           'p8_operational': 'NO-GO'}
    doc['sha256'] = digest(doc)
    return doc


def verify_durable_a5_link(report: dict[str, Any], review: dict[str, Any],
                           journal_root: Path, request_id: str) -> bool:
    need(type(report) is dict and type(report.get('sha256')) is str and
         HEX.fullmatch(report['sha256']) is not None, 'LINK_REPORT_SCHEMA')
    need(canonical(report) == canonical(build_durable_a5_link(
         review, journal_root, request_id)), 'LINK_REPORT_NOT_REPRODUCIBLE')
    return True
