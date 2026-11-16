"""R58-U: replay-verifiable, source-pinned T8/T9/T10 *sandbox overlay*.

Never changes R58-T, any operational ARDREC state, R34, F11 or P8. All
condition references are explicitly SYNTHETIC assumptions, not authenticated
facts or approvals. Requires R58-T's intact SQLite T1 snapshot every time.
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

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.coordination import r58t_counterfactual_state_store as t
from ardrec.state import ServicePhase, Transition

SCHEMA = 'ardrec-r58u-counterfactual-t8-t9-t10-private-sqlite-v1'
BASE = '6099ec3ed37688ee9a3e494eba4db0c1a581bac6'
MODE = 'OFFLINE_MODEL_ASSUMPTIONS_NO_OPERATOR_AUTHORITY'
ZERO_SHA = '0' * 64
ID = re.compile(r'SIM_[A-Z0-9_]{1,72}\Z', re.ASCII)
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
CASE = re.compile(r'CASE_[0-9A-F]{48}\Z', re.ASCII)
ALLOWED = {Transition.PAUSAR.value, Transition.REANUDAR.value, Transition.DETENER.value}
REQUIRED = {
    Transition.PAUSAR.value: frozenset(('external_wait_registered', 'pause_authorized', 'precedence_resolved')),
    Transition.REANUDAR.value: frozenset(('new_authorization', 'wait_resolved', 'preconditions_valid')),
    Transition.DETENER.value: frozenset(('cause_verified', 'effect_processable')),
}
CAUSES = frozenset(('SEGURIDAD', 'INTEGRIDAD', 'AUTORIZACION', 'LIMPIEZA', 'CONTROL'))
MAX_EVENTS_PER_CASE = 8
MAX_BYTES = 4_000_000


class OverlayError(ValueError):
    """Reject uncertain sources, invalid synthetic transitions and corruption."""


def need(value: bool, code: str) -> None:
    if not value:
        raise OverlayError(code)


def _source(overlay_root: Path, sim_root: Path, gate_root: Path,
            proposal_root: Path, trace: dict[str, Any], scenario: dict[str, Any],
            review: dict[str, Any], a3_report: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Revalidate actual R58-S denial AND exact R58-T database at every use."""
    directories = [t._root(p) for p in (overlay_root, sim_root, gate_root, proposal_root)]
    need(len({(p.stat().st_dev, p.stat().st_ino) for p in directories}) == 4,
         'ALL_FOUR_ROOTS_MUST_DIFFER')
    gate = t._source(gate_root, proposal_root, trace, scenario, review, a3_report)
    state = t.inspect_simulator(sim_root, gate_root, proposal_root, trace,
                                scenario, review, a3_report)
    need(state['source_gate_sha256'] == gate['sha256'] and
         0 <= state['simulated_t1_count'] <= 54 and
         state['simulated_pending_count'] == state['simulated_t1_count'] and
         state['case_count'] == gate['case_count'] and
         state['operational_transitions_applied'] == 0 and
         state['operational_state_mutated'] is False and
         state['operational_dispatch'] is False and
         state['p8_operational'] == 'NO-GO', 'T1_SOURCE_NOT_SAFE')
    return gate, state


def _source_state(gate: dict[str, Any], t1: dict[str, Any],
                  sim_root: Path) -> list[tuple[str, str, str]]:
    """Bind each exact R58-T T1 case to the original denial-only A7 identity."""
    conn = t._connect(t._db_path(sim_root, gate))
    try:
        # The real inspector rejects forged T1 chains before these are used.
        need(t._inspect(conn, gate)['last_event_sha256'] == t1['last_event_sha256'],
             'T1_SNAPSHOT_CHANGED')
        rows = conn.execute('SELECT case_key, phase FROM cases ORDER BY case_key').fetchall()
    finally:
        conn.close()
    identities = {t._key(row): row['case_id_a7'] for row in gate['cases']}
    need(len(identities) == gate['case_count'] and
         set(key for key, _ in rows) == set(identities), 'T1_CASE_SET_CHANGED')
    source = [(key, identities[key], phase) for key, phase in rows]
    need(all(phase in ('PREPARADO', 'PENDIENTE') for _, _, phase in source),
         'T1_SOURCE_PHASE_INVALID')
    return source


def _path(root: Path, gate: dict[str, Any]) -> Path:
    t._root(root)
    session = gate['session_id']
    need(type(session) is str and len(session) <= 80 and session.isascii(),
         'SESSION_INVALID')
    token = hashlib.sha256(b'ARDREC-R58U-OFFLINE-OVERLAY\0' + session.encode('ascii')).hexdigest()
    return root / ('r58u_' + token + '.sqlite3')


def _open(path: Path) -> sqlite3.Connection:
    need(not path.is_symlink() and path.is_file(), 'DB_MISSING_OR_SYMLINK')
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
         info.st_nlink == 1 and (stat.S_IMODE(info.st_mode) & 0o077) == 0 and
         info.st_size <= MAX_BYTES, 'DB_OWNER_MODE_OR_SIZE')
    conn = sqlite3.connect(path, timeout=5, isolation_level=None)
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('PRAGMA busy_timeout=5000')
    conn.execute('PRAGMA trusted_schema=OFF')
    conn.execute('PRAGMA synchronous=FULL')
    conn.execute('PRAGMA journal_mode=DELETE')
    return conn


def _validate_refs(transition: str, references: dict[str, Any],
                   cause: str | None) -> dict[str, str]:
    need(type(transition) is str and transition in ALLOWED and
         type(references) is dict and set(references) == REQUIRED[transition],
         'TRANSITION_OR_MODEL_FACTS_NOT_EXACT')
    need(all(type(v) is str and ID.fullmatch(v) is not None
             for v in references.values()), 'MODEL_FACT_REFERENCE_INVALID')
    need((cause is None if transition != Transition.DETENER.value
          else type(cause) is str and cause in CAUSES), 'STOP_CAUSE_INVALID')
    return dict(sorted(references.items()))


def _evolve(before: dict[str, Any], transition: str,
            references: dict[str, str], cause: str | None) -> dict[str, Any]:
    """Pure model transition. References are not evidence or approvals."""
    phase = before['phase']
    need(phase not in ('CERRADO', 'DETENIDO'), 'TERMINAL_PHASE_IMMUTABLE')
    after = dict(before)
    if transition == Transition.PAUSAR.value:
        need(phase == ServicePhase.PENDIENTE.value, 'PAUSE_REQUIRES_PENDING')
        after.update(phase='PAUSADO', wait_ref=references['external_wait_registered'],
                     pause_ref=references['pause_authorized'], stop_cause=None)
    elif transition == Transition.REANUDAR.value:
        need(phase == ServicePhase.PAUSADO.value, 'RESUME_REQUIRES_PAUSED')
        need(references['wait_resolved'] == before['wait_ref'],
             'RESUME_WAIT_REFERENCE_MISMATCH')
        need(references['new_authorization'] != before['pause_ref'],
             'RESUME_REQUIRES_DIFFERENT_MODEL_AUTHORIZATION')
        after.update(phase='PENDIENTE', wait_ref=None, pause_ref=None, stop_cause=None)
    elif transition == Transition.DETENER.value:
        need(phase in ('PREPARADO', 'PENDIENTE', 'PAUSADO'),
             'STOP_SOURCE_PHASE_INVALID')
        after.update(phase='DETENIDO', wait_ref=None, pause_ref=None, stop_cause=cause)
    else:
        raise OverlayError('TRANSITION_UNSUPPORTED')
    after['revision'] += 1
    return after


def _event_sha(record: dict[str, Any]) -> str:
    return digest({'schema': SCHEMA, 'event': record})


def _inspect(conn: sqlite3.Connection, gate: dict[str, Any],
             t1: dict[str, Any], initial: list[tuple[str, str, str]]) -> dict[str, Any]:
    need(conn.execute('PRAGMA integrity_check').fetchone() == ('ok',),
         'SQLITE_INTEGRITY_FAILED')
    need(conn.execute('PRAGMA foreign_key_check').fetchall() == [],
         'SQLITE_FOREIGN_KEYS_FAILED')
    tables = {(kind, name) for kind, name in conn.execute(
        "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
    need(tables == {('table','meta'), ('table','cases'), ('table','events')},
         'OVERLAY_SCHEMA_CHANGED')
    expected_meta = [(SCHEMA, MODE, gate['session_id'], gate['sha256'],
                      t1['last_event_sha256'], t1['simulated_t1_count'],
                      digest(initial))]
    need(conn.execute('SELECT * FROM meta').fetchall() == expected_meta,
         'OVERLAY_SOURCE_PIN_MISMATCH')
    db_cases = conn.execute(
        'SELECT case_key,case_id,initial_phase,phase,revision,wait_ref,pause_ref,stop_cause '
        'FROM cases ORDER BY case_key').fetchall()
    need([(a,b,c) for a,b,c,*_ in db_cases] == initial,
         'OVERLAY_CASES_NOT_BIJECTIVE')
    computed = {key: {'phase': phase, 'revision': 0,
                      'wait_ref': None, 'pause_ref': None, 'stop_cause': None}
                for key, _, phase in initial}
    case_counts: Counter[str] = Counter()
    prev_sha = ZERO_SHA
    requests: set[str] = set()
    events = conn.execute(
        'SELECT seq,request_id,case_key,transition_code,before_phase,after_phase,'
        'revision_before,revision_after,reference_json,cause,prev_sha,sha '
        'FROM events ORDER BY seq').fetchall()
    need(len(events) <= 54 * MAX_EVENTS_PER_CASE, 'TOO_MANY_MODEL_EVENTS')
    for index, event in enumerate(events, 1):
        (seq, request, key, transition, phase0, phase1, rev0, rev1,
         encoded_refs, cause, previous, actual_sha) = event
        need(seq == index and type(request) is str and ID.fullmatch(request) is not None and
             request not in requests and key in computed and
             type(actual_sha) is str and HEX.fullmatch(actual_sha) is not None and
             previous == prev_sha and type(encoded_refs) is str,
             'EVENT_SEQUENCE_REQUEST_OR_HASH_INVALID')
        try:
            references = json.loads(encoded_refs)
        except (ValueError, TypeError, UnicodeError) as exc:
            raise OverlayError('EVENT_FACT_JSON_INVALID') from exc
        refs = _validate_refs(transition, references, cause)
        need(canonical(refs).decode('ascii') == encoded_refs,
             'EVENT_FACTS_NONCANONICAL')
        current = computed[key]
        need(current['phase'] == phase0 and current['revision'] == rev0,
             'EVENT_PRECONDITION_CHANGED')
        next_state = _evolve(current, transition, refs, cause)
        need(next_state['phase'] == phase1 and next_state['revision'] == rev1,
             'EVENT_TRANSITION_CHANGED')
        payload = {'seq': seq, 'request_id': request, 'case_key': key,
                   'transition': transition, 'before': phase0, 'after': phase1,
                   'revision_before': rev0, 'revision_after': rev1,
                   'model_condition_references': refs, 'stop_cause': cause,
                   'previous_sha256': previous, 'source_gate_sha256': gate['sha256'],
                   'source_t1_head_sha256': t1['last_event_sha256'],
                   'authority': 'FIXTURE_ASSUMPTIONS_NEVER_ATTESTED'}
        need(_event_sha(payload) == actual_sha, 'MODEL_EVENT_DIGEST_CHANGED')
        computed[key] = next_state
        prev_sha = actual_sha
        case_counts[key] += 1
        need(case_counts[key] <= MAX_EVENTS_PER_CASE,
             'MODEL_CASE_EVENT_BUDGET_EXCEEDED')
        requests.add(request)
    for key, case_id, first, last, revision, wait, pause, stop in db_cases:
        expected = computed[key]
        need((last, revision, wait, pause, stop) ==
             (expected['phase'],expected['revision'],expected['wait_ref'],
              expected['pause_ref'],expected['stop_cause']),
             'MODEL_SNAPSHOT_TAMPER')
    phases = Counter(row['phase'] for row in computed.values())
    return {'schema': SCHEMA, 'mode': MODE, 'case_count': len(initial),
            'source_gate_sha256': gate['sha256'],
            'source_t1_head_sha256': t1['last_event_sha256'],
            'source_t1_count': t1['simulated_t1_count'],
            'simulated_event_count': len(events),
            'simulated_phase_counts': {k: phases[k] for k in
                                       ('PREPARADO','PENDIENTE','PAUSADO','DETENIDO')},
            'last_event_sha256': prev_sha,
            'model_state_mutated': bool(events),
            'independent_authority_attested': False,
            'operational_transitions_applied': 0,
            'operational_state_mutated': False,
            'a6_classification': 'ND', 'confirmed_final_risk': None,
            'published_generation': None, 'operational_dispatch': False,
            'p8_operational': 'NO-GO'}


def _context(root: Path, sim_root: Path, gate_root: Path, proposal_root: Path,
             trace: dict[str, Any], scenario: dict[str, Any],
             review: dict[str, Any], a3_report: dict[str, Any]):
    gate, t1 = _source(root, sim_root, gate_root, proposal_root,
                       trace, scenario, review, a3_report)
    initial = _source_state(gate, t1, sim_root)
    return gate, t1, initial, _path(root, gate)


def initialize_overlay(root: Path, sim_root: Path, gate_root: Path,
                       proposal_root: Path, trace: dict[str, Any],
                       scenario: dict[str, Any], review: dict[str, Any],
                       a3_report: dict[str, Any]) -> dict[str, Any]:
    """Create a new source-anchored SQLite overlay, never upgrade R58-T in place."""
    gate, t1, initial, path = _context(root, sim_root, gate_root, proposal_root,
                                       trace, scenario, review, a3_report)
    if path.exists() or path.is_symlink():
        conn = _open(path)
        try: return {'persist_status': 'REPLAY_IDENTICAL', **_inspect(conn,gate,t1,initial)}
        finally: conn.close()
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     getattr(os, 'O_NOFOLLOW', 0) |
                     getattr(os, 'O_CLOEXEC', 0), 0o600)
    except FileExistsError:
        conn = _open(path)
        try: return {'persist_status': 'REPLAY_IDENTICAL', **_inspect(conn,gate,t1,initial)}
        finally: conn.close()
    else:
        os.close(fd)
    try:
        conn = _open(path)
        try:
            conn.execute('BEGIN IMMEDIATE')
            conn.execute('CREATE TABLE meta(schema TEXT NOT NULL, mode TEXT NOT NULL, '
                         'session_id TEXT NOT NULL, gate_sha TEXT NOT NULL, '
                         't1_head TEXT NOT NULL, t1_count INTEGER NOT NULL, '
                         'initial_sha TEXT NOT NULL)')
            conn.execute("CREATE TABLE cases(case_key TEXT PRIMARY KEY, case_id TEXT UNIQUE NOT NULL, "
                         "initial_phase TEXT NOT NULL, phase TEXT NOT NULL "
                         "CHECK(phase IN ('PREPARADO','PENDIENTE','PAUSADO','DETENIDO')), "
                         "revision INTEGER NOT NULL CHECK(revision>=0 AND revision<=8), "
                         "wait_ref TEXT, pause_ref TEXT, stop_cause TEXT)")
            conn.execute('CREATE TABLE events(seq INTEGER PRIMARY KEY,request_id TEXT UNIQUE NOT NULL,'
                         'case_key TEXT NOT NULL REFERENCES cases(case_key),'
                         'transition_code TEXT NOT NULL,before_phase TEXT NOT NULL,'
                         'after_phase TEXT NOT NULL,revision_before INTEGER NOT NULL,'
                         'revision_after INTEGER NOT NULL,reference_json TEXT NOT NULL,'
                         'cause TEXT,prev_sha TEXT NOT NULL,sha TEXT NOT NULL)')
            conn.execute('INSERT INTO meta VALUES(?,?,?,?,?,?,?)',
                         (SCHEMA,MODE,gate['session_id'],gate['sha256'],
                          t1['last_event_sha256'],t1['simulated_t1_count'],digest(initial)))
            conn.executemany('INSERT INTO cases VALUES(?,?,?,?,?,?,?,?)',
                             [(key,case_id,phase,phase,0,None,None,None)
                              for key,case_id,phase in initial])
            status = _inspect(conn,gate,t1,initial)
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()
        os.chmod(path, 0o600)
        dfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
        return {'persist_status':'CREATED', **status}
    except BaseException:
        if path.exists(): path.unlink()
        raise


def inspect_overlay(root: Path, sim_root: Path, gate_root: Path,
                    proposal_root: Path, trace: dict[str, Any],
                    scenario: dict[str, Any], review: dict[str, Any],
                    a3_report: dict[str, Any]) -> dict[str, Any]:
    gate, t1, initial, path = _context(root,sim_root,gate_root,proposal_root,
                                       trace,scenario,review,a3_report)
    conn = _open(path)
    try: return _inspect(conn,gate,t1,initial)
    finally: conn.close()


def simulate_transition(root: Path, sim_root: Path, gate_root: Path,
                        proposal_root: Path, trace: dict[str, Any],
                        scenario: dict[str, Any], review: dict[str, Any],
                        a3_report: dict[str, Any], *, case_id_a7: str,
                        request_id: str, transition_code: str,
                        model_condition_references: dict[str, str],
                        expected_revision: int, stop_cause: str | None = None,
                        fault_before_commit: bool = False) -> dict[str, Any]:
    """Commit *only* simulated T8/T9/T10 with exact offline-model assumptions."""
    need(type(case_id_a7) is str and CASE.fullmatch(case_id_a7) is not None and
         type(request_id) is str and ID.fullmatch(request_id) is not None and
         type(expected_revision) is int and 0 <= expected_revision < 8 and
         type(fault_before_commit) is bool, 'MODEL_REQUEST_SCHEMA')
    refs = _validate_refs(transition_code,model_condition_references,stop_cause)
    gate, t1, initial, path = _context(root,sim_root,gate_root,proposal_root,
                                       trace,scenario,review,a3_report)
    match = [(key,phase) for key,cid,phase in initial if cid == case_id_a7]
    need(len(match)==1,'MODEL_CASE_ID_UNKNOWN_OR_DUPLICATE')
    key = match[0][0]
    conn = _open(path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        before = _inspect(conn,gate,t1,initial)
        old = conn.execute('SELECT case_key,transition_code,reference_json,cause FROM events WHERE request_id=?',
                           (request_id,)).fetchone()
        if old:
            need(old == (key,transition_code,canonical(refs).decode('ascii'),stop_cause),
                 'MODEL_REQUEST_REPLAY_CONFLICT')
            conn.commit()
            return {'persist_status':'REPLAY_IDENTICAL',**before}
        prior = conn.execute('SELECT phase,revision,wait_ref,pause_ref,stop_cause '
                             'FROM cases WHERE case_key=?',(key,)).fetchone()
        need(prior is not None and prior[1] == expected_revision,
             'MODEL_REVISION_CONFLICT')
        state = {'phase':prior[0],'revision':prior[1],
                 'wait_ref':prior[2],'pause_ref':prior[3],'stop_cause':prior[4]}
        after = _evolve(state,transition_code,refs,stop_cause)
        need(after['revision'] <= MAX_EVENTS_PER_CASE,'MODEL_EVENT_BUDGET')
        seq = before['simulated_event_count'] + 1
        payload = {'seq':seq,'request_id':request_id,'case_key':key,
                   'transition':transition_code,'before':state['phase'],
                   'after':after['phase'],'revision_before':state['revision'],
                   'revision_after':after['revision'],
                   'model_condition_references':refs,'stop_cause':stop_cause,
                   'previous_sha256':before['last_event_sha256'],
                   'source_gate_sha256':gate['sha256'],
                   'source_t1_head_sha256':t1['last_event_sha256'],
                   'authority':'FIXTURE_ASSUMPTIONS_NEVER_ATTESTED'}
        new_sha = _event_sha(payload)
        conn.execute('UPDATE cases SET phase=?,revision=?,wait_ref=?,pause_ref=?,stop_cause=? '
                     'WHERE case_key=? AND phase=? AND revision=?',
                     (after['phase'],after['revision'],after['wait_ref'],after['pause_ref'],
                      after['stop_cause'],key,state['phase'],state['revision']))
        need(conn.execute('SELECT changes()').fetchone() == (1,),
             'MODEL_COMPARE_AND_SWAP_FAILED')
        conn.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                     (seq,request_id,key,transition_code,state['phase'],after['phase'],
                      state['revision'],after['revision'],canonical(refs).decode('ascii'),
                      stop_cause,before['last_event_sha256'],new_sha))
        current = _inspect(conn,gate,t1,initial)
        need(current['simulated_event_count']==seq and
             current['last_event_sha256']==new_sha,'MODEL_COMMIT_NOT_CONSISTENT')
        if fault_before_commit:
            raise OverlayError('INJECTED_ROLLBACK_BEFORE_COMMIT')
        conn.commit()
        return {'persist_status':'COMMITTED_IN_SANDBOX_ONLY',**current}
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
