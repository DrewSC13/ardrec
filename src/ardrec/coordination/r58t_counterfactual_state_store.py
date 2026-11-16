"""R58-T: SQLite-atomic counterfactual T1 simulator, separate from ARDREC state.

The source gate R58-S must remain DENIED. A simulated PREPARADO->PENDIENTE
transition cannot confer authority, launch A5, or publish A9. The database is
private, single-session, source-pinned, and independently replay-verifiable.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.coordination.r58r_durable_transition_proposal import _root
from ardrec.coordination.r58s_transition_deny_gate import (
    build_deny_gate, verify_persisted_deny_gate,
)
from ardrec.state import ServicePhase, Transition

SCHEMA = 'ardrec-r58t-counterfactual-t1-private-sqlite-v1'
BASE = 'e441c9f890d0f59f4f1c428bb606c1db91324ebe'
MODE = 'SANDBOX_COUNTERFACTUAL_NO_OPERATIONAL_AUTHORITY'
DENIED = 'INDEPENDENT_APPROVAL_AND_COMMIT_NOT_ATTESTED'
ID_FIELDS = ('service_id', 'session_id', 'derived_case_id', 'assessment_index')
ZERO_SHA = '0' * 64
REQ = re.compile(r'SIM_[A-Z0-9_]{1,72}\Z', re.ASCII)
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
MAX_CASES = 54


class SimulatorError(ValueError):
    """Fail closed on invalid state, source, replay, or storage integrity."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise SimulatorError(code)


def _key(row: dict[str, Any]) -> str:
    return digest({name: row[name] for name in ID_FIELDS})


def _source(gate_root: Path, proposal_root: Path, trace: dict[str, Any],
            scenario: dict[str, Any], review: dict[str, Any],
            a3_report: dict[str, Any]) -> dict[str, Any]:
    proven = verify_persisted_deny_gate(gate_root, proposal_root, trace,
                                         scenario, review, a3_report)
    gate = build_deny_gate(proposal_root, trace, scenario, review, a3_report)
    need(type(proven) is dict and
         proven.get('verification') == 'PASS_DOCUMENTARY_DENIAL_ONLY_NO_TRANSITION' and
         proven.get('receipt_sha256') == gate.get('sha256') and
         proven.get('transitions_applied') == 0 and
         proven.get('state_machine_mutated') is False and
         proven.get('operational_dispatch') is False and
         proven.get('p8_operational') == 'NO-GO', 'SOURCE_DENIAL_NOT_VERIFIED')
    need(type(gate) is dict and gate.get('schema') ==
         'ardrec-r58s-a3-a4-deny-only-transition-gate-v1' and
         type(gate.get('sha256')) is str and
         HEX.fullmatch(gate['sha256']) is not None and
         digest({k:v for k,v in gate.items() if k != 'sha256'}) == gate['sha256'] and
         type(gate.get('cases')) is list and
         type(gate.get('case_count')) is int and
         0 < gate['case_count'] <= MAX_CASES and
         len(gate['cases']) == gate['case_count'] and
         gate.get('all_requests_denied') is True and
         gate.get('transitions_applied') == 0 and
         gate.get('confirmed_pending_case_count') == 0 and
         gate.get('independent_authority_attested') is False and
         gate.get('signed_approval_attested') is False and
         gate.get('transition_commit_attested') is False and
         gate.get('state_machine_mutated') is False and
         gate.get('a6_classification') == 'ND' and
         gate.get('technical_truth_accredited') is False and
         gate.get('published_generation') is None and
         gate.get('operational_dispatch') is False and
         gate.get('p8_operational') == 'NO-GO', 'DENIAL_GATE_AUTHORITY_INVALID')
    keys = set()
    a7_ids = set()
    possible = 0
    for row in gate['cases']:
        need(type(row) is dict and row.get('current_phase') == 'PREPARADO' and
             row.get('review_outcome') == 'DENIED' and
             row.get('state_committed') is None and
             row.get('independent_authority_attested') is False and
             row.get('signed_approval_attested') is False and
             row.get('transition_commit_attested') is False and
             type(row.get('logical_candidate')) is bool and
             row.get('counterfactual_phase') in ('PREPARADO','PENDIENTE'),
             'DENIAL_CASE_NOT_SAFE')
        k = _key(row)
        case_id = row.get('case_id_a7')
        need(type(case_id) is str and len(case_id) == 53 and
             case_id.startswith('CASE_') and
             all(char in '0123456789ABCDEF' for char in case_id[5:]) and
             case_id not in a7_ids, 'CASE_ID_A7_INVALID_OR_DUPLICATE')
        need(k not in keys, 'DUPLICATE_CASE_IDENTITY')
        keys.add(k)
        a7_ids.add(case_id)
        logical = row['logical_candidate']
        need((row['counterfactual_phase'] == 'PENDIENTE') is logical and
             row.get('deny_reason') ==
             (DENIED if logical else 'CASE_NOT_A3_LOGICALLY_ELIGIBLE') and
             (not logical or row.get('a3_guard_truth') == 'VERDADERO'),
             'DENIAL_CASE_GUARD_INVALID')
        possible += int(logical)
    need(possible == gate.get('request_count') == gate.get('logical_candidates_count') and
         gate.get('not_eligible_count') == len(keys) - possible,
         'DENIAL_GATE_COUNT_INVALID')
    return gate


def _db_path(root: Path, gate: dict[str, Any]) -> Path:
    directory = _root(root)
    session = gate['session_id']
    need(type(session) is str and len(session) <= 80 and session.isascii(),
         'SESSION_UNSAFE')
    name = 'r58t_' + hashlib.sha256(
        b'ARDREC-R58T-SIM-ONLY\x00' + session.encode('ascii')).hexdigest() + '.sqlite3'
    return directory / name


def _check_file(path: Path) -> None:
    need(not path.is_symlink() and path.is_file(), 'SIM_DB_MISSING_OR_SYMLINK')
    st = path.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and
         st.st_nlink == 1 and (stat.S_IMODE(st.st_mode) & 0o077) == 0 and
         st.st_size <= 4_000_000, 'SIM_DB_OWNER_MODE_SIZE')


def _connect(path: Path) -> sqlite3.Connection:
    _check_file(path)
    conn = sqlite3.connect(path, isolation_level=None, timeout=5)
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('PRAGMA busy_timeout=5000')
    conn.execute('PRAGMA trusted_schema=OFF')
    conn.execute('PRAGMA synchronous=FULL')
    conn.execute('PRAGMA journal_mode=DELETE')
    return conn


def _initial(gate: dict[str, Any]) -> list[tuple[str, str]]:
    cases = [(_key(row), canonical({f:row[f] for f in ID_FIELDS}).decode('ascii'))
             for row in gate['cases']]
    cases.sort()
    need(len({k for k,_ in cases}) == len(cases), 'DUPLICATE_INITIAL_CASE')
    return cases


def _event_sha(payload: dict[str, Any]) -> str:
    return digest({'schema': SCHEMA, 'record': payload})


def _inspect(conn: sqlite3.Connection, gate: dict[str, Any]) -> dict[str, Any]:
    need(conn.execute('PRAGMA integrity_check').fetchone() == ('ok',),
         'SQLITE_INTEGRITY_FAILED')
    need(conn.execute('PRAGMA foreign_key_check').fetchall() == [],
         'SQLITE_FOREIGN_KEY_FAILURE')
    names = {(r[0],r[1]) for r in conn.execute(
        "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
    need(names == {('table','meta'),('table','cases'),('table','events')},
         'SIM_DB_SCHEMA_DRIFT')
    meta = conn.execute('SELECT schema,mode,gate_sha,session_id,case_count,initial_sha FROM meta').fetchall()
    initial = _initial(gate)
    need(meta == [(SCHEMA,MODE,gate['sha256'],gate['session_id'],len(initial),digest(initial))],
         'SIM_SOURCE_PIN_CHANGED')
    rows = conn.execute('SELECT case_key,identity_json,phase,revision FROM cases ORDER BY case_key').fetchall()
    need(len(rows) == len(initial) and
         [(a,b) for a,b,_,_ in rows] == initial, 'SIM_CASE_SET_CHANGED')
    known = {k:(p,v) for k,_,p,v in rows}
    candidates = {_key(x) for x in gate['cases'] if x['logical_candidate']}
    events = conn.execute('SELECT seq,request_id,case_key,before_phase,after_phase,revision_before,revision_after,prev_sha,sha FROM events ORDER BY seq').fetchall()
    need(len(events) <= len(candidates), 'SIM_EVENT_COUNT_LIMIT')
    previous = ZERO_SHA
    per_case: set[str] = set()
    requests: set[str] = set()
    for num, e in enumerate(events,1):
        seq,req,key,before,after,rev0,rev1,prev,stored = e
        need(seq == num and type(req) is str and REQ.fullmatch(req) is not None and
             req not in requests and key in candidates and key not in per_case and
             before == ServicePhase.PREPARADO.value and
             after == ServicePhase.PENDIENTE.value and
             rev0 == 0 and rev1 == 1 and
             prev == previous and type(stored) is str and
             HEX.fullmatch(stored) is not None, 'SIM_EVENT_STATE_CHAIN_INVALID')
        payload = {'sequence':seq,'request_id':req,'case_key':key,
                   'transition':Transition.PREPARAR.value,
                   'before':before,'after':after,
                   'revision_before':rev0,'revision_after':rev1,
                   'prev_sha256':prev,'source_gate_sha256':gate['sha256'],
                   'authority':'COUNTERFACTUAL_SIM_ONLY'}
        need(stored == _event_sha(payload), 'SIM_EVENT_HASH_CHANGED')
        previous = stored
        per_case.add(key)
        requests.add(req)
    for key, (phase,version) in known.items():
        expected = ('PENDIENTE',1) if key in per_case else ('PREPARADO',0)
        need((phase,version) == expected, 'SIM_CASE_STATE_OR_REVISION_TAMPER')
    return {
        'schema':SCHEMA, 'source_gate_sha256':gate['sha256'],
        'session_id':gate['session_id'], 'case_count':len(known),
        'simulated_t1_count':len(events),
        'simulated_pending_count':len(per_case),
        'simulated_prepared_count':len(known)-len(per_case),
        'last_event_sha256':previous,
        'simulated_state_mutated':bool(per_case),
        'operational_transitions_applied':0,
        'operational_state_mutated':False,
        'technical_truth_accredited':False,
        'a6_classification':'ND', 'confirmed_final_risk':None,
        'published_generation':None, 'operational_dispatch':False,
        'p8_operational':'NO-GO',
    }


def _source_roots(root: Path, gate_root: Path, proposal_root: Path) -> None:
    names = [_root(p) for p in (root,gate_root,proposal_root)]
    need(len({(p.stat().st_dev,p.stat().st_ino) for p in names}) == 3,
         'SIM_ROOTS_MUST_BE_SEPARATE')


def initialize_simulator(root: Path, gate_root: Path, proposal_root: Path,
                         trace: dict[str, Any], scenario: dict[str, Any],
                         review: dict[str, Any], a3_report: dict[str, Any]) -> dict[str, Any]:
    """Create one source-pinned private sandbox database; identical replay only."""
    _source_roots(root,gate_root,proposal_root)
    gate = _source(gate_root,proposal_root,trace,scenario,review,a3_report)
    path = _db_path(root,gate)
    if path.exists() or path.is_symlink():
        conn = _connect(path)
        try:
            current = _inspect(conn,gate)
        finally:
            conn.close()
        return {'persist_status':'REPLAY_IDENTICAL', **current}
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_CLOEXEC',0),0o600)
    except FileExistsError:
        conn = _connect(path)
        try:
            current = _inspect(conn,gate)
        finally:
            conn.close()
        return {'persist_status':'REPLAY_IDENTICAL',**current}
    else:
        os.close(fd)
    try:
        conn = _connect(path)
        try:
            conn.execute('BEGIN IMMEDIATE')
            conn.execute('CREATE TABLE meta(schema TEXT NOT NULL, mode TEXT NOT NULL, gate_sha TEXT NOT NULL, session_id TEXT NOT NULL, case_count INTEGER NOT NULL, initial_sha TEXT NOT NULL)')
            conn.execute("CREATE TABLE cases(case_key TEXT PRIMARY KEY, identity_json TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('PREPARADO','PENDIENTE')), revision INTEGER NOT NULL CHECK(revision IN (0,1)))")
            conn.execute('CREATE TABLE events(seq INTEGER PRIMARY KEY, request_id TEXT UNIQUE NOT NULL, case_key TEXT NOT NULL REFERENCES cases(case_key), before_phase TEXT NOT NULL, after_phase TEXT NOT NULL, revision_before INTEGER NOT NULL, revision_after INTEGER NOT NULL, prev_sha TEXT NOT NULL, sha TEXT NOT NULL)')
            initial = _initial(gate)
            conn.execute('INSERT INTO meta VALUES (?,?,?,?,?,?)',
                         (SCHEMA,MODE,gate['sha256'],gate['session_id'],len(initial),digest(initial)))
            conn.executemany('INSERT INTO cases VALUES (?,?,?,?)',
                             [(k,v,'PREPARADO',0) for k,v in initial])
            current = _inspect(conn,gate)
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()
        os.chmod(path,0o600)
        dfd = os.open(root,os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        return {'persist_status':'CREATED', **current}
    except BaseException:
        # Only the newly created file can be removed; never touch existing data.
        if path.exists():
            path.unlink()
        raise


def inspect_simulator(root: Path, gate_root: Path, proposal_root: Path,
                      trace: dict[str, Any], scenario: dict[str, Any],
                      review: dict[str, Any], a3_report: dict[str, Any]) -> dict[str, Any]:
    _source_roots(root,gate_root,proposal_root)
    gate = _source(gate_root,proposal_root,trace,scenario,review,a3_report)
    conn = _connect(_db_path(root,gate))
    try:
        return _inspect(conn,gate)
    finally:
        conn.close()


def simulate_t1(root: Path, gate_root: Path, proposal_root: Path,
                trace: dict[str, Any], scenario: dict[str, Any],
                review: dict[str, Any], a3_report: dict[str, Any],
                *, case_id_a7: str, request_id: str, expected_revision: int = 0,
                fault_before_commit: bool = False) -> dict[str, Any]:
    """Atomic simulated T1, never invokes operational state transitions."""
    need(type(case_id_a7) is str and len(case_id_a7) == 53 and
         case_id_a7.startswith('CASE_') and
         type(request_id) is str and REQ.fullmatch(request_id) is not None and
         type(expected_revision) is int and expected_revision == 0 and
         type(fault_before_commit) is bool, 'SIM_REQUEST_SCHEMA_INVALID')
    _source_roots(root,gate_root,proposal_root)
    gate = _source(gate_root,proposal_root,trace,scenario,review,a3_report)
    matches = [c for c in gate['cases'] if c['case_id_a7'] == case_id_a7]
    need(len(matches) == 1, 'CASE_ID_UNKNOWN_OR_AMBIGUOUS')
    target = matches[0]
    need(target['logical_candidate'] is True and
         target['review_outcome'] == 'DENIED' and
         target['deny_reason'] == DENIED,
         'SIM_T1_NOT_LOGICALLY_ELIGIBLE')
    key = _key(target)
    conn = _connect(_db_path(root,gate))
    try:
        conn.execute('BEGIN IMMEDIATE')
        before = _inspect(conn,gate)
        prior = conn.execute('SELECT case_key FROM events WHERE request_id=?',(request_id,)).fetchone()
        if prior is not None:
            need(prior[0] == key, 'REQUEST_REPLAY_CONFLICT')
            conn.commit()
            return {'persist_status':'REPLAY_IDENTICAL',**before}
        state = conn.execute('SELECT phase,revision FROM cases WHERE case_key=?',(key,)).fetchone()
        need(state == ('PREPARADO',expected_revision),
             'SIM_CASE_ALREADY_TRANSITIONED_OR_REVISION_CONFLICT')
        seq = before['simulated_t1_count']+1
        payload = {'sequence':seq,'request_id':request_id,'case_key':key,
                   'transition':Transition.PREPARAR.value,
                   'before':ServicePhase.PREPARADO.value,
                   'after':ServicePhase.PENDIENTE.value,
                   'revision_before':0,'revision_after':1,
                   'prev_sha256':before['last_event_sha256'],
                   'source_gate_sha256':gate['sha256'],
                   'authority':'COUNTERFACTUAL_SIM_ONLY'}
        sha = _event_sha(payload)
        conn.execute('UPDATE cases SET phase=?, revision=1 WHERE case_key=? AND phase=? AND revision=0',
                     ('PENDIENTE',key,'PREPARADO'))
        need(conn.execute('SELECT changes()').fetchone() == (1,),
             'CAS_REVISION_FAILED')
        conn.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',
                     (seq,request_id,key,'PREPARADO','PENDIENTE',0,1,
                      before['last_event_sha256'],sha))
        after = _inspect(conn,gate)
        need(after['simulated_t1_count'] == seq and
             after['last_event_sha256'] == sha,'SIM_ATOMIC_EVENT_FAILURE')
        if fault_before_commit:
            raise SimulatorError('INJECTED_ROLLBACK_BEFORE_COMMIT')
        conn.commit()
        return {'persist_status':'COMMITTED_IN_SANDBOX_ONLY',**after}
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
