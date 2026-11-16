"""R58-W: source-pinned SQLite ledger of *model-only* A5 intent/no-start.

Consumes an immutable, verified R58-V handoff. The existing denial R58-S
remains true. No attempt is reserved or started, no A6 evidence is admitted,
no Rf is confirmed, and no operational generation is published. The only
mutable resource is an explicitly supplied private, isolated sandbox ledger.
"""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any

from ardrec.analytics.exact_preview import digest
from ardrec.coordination.r58r_durable_transition_proposal import _root
from ardrec.coordination.r58v_a5_a6_readonly_handoff import (
    build_handoff, verify_persisted_handoff,
)

SCHEMA = 'ardrec-r58w-a5-model-intent-no-start-ledger-v1'
MODE = 'COUNTERFACTUAL_DECLARED_INTENT_NO_EXECUTION'
BASE = '3ba8048bfd92a57ce5ede26a45c3b778a07e8613'
ZERO = '0' * 64
REQ = re.compile(r'SIM_[A-Z0-9_]{1,72}\Z', re.ASCII)
CASE = re.compile(r'CASE_[0-9A-F]{48}\Z', re.ASCII)
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
MAX_BYTES = 4_000_000

# An explicitly scoped, read-only verification snapshot. No global cross-run cache.
_VERIFIED_BATCH: ContextVar[dict[str, Any] | None] = ContextVar(
    'ardrec_r58w_batch', default=None)


class ModelIntentError(ValueError):
    """Fail-closed for source drift, invalid events, or simulated authority."""


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise ModelIntentError(reason)


def _source(handoff_root: Path, source: tuple[Any, ...]) -> dict[str, Any]:
    need(len(source) == 8 and all(isinstance(x, Path) for x in source[:4]),
         'SOURCE_ARGUMENTS_INVALID')
    batch = _VERIFIED_BATCH.get()
    if batch is not None:
        need(handoff_root == batch['handoff_root'], 'BATCH_HANDOFF_ROOT_DRIFT')
        need(_source_fingerprint(handoff_root, source) == batch['fingerprint'],
             'BATCH_SOURCE_CHANGED_OR_TAMPERED')
        return deepcopy(batch['handoff'])
    verified = verify_persisted_handoff(handoff_root, *source)
    handoff = build_handoff(*source)
    need(type(verified) is dict and
         verified.get('verification') == 'PASS_READONLY_MODEL_HANDOFF_NO_A5_OR_A6' and
         verified.get('receipt_sha256') == handoff.get('sha256') and
         verified.get('a5_attempts_started') == 0 and
         verified.get('a6_classification') == 'ND' and
         verified.get('operational_dispatch') is False and
         verified.get('p8_operational') == 'NO-GO',
         'READONLY_HANDOFF_NOT_VERIFIED')
    need(type(handoff) is dict and
         handoff.get('schema') == 'ardrec-r58v-sandbox-a5-a6-readonly-handoff-v1' and
         handoff.get('mode') == 'OFFLINE_HANDOFF_NO_ATTEMPT_NO_EVIDENCE' and
         type(handoff.get('sha256')) is str and
         HEX.fullmatch(handoff['sha256']) is not None and
         digest({k:v for k,v in handoff.items() if k != 'sha256'}) == handoff['sha256'] and
         type(handoff.get('case_count')) is int and 0 < handoff['case_count'] <= 54 and
         type(handoff.get('family_count')) is int and 0 < handoff['family_count'] <= 25 and
         type(handoff.get('cases')) is list and
         len(handoff['cases']) == handoff['case_count'] and
         handoff.get('all_source_requests_denied') is True and
         handoff.get('a5_status') == 'NOT_SUBMITTED_NO_START' and
         handoff.get('a5_intents_submitted') == 0 and
         handoff.get('a5_attempts_reserved') == 0 and
         handoff.get('a5_attempts_started') == 0 and
         handoff.get('a6_accredited_evidence_count') == 0 and
         handoff.get('a6_classification') == 'ND' and
         handoff.get('technical_truth_accredited') is False and
         handoff.get('confirmed_final_risk') is None and
         handoff.get('published_generation') is None and
         handoff.get('operational_transitions_applied') == 0 and
         handoff.get('operational_dispatch') is False and
         handoff.get('p8_operational') == 'NO-GO',
         'HANDOFF_OPERATIONAL_AUTHORITY_INVALID')
    seen = set()
    candidates = []
    for item in handoff['cases']:
        need(type(item) is dict and
             type(item.get('case_id_a7')) is str and
             CASE.fullmatch(item['case_id_a7']) is not None and
             item['case_id_a7'] not in seen and
             item.get('a5_intent_submitted') is False and
             item.get('a5_start_count') == 0 and
             item.get('a6_classification') == 'ND' and
             item.get('evidence_accredited') is False and
             item.get('model_a5_disposition') in (
                 'MODEL_PENDING_REVIEW_ONLY_NO_DISPATCH',
                 'MODEL_PAUSED_NO_ATTEMPT',
                 'MODEL_TERMINAL_NO_ATTEMPT',
                 'MODEL_PREPARED_NO_ATTEMPT'),
             'HANDOFF_CASE_INVALID_OR_DUPLICATE')
        seen.add(item['case_id_a7'])
        if item['current_model_phase'] == 'PENDIENTE':
            need(item['logical_candidate'] is True and
                 item['model_a5_disposition'] == 'MODEL_PENDING_REVIEW_ONLY_NO_DISPATCH' and
                 item['deny_reason'] == 'INDEPENDENT_APPROVAL_AND_COMMIT_NOT_ATTESTED',
                 'PENDING_NOT_DENIED_OR_NOT_ELIGIBLE')
            candidates.append(item['case_id_a7'])
        else:
            need(item['current_model_phase'] in ('PREPARADO','PAUSADO','DETENIDO'),
                 'UNKNOWN_MODEL_PHASE')
    need(len(candidates) == handoff['model_a5_review_candidate_count'] and
         len(candidates) == handoff['simulated_phase_counts']['PENDIENTE'],
         'HANDOFF_CANDIDATE_COUNT_MISMATCH')
    return handoff


def _roots(root: Path, handoff_root: Path, source: tuple[Any, ...]) -> None:
    batch = _VERIFIED_BATCH.get()
    if batch is not None:
        need(root == batch['model_root'] and handoff_root == batch['handoff_root'],
             'BATCH_MODEL_OR_HANDOFF_ROOT_CHANGED')
    roots = [_root(x) for x in (root,handoff_root,*source[:4])]
    need(len({(x.stat().st_dev, x.stat().st_ino) for x in roots}) == 6,
         'MODEL_LEDGER_ROOTS_MUST_DIFFER')


def _private_file_fingerprint(path: Path) -> tuple[Any, ...]:
    """Hash exact owner-private file bytes using a no-follow fd and stable fstat."""
    need(not path.is_symlink(), 'BATCH_SOURCE_FILE_SYMLINK')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ModelIntentError('BATCH_SOURCE_FILE_NOT_READABLE') from exc
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
             before.st_nlink == 1 and (stat.S_IMODE(before.st_mode) & 0o077) == 0 and
             0 < before.st_size <= MAX_BYTES, 'BATCH_SOURCE_FILE_MODE_OR_SIZE')
        h = hashlib.sha256()
        remaining = before.st_size + 1
        count = 0
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            h.update(chunk)
            count += len(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        need(count == before.st_size and
             (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
              before.st_ctime_ns, before.st_mode) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
              after.st_ctime_ns, after.st_mode),
             'BATCH_SOURCE_FILE_CHANGED_DURING_READ')
        return (path.name, before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns,
                stat.S_IMODE(before.st_mode), h.hexdigest())
    finally:
        os.close(fd)


def _source_fingerprint(handoff_root: Path,
                        source: tuple[Any, ...]) -> tuple[Any, ...]:
    """Bind source arguments AND every private source-file byte to the batch.

    Re-read raw hashes on every ledger operation; any addition/deletion,
    source mutation or permission drift fails closed. Never trust file names
    or mtime alone and never cache between processes or independent calls.
    """
    need(len(source) == 8 and all(isinstance(x, Path) for x in source[:4]),
         'BATCH_SOURCE_SCHEMA')
    dirs = (handoff_root, *source[:4])
    inventory = []
    for root in dirs:
        _root(root)
        root_st = root.stat()
        items = sorted(root.iterdir(), key=lambda p: p.name)
        need(1 <= len(items) <= 8, 'BATCH_SOURCE_INVENTORY_COUNT')
        hashes = tuple(_private_file_fingerprint(item) for item in items)
        root_after = root.stat()
        need((root_st.st_dev, root_st.st_ino, root_st.st_mtime_ns,
              root_st.st_ctime_ns) ==
             (root_after.st_dev, root_after.st_ino, root_after.st_mtime_ns,
              root_after.st_ctime_ns),
             'BATCH_SOURCE_DIRECTORY_CHANGED')
        inventory.append((str(root), root_st.st_dev, root_st.st_ino,
                          stat.S_IMODE(root_st.st_mode), hashes))
    document_sha = digest(source[4:])
    return (document_sha, tuple(inventory))


@contextmanager
def verified_model_source_batch(root: Path, handoff_root: Path,
                                *source: Any):
    """Bounded speedup for a single synthetic CLI run, not an authority cache.

    Fully validate R58-V once, then cryptographically recheck every backing
    source and all four source documents before EACH independent model action
    and again at exit. On drift, abort rather than recompute or promote.
    Outside this context every operation uses the original full verification.
    """
    need(_VERIFIED_BATCH.get() is None, 'BATCH_NESTING_NOT_ALLOWED')
    _roots(root, handoff_root, source)
    before = _source_fingerprint(handoff_root, source)
    verified = _source(handoff_root, source)
    need(_source_fingerprint(handoff_root, source) == before,
         'BATCH_SOURCE_CHANGED_DURING_FULL_VERIFICATION')
    token = _VERIFIED_BATCH.set({
        'model_root': root, 'handoff_root': handoff_root,
        'fingerprint': before, 'handoff': deepcopy(verified),
    })
    try:
        yield
    finally:
        try:
            need(_source_fingerprint(handoff_root, source) == before,
                 'BATCH_SOURCE_CHANGED_BEFORE_EXIT')
        finally:
            _VERIFIED_BATCH.reset(token)


def _path(root: Path, report: dict[str, Any]) -> Path:
    session = report['session_id']
    need(type(session) is str and re.fullmatch(r'[A-Za-z0-9_:-]{1,80}',session),
         'SESSION_ID_INVALID')
    name = hashlib.sha256(b'ARDREC-R58W-A5-MODEL-ONLY\x00'+session.encode('ascii')).hexdigest()
    return root / ('r58w_'+name+'.sqlite3')


def _open(path: Path) -> sqlite3.Connection:
    need(not path.is_symlink() and path.is_file(), 'LEDGER_MISSING_OR_SYMLINK')
    st = path.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and
         st.st_nlink == 1 and (stat.S_IMODE(st.st_mode) & 0o077) == 0 and
         0 <= st.st_size <= MAX_BYTES, 'LEDGER_FILE_OWNER_MODE_SIZE')
    db = sqlite3.connect(path,timeout=5,isolation_level=None)
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA trusted_schema=OFF')
    db.execute('PRAGMA synchronous=FULL')
    db.execute('PRAGMA journal_mode=DELETE')
    db.execute('PRAGMA busy_timeout=5000')
    return db


def _event_sha(seq: int, request: str, case: str, kind: str,
               previous: str, handoff_sha: str) -> str:
    return digest({'schema':SCHEMA,'sequence':seq,'request_id':request,
                   'case_id_a7':case,'kind':kind,'prev_sha256':previous,
                   'source_handoff_sha256':handoff_sha,
                   'authority':'DECLARED_SIMULATION_ONLY'})


def _inspect(db: sqlite3.Connection, report: dict[str, Any]) -> dict[str, Any]:
    need(db.execute('PRAGMA integrity_check').fetchone() == ('ok',),
         'SQLITE_INTEGRITY_FAILED')
    need(db.execute('PRAGMA foreign_key_check').fetchall() == [],
         'FOREIGN_KEY_INTEGRITY_FAILED')
    tables = {(t,n) for t,n in db.execute(
        "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
    need(tables == {('table','meta'),('table','intents'),('table','events')},
         'LEDGER_SCHEMA_DRIFT')
    source_sha = report['sha256']
    expected_meta = [(SCHEMA,MODE,report['session_id'],source_sha,
                      report['case_count'],report['model_a5_review_candidate_count'])]
    meta = db.execute('SELECT schema,mode,session_id,handoff_sha,case_count,candidate_count FROM meta').fetchall()
    need(meta == expected_meta, 'LEDGER_SOURCE_BINDING_MISMATCH')
    by_case = {r['case_id_a7']:r for r in report['cases']}
    eligible = {k for k,v in by_case.items() if v['current_model_phase']=='PENDIENTE'}
    events = db.execute('SELECT seq,request_id,case_id,kind,prev_sha,sha FROM events ORDER BY seq').fetchall()
    need(len(events) <= 2*len(eligible), 'MODEL_EVENT_COUNT_LIMIT')
    reconstructed: dict[str, tuple[str,str,str|None]] = {}
    used = set()
    previous = ZERO
    for seq, row in enumerate(events,1):
        n,req,case,kind,prev,stored = row
        need(n == seq and type(req) is str and REQ.fullmatch(req) is not None and
             req not in used and case in eligible and
             kind in ('DECLARE_INTENT','RESOLVE_NO_START') and
             prev == previous and type(stored) is str and
             HEX.fullmatch(stored) is not None and
             stored == _event_sha(n,req,case,kind,prev,source_sha),
             'MODEL_EVENT_CHAIN_INVALID')
        used.add(req)
        if kind == 'DECLARE_INTENT':
            need(case not in reconstructed, 'MODEL_DUPLICATE_INTENT')
            reconstructed[case] = ('DECLARED',req,None)
        else:
            need(case in reconstructed and reconstructed[case][0]=='DECLARED',
                 'MODEL_RESOLVE_WITHOUT_DECLARATION')
            reconstructed[case] = ('RESOLVED_NO_START',reconstructed[case][1],req)
        previous = stored
    materialized = db.execute('SELECT case_id,status,declare_request,resolve_request FROM intents ORDER BY case_id').fetchall()
    expected = sorted((k,*v) for k,v in reconstructed.items())
    need(materialized == expected, 'MODEL_INTENT_MATERIALIZATION_MISMATCH')
    open_count = sum(v[0]=='DECLARED' for v in reconstructed.values())
    resolved = sum(v[0]=='RESOLVED_NO_START' for v in reconstructed.values())
    return {'schema':SCHEMA,'mode':MODE,
            'source_handoff_sha256':source_sha,
            'source_r58s_deny_sha256':report['source_r58s_deny_sha256'],
            'case_count':report['case_count'],
            'family_count':report['family_count'],
            'model_review_candidate_count':len(eligible),
            'model_intents_declared':len(reconstructed),
            'model_intents_open':open_count,
            'model_no_start_resolutions':resolved,
            'model_event_count':len(events),
            'last_event_sha256':previous,
            'source_denials_preserved':True,
            'a5_operational_intents_submitted':0,
            'a5_operational_reservations':0,
            'a5_attempts_started':0,
            'a6_classification':'ND',
            'a6_accredited_evidence_count':0,
            'technical_truth_accredited':False,
            'confirmed_final_risk':None,
            'published_generation':None,
            'operational_state_mutated':False,
            'operational_dispatch':False,
            'p8_operational':'NO-GO'}


def initialize_model_ledger(root: Path, handoff_root: Path,
                            *source: Any) -> dict[str, Any]:
    _roots(root,handoff_root,source)
    report = _source(handoff_root,source)
    path = _path(root,report)
    if path.exists() or path.is_symlink():
        db = _open(path)
        try: state=_inspect(db,report)
        finally: db.close()
        return {'persist_status':'REPLAY_IDENTICAL',**state}
    try:
        fd = os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|
                     getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0),0o600)
    except FileExistsError:
        db = _open(path)
        try: state=_inspect(db,report)
        finally: db.close()
        return {'persist_status':'REPLAY_IDENTICAL',**state}
    else:
        os.close(fd)
    try:
        db = _open(path)
        try:
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE meta(schema TEXT NOT NULL,mode TEXT NOT NULL,session_id TEXT NOT NULL,handoff_sha TEXT NOT NULL,case_count INTEGER NOT NULL,candidate_count INTEGER NOT NULL)')
            db.execute("CREATE TABLE intents(case_id TEXT PRIMARY KEY,status TEXT NOT NULL CHECK(status IN ('DECLARED','RESOLVED_NO_START')),declare_request TEXT UNIQUE NOT NULL,resolve_request TEXT UNIQUE)")
            db.execute("CREATE TABLE events(seq INTEGER PRIMARY KEY,request_id TEXT UNIQUE NOT NULL,case_id TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('DECLARE_INTENT','RESOLVE_NO_START')),prev_sha TEXT NOT NULL,sha TEXT NOT NULL)")
            db.execute('INSERT INTO meta VALUES(?,?,?,?,?,?)',(SCHEMA,MODE,report['session_id'],report['sha256'],report['case_count'],report['model_a5_review_candidate_count']))
            state=_inspect(db,report)
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally: db.close()
        os.chmod(path,0o600)
        fd_dir=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd_dir)
        finally: os.close(fd_dir)
        return {'persist_status':'CREATED',**state}
    except BaseException:
        if path.exists(): path.unlink()
        raise


def inspect_model_ledger(root: Path,handoff_root: Path,
                         *source: Any) -> dict[str, Any]:
    _roots(root,handoff_root,source)
    report=_source(handoff_root,source)
    db=_open(_path(root,report))
    try: return _inspect(db,report)
    finally: db.close()


def _commit_event(root: Path, handoff_root: Path, source: tuple[Any,...],
                  *,case_id_a7: str, request_id: str, kind: str,
                  fault_before_commit: bool) -> dict[str, Any]:
    need(type(case_id_a7) is str and CASE.fullmatch(case_id_a7) is not None and
         type(request_id) is str and REQ.fullmatch(request_id) is not None and
         type(fault_before_commit) is bool, 'MODEL_REQUEST_INVALID')
    _roots(root,handoff_root,source)
    report=_source(handoff_root,source)
    eligible={r['case_id_a7'] for r in report['cases'] if
              r['current_model_phase']=='PENDIENTE'}
    need(case_id_a7 in eligible, 'MODEL_CASE_NOT_PENDING_OR_UNAUTHORIZED')
    db=_open(_path(root,report))
    try:
        db.execute('BEGIN IMMEDIATE')
        before=_inspect(db,report)
        previous_req=db.execute('SELECT case_id,kind FROM events WHERE request_id=?',(request_id,)).fetchone()
        if previous_req is not None:
            need(previous_req==(case_id_a7,kind), 'MODEL_REQUEST_REPLAY_CONFLICT')
            db.commit()
            return {'persist_status':'REPLAY_IDENTICAL',**before}
        current=db.execute('SELECT status,declare_request,resolve_request FROM intents WHERE case_id=?',(case_id_a7,)).fetchone()
        if kind=='DECLARE_INTENT':
            need(current is None, 'MODEL_INTENT_ALREADY_EXISTS')
        elif kind=='RESOLVE_NO_START':
            need(current is not None and current[0]=='DECLARED' and
                 current[2] is None, 'MODEL_INTENT_NOT_OPEN')
        else:
            raise ModelIntentError('MODEL_EVENT_KIND_INVALID')
        seq=before['model_event_count']+1
        sha=_event_sha(seq,request_id,case_id_a7,kind,before['last_event_sha256'],report['sha256'])
        if kind=='DECLARE_INTENT':
            db.execute('INSERT INTO intents VALUES(?,?,?,?)',(case_id_a7,'DECLARED',request_id,None))
        else:
            db.execute('UPDATE intents SET status=?,resolve_request=? WHERE case_id=? AND status=?',
                       ('RESOLVED_NO_START',request_id,case_id_a7,'DECLARED'))
            need(db.execute('SELECT changes()').fetchone()==(1,),
                 'MODEL_RESOLUTION_CAS_FAILED')
        db.execute('INSERT INTO events VALUES(?,?,?,?,?,?)',
                   (seq,request_id,case_id_a7,kind,before['last_event_sha256'],sha))
        after=_inspect(db,report)
        need(after['model_event_count']==seq and after['last_event_sha256']==sha,
             'MODEL_COMMIT_INSPECTION_FAILED')
        if fault_before_commit:
            raise ModelIntentError('INJECTED_MODEL_ROLLBACK')
        db.commit()
        return {'persist_status':'COMMITTED_IN_MODEL_ONLY',**after}
    except BaseException:
        db.rollback()
        raise
    finally: db.close()


def declare_model_intent(root:Path,handoff_root:Path,*source:Any,
                         case_id_a7:str,request_id:str,
                         fault_before_commit:bool=False)->dict[str,Any]:
    return _commit_event(root,handoff_root,source,case_id_a7=case_id_a7,
                         request_id=request_id,kind='DECLARE_INTENT',
                         fault_before_commit=fault_before_commit)


def resolve_model_no_start(root:Path,handoff_root:Path,*source:Any,
                           case_id_a7:str,request_id:str,
                           fault_before_commit:bool=False)->dict[str,Any]:
    return _commit_event(root,handoff_root,source,case_id_a7=case_id_a7,
                         request_id=request_id,kind='RESOLVE_NO_START',
                         fault_before_commit=fault_before_commit)
