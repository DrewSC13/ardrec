"""R58-N: durable, *declared-only* A4/A5 identity receipt and replay barrier.

A local benign journal records no ARDREC service/session/case/window. This
sidecar binds the declaration to an exact verified snapshot but cannot prove
its independent physical origin. Never calls submit/accept/execute/recover.
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
from ardrec.coordination.r58m_durable_a5_audit import (
    build_durable_a5_link, verify_durable_a5_link,
)
from ardrec.coordination.r58l_a4_a5_family_review import verify_a4_a5_review

SCHEMA = 'ardrec-r58n-a4-a5-declared-durable-binding-v1'
BASE = 'b07f50f3e4aa0764b47024395caab5bb9b6694e5'
MAX_BYTES = 65536
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
RECEIPT_FIELDS = frozenset((
    'schema', 'mode', 'source_base_commit', 'r58l_review_sha256',
    'a4_selection_sha256', 'a4_selected_identity', 'declared_request_id',
    'a5_fixture_journal_sha256', 'a5_fixture_request_fingerprint',
    'a5_fixture_event_head_sha256', 'a5_fixture_state',
    'a5_fixture_start_intent_count', 'a5_fixture_event_count',
    'r58m_link_sha256', 'identity_declaration_independently_attested',
    'physical_case_binding_accredited', 'technical_truth_accredited',
    'a6_classification', 'confirmed_final_risk', 'applied_state_transition',
    'published_generation', 'operational_dispatch', 'p8_operational', 'sha256',
))

class BindingError(ValueError):
    """Fail-closed identity, journal snapshot, and immutable receipt error."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise BindingError(code)


def _record_name(rid: str) -> str:
    return 'r58n_' + hashlib.sha256(
        b'ARDREC-R58N-REQUEST-NAME-V1\0' + rid.encode('ascii')
    ).hexdigest() + '.json'


def _root(root: Path) -> Path:
    need(isinstance(root, Path) and root.is_absolute(), 'RECEIPT_ROOT_ABSOLUTE_REQUIRED')
    need(not root.is_symlink() and root.is_dir(), 'RECEIPT_ROOT_UNSAFE')
    st = root.stat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and
         (stat.S_IMODE(st.st_mode) & 0o077) == 0, 'RECEIPT_ROOT_MODE_OR_OWNER')
    return root


def _checked_bytes(path: Path) -> bytes:
    need(not path.is_symlink() and path.is_file(), 'RECEIPT_NOT_REGULAR')
    st = path.stat()
    need(st.st_uid == os.getuid() and st.st_nlink == 1 and
         (stat.S_IMODE(st.st_mode) & 0o077) == 0 and
         0 < st.st_size <= MAX_BYTES, 'RECEIPT_FILE_PERMISSIONS_OR_SIZE')
    raw = path.read_bytes()
    need(len(raw) == st.st_size, 'RECEIPT_CHANGED_DURING_READ')
    return raw


def build_binding(review: dict[str, Any], journal_root: Path,
                  request_id: str) -> dict[str, Any]:
    """Recompute a full journal/review-bound declared-only receipt."""
    verify_a4_a5_review(review)
    link = build_durable_a5_link(review, journal_root, request_id)
    verify_durable_a5_link(link, review, journal_root, request_id)
    audit = link['durable_a5']
    selected = link['declared_case_identity']
    need(review['a4_selected_identity'] == selected and
         review['attempt_intent']['attempt_id'] == request_id and
         review['a5']['actual_attempts_started'] == 0 and
         review['a5']['actual_attempt_reservations'] == 0 and
         link['case_identity_binding_accredited'] is False and
         link['actual_operational_attempts_started'] == 0,
         'REVIEW_OR_LINK_AUTHORITY')
    need(type(request_id) is str and request_id.isascii() and
         len(request_id) <= 64 and request_id and
         all(c.isalnum() or c in '._-' for c in request_id),
         'REQUEST_ID_UNSAFE')
    need(audit['journal_state'] in ('RESERVED','ACCEPTED','START_INTENT',
                                   'RECOVERY_UNCERTAIN','RECORDED_LIMITED') and
         audit['ordinary_retry_allowed'] is False and
         audit['case_identity_stored_in_journal'] is False and
         audit['independent_origin_attested'] is False,
         'JOURNAL_AUTHORITY_UNEXPECTED')
    report = {
        'schema': SCHEMA,
        'mode': 'DURABLE_LOCAL_DECLARATION_NO_TECHNICAL_AUTHORITY',
        'source_base_commit': BASE,
        'r58l_review_sha256': review['sha256'],
        'a4_selection_sha256': review['a4']['sha256'],
        'a4_selected_identity': dict(selected),
        'declared_request_id': request_id,
        'a5_fixture_journal_sha256': audit['journal_file_sha256'],
        'a5_fixture_request_fingerprint': audit['request_fingerprint'],
        'a5_fixture_event_head_sha256': audit['event_head_sha256'],
        'a5_fixture_state': audit['journal_state'],
        'a5_fixture_start_intent_count': audit['local_fixture_start_intent_count'],
        'a5_fixture_event_count': audit['event_count'],
        'r58m_link_sha256': link['sha256'],
        'identity_declaration_independently_attested': False,
        'physical_case_binding_accredited': False,
        'technical_truth_accredited': False,
        'a6_classification': 'ND',
        'confirmed_final_risk': None,
        'applied_state_transition': None,
        'published_generation': None,
        'operational_dispatch': False,
        'p8_operational': 'NO-GO',
    }
    need(len(canonical(report)) < MAX_BYTES - 100, 'RECEIPT_TOO_LARGE')
    report['sha256'] = digest(report)
    need(set(report) == RECEIPT_FIELDS, 'RECEIPT_SCHEMA_DRIFT')
    return report


def verify_binding(doc: dict[str, Any], review: dict[str, Any],
                   journal_root: Path, request_id: str) -> bool:
    need(type(doc) is dict and set(doc) == RECEIPT_FIELDS and
         type(doc['sha256']) is str and HEX.fullmatch(doc['sha256']) is not None,
         'RECEIPT_SCHEMA')
    expected = build_binding(review, journal_root, request_id)
    need(canonical(doc) == canonical(expected), 'RECEIPT_SNAPSHOT_OR_AUTHORITY_CHANGED')
    return True


def persist_binding(receipt_root: Path, review: dict[str, Any],
                    journal_root: Path, request_id: str) -> dict[str, Any]:
    """Create one fsynced receipt per RID; identical replay or hard conflict.

    Receipt is not an authorization. No process launch or source journal write.
    """
    directory = _root(receipt_root)
    receipt = build_binding(review, journal_root, request_id)
    verify_binding(receipt, review, journal_root, request_id)
    raw = canonical(receipt) + b'\n'
    filename = _record_name(request_id)
    target = directory / filename
    need(not target.is_symlink(), 'RECEIPT_SYMLINK_REFUSED')
    action = 'REPLAY_IDENTICAL'
    if not target.exists():
        try:
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                         getattr(os, 'O_NOFOLLOW', 0), 0o600)
        except FileExistsError:
            pass  # concurrent creator; validate exact bytes below
        else:
            action = 'CREATED'
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except BaseException:
                # A partially written receipt remains a hard conflict; never
                # claim success or overwrite it automatically.
                raise
    need(_checked_bytes(target) == raw, 'RECEIPT_REPLAY_CONFLICT_OR_TAMPER')
    # A journal change concurrent with persistence invalidates even a new
    # receipt: recompute the source snapshot before returning success.
    verify_binding(receipt, review, journal_root, request_id)
    return {'receipt': receipt, 'receipt_filename': filename,
            'persist_status': action,
            'case_binding_accredited': False, 'operational_dispatch': False,
            'p8_operational': 'NO-GO'}


def verify_persisted(receipt_root: Path, review: dict[str, Any],
                     journal_root: Path, request_id: str) -> dict[str, Any]:
    directory = _root(receipt_root)
    path = directory / _record_name(request_id)
    raw = _checked_bytes(path)
    try:
        saved = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise BindingError('RECEIPT_JSON_CORRUPT') from exc
    verify_binding(saved, review, journal_root, request_id)
    need(raw == canonical(saved) + b'\n', 'RECEIPT_NOT_CANONICAL')
    return {'receipt_sha256': saved['sha256'],
            'receipt_filename': path.name,
            'persisted_verification': 'PASS_DECLARED_ONLY_NO_AUTHORITY',
            'retry_allowed': False,
            'physical_case_binding_accredited': False,
            'operational_dispatch': False, 'p8_operational': 'NO-GO'}


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj = {}
    for k, v in pairs:
        need(k not in obj, 'DUPLICATE_RECEIPT_JSON_KEY')
        obj[k] = v
    return obj
