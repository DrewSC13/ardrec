"""R59-D: strict A5 result-candidate intake; A6 stays ND without physical attestation.

A source can *declare* that an attempt started. This module does not attest
execution, approve P8, evaluate technical truth, transition A8 or publish A9.
Designed as the source-only receive/validate/store boundary for a future
separately authorized physically witnessed executor; no processes/network.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

SCHEMA_INTENT = 'ardrec-r59d-a5-case-intent-v1'
SCHEMA_RECEIPT = 'ardrec-r59d-a5-candidate-result-v1'
SCHEMA_REPORT = 'ardrec-r59d-a5-a6-candidate-intake-v1'
INTENT_FIELDS = frozenset({
    'schema', 'service_id', 'session_id', 'family_id', 'derived_case_id',
    'assessment_index', 'attempt_id', 'configuration_sha256', 'method_id',
    'model_phase', 'source_mode', 'p8_operational', 'sha256',
})
RECEIPT_FIELDS = frozenset({
    'schema', 'intent_sha256', 'service_id', 'session_id', 'family_id',
    'derived_case_id', 'assessment_index', 'attempt_id', 'configuration_sha256',
    'method_id', 'declared_started_at_utc', 'declared_finished_at_utc',
    'declared_outcome', 'support_sha256', 'support_bytes', 'source_kind',
    'physical_authority_receipt_sha256',
})
REPORT_FIELDS = frozenset({
    'schema', 'intent', 'receipt', 'status', 'a5_physical_start_accredited',
    'a5_case_binding_independently_attested', 'a6_classification',
    'a6_technical_truth_accredited', 'a7_confirmed_rf', 'a9_published_generation',
    'p8_operational', 'operational_dispatch', 'support_sha256', 'sha256',
})
SERVICES = {
    'SSH_DEV': ('SSH', 8, 'SSH_EFFECTIVE_CONFIG_READONLY'),
    'FTP_DEV': ('FTP', 8, 'FTP_EFFECTIVE_CONFIG_READONLY'),
    'SMB_DEV': ('SMB', 9, 'SMB_EFFECTIVE_CONFIG_READONLY'),
}
OUTCOMES = frozenset({'NO_START', 'OBSERVADO_POSITIVO', 'OBSERVADO_NEGATIVO',
                      'INCONCLUSO', 'INCIDENCIA'})
SOURCES = frozenset({'LOCAL_BENIGN_FIXTURE', 'EXTERNAL_UNVERIFIED'})
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
SESSION = re.compile(r'[A-Za-z0-9_:-]{1,80}\Z', re.ASCII)
ATTEMPT = re.compile(r'ATT_[A-Z0-9_]{1,76}\Z', re.ASCII)
UTC = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z', re.ASCII)
MAX_SUPPORT = 1_048_576
MAX_REPORT = 64_000


class IntakeError(ValueError):
    """Stable, fail-closed contract error."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise IntakeError(code)


def canonical(obj: Any) -> bytes:
    try:
        return json.dumps(obj, ensure_ascii=True, allow_nan=False,
                          separators=(',', ':'), sort_keys=True).encode('ascii')
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise IntakeError('CANONICAL_SERIALIZATION') from exc


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(obj: Any) -> str:
    return sha(canonical(obj))


def _hex(v: Any) -> bool:
    return type(v) is str and HEX.fullmatch(v) is not None


def _time(v: Any) -> datetime:
    need(type(v) is str and UTC.fullmatch(v) is not None, 'TIME_FORMAT')
    try:
        stamp = datetime.strptime(v, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise IntakeError('TIME_INVALID') from exc
    need(stamp.strftime('%Y-%m-%dT%H:%M:%SZ') == v, 'TIME_NONCANONICAL')
    return stamp


def build_intent(*, service_id: str, session_id: str, family_id: str,
                 derived_case_id: str, assessment_index: int, attempt_id: str,
                 configuration_sha256: str, method_id: str) -> dict[str, Any]:
    """Bind an A5 model intent to exactly one thesis-family case/window."""
    need(type(service_id) is str and service_id in SERVICES, 'SERVICE_UNKNOWN')
    protocol, upper, expected_method = SERVICES[service_id]
    need(type(family_id) is str and re.fullmatch(
         rf'{protocol}-T(?:0[1-9]|{upper:02d})', family_id) is not None,
         'FAMILY_SERVICE_INVALID')
    # Explicit numeric range avoids the SSH/FTP 09 family and SMB 10 family.
    number = int(family_id.rsplit('-T', 1)[1])
    need(1 <= number <= upper, 'FAMILY_OUT_OF_RANGE')
    need(type(derived_case_id) is str and
         re.fullmatch(re.escape(family_id) + r'-S\d{2}-\d{2}', derived_case_id) is not None,
         'DERIVED_CASE_FAMILY_MISMATCH')
    need(type(session_id) is str and SESSION.fullmatch(session_id) is not None,
         'SESSION_INVALID')
    need(type(assessment_index) is int and 0 <= assessment_index < 2**31,
         'ASSESSMENT_INDEX_INVALID')
    need(type(attempt_id) is str and ATTEMPT.fullmatch(attempt_id) is not None,
         'ATTEMPT_ID_INVALID')
    need(_hex(configuration_sha256), 'CONFIGURATION_DIGEST_INVALID')
    need(type(method_id) is str and method_id == expected_method,
         'METHOD_SERVICE_MISMATCH')
    doc = {
        'schema': SCHEMA_INTENT, 'service_id': service_id, 'session_id': session_id,
        'family_id': family_id, 'derived_case_id': derived_case_id,
        'assessment_index': assessment_index, 'attempt_id': attempt_id,
        'configuration_sha256': configuration_sha256, 'method_id': method_id,
        'model_phase': 'PENDIENTE',
        'source_mode': 'DECLARED_INTENT_ONLY_NO_EXECUTION_AUTHORITY',
        'p8_operational': 'NO-GO',
    }
    doc['sha256'] = digest(doc)
    return doc


def verify_intent(doc: dict[str, Any]) -> bool:
    need(type(doc) is dict and set(doc) == INTENT_FIELDS and _hex(doc.get('sha256')),
         'INTENT_SCHEMA')
    original = build_intent(**{k: doc[k] for k in (
        'service_id', 'session_id', 'family_id', 'derived_case_id', 'assessment_index',
        'attempt_id', 'configuration_sha256', 'method_id')})
    need(canonical(doc) == canonical(original), 'INTENT_SEMANTICS_OR_HASH_DRIFT')
    return True


def make_receipt(intent: dict[str, Any], *, outcome: str = 'NO_START',
                 source_kind: str = 'LOCAL_BENIGN_FIXTURE',
                 support: bytes = b'', start_utc: str | None = None,
                 finish_utc: str | None = None) -> dict[str, Any]:
    """Make a typed **declaration**, NOT independent execution testimony."""
    verify_intent(intent)
    need(type(support) is bytes and len(support) <= MAX_SUPPORT, 'SUPPORT_TYPE_OR_SIZE')
    return {
        'schema': SCHEMA_RECEIPT,
        'intent_sha256': intent['sha256'],
        **{k: intent[k] for k in (
            'service_id', 'session_id', 'family_id', 'derived_case_id',
            'assessment_index', 'attempt_id', 'configuration_sha256', 'method_id')},
        'declared_started_at_utc': start_utc, 'declared_finished_at_utc': finish_utc,
        'declared_outcome': outcome, 'support_sha256': sha(support),
        'support_bytes': len(support), 'source_kind': source_kind,
        'physical_authority_receipt_sha256': None,
    }


def build_candidate(intent: dict[str, Any], receipt: dict[str, Any],
                    support: bytes) -> dict[str, Any]:
    """Validate a bounded candidate and preserve A6 ND until real attestation."""
    verify_intent(intent)
    need(type(receipt) is dict and set(receipt) == RECEIPT_FIELDS,
         'RECEIPT_SCHEMA')
    need(type(support) is bytes and len(support) <= MAX_SUPPORT,
         'SUPPORT_TYPE_OR_SIZE')
    need(receipt.get('schema') == SCHEMA_RECEIPT and
         receipt.get('intent_sha256') == intent['sha256'],
         'RECEIPT_INTENT_DIGEST_MISMATCH')
    for key in ('service_id', 'session_id', 'family_id', 'derived_case_id',
                'assessment_index', 'attempt_id', 'configuration_sha256', 'method_id'):
        need(type(receipt[key]) is type(intent[key]) and receipt[key] == intent[key],
             'RECEIPT_CASE_OR_ATTEMPT_MISMATCH:'+key)
    need(receipt['physical_authority_receipt_sha256'] is None,
         'PHYSICAL_ATTESTATION_UNSUPPORTED_IN_R59D')
    need(type(receipt['source_kind']) is str and receipt['source_kind'] in SOURCES,
         'SOURCE_KIND_INVALID')
    need(type(receipt['declared_outcome']) is str and
         receipt['declared_outcome'] in OUTCOMES, 'OUTCOME_INVALID')
    need(type(receipt['support_bytes']) is int and
         receipt['support_bytes'] == len(support) and
         receipt['support_sha256'] == sha(support), 'SUPPORT_DIGEST_OR_SIZE_MISMATCH')
    if receipt['declared_outcome'] == 'NO_START':
        need(receipt['declared_started_at_utc'] is None and
             receipt['declared_finished_at_utc'] is None and len(support) == 0,
             'NO_START_MUST_HAVE_NO_TIMES_OR_SUPPORT')
        status = 'DECLARED_NO_START_NO_A5'
    else:
        need(0 < len(support) <= MAX_SUPPORT, 'CANDIDATE_SUPPORT_MISSING')
        first = _time(receipt['declared_started_at_utc'])
        last = _time(receipt['declared_finished_at_utc'])
        need(first <= last, 'TIME_REVERSED')
        status = 'DECLARED_OUTCOME_AWAITING_INDEPENDENT_ATTESTATION'
    doc = {
        'schema': SCHEMA_REPORT, 'intent': intent, 'receipt': receipt,
        'status': status, 'a5_physical_start_accredited': False,
        'a5_case_binding_independently_attested': False,
        'a6_classification': 'ND', 'a6_technical_truth_accredited': False,
        'a7_confirmed_rf': None, 'a9_published_generation': None,
        'p8_operational': 'NO-GO', 'operational_dispatch': False,
        'support_sha256': sha(support),
    }
    need(len(canonical(doc)) < MAX_REPORT - 200, 'REPORT_TOO_LARGE')
    doc['sha256'] = digest(doc)
    return doc


def verify_candidate(doc: dict[str, Any], support: bytes) -> bool:
    need(type(doc) is dict and set(doc) == REPORT_FIELDS and _hex(doc.get('sha256')),
         'REPORT_SCHEMA')
    expected = build_candidate(doc['intent'], doc['receipt'], support)
    need(canonical(expected) == canonical(doc), 'REPORT_SEMANTICS_OR_DIGEST_DRIFT')
    return True


def _private_root(root: Path) -> Path:
    need(isinstance(root, Path) and root.is_absolute() and root.is_dir() and
         not root.is_symlink() and not any(p.is_symlink() for p in root.parents),
         'PRIVATE_ROOT_INVALID')
    s = root.stat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid() and
         (stat.S_IMODE(s.st_mode) & 0o777) == 0o700 and
         (stat.S_IMODE(s.st_mode) & 0o4000) == 0,
         'PRIVATE_ROOT_MODE_OR_OWNER')
    return root


def _read_private(path: Path, limit: int) -> bytes:
    need(not path.is_symlink() and path.is_file(), 'PRIVATE_FILE_MISSING_OR_SYMLINK')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and
             s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600 and
             0 < s.st_size <= limit, 'PRIVATE_FILE_MODE_SIZE_OR_OWNER')
        before = (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        raw = b''
        while len(raw) < s.st_size + 1:
            chunk = os.read(fd, min(65536, s.st_size + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
        aft = os.fstat(fd)
        now = (aft.st_dev, aft.st_ino, aft.st_size, aft.st_mtime_ns, aft.st_ctime_ns)
        need(len(raw) == s.st_size and now == before,
             'PRIVATE_FILE_CHANGED_DURING_READ')
        return raw
    finally:
        os.close(fd)


def _store_once(path: Path, raw: bytes, maximum: int) -> str:
    need(0 < len(raw) <= maximum and not path.is_symlink(), 'WRITE_INPUT_INVALID')
    created = False
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
    except FileExistsError:
        pass
    else:
        created = True
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            # Failure before a complete, fsynced write must not leave a trusted file.
            try:
                path.unlink()
            except OSError:
                pass
            raise
    need(_read_private(path, maximum) == raw, 'PERSISTED_BYTES_CONFLICT')
    return 'CREATED' if created else 'REPLAY_IDENTICAL'


def persist_candidate(root: Path, intent: dict[str, Any],
                      receipt: dict[str, Any], support: bytes) -> dict[str, Any]:
    """Persist private content-addressed support FIRST, candidate report SECOND."""
    _private_root(root)
    doc = build_candidate(intent, receipt, support)
    support_name = 'r59d-support-' + sha(support) + '.bin'
    report_name = 'r59d-a5-' + doc['sha256'] + '.json'
    # For NO_START, there is no support artifact to store or falsely count.
    support_action = 'NONE_NO_START'
    if support:
        support_action = _store_once(root / support_name, support, MAX_SUPPORT)
    action = _store_once(root / report_name, canonical(doc)+b'\n', MAX_REPORT)
    directory_fd = os.open(root, os.O_RDONLY | getattr(os,'O_DIRECTORY',0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    verify_stored_candidate(root, doc['sha256'])
    return {'status': action, 'support_status': support_action,
            'report_sha256': doc['sha256'], 'report_path': str(root/report_name),
            'a6_classification': 'ND', 'p8_operational': 'NO-GO'}


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out = {}
    for k, v in pairs:
        need(k not in out, 'DUPLICATE_JSON_KEY')
        out[k] = v
    return out


def verify_stored_candidate(root: Path, report_sha256: str) -> dict[str, Any]:
    _private_root(root)
    need(_hex(report_sha256), 'REPORT_DIGEST_INVALID')
    raw = _read_private(root/('r59d-a5-'+report_sha256+'.json'), MAX_REPORT)
    try:
        doc = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise IntakeError('REPORT_JSON_INVALID') from exc
    need(type(doc) is dict and doc.get('sha256') == report_sha256 and
         raw == canonical(doc)+b'\n', 'REPORT_FILE_OR_DIGEST_MISMATCH')
    rec = doc.get('receipt')
    need(type(rec) is dict and type(rec.get('support_bytes')) is int,
         'REPORT_RECEIPT_INVALID')
    if rec['support_bytes'] == 0:
        support = b''
    else:
        need(_hex(rec.get('support_sha256')), 'RECEIPT_SUPPORT_DIGEST_INVALID')
        support = _read_private(root/('r59d-support-'+rec['support_sha256']+'.bin'),
                                MAX_SUPPORT)
    verify_candidate(doc, support)
    return doc
