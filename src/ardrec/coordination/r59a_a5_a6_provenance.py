"""R59-A: conciliación SOLO LECTURA de fuentes A5 y observación SSH R58-Y.

Verifica por separado el SQLite físico R58-Y/R58-Z y el diario P9/P12
benigno (si se solicita). El esquema P9 NO contiene identidad de caso,
por tanto nunca acredita vínculo A5→A6, verdad técnica, Rf ni A9.
No ejecuta procesos, intentos, VM, red ni despacho P8.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import json
import os
import re
import stat
from typing import Any

from ardrec.coordination import r58z_verified_workspace as z
from ardrec.coordination import r58m_durable_a5_audit as m

SCHEMA = 'ardrec-p14-r59a-a5-a6-verified-source-reconciliation-v1'
MODE = 'VERIFIED_READONLY_SOURCE_RECONCILIATION_NO_CASE_JOIN'
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
REQUEST_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z', re.ASCII)
MAX_REPORT_BYTES = 100_000
EXACT_FIELDS = frozenset({
    'schema','mode','r58z_snapshot_sha256','r58y_record_ids',
    'r58m_local_benign_a5','a5_reconciliation','a6_reconciliation',
    'a5_operational_starts','a6_accredited_conditions','a6_classification',
    'confirmed_final_risk','published_generation','p8_operational',
    'operational_dispatch','source_linkage_accredited','technical_truth_accredited',
    'sha256',
})


class ReconciliationError(ValueError):
    """No se pueden afirmar relaciones A5–A6 sin identidad de caso."""


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise ReconciliationError(reason)


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def _validated_benign_audit(audit: dict[str, Any]) -> dict[str, Any]:
    """Normaliza datos DEV ya verificados por el auditor P9/P12 R58-M."""
    need(type(audit) is dict and audit.get('schema') == m.SCHEMA and
         audit.get('source') == 'P9_P12_EXISTING_SQLITE_READ_ONLY' and
         audit.get('p8_operational') == 'NO-GO' and
         audit.get('operational_dispatch') is False and
         audit.get('local_receipt_chain_self_consistent') is True and
         audit.get('case_identity_stored_in_journal') is False and
         audit.get('independent_origin_attested') is False and
         audit.get('ordinary_retry_allowed') is False,
         'P9_AUDIT_AUTHORITY_INVALID')
    need(type(audit.get('request_id')) is str and
         REQUEST_ID.fullmatch(audit['request_id']) is not None and
         all(type(audit.get(k)) is str and HEX.fullmatch(audit[k]) is not None
             for k in ('journal_file_sha256','request_fingerprint','event_head_sha256')),
         'P9_AUDIT_DIGEST_OR_ID_INVALID')
    need(audit.get('journal_state') in m.STATES and
         type(audit.get('local_fixture_start_intent_count')) is int and
         0 <= audit['local_fixture_start_intent_count'] <= 1 and
         type(audit.get('event_count')) is int and
         1 <= audit['event_count'] <= m.MAX_EVENTS,
         'P9_AUDIT_LIFECYCLE_INVALID')
    need(audit.get('local_fixture_name') in m.ALLOWED_FIXTURES,
         'P9_NOT_BENIGN')
    expected_artifacts = audit['journal_state'] == 'RECORDED_LIMITED'
    need(audit.get('recorded_artifacts_integrity_checked') is expected_artifacts and
         (audit.get('result_outcome') in m.OUTCOMES if expected_artifacts
          else audit.get('result_outcome') is None),
         'P9_RESULT_NOT_VERIFIED')
    return {
        'source': 'VERIFIED_P9_P12_LOCAL_BENIGN_ONLY',
        'request_id': audit['request_id'],
        'journal_file_sha256': audit['journal_file_sha256'],
        'request_fingerprint': audit['request_fingerprint'],
        'event_head_sha256': audit['event_head_sha256'],
        'state': audit['journal_state'],
        'local_fixture_start_intent_count': audit['local_fixture_start_intent_count'],
        'event_count': audit['event_count'],
        'result_outcome': audit['result_outcome'],
        'case_identity_stored_in_journal': False,
        'source_independently_attested': False,
        'valid_only_for_benign_local_fixture': True,
    }


def _read_sources(db: Path, *, journal_root: Path | None,
                  request_id: str | None) -> tuple[dict[str, Any], dict[str, Any] | None]:
    need(isinstance(db, Path) and db.is_absolute(), 'DB_ABSOLUTE_PATH_REQUIRED')
    need((journal_root is None) == (request_id is None),
         'P9_ROOT_AND_REQUEST_ID_REQUIRED_TOGETHER')
    workspace = z.from_database(db)  # Revalida recibos físicos R42.2 y R42.3.
    z.verify_workspace(workspace)
    audit = None
    if journal_root is not None:
        need(isinstance(journal_root, Path) and journal_root.is_absolute(),
             'P9_ROOT_ABSOLUTE_PATH_REQUIRED')
        need(type(request_id) is str and REQUEST_ID.fullmatch(request_id) is not None,
             'P9_REQUEST_ID_INVALID')
        audit = _validated_benign_audit(m.audit_benign_journal(journal_root, request_id))
    return workspace, audit


def _expected_rows(workspace: dict[str, Any]) -> list[dict[str, Any]]:
    z.verify_workspace(workspace)
    need(workspace['source_type'] == 'VERIFIED_HISTORICAL_R58Y_SQLITE' and
         workspace['a5_operational_starts'] == 0 and
         workspace['a6_accredited_conditions'] == 0,
         'SOURCE_WORKSPACE_UNEXPECTED')
    rows = []
    for group in workspace['services']:
        for observation in group['observations']:
            need(observation['a5_attempt_id'] is None and
                 observation['a6_classification'] == 'ND',
                 'R58Y_HISTORICAL_HAS_FALSE_A5_OR_A6')
            rows.append({'observation_id': observation['record_id'],
                         'service': group['service'],
                         'a5_binding': 'NO_ATTEMPT_ID_IN_HISTORICAL_SOURCE',
                         'a6_decision': 'ND_UNBOUND_NO_DECLARED_CONDITION',
                         'source_kind': observation['origin']})
    return sorted(rows, key=lambda row: row['observation_id'])


def _report(workspace: dict[str, Any], audit: dict[str, Any] | None) -> dict[str, Any]:
    rows = _expected_rows(workspace)
    if audit is not None:
        audit = _validated_normalized(audit)
    reasons = ['R58Y_HISTORICAL_SNAPSHOT_HAS_NO_A5_ATTEMPT_ID',
               'R58Y_HISTORICAL_SNAPSHOT_HAS_NO_DECLARED_CONDITION_BINDING']
    if audit is not None:
        reasons += ['P9_BENIGN_JOURNAL_HAS_NO_CASE_IDENTITY',
                    'INDEPENDENT_PHYSICAL_PROVENANCE_NOT_ATTESTED']
    doc = {
        'schema': SCHEMA,
        'mode': MODE,
        'r58z_snapshot_sha256': workspace['sha256'],
        'r58y_record_ids': [row['observation_id'] for row in rows],
        'r58m_local_benign_a5': audit,
        'a5_reconciliation': {
            'observations_checked': rows,
            'local_benign_a5_audited': audit is not None,
            'operational_attempt_started': False,
            'case_join': 'NOT_ACREDITED',
            'reasons': reasons,
        },
        'a6_reconciliation': {
            'status': 'ND',
            'admitted_evidence_count': 0,
            'matched_declared_conditions': 0,
            'next_requirement': 'INDEPENDENTLY_ATTESTED_A5_CASE_AND_SUPPORTS',
        },
        'a5_operational_starts': 0,
        'a6_accredited_conditions': 0,
        'a6_classification': 'ND',
        'confirmed_final_risk': None,
        'published_generation': None,
        'p8_operational': 'NO-GO',
        'operational_dispatch': False,
        'source_linkage_accredited': False,
        'technical_truth_accredited': False,
    }
    doc['sha256'] = digest(canonical(doc))
    return doc


def _validated_normalized(audit: dict[str, Any]) -> dict[str, Any]:
    """Valida forma canónica del resumen; no acepta material de autoridad nuevo."""
    keys = {'source','request_id','journal_file_sha256','request_fingerprint',
            'event_head_sha256','state','local_fixture_start_intent_count',
            'event_count','result_outcome','case_identity_stored_in_journal',
            'source_independently_attested','valid_only_for_benign_local_fixture'}
    need(type(audit) is dict and set(audit) == keys and
         audit.get('source') == 'VERIFIED_P9_P12_LOCAL_BENIGN_ONLY' and
         audit.get('case_identity_stored_in_journal') is False and
         audit.get('source_independently_attested') is False and
         audit.get('valid_only_for_benign_local_fixture') is True and
         type(audit.get('request_id')) is str and
         REQUEST_ID.fullmatch(audit['request_id']) is not None and
         all(type(audit.get(k)) is str and HEX.fullmatch(audit[k]) is not None
             for k in ('journal_file_sha256','request_fingerprint','event_head_sha256')) and
         audit.get('state') in m.STATES and
         type(audit.get('local_fixture_start_intent_count')) is int and
         0 <= audit['local_fixture_start_intent_count'] <= 1 and
         type(audit.get('event_count')) is int and
         1 <= audit['event_count'] <= m.MAX_EVENTS and
         (audit.get('result_outcome') in m.OUTCOMES if audit['state'] == 'RECORDED_LIMITED'
          else audit.get('result_outcome') is None),
         'NORMALIZED_AUDIT_INVALID')
    return audit


def verify_report(doc: dict[str, Any]) -> bool:
    need(type(doc) is dict and set(doc) == EXACT_FIELDS and
         type(doc['sha256']) is str and HEX.fullmatch(doc['sha256']) is not None and
         digest(canonical({k: v for k, v in doc.items() if k != 'sha256'})) == doc['sha256'],
         'REPORT_DIGEST_OR_SCHEMA_INVALID')
    need(doc['schema'] == SCHEMA and doc['mode'] == MODE and
         doc['p8_operational'] == 'NO-GO' and doc['operational_dispatch'] is False and
         doc['source_linkage_accredited'] is False and
         doc['technical_truth_accredited'] is False and
         doc['a5_operational_starts'] == 0 and
         doc['a6_accredited_conditions'] == 0 and
         doc['a6_classification'] == 'ND' and
         doc['confirmed_final_risk'] is None and doc['published_generation'] is None and
         type(doc['r58z_snapshot_sha256']) is str and
         HEX.fullmatch(doc['r58z_snapshot_sha256']) is not None,
         'REPORT_FALSE_AUTHORITY')
    local = doc['r58m_local_benign_a5']
    if local is not None:
        _validated_normalized(local)
    rows = doc['a5_reconciliation']['observations_checked']
    need(type(rows) is list and len(rows) <= 128 and
         [row.get('observation_id') for row in rows if type(row) is dict] ==
         sorted(doc['r58y_record_ids']), 'REPORT_OBSERVATION_ORDER')
    need(len(rows) == len(set(doc['r58y_record_ids'])) and
         all(type(row) is dict and set(row) ==
             {'observation_id','service','a5_binding','a6_decision','source_kind'} and
             row['service'] == 'SSH' and
             re.fullmatch(r'OBS_SSH_[a-f0-9]{64}',row['observation_id']) is not None and
             row['a5_binding'] == 'NO_ATTEMPT_ID_IN_HISTORICAL_SOURCE' and
             row['a6_decision'] == 'ND_UNBOUND_NO_DECLARED_CONDITION' and
             row['source_kind'] == 'REAL_READONLY_SSH_SNAPSHOT'
             for row in rows), 'REPORT_OBSERVATION_INJECTION')
    # Reconstruye todas las afirmaciones derivadas, incluso si el hash fue recalculado.
    expected = _report_from_source_summary(doc['r58z_snapshot_sha256'], rows, local)
    need(canonical(doc) == canonical(expected), 'REPORT_SEMANTICS_CHANGED')
    return True


def _report_from_source_summary(workspace_sha: str, rows: list[dict[str, Any]],
                                audit: dict[str, Any] | None) -> dict[str, Any]:
    # Sólo se utiliza para semántica intrínseca; la fuente real se revalida aparte.
    # _expected_rows no debe ser eludida: construir según reglas propias,
    # pero sin acceder a R42.2/R42.3 durante la verificación sintáctica.
    reasons = ['R58Y_HISTORICAL_SNAPSHOT_HAS_NO_A5_ATTEMPT_ID',
               'R58Y_HISTORICAL_SNAPSHOT_HAS_NO_DECLARED_CONDITION_BINDING']
    if audit is not None:
        reasons += ['P9_BENIGN_JOURNAL_HAS_NO_CASE_IDENTITY',
                    'INDEPENDENT_PHYSICAL_PROVENANCE_NOT_ATTESTED']
    obj = {
        'schema': SCHEMA,'mode': MODE,'r58z_snapshot_sha256': workspace_sha,
        'r58y_record_ids': [r['observation_id'] for r in rows],
        'r58m_local_benign_a5': audit,
        'a5_reconciliation': {
            'observations_checked': rows,
            'local_benign_a5_audited': audit is not None,
            'operational_attempt_started': False,
            'case_join': 'NOT_ACREDITED',
            'reasons': reasons,
        },
        'a6_reconciliation': {
            'status': 'ND','admitted_evidence_count': 0,
            'matched_declared_conditions': 0,
            'next_requirement': 'INDEPENDENTLY_ATTESTED_A5_CASE_AND_SUPPORTS',
        },
        'a5_operational_starts': 0,'a6_accredited_conditions': 0,
        'a6_classification': 'ND','confirmed_final_risk': None,
        'published_generation': None,'p8_operational': 'NO-GO',
        'operational_dispatch': False,'source_linkage_accredited': False,
        'technical_truth_accredited': False,
    }
    obj['sha256'] = digest(canonical(obj))
    return obj


def build_report(db: Path, *, journal_root: Path | None = None,
                 request_id: str | None = None) -> dict[str, Any]:
    workspace, audit = _read_sources(db, journal_root=journal_root, request_id=request_id)
    report = _report(workspace, audit)
    verify_report(report)
    return report


def _private_directory(directory: Path) -> None:
    need(isinstance(directory, Path) and directory.is_absolute() and
         directory.is_dir() and not any(p.is_symlink() for p in
         (directory, *directory.parents)), 'PRIVATE_DIRECTORY_INVALID')
    st = directory.stat()
    need(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) & 0o077 == 0,
         'PRIVATE_DIRECTORY_PERMISSIONS')


def _path(directory: Path, doc: dict[str, Any]) -> Path:
    return directory / ('r59a-a5-a6-' + doc['sha256'] + '.json')


def save_report(directory: Path, doc: dict[str, Any]) -> tuple[str, Path]:
    verify_report(doc)
    _private_directory(directory)
    raw = canonical(doc) + b'\n'
    need(len(raw) <= MAX_REPORT_BYTES, 'REPORT_TOO_LARGE')
    path = _path(directory, doc)
    if path.exists() or path.is_symlink():
        need(read_report(path) == doc, 'REPORT_CONFLICT_EXISTING')
        return 'REPLAY_IDENTICAL', path
    try:
        fd = os.open(path, os.O_EXCL | os.O_CREAT | os.O_WRONLY | getattr(os,'O_NOFOLLOW',0), 0o600)
    except FileExistsError:
        need(read_report(path) == doc, 'REPORT_CONFLICT_RACE')
        return 'REPLAY_IDENTICAL', path
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    dirfd = os.open(directory, os.O_RDONLY | getattr(os,'O_DIRECTORY',0))
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)
    need(read_report(path) == doc, 'REPORT_READBACK_INVALID')
    return 'CREATED_READONLY_RECONCILIATION', path


def read_report(path: Path) -> dict[str, Any]:
    need(isinstance(path, Path) and path.is_absolute() and
         not any(p.is_symlink() for p in (path, *path.parents)) and
         path.is_file(), 'REPORT_PATH_INVALID')
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
         info.st_nlink == 1 and stat.S_IMODE(info.st_mode) & 0o077 == 0 and
         0 < info.st_size <= MAX_REPORT_BYTES, 'REPORT_FILE_UNSAFE')
    raw = path.read_bytes()
    need(len(raw) == info.st_size and raw.endswith(b'\n'), 'REPORT_CHANGED_OR_FORMAT')
    try:
        doc = json.loads(raw, object_pairs_hook=_unique_keys)
    except ReconciliationError:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ReconciliationError('REPORT_JSON_INVALID') from exc
    verify_report(doc)
    need(raw == canonical(doc) + b'\n' and path.name == _path(path.parent, doc).name,
         'REPORT_NONCANONICAL_FILE')
    return doc


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for name, value in pairs:
        need(name not in result, 'DUPLICATE_JSON_KEY')
        result[name] = value
    return result


def verify_saved(path: Path, db: Path, *, journal_root: Path | None = None,
                 request_id: str | None = None) -> dict[str, Any]:
    saved = read_report(path)
    current = build_report(db, journal_root=journal_root, request_id=request_id)
    need(saved == current, 'SOURCE_CHANGED_SINCE_RECONCILIATION')
    return current


def format_text(doc: dict[str, Any]) -> str:
    verify_report(doc)
    local = doc['r58m_local_benign_a5']
    lines = [
        'ARDREC R59-A / CONCILIACION REAL DE FUENTES A5-A6 / SOLO LECTURA',
        'R58Z_SHA256: ' + doc['r58z_snapshot_sha256'],
        'OBSERVACIONES R58-Y: ' + str(len(doc['r58y_record_ids'])),
        'AUDITORIA P9/P12 BENIGNA: ' + ('SI' if local else 'NO'),
        'A5 OPERACIONAL: SIN INICIO ACREDITADO',
        'A5 VINCULO A CASO: NO ACREDITADO',
        'A6: ND / SIN EVIDENCIA TECNICA ACREDITADA',
        'Rf: NO CONFIRMADO  A9: NO PUBLICADA  P8: NO-GO',
    ]
    if local is not None:
        lines.extend([
            'P9 REQUEST_ID: ' + local['request_id'],
            'P9 ESTADO: ' + local['state'],
            'P9 INICIOS DE INTENCION BENIGNA: ' +
                str(local['local_fixture_start_intent_count']),
            'P9 EVENT_HEAD: ' + local['event_head_sha256'],
            'P9 NO GUARDA IDENTIDAD DE CASO DE SERVICIO',
        ])
    for row in doc['a5_reconciliation']['observations_checked']:
        lines.extend(['OBSERVACION ' + row['observation_id'],
                      '  SERVICIO: ' + row['service'],
                      '  A5: ' + row['a5_binding'],
                      '  A6: ' + row['a6_decision']])
    lines += ['CAUSAS:'] + ['  - ' + s for s in doc['a5_reconciliation']['reasons']]
    lines += ['HUELLA_RECONCILIACION: ' + doc['sha256']]
    return '\n'.join(lines)
