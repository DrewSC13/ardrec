"""R118: vínculo criptográfico fuente/candidato/main, exclusivamente SOURCE_ONLY.

No reemplaza admisión A3, arranque, P8, autorización de red ni revocación
operacional. No modifica la instalación F5B V3 ni acepta aprobaciones antiguas.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Callable, Mapping

from ardrec.coordination import r117_f4_root_release as crypto

SCHEMA = 'ARDREC-R118-POSTMERGE-SOURCE-LINEAGE-v1'
REVOKE_SCHEMA = 'ARDREC-R118-POSTMERGE-SOURCE-REVOCATION-v1'
REPORT_SCHEMA = 'ARDREC-R118-POSTMERGE-SOURCE-REPORT-v1'
PREFIX = b'ARDREC-R118-POSTMERGE-SOURCE-LINEAGE-v1\x00'
REVOCATION_PREFIX = b'ARDREC-R118-POSTMERGE-SOURCE-REVOCATION-v1\x00'
CLOSURE_SCHEMA = 'ARDREC-R117-F5B-PHYSICAL-CLOSURE-v3'
CLOSURE_PIN = '63629945aa1164973b0687318997be464c1c35be0f39c903a7dcf4a7c6381b74'
HEX = re.compile(r'[0-9a-f]{64}\Z')
GIT = re.compile(r'[0-9a-f]{40}\Z')
STAMP = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z')
SOURCES = (
    'src/ardrec/coordination/r117_f4_controlled_boot.py',
    'src/ardrec/coordination/r117_f4_root_release.py',
    'src/ardrec/coordination/r117_f4_runner_ftp_boot.py',
    'src/ardrec/coordination/r115_f14_a5_a6_handoff.py',
    'src/ardrec/coordination/r118_postmerge_gate.py',
)
STATEMENT = {
    'schema', 'candidate_head', 'candidate_sha256', 'integrated_head',
    'source_sha256', 'issued_at', 'valid_until', 'scope', 'p8',
    'boot_authorized', 'network_authorized',
}
REVOCATION = {
    'schema', 'lineage_sha256', 'integrated_head', 'issued_at',
    'valid_until', 'revoked', 'p8',
}
CLOSURE = {
    'schema','observed_at_utc','clock_source','closure_scope',
    'candidate_head','candidate_sha256','installed_files_verified',
    'journal_phases','pending_activations','approval_sha256',
    'approval_signature_sha256','revocation_sha256',
    'revocation_signature_sha256','release_receipt_sha256',
    'activation_sha256','authorization_ledger_sha256',
    'transaction','transaction_complete_sha256',
    'historical_signature_verification','current_nonrevocation_status',
    'operational_validation','boot_authorized','network_authorized','p8',
}


class Stop(ValueError):
    """Rechazo con código estable (sin efectos sobre el anfitrión)."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise Stop(code)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pairs(pairs):
    doc = {}
    for key, value in pairs:
        need(key not in doc, 'DUPLICATE_JSON_FIELD')
        doc[key] = value
    return doc


def strict(raw: bytes, *, limit: int = 16384,
           canonical_required: bool = True) -> dict:
    need(type(raw) is bytes and 0 < len(raw) <= limit, 'JSON_SIZE')
    try:
        doc = json.loads(raw, object_pairs_hook=_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(Stop('NONFINITE_JSON')))
        need(type(doc) is dict, 'JSON_OBJECT_REQUIRED')
        encoded = (json.dumps(doc, sort_keys=True, ensure_ascii=True,
                              separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')
        if canonical_required:
            need(encoded == raw, 'NONCANONICAL_JSON')
        return doc
    except (ValueError, UnicodeError, OverflowError, TypeError) as exc:
        if isinstance(exc, Stop):
            raise
        raise Stop('INVALID_JSON') from exc


def canonical(doc: dict) -> bytes:
    need(type(doc) is dict, 'CANONICAL_OBJECT_REQUIRED')
    try:
        return (json.dumps(doc, sort_keys=True, ensure_ascii=True,
                           separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')
    except (ValueError, TypeError, OverflowError) as exc:
        raise Stop('INVALID_CANONICAL_DATA') from exc


def utc(value: str) -> datetime:
    need(type(value) is str and STAMP.fullmatch(value) is not None,
         'TIMESTAMP_FORMAT')
    try:
        result = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError as exc:
        raise Stop('TIMESTAMP_INVALID') from exc
    return result.replace(tzinfo=timezone.utc)


def window(doc: dict, now: datetime, max_seconds: int) -> None:
    need(isinstance(now, datetime) and now.tzinfo is not None,
         'CLOCK_UNTRUSTED')
    a, b = utc(doc['issued_at']), utc(doc['valid_until'])
    need(a <= now.astimezone(timezone.utc) < b and
         0 < (b-a).total_seconds() <= max_seconds, 'FRESHNESS_REQUIRED')


def closure_status(raw: bytes) -> dict:
    """Valida solo el documento versionado, NO verifica de nuevo el host."""
    need(sha(raw) == CLOSURE_PIN, 'CLOSURE_DIGEST_CHANGED')
    c = strict(raw, canonical_required=False)
    need(set(c) == CLOSURE and c['schema'] == CLOSURE_SCHEMA,
         'CLOSURE_SCHEMA_OR_FIELDS')
    need(c['closure_scope'] == 'F5B_SOURCE_ONLY' and c['p8'] == 'NO-GO' and
         c['boot_authorized'] is False and c['network_authorized'] is False and
         c['operational_validation'] == 'PENDING' and
         c['current_nonrevocation_status'] == 'NOT_ASSESSED' and
         c['installed_files_verified'] == 39 and c['pending_activations'] == 0 and
         c['historical_signature_verification'] == 'PASS_DURING_ORIGINAL_INSTALLATION' and
         type(c['journal_phases']) is list and c['journal_phases'] == [
             'PREPARED','PILOT_PUBLISHED','RELEASE_PUBLISHED',
             'COMPLETION_DURABLE','ACTIVATION_PUBLISHED'],
         'CLOSURE_INVARIANTS')
    need(type(c['candidate_head']) is str and GIT.fullmatch(c['candidate_head']) is not None and
         type(c['candidate_sha256']) is str and HEX.fullmatch(c['candidate_sha256']) is not None,
         'CANDIDATE_ID')
    return c


def signed_doc(raw: bytes, *, schema: str, expected_keys: set[str]) -> tuple[dict, bytes]:
    d = strict(raw)
    need(set(d) == {'statement','signature_b64'}, 'SIGNED_ENVELOPE_FIELDS')
    s = d['statement']
    need(type(s) is dict and set(s) == expected_keys and s.get('schema') == schema,
         'SIGNED_STATEMENT_FIELDS')
    encoded = d['signature_b64']
    need(type(encoded) is str and 80 <= len(encoded) <= 96, 'SIGNATURE_ENCODING')
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Stop('SIGNATURE_ENCODING') from exc
    need(len(signature) == 64, 'SIGNATURE_LENGTH')
    return s, signature


def verify_lineage(closure_raw: bytes, integrated_head: str,
                   source_bytes: Mapping[str, bytes], approval_raw: bytes,
                   revocation_raw: bytes, *, approval_public: bytes,
                   revocation_public: bytes, now: datetime,
                   verifier: Callable[[bytes, bytes, bytes], None] = crypto._ed25519_verify) -> dict:
    """Admite únicamente linaje de fuente; no retorna nunca permiso de boot/red.

    Las claves públicas deben proceder de la autoridad instalada con anclaje y
    lectura protegida independientes; este método puro NO autentica su origen.
    """
    closure = closure_status(closure_raw)
    need(type(integrated_head) is str and GIT.fullmatch(integrated_head) is not None,
         'INTEGRATED_HEAD')
    need(type(source_bytes) is dict and set(source_bytes) == set(SOURCES),
         'SOURCE_SET')
    for path, raw in source_bytes.items():
        need(type(raw) is bytes and 0 < len(raw) <= 262144, 'SOURCE_BYTES_'+path)
    approval, signature = signed_doc(approval_raw, schema=SCHEMA, expected_keys=STATEMENT)
    need(approval['candidate_head'] == closure['candidate_head'] and
         approval['candidate_sha256'] == closure['candidate_sha256'] and
         approval['integrated_head'] == integrated_head and
         approval['scope'] == 'SOURCE_CONTINUITY_ONLY' and
         approval['p8'] == 'NO-GO' and approval['boot_authorized'] is False and
         approval['network_authorized'] is False,
         'LINEAGE_SCOPE')
    expected = {path: sha(raw) for path, raw in source_bytes.items()}
    need(type(approval['source_sha256']) is dict and
         approval['source_sha256'] == expected, 'SOURCE_MISMATCH')
    window(approval, now, 600)
    need(type(approval_public) is bytes and type(revocation_public) is bytes and
         0 < len(approval_public) <= 4096 and 0 < len(revocation_public) <= 4096 and
         sha(approval_public) != sha(revocation_public), 'TRUST_IDENTITIES_NOT_DISTINCT')
    # La verificación puede fallar: siempre con rechazo, nunca fallback no firmado.
    try:
        verifier(approval_public, signature, PREFIX + canonical(approval))
    except (Exception,) as exc:
        raise Stop('LINEAGE_SIGNATURE_INVALID') from exc
    rev, rev_sig = signed_doc(revocation_raw, schema=REVOKE_SCHEMA,
                              expected_keys=REVOCATION)
    need(rev['lineage_sha256'] == sha(approval_raw) and
         rev['integrated_head'] == integrated_head and
         rev['revoked'] is False and rev['p8'] == 'NO-GO',
         'LINEAGE_REVOKED_OR_MISMATCH')
    window(rev, now, 90)
    try:
        verifier(revocation_public, rev_sig,
                 REVOCATION_PREFIX + canonical(rev))
    except (Exception,) as exc:
        raise Stop('REVOCATION_SIGNATURE_INVALID') from exc
    return {
        'schema': REPORT_SCHEMA,
        'integrated_head': integrated_head,
        'candidate_head': closure['candidate_head'],
        'candidate_sha256': closure['candidate_sha256'],
        'closure_sha256': sha(closure_raw),
        'lineage_sha256': sha(approval_raw),
        'revocation_sha256': sha(revocation_raw),
        'source_sha256': expected,
        'source_continuity_verified': True,
        'host_installation_currently_verified': False,
        'runtime_started': False,
        'p8': 'NO-GO',
        'boot_authorized': False,
        'network_authorized': False,
        'operational_validation': 'PENDING',
    }
