"""R58-G: independently pinned, offline documentary trust registry.

An external digest pins this registry independently of untrusted witness bundles.
Registration, organisational separation and signatures DO NOT attest physical
independence, technical truth, experimental acceptance or execution authority.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Any

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.evidence.r58f_signed_witness import SERVICES, ROLES

SCHEMA = 'ardrec-r58g-a6-trust-registry-v1'
MAX_REGISTRY_BYTES = 65536
MAX_UNITS = 54
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
IDENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}\Z', re.ASCII)
UTC = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z', re.ASCII)
REGISTRY_FIELDS = frozenset({'schema', 'campaign_id', 'session_id', 'review_status',
                              'window_start_utc', 'window_end_utc', 'scope', 'authorities'})
SCOPE_FIELDS = frozenset({'service_id', 'case_id', 'assessment_index',
                          'configuration_sha256', 'method_id'})
AUTH_FIELDS = frozenset({'role', 'key_id', 'owner_id', 'organization_id',
                         'public_key_pem', 'enrolled_at_utc', 'valid_from_utc',
                         'valid_until_utc', 'revoked_at_utc'})


class RegistryError(ValueError):
    """Fail-closed, stable registry policy error."""


def need(condition: bool, code: str) -> None:
    if not condition:
        raise RegistryError(code)


def utc(value: Any) -> datetime:
    need(type(value) is str and UTC.fullmatch(value) is not None, 'REGISTRY_TIME_FORMAT')
    try:
        result = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise RegistryError('REGISTRY_TIME_INVALID') from exc
    need(result.strftime('%Y-%m-%dT%H:%M:%SZ') == value, 'REGISTRY_TIME_NONCANONICAL')
    return result


def identifier(value: Any) -> bool:
    return type(value) is str and IDENT.fullmatch(value) is not None


def hex256(value: Any) -> bool:
    return type(value) is str and HEX.fullmatch(value) is not None


def registry_digest(registry: dict[str, Any]) -> str:
    need(type(registry) is dict, 'REGISTRY_NOT_OBJECT')
    try:
        encoded = canonical(registry)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise RegistryError('REGISTRY_SERIALIZATION') from exc
    need(len(encoded) <= MAX_REGISTRY_BYTES, 'REGISTRY_TOO_LARGE')
    return hashlib.sha256(encoded).hexdigest()


def validate_registry(registry: dict[str, Any], *, pinned_sha256: str) -> dict[str, Any]:
    """Validate only an *externally supplied* SHA-256 pin, never one in evidence."""
    need(hex256(pinned_sha256), 'REGISTRY_PIN_INVALID')
    need(registry_digest(registry) == pinned_sha256, 'REGISTRY_PIN_MISMATCH')
    need(set(registry) == REGISTRY_FIELDS and registry['schema'] == SCHEMA,
         'REGISTRY_SCHEMA')
    need(registry['review_status'] == 'DOCUMENTARY_ONLY_NO_TECHNICAL_AUTHORITY',
         'REGISTRY_MUST_BE_NON_OPERATIONAL')
    need(identifier(registry['campaign_id']) and identifier(registry['session_id']),
         'CAMPAIGN_IDENTITY')
    start, end = utc(registry['window_start_utc']), utc(registry['window_end_utc'])
    need(start < end, 'CAMPAIGN_WINDOW_INVALID')
    scopes = registry['scope']
    need(type(scopes) is list and 0 < len(scopes) <= MAX_UNITS, 'CAMPAIGN_SCOPE_COUNT')
    known: set[tuple[str, str, int]] = set()
    for row in scopes:
        need(type(row) is dict and set(row) == SCOPE_FIELDS, 'CAMPAIGN_SCOPE_SCHEMA')
        service, case, idx = row['service_id'], row['case_id'], row['assessment_index']
        need(type(service) is str and service in SERVICES and identifier(case), 'CAMPAIGN_SCOPE_ID')
        need(type(idx) is int and 0 <= idx < 2**31, 'CAMPAIGN_WINDOW_INDEX')
        need(row['method_id'] == SERVICES[service] and hex256(row['configuration_sha256']),
             'CAMPAIGN_CONFIG_METHOD')
        key = (service, case, idx)
        need(key not in known, 'CAMPAIGN_DUPLICATE_UNIT')
        known.add(key)
    need(scopes == sorted(scopes, key=lambda row: (
        row['service_id'], row['case_id'], row['assessment_index'])),
        'CAMPAIGN_SCOPE_NOT_CANONICAL')
    authority = registry['authorities']
    need(type(authority) is list and len(authority) == 2, 'REGISTRY_TWO_ROLES_REQUIRED')
    need([entry.get('role') if type(entry) is dict else None for entry in authority]
         == list(ROLES), 'REGISTRY_ROLE_ORDER')
    ids: set[str] = set()
    owners: set[str] = set()
    organizations: set[str] = set()
    keyhashes: set[str] = set()
    for entry in authority:
        need(type(entry) is dict and set(entry) == AUTH_FIELDS, 'REGISTRY_AUTHORITY_SCHEMA')
        for field in ('key_id', 'owner_id', 'organization_id'):
            need(identifier(entry[field]), 'REGISTRY_AUTHORITY_ID')
        kid, owner, org = entry['key_id'], entry['owner_id'], entry['organization_id']
        need(kid not in ids and owner not in owners and org not in organizations,
             'REGISTRY_ROLE_SEPARATION')
        ids.add(kid); owners.add(owner); organizations.add(org)
        pem = entry['public_key_pem']
        need(type(pem) is str and 80 <= len(pem) <= 1024 and pem.isascii() and
             pem.startswith('-----BEGIN PUBLIC KEY-----\n') and
             pem.endswith('-----END PUBLIC KEY-----\n'), 'REGISTRY_PEM_FORMAT')
        # Fingerprint canonical SubjectPublicKeyInfo bytes, NOT PEM text.
        # Different line-wrapping of the same Ed25519 key cannot represent
        # two distinct registered roles.
        der_fingerprint = _ed25519_public_key(pem)
        need(der_fingerprint not in keyhashes, 'REGISTRY_PUBLIC_KEY_DUPLICATE')
        keyhashes.add(der_fingerprint)
        enrolled = utc(entry['enrolled_at_utc'])
        begin = utc(entry['valid_from_utc'])
        until = utc(entry['valid_until_utc'])
        need(enrolled <= begin < until, 'REGISTRY_KEY_LIFETIME')
        revoked = entry['revoked_at_utc']
        if revoked is not None:
            need(utc(revoked) >= enrolled, 'REGISTRY_REVOCATION_BEFORE_ENROLLMENT')
    return registry


def trusted_for_capture(registry: dict[str, Any], *, pinned_sha256: str,
                        captured_at_utc: str, review_at_utc: str) -> dict[str, Any]:
    """Authorize a key for a *documentary review*, not an execution or A6 truth."""
    validate_registry(registry, pinned_sha256=pinned_sha256)
    capture, review = utc(captured_at_utc), utc(review_at_utc)
    need(utc(registry['window_start_utc']) <= capture <= review <=
         utc(registry['window_end_utc']), 'CAMPAIGN_CAPTURE_WINDOW')
    trust: dict[str, Any] = {}
    for entry in registry['authorities']:
        begin, until = utc(entry['valid_from_utc']), utc(entry['valid_until_utc'])
        need(begin <= capture <= review <= until, 'SIGNER_NOT_VALID_AT_CAPTURE_AND_REVIEW')
        revoked = entry['revoked_at_utc']
        need(revoked is None or utc(revoked) > review, 'SIGNER_REVOKED_BY_REVIEW')
        trust[entry['role']] = {
            'key_id': entry['key_id'], 'public_key_pem': entry['public_key_pem'].encode('ascii')}
    return trust



def _ed25519_public_key(pem: str) -> str:
    """Return canonical DER SPKI fingerprint of a genuine Ed25519 public key."""
    openssl = '/usr/bin/openssl'
    need(Path(openssl).is_file(), 'REGISTRY_OPENSSL_MISSING')
    with tempfile.TemporaryDirectory(prefix='ardrec-r58g-keycheck-') as folder:
        path = Path(folder) / 'enrolled-public.pem'
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(pem.encode('ascii'))
        try:
            check = subprocess.run(
                [openssl, 'pkey', '-pubin', '-in', str(path), '-text_pub', '-noout'],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=5, check=False, env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            der = subprocess.run(
                [openssl, 'pkey', '-pubin', '-in', str(path), '-pubout', '-outform', 'DER'],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=5, check=False, env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RegistryError('REGISTRY_KEY_VERIFIER_UNAVAILABLE') from exc
    need(check.returncode == 0 and check.stdout.startswith(b'ED25519 Public-Key:') and
         der.returncode == 0 and len(der.stdout) == 44,
         'REGISTRY_ED25519_KEY_REQUIRED')
    return hashlib.sha256(der.stdout).hexdigest()


def _no_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for name, value in pairs:
        need(name not in result, 'REGISTRY_DUPLICATE_JSON_KEY')
        result[name] = value
    return result


def read_pinned_registry(path: Path, *, pinned_sha256: str) -> dict[str, Any]:
    """Read an external JSON registry; no symlink, no path inside the Git checkout."""
    need(isinstance(path, Path) and path.is_absolute() and not path.is_symlink(),
         'REGISTRY_PATH_INVALID')
    repo = Path(__file__).resolve().parents[3]
    resolved = path.resolve()
    need(resolved != repo and repo not in resolved.parents, 'REGISTRY_CANNOT_BE_IN_GIT')
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as handle:
            fd = None
            info = os.fstat(handle.fileno())
            need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_REGISTRY_BYTES + 1,
                 'REGISTRY_FILE_NOT_REGULAR')
            raw = handle.read(MAX_REGISTRY_BYTES + 2)
        need(len(raw) == info.st_size, 'REGISTRY_FILE_CHANGED')
        registry = json.loads(raw, object_pairs_hook=_no_duplicate_json_keys)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, RegistryError):
            raise
        raise RegistryError('REGISTRY_READ_OR_JSON_INVALID') from exc
    finally:
        if fd is not None:
            os.close(fd)
    need(raw == canonical(registry) + b'\n', 'REGISTRY_FILE_NOT_CANONICAL')
    validate_registry(registry, pinned_sha256=pinned_sha256)
    return registry
