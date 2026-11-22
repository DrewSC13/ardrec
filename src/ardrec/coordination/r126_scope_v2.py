"""R126-Scope V2: source-current signed FTP-T01 documentary review.

Replaces neither historical F6 approvals nor their pins.  Dedicated,
independently provisioned root trust and a fresh revocation are required.
This module cannot authorize boot, network access, A6, A9 or P8.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat
from typing import Callable

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r115_f6_signed_scope_and_activation as f6
from ardrec.coordination import r115_f15_p7_independent_pilot as f15

SCHEMA = 'ARDREC-R126-FTP-T01-CURRENT-SOURCE-SCOPE-v2'
TRUST = Path('/etc/ardrec/r126-ftp-t01-scope-trust-v2.json')
REVOCATION = Path('/etc/ardrec/r126-ftp-t01-scope-revocation-v2.json')
TRUST_PATHS = (TRUST, REVOCATION)
MAX_AGE_SECONDS = 30
MAX_POLICY_BYTES = 8192

class Stop(ValueError):
    """Deterministic failure. Never a root authorization."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise Stop(code)


def _root_file(path: Path) -> bytes:
    """Accept only fixed root-owned files. No caller-provided trust files."""
    need(path in TRUST_PATHS, 'ROOT_PATH_NOT_ALLOWLISTED')
    for parent in (Path('/'), Path('/etc'), Path('/etc/ardrec')):
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and
             not (st.st_mode & 0o022), 'ROOT_PARENT_UNTRUSTED')
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
         not (st.st_mode & 0o077) and 0 < st.st_size <= MAX_POLICY_BYTES,
         'ROOT_FILE_UNTRUSTED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        pre = os.fstat(fd)
        need((pre.st_dev, pre.st_ino, pre.st_size, pre.st_uid, pre.st_nlink) ==
             (st.st_dev, st.st_ino, st.st_size, st.st_uid, st.st_nlink),
             'ROOT_FILE_RACE')
        data = os.read(fd, MAX_POLICY_BYTES + 1)
        post = os.fstat(fd)
        need(len(data) == st.st_size and
             (post.st_dev, post.st_ino, post.st_size, post.st_uid, post.st_nlink,
              post.st_mtime_ns) ==
             (pre.st_dev, pre.st_ino, pre.st_size, pre.st_uid, pre.st_nlink,
              pre.st_mtime_ns), 'ROOT_FILE_CHANGED')
        return data
    finally:
        os.close(fd)


def _strict(raw: bytes) -> dict:
    doc = f1.load(raw)
    need(raw == f1.canonical(doc), 'NON_CANONICAL_SIGNED_DOCUMENT')
    return doc


def _now(now: datetime) -> datetime:
    need(type(now) is datetime and now.tzinfo is not None and
         now.utcoffset() is not None and now.microsecond == 0,
         'CURRENT_CLOCK_REQUIRED')
    return now.astimezone(timezone.utc)


def review_scope(*, contract_raw: bytes, authorization_raw: bytes,
                 catalog_raw: bytes, expected_head: str, now: datetime,
                 root_loader: Callable[[Path], bytes] = _root_file) -> tuple[str, str, str | None]:
    """Check a current signed scope, never a network or boot permit.

    The injected loader exists solely for hermetic test cases. Real runtime
    uses `_root_file` through `for_head` and cannot supply trust via CLI.
    """
    at = _now(now)
    need(type(expected_head) is str and f1.GIT_SHA.fullmatch(expected_head),
         'EXPECTED_SOURCE_HEAD_INVALID')
    need(type(contract_raw) is bytes and type(authorization_raw) is bytes and
         type(catalog_raw) is bytes and callable(root_loader), 'SCOPE_INPUTS_INVALID')
    try:
        contract = _strict(contract_raw)
        authorization = _strict(authorization_raw)
        f1.validate(contract, f1.load(catalog_raw), catalog_raw)
    except (f1.Rejected, ValueError, KeyError, TypeError) as exc:
        raise Stop('SCOPE_CONTRACT_INVALID') from exc
    need(contract['source_commit'] == expected_head, 'SOURCE_COMMIT_MISMATCH')
    need(contract['source_commit'] != f6.BASE, 'LEGACY_F6_BASE_NOT_ACCEPTED')
    # Do not treat local candidate presence or historical R117 approval as trust.
    need(TRUST != f6.TRUST and REVOCATION != f6.REVOCATION,
         'LEGACY_AUTHORITY_REUSE')
    try:
        trust = _strict(root_loader(TRUST))
        revoked = _strict(root_loader(REVOCATION))
        f3.trust_check(trust)
        # Revocation is never accepted by file name or unsigned attributes.
        result = f3.auth_review(contract, authorization, revoked, trust,
                                now=at.isoformat())
    except FileNotFoundError:
        return ('ND', 'INDEPENDENT_V2_TRUST_OR_REVOCATION_NOT_PROVISIONED', None)
    except PermissionError:
        return ('ND', 'INDEPENDENT_V2_ROOT_TRUST_INACCESSIBLE', None)
    except (OSError, ValueError, TypeError, KeyError, f1.Rejected,
            f3.Stop, Stop) as exc:
        return ('FALSO', 'INDEPENDENT_V2_SIGNATURE_OR_TRUST_REJECTED_' +
                type(exc).__name__, None)
    need(type(result) is dict and type(result.get('crypto_verified')) is bool and
         result['crypto_verified'] is True and
         type(result.get('authorization_sha256')) is str and
         f1.SHA.fullmatch(result['authorization_sha256']),
         'CRYPTO_RESULT_INVALID')
    auth_sha = f1.digest(f1.canonical(authorization))
    need(result['authorization_sha256'] == auth_sha, 'AUTH_DIGEST_CHANGED')
    if result['status'] == 'FALSO':
        return ('FALSO', 'INDEPENDENT_V2_SIGNED_REVOCATION', auth_sha)
    if result['status'] != 'ND' or result.get('reason') != 'CRYPTO_VALID_BUT_HOST_AUTHORITY_NOT_PINNED':
        return ('ND', 'INDEPENDENT_V2_SCOPE_NOT_CURRENT', auth_sha)
    statement = revoked['statement']
    issued = f1._instant(statement['issued_at'], 'REVOCATION_ISSUED')
    rev_until = f1._instant(statement['valid_until'], 'REVOCATION_EXPIRES')
    start = f1._instant(contract['valid_from'], 'CONTRACT_START')
    until = f1._instant(contract['valid_until'], 'CONTRACT_EXPIRES')
    age = (at - issued).total_seconds()
    if not (0 <= age <= MAX_AGE_SECONDS and issued <= at < rev_until and
            start <= at < until and rev_until > issued):
        return ('ND', 'INDEPENDENT_V2_SCOPE_OR_REVOCATION_STALE', auth_sha)
    return ('VERDADERO', 'SIGNED_V2_ROOT_SCOPE_DOCUMENT_ONLY_NOT_P8', auth_sha)


def for_head(expected_head: str):
    """Freeze the actual expected commit in F15's reviewer callback."""
    need(type(expected_head) is str and f1.GIT_SHA.fullmatch(expected_head),
         'EXPECTED_HEAD_INVALID')
    def reviewer(contract_raw: bytes, authorization_raw: bytes,
                 *, catalog_raw: bytes, now: datetime):
        return review_scope(contract_raw=contract_raw,
                            authorization_raw=authorization_raw,
                            catalog_raw=catalog_raw, expected_head=expected_head,
                            now=now)
    return reviewer


def verify_signer_separation(scope_trust: dict, pilot_trust: dict) -> bool:
    """Pure role separation check; root ownership is checked by the live caller."""
    try:
        f3.trust_check(scope_trust)
        f15.trust_check(pilot_trust)
        names=(scope_trust['scope_signer'],scope_trust['revocation_signer'],
               pilot_trust['pilot_signer'],pilot_trust['revocation_signer'])
        keys=[f1.digest(x['public_key_pem'].encode('ascii')) for x in names]
        ids=[x['key_id'] for x in names]
    except (KeyError,TypeError,AttributeError,UnicodeError,f3.Stop,f15.Stop) as exc:
        raise Stop('AUTHORITY_SIGNER_SCHEMA_INVALID') from exc
    need(len(set(keys))==4 and len(set(ids))==4,
         'SCOPE_AND_PILOT_SIGNERS_NOT_INDEPENDENT')
    return True


def root_role_separation() -> bool:
    """Read both pinned root-owned trust documents, never a user-supplied key."""
    return verify_signer_separation(_strict(_root_file(TRUST)),
                                    _strict(f15._root_read(f15.TRUST)))


def enrollment_plan(*, expected_head: str) -> dict:
    """Unsigned requirements for an external independent operator, not keys."""
    need(type(expected_head) is str and f1.GIT_SHA.fullmatch(expected_head),
         'EXPECTED_HEAD_INVALID')
    return {'schema':SCHEMA+'-enrollment-plan', 'source_commit':expected_head,
            'source_commit_must_be_final_signed_candidate':True,
            'scope_trust_path':str(TRUST),
            'scope_revocation_path':str(REVOCATION),
            'additional_independent_root_policies':{
                'pilot_trust':str(f15.TRUST),
                'pilot_revocation':str(f15.REVOCATION),
                'boot_trust':'/etc/ardrec/r115-boot-trust-v1.json',
                'boot_revocation':'/etc/ardrec/r115-boot-revocation-v1.json',
                'traffic_trust':'/etc/ardrec/r115-p8-trust-v1.json',
                'traffic_revocation':'/etc/ardrec/r115-p8-revocation-v1.json',
                'physical_witness_trust':'/etc/ardrec/r127-root-closure-witness-v1.json'},
            'root_directory':'/etc/ardrec',
            'root_policy_mode':'0600',
            'distinct_scope_and_revocation_signers':True,
            'pilot_signer_must_be_independent_of_scope_signer':True,
            'legacy_r117_approval_is_not_operational_authority':True,
            'legacy_f6_v1_trust_must_not_be_reused':True,
            'signature_issued_here':False,'private_keys_generated_here':False,
            'root_install_performed_here':False,
            'network_traffic_authorized':False,'guest_boot_authorized':False,
            'a6':'ND','a9':None,'p8':'NO-GO'}
