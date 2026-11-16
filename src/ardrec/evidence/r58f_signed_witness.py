"""R58-F: dual-signature Ed25519 witness intake, offline and source-only.

Cryptographic attribution DOES NOT certify measurement truth, signer
independence, host isolation or permission to transition/publish risk.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any

from ardrec.analytics.exact_preview import canonical, digest

SCHEMA = 'ardrec-r58f-a6-signed-witness-statement-v1'
REPORT = 'ardrec-r58f-a6-signed-witness-review-v1'
PREFIX = b'ARDREC-R58F-A6-SIGNED-WITNESS-V1\x00'
ROLES = ('observer', 'reviewer')
SERVICES = {
    'SSH_DEV': 'SSH_EFFECTIVE_CONFIG_READONLY',
    'FTP_DEV': 'FTP_EFFECTIVE_CONFIG_READONLY',
    'SMB_DEV': 'SMB_EFFECTIVE_CONFIG_READONLY',
}
FIELDS = frozenset({'schema','record_id','session_id','service_id','case_id',
                    'assessment_index','configuration_sha256','captured_at_utc',
                    'method_id','observed_claim','support_sha256','support_bytes'})
HEX = re.compile(r'[a-f0-9]{64}\Z', re.ASCII)
IDENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}\Z', re.ASCII)
UTC = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z', re.ASCII)
MAX_SUPPORT_BYTES = 1048576
MAX_AGE_SECONDS = 86400
OPENSSL = '/usr/bin/openssl'

class WitnessError(ValueError):
    pass

def need(ok: bool, reason: str) -> None:
    if not ok:
        raise WitnessError(reason)

def _utc(s: Any) -> datetime:
    need(type(s) is str and UTC.fullmatch(s) is not None, 'TIME_FORMAT')
    try:
        dt = datetime.strptime(s,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise WitnessError('TIME_INVALID') from exc
    need(dt.strftime('%Y-%m-%dT%H:%M:%SZ') == s, 'TIME_NOT_CANONICAL')
    return dt

def _sha_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def signing_bytes(statement: dict[str,Any]) -> bytes:
    need(type(statement) is dict and set(statement) == FIELDS, 'STATEMENT_FIELDS')
    need(statement['schema'] == SCHEMA, 'STATEMENT_SCHEMA')
    for name in ('record_id','session_id','case_id'):
        need(type(statement[name]) is str and IDENT.fullmatch(statement[name]) is not None,
             'STATEMENT_ID_'+name)
    sid=statement['service_id']
    need(type(sid) is str and sid in SERVICES, 'SERVICE_UNKNOWN')
    need(statement['method_id'] == SERVICES[sid], 'METHOD_SERVICE_MISMATCH')
    need(type(statement['observed_claim']) is str and
         statement['observed_claim'] in ('MATCH','DIFF','INCONCLUSIVE'), 'CLAIM_UNKNOWN')
    need(type(statement['assessment_index']) is int and
         0 <= statement['assessment_index'] < 2**31, 'ASSESSMENT_INDEX')
    for name in ('configuration_sha256','support_sha256'):
        need(type(statement[name]) is str and HEX.fullmatch(statement[name]) is not None,
             'STATEMENT_SHA_'+name)
    need(type(statement['support_bytes']) is int and
         0 < statement['support_bytes'] <= MAX_SUPPORT_BYTES, 'SUPPORT_SIZE')
    _utc(statement['captured_at_utc'])
    try:
        data = canonical(statement)
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise WitnessError('STATEMENT_CANONICAL_FAILED') from exc
    need(len(data) <= 8192, 'STATEMENT_OVERSIZED')
    return PREFIX + data

def _verify_signature(key: bytes, msg: bytes, signature: bytes) -> None:
    """OpenSSL subprocess with fixed argv, no shell, private temporary files."""
    need(type(key) is bytes and 80 <= len(key) <= 1024 and
         key.startswith(b'-----BEGIN PUBLIC KEY-----\n') and
         key.endswith(b'-----END PUBLIC KEY-----\n'), 'PUBLIC_KEY_FORMAT')
    need(type(signature) is bytes and len(signature) == 64, 'SIGNATURE_LENGTH')
    need(Path(OPENSSL).is_file(), 'OPENSSL_NOT_PRESENT')
    with tempfile.TemporaryDirectory(prefix='ardrec-r58f-') as folder:
        root=Path(folder)
        for fn,content in [('public.pem',key),('message.bin',msg),('signature.bin',signature)]:
            fd=os.open(root/fn,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as out: out.write(content)
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}
        try:
            info=subprocess.run([OPENSSL,'pkey','-pubin','-in',str(root/'public.pem'),
                                 '-text_pub','-noout'],
                                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,timeout=5,check=False,env=env)
            need(info.returncode == 0 and info.stdout.startswith(b'ED25519 Public-Key:'),
                 'ED25519_PUBLIC_KEY_REQUIRED')
            result=subprocess.run([OPENSSL,'pkeyutl','-verify','-pubin',
                                   '-inkey',str(root/'public.pem'),'-rawin',
                                   '-in',str(root/'message.bin'),'-sigfile',str(root/'signature.bin')],
                                  stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,timeout=5,check=False,env=env)
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise WitnessError('CRYPTO_VERIFIER_UNAVAILABLE') from exc
        need(result.returncode == 0, 'SIGNATURE_INVALID')

def _signature_data(signatures: dict[str,Any], trust: dict[str,Any], msg: bytes) -> list[dict[str, str]]:
    need(type(signatures) is dict and set(signatures) == set(ROLES), 'SIGNATURE_ROLES')
    need(type(trust) is dict and set(trust) == set(ROLES), 'TRUST_ROLES')
    names=set(); keys=set(); verified=[]
    for role in ROLES:
        entry,authority=signatures[role],trust[role]
        need(type(entry) is dict and set(entry) == {'key_id','signature_b64'}, 'SIGNATURE_SCHEMA')
        need(type(authority) is dict and set(authority) == {'key_id','public_key_pem'}, 'TRUST_SCHEMA')
        kid=entry['key_id']
        need(type(kid) is str and IDENT.fullmatch(kid) is not None and
             kid == authority['key_id'] and kid not in names, 'SIGNER_NOT_TRUSTED_OR_REUSED')
        names.add(kid)
        key=authority['public_key_pem']
        need(type(key) is bytes, 'TRUST_KEY_NOT_BYTES')
        keyhash=_sha_bytes(key)
        need(keyhash not in keys, 'PUBLIC_KEY_REUSED')
        keys.add(keyhash)
        sigb64=entry['signature_b64']
        need(type(sigb64) is str and 20 <= len(sigb64) <= 128, 'SIGNATURE_BASE64')
        try:
            sig=base64.b64decode(sigb64,validate=True)
        except (ValueError,base64.binascii.Error) as exc:
            raise WitnessError('SIGNATURE_BASE64') from exc
        need(base64.b64encode(sig).decode('ascii') == sigb64, 'SIGNATURE_NONCANONICAL')
        _verify_signature(key,msg,sig)
        verified.append({'role':role,'key_id':kid,
                         'public_key_sha256':keyhash,'signature_sha256':_sha_bytes(sig)})
    return verified

def admit_signed_witness(statement: dict[str,Any], signatures: dict[str,Any],
                         trust: dict[str,Any], support: bytes, *,
                         expected: dict[str,Any], as_of_utc: str) -> dict[str,Any]:
    """Verify signatures, support integrity and exact scope; NO technical accreditation."""
    msg=signing_bytes(statement)
    need(type(support) is bytes and 0 < len(support) <= MAX_SUPPORT_BYTES,
         'SUPPORT_BYTES_INVALID')
    need(len(support) == statement['support_bytes'] and
         _sha_bytes(support) == statement['support_sha256'], 'SUPPORT_DIGEST_OR_SIZE')
    need(type(expected) is dict and set(expected) ==
         {'session_id','service_id','case_id','assessment_index','configuration_sha256'},
         'EXPECTED_SCOPE_SCHEMA')
    for field in expected:
        need(type(expected[field]) is type(statement[field]) and
             expected[field] == statement[field], 'SCOPE_MISMATCH_'+field)
    captured=_utc(statement['captured_at_utc']); current=_utc(as_of_utc)
    delta=(current-captured).total_seconds()
    need(0 <= delta <= MAX_AGE_SECONDS, 'CAPTURE_OUTSIDE_REVIEW_WINDOW')
    roles=_signature_data(signatures,trust,msg)
    doc={
        'schema':REPORT,'decision':'SIGNED_WITNESS_STATEMENT_FOR_DOCUMENTARY_REVIEW',
        'source_kind':'TWO_SIGNED_DECLARATIONS_NO_PHYSICAL_TRUTH',
        'statement':statement,'statement_sha256':_sha_bytes(msg),
        'support_sha256_verified':_sha_bytes(support),
        'as_of_utc':as_of_utc,'roles':roles,
        'cryptographic_attribution_verified':True,
        'signer_independence_physically_attested':False,
        'technical_truth_accredited':False,'a6_classification':'ND',
        'evidence_contribution':None,'confirmed_rf':None,
        'applied_transition':None,'published_generation':None,
        'operational_dispatch':False,'p8':'NO-GO',
    }
    need(len(canonical(doc)) <= 32768, 'REPORT_OVERSIZED')
    doc['sha256']=digest(doc)
    return doc

def verify_signed_witness(report:dict[str,Any],signatures:dict[str,Any],
                          trust:dict[str,Any],support:bytes,*,
                          expected:dict[str,Any]) -> bool:
    need(type(report) is dict and type(report.get('sha256')) is str and
         HEX.fullmatch(report['sha256']) is not None,'REPORT_INVALID')
    source=admit_signed_witness(report.get('statement'),signatures,trust,support,
                                expected=expected,as_of_utc=report.get('as_of_utc'))
    need(canonical(source) == canonical(report),'REPORT_RECONSTRUCTION_MISMATCH')
    return True
