"""R129-B11: independently attested FTP-T01 control-connectivity admission.

A copied B9 JSON is NEVER physical origin. Only root-owned B9 reads, a live
R127 root-anchored crash witness, independently pinned Ed25519 technical/source
reviewers and a fresh signed revocation can produce a narrow A6 condition.

A6 here means control *connectivity* only (FTP-T01). It does not establish
vulnerability, authentication, files, calibration, A7 Rf, A8 or A9. No VM,
socket, nft or DurableStore write exists in this module. Root-trust creation,
key management and provision are deliberately outside its scope.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r127_closure_witness as r127
from ardrec.coordination import r129_b9_receipt_gate as b10

SCHEMA = 'ARDREC-R129-B11-INDEPENDENT-FTP-T01-A6-v1'
TRUST_SCHEMA = SCHEMA+'-root-trust'
SOURCE_SCHEMA = SCHEMA+'-root-source-attestation'
TECH_SCHEMA = SCHEMA+'-technical-adjudication'
REV_SCHEMA = SCHEMA+'-revocation'
SOURCE_PREFIX = (SOURCE_SCHEMA+'\x00').encode('ascii')
TECH_PREFIX = (TECH_SCHEMA+'\x00').encode('ascii')
REV_PREFIX = (REV_SCHEMA+'\x00').encode('ascii')
TRUST = Path('/etc/ardrec/r129-a6-ftp-t01-trust-v1.json')
ROOT = Path('/var/lib/ardrec/r128-one-session-v2')
INSTALLED = Path('/var/lib/ardrec/r129-a6-ftp-t01-v1')
INSTALLED_CODE = INSTALLED/'root-admission.py'
INSTALLED_MANIFEST = INSTALLED/'manifest.json'
MAX_POLICY = 8192
MAX_RECEIPT = 16384
MAX_REVOCATION_AGE = 30
MAX_DECISION_SECONDS = 60
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)

class Stop(ValueError):
    """Stable fail-closed source, signature, or policy rejection."""


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise Stop(reason)


def sha(value: dict) -> str:
    return f1.digest(f1.canonical(value))


def exact(value: Any, fields: set[str], reason: str) -> dict:
    need(type(value) is dict and set(value)==fields,reason)
    return value


def utc(value: Any) -> datetime:
    try:
        out=f1._instant(value,'B11_TIME')
    except (TypeError, ValueError, f1.Rejected) as exc:
        raise Stop('INVALID_UTC_TIMESTAMP') from exc
    need(out.utcoffset() is not None,'INVALID_UTC_TIMESTAMP')
    return out.astimezone(timezone.utc)


def _private_root_directory(path: Path, *, exact_mode: bool=False) -> None:
    st=path.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and
         (st.st_mode & 0o022)==0 and not path.is_symlink(),
         'ROOT_DIRECTORY_UNTRUSTED')
    if exact_mode:
        need(stat.S_IMODE(st.st_mode)==0o700,'ROOT_DIRECTORY_NOT_PRIVATE')


def _root_bytes(path: Path, *, policy: bool=False) -> bytes:
    """No symlink, no writable ancestor, root uid + exact file mode + fstat."""
    need(isinstance(path,Path) and path.is_absolute(),'ROOT_PATH_INVALID')
    parents=(Path('/'),Path('/etc'),Path('/etc/ardrec')) if policy else (
        Path('/'),Path('/var'),Path('/var/lib'),Path('/var/lib/ardrec'),
        INSTALLED if path.parent==INSTALLED else ROOT)
    permitted=(path in (INSTALLED_CODE,INSTALLED_MANIFEST,ROOT/'f13-handoff.json') or
         (path.parent.parent==ROOT and path.parent.name.startswith('pilot-') and
          b10.SESSION.fullmatch(path.parent.name[6:]) is not None and
          path.name in ('intent.json','receipt.json','guest-result.json','guest-qga.json')))
    need(path==TRUST if policy else permitted,
         'ROOT_PATH_NOT_ALLOWLISTED')
    for parent in parents:
        _private_root_directory(parent,exact_mode=parent in (ROOT,INSTALLED) and not policy)
    if not policy and path.parent not in (ROOT,INSTALLED):
        _private_root_directory(path.parent,exact_mode=True)
    st=path.lstat()
    limit=MAX_POLICY if policy else MAX_RECEIPT
    need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
         stat.S_IMODE(st.st_mode)==0o600 and 0<st.st_size<=limit,
         'ROOT_RECEIPT_UNTRUSTED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need((before.st_dev,before.st_ino,before.st_uid,before.st_size,
              before.st_nlink,before.st_mtime_ns)==
             (st.st_dev,st.st_ino,st.st_uid,st.st_size,st.st_nlink,st.st_mtime_ns),
             'ROOT_RECEIPT_RACE')
        data=os.read(fd,limit+1)
        after=os.fstat(fd)
        need(len(data)==st.st_size and
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)==
             (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns),
             'ROOT_RECEIPT_CHANGED')
        return data
    finally:
        os.close(fd)


def _root_sources(session: str) -> tuple[dict,dict,dict,dict,dict]:
    """Read the actual fixed root B9 folder; copied JSON is not sufficient."""
    need(type(session) is str and b10.SESSION.fullmatch(session),
         'SESSION_INVALID')
    folder=ROOT/('pilot-'+session)
    handoff_raw=_root_bytes(ROOT/'f13-handoff.json')
    handoff=f1.load(handoff_raw)
    need(type(handoff) is dict and
         handoff_raw in (f1.canonical(handoff),f1.canonical(handoff)+b'\n'),
         'ROOT_F13_HANDOFF_NOT_CANONICAL')
    documents=[handoff]
    for name in ('intent.json','receipt.json','guest-result.json','guest-qga.json'):
        raw=_root_bytes(folder/name)
        value=f1.load(raw)
        # Both B9 and historical F3 write canonical JSON plus a final LF;
        # the QGA raw response also comes from a system tool and may vary.
        need(type(value) is dict,'ROOT_RECEIPT_NOT_JSON_OBJECT')
        if name!='guest-qga.json':
            need(raw in (f1.canonical(value),f1.canonical(value)+b'\n'),
                 'ROOT_RECEIPT_NOT_CANONICAL')
        documents.append(value)
    return tuple(documents)


def _trusted_install(head: str) -> None:
    """Reject root execution from mutable Git trees, even by sudo.

    Operator independently installs the exact signed final candidate into the
    fixed root-owned directory; B11 cannot perform that installation.
    """
    need(type(head) is str and f1.GIT_SHA.fullmatch(head),
         'APPROVED_HEAD_INVALID')
    need(Path(__file__).resolve()==INSTALLED_CODE,
         'INDEPENDENT_A6_ROOT_INSTALL_REQUIRED')
    data=_root_bytes(INSTALLED_MANIFEST)
    doc=f1.load(data)
    exact(doc,{'schema','approved_head','source_sha256',
               'independent_root_install','p8'},'A6_ROOT_MANIFEST_FIELDS')
    need(doc['schema']==SCHEMA+'-root-install' and
         doc['approved_head']==head and
         doc['independent_root_install'] is True and
         doc['p8']=='NO-GO' and
         doc['source_sha256']==hashlib.sha256(_root_bytes(INSTALLED_CODE)).hexdigest(),
         'A6_ROOT_CODE_OR_HEAD_NOT_APPROVED')


def trust_check(trust: dict) -> tuple[dict,dict,dict]:
    exact(trust,{'schema','source_signer','technical_signer','revocation_signer'},
          'A6_TRUST_FIELDS')
    need(trust['schema']==TRUST_SCHEMA,'A6_TRUST_SCHEMA')
    keys=[]
    for k in ('source_signer','technical_signer','revocation_signer'):
        item=exact(trust[k],{'key_id','public_key_pem'},'A6_SIGNER_FIELDS')
        need(type(item['key_id']) is str and f1.ID.fullmatch(item['key_id']) and
             type(item['public_key_pem']) is str,'A6_SIGNER_INVALID')
        try: raw=item['public_key_pem'].encode('ascii')
        except UnicodeError as exc: raise Stop('A6_SIGNER_NONASCII') from exc
        need(raw.startswith(b'-----BEGIN PUBLIC KEY-----\n') and
             raw.endswith(b'-----END PUBLIC KEY-----\n') and len(raw)<=1024,
             'A6_PUBLIC_KEY_INVALID')
        keys.append((item['key_id'],hashlib.sha256(raw).hexdigest()))
    need(len({k[0] for k in keys})==3 and len({k[1] for k in keys})==3,
         'A6_SIGNERS_NOT_INDEPENDENT')
    return (trust['source_signer'],trust['technical_signer'],trust['revocation_signer'])


def signed_review(*, candidate: dict, source: dict, technical: dict,
                  revocation: dict, witness: dict, trust: dict, now: datetime) -> dict:
    """Pure cryptographic review; never claims root or physical authority."""
    need(type(now) is datetime and now.tzinfo is not None and
         now.utcoffset() is not None,'CLOCK_REQUIRED')
    now=now.astimezone(timezone.utc)
    need(type(candidate) is dict and candidate.get('schema')==b10.SCHEMA and
         candidate.get('sha256')==sha({k:v for k,v in candidate.items() if k!='sha256'}) and
         candidate.get('p8')=='NO-GO' and candidate.get('a6')=='ND' and
         candidate.get('root_receipt_status')=='FTP_GUEST_CANDIDATE_ONLY' and
         candidate.get('banner_is_complete_220') is True and
         candidate.get('guest_result_candidate_sha256') is not None and
         candidate.get('qga_candidate_sha256') is not None and
         candidate.get('independent_root_origin_verified') is False,
         'A5_CANDIDATE_NOT_POSITIVE_OR_UNTRUSTED')
    source_key, technical_key, revocation_key=trust_check(trust)
    exact(source,{'statement','signer_key_id','signature_b64'},'A6_SOURCE_WRAPPER')
    exact(technical,{'statement','signer_key_id','signature_b64'},'A6_TECH_WRAPPER')
    exact(revocation,{'statement','signer_key_id','signature_b64'},'A6_REV_WRAPPER')
    sw=exact(source['statement'],{'schema','head','session','case_id','family_id',
           'root_readback_method','b9_intent_sha256','b9_receipt_sha256',
           'guest_sha256','qga_sha256','r127_witness_sha256','observed_at'},
           'A6_SOURCE_FIELDS')
    need(sw['schema']==SOURCE_SCHEMA and sw['head']==candidate['head'] and
         sw['session']==candidate['session'] and sw['case_id']==candidate['case_id'] and
         sw['family_id']=='FTP-T01' and
         sw['root_readback_method']=='INDEPENDENT_ROOT_OWNED_B9_READBACK' and
         sw['b9_intent_sha256']==candidate['root_intent_candidate_sha256'] and
         sw['b9_receipt_sha256']==candidate['root_receipt_candidate_sha256'] and
         sw['guest_sha256']==candidate['guest_result_candidate_sha256'] and
         sw['qga_sha256']==candidate['qga_candidate_sha256'] and
         type(witness) is dict and type(witness.get('statement')) is dict and
         witness['statement'].get('schema')==r127.SCHEMA and
         sw['r127_witness_sha256']==sha(witness) and
         sw['r127_witness_sha256']!='0'*64,
         'A6_SOURCE_NOT_BOUND')
    when=utc(sw['observed_at'])
    need(0<=(now-when).total_seconds()<=MAX_DECISION_SECONDS,
         'A6_SOURCE_STALE')
    tw=exact(technical['statement'],{'schema','head','session','case_id',
         'source_attestation_sha256','r127_witness_sha256','condition_id',
         'required_supports','decision','interpretation_boundary',
         'issued_at','valid_until'},'A6_TECH_FIELDS')
    need(tw['schema']==TECH_SCHEMA and tw['head']==candidate['head'] and
         tw['session']==candidate['session'] and tw['case_id']==candidate['case_id'] and
         tw['source_attestation_sha256']==sha(source) and
         tw['r127_witness_sha256']==sha(witness) and
         tw['condition_id']=='FTP-T01_CONTROL_CONNECTION' and
         tw['required_supports']==[
             'TARGET_ATTESTATION','INTEGRITY_PROVENANCE','CONTROL_CHANNEL_RESPONSE'] and
         tw['decision']=='CONTROL_CONNECTION_CONFIRMED' and
         tw['interpretation_boundary']=='NOT_AUTHENTICATION_NOT_FILE_ACCESS_NOT_VULNERABILITY',
         'A6_TECH_DECISION_NOT_FTP_T01')
    start,end=utc(tw['issued_at']),utc(tw['valid_until'])
    need(start<=now<end and start>=when and
         0<(end-start).total_seconds()<=MAX_DECISION_SECONDS,
         'A6_TECH_DECISION_EXPIRED')
    rw=exact(revocation['statement'],{'schema','source_attestation_sha256',
         'technical_verdict_sha256','issued_at','valid_until','revoked','reason_code'},
         'A6_REVOCATION_FIELDS')
    need(rw['schema']==REV_SCHEMA and
         rw['source_attestation_sha256']==sha(source) and
         rw['technical_verdict_sha256']==sha(technical) and
         type(rw['revoked']) is bool and
         type(rw['reason_code']) is str and f1.ID.fullmatch(rw['reason_code']),
         'A6_REVOCATION_NOT_BOUND')
    rstart,rend=utc(rw['issued_at']),utc(rw['valid_until'])
    need(rstart<=now<rend and 0<=(now-rstart).total_seconds()<=MAX_REVOCATION_AGE and
         rend>rstart and rw['revoked'] is False,
         'A6_REVOKED_OR_REVOCATION_STALE')
    try:
        f3.verified_signature(source,sw,source_key,SOURCE_PREFIX)
        f3.verified_signature(technical,tw,technical_key,TECH_PREFIX)
        f3.verified_signature(revocation,rw,revocation_key,REV_PREFIX)
    except (f3.Stop, ValueError, KeyError, TypeError) as exc:
        raise Stop('A6_INDEPENDENT_SIGNATURE_REJECTED') from exc
    return {'schema':SCHEMA+'-documentary-review',
            'source_sha256':sha(source),'technical_sha256':sha(technical),
            'revocation_sha256':sha(revocation),'witness_sha256':sha(witness),
            'candidate_sha256':candidate['sha256'],
            'signatures_verified':True,'source_root_owned_replayed':False,
            'root_r127_physically_verified':False,
            'scope':'FTP_T01_CONTROL_CONNECTIVITY_ONLY',
            'a6':'ND','confirmed_rf':None,'a8':None,'a9':None,'p8':'NO-GO'}


def admit_live(*, candidate:dict, source:dict, technical:dict,
               revocation:dict, witness:dict, pre:dict, post:dict,
               now:datetime) -> dict:
    """Root-only verification of independently staged B9 and R127 original bytes.

    F13's private disk journal belongs to the unprivileged user.  It must be
    replayed by B10 *before* this root call; root MUST NOT change ownership or
    bypass F13's protected owner requirement. B9's independently approved
    root-sealed F13 handoff binds the pre-replayed candidate to this source.

    No caller-selected root directory or trust loader exists here. This API is
    for a separately reviewed and root-installed operational admission service,
    never for invocation from the mutable checkout.
    """
    need(os.geteuid()==0,'INDEPENDENT_ROOT_A6_REVIEW_REQUIRED')
    _trusted_install(candidate.get('head') if type(candidate) is dict else None)
    signed=signed_review(candidate=candidate,source=source,technical=technical,
                         revocation=revocation,witness=witness,
                         trust=f1.load(_root_bytes(TRUST,policy=True)),now=now)
    handoff,intent,receipt,guest,qga=_root_sources(candidate['session'])
    need(sha(handoff)==candidate['f13_handoff_sha256'] and
         handoff.get('head')==candidate['head'] and
         handoff.get('session')==candidate['session'] and
         handoff.get('case_id')==candidate['case_id'] and
         sha(intent)==candidate['root_intent_candidate_sha256'] and
         sha(receipt)==candidate['root_receipt_candidate_sha256'] and
         sha(guest)==candidate['guest_result_candidate_sha256'] and
         sha(qga)==candidate['qga_candidate_sha256'] and
         intent.get('boot_id')==witness['statement'].get('boot_id') and
         intent.get('f13_handoff_sha256')==candidate['f13_handoff_sha256'],
         'ROOT_B9_BYTES_AND_EXPORTED_EVIDENCE_DIVERGE')
    # Recompute the actual guest/QGA source semantics from ROOT-owned bytes.
    # This is independent of the user's pre-replayed B10 JSON and signatures.
    result=b10.guest_review(guest,qga,case_id=candidate['case_id'])
    need(result['guest_sha256']==receipt.get('guest_result_sha256') and
         result['guest_sha256']==candidate['guest_result_candidate_sha256'] and
         result['qga_sha256']==candidate['qga_candidate_sha256'] and
         result['banner_is_complete_220'] is True and
         guest.get('tcp')=='CONNECTED' and guest.get('response')=='RECEIVED' and
         receipt.get('result')=='FTP_GUEST_CANDIDATE_ONLY' and
         receipt.get('session')==candidate['session'] and
         receipt.get('head')==candidate['head'] and
         receipt.get('case_id')==candidate['case_id'] and
         receipt.get('denies_restored_and_verified') is True and
         receipt.get('timer_armed') is True and
         receipt.get('traffic_window_opened') is True and
         receipt.get('error') is None and
         type(receipt.get('elapsed_monotonic_ns')) is int and
         0<=receipt['elapsed_monotonic_ns']<=60_000_000_000 and
         receipt.get('a6')=='ND' and receipt.get('a9') is None and
         receipt.get('p8')=='NO-GO',
         'ROOT_GUEST_SEMANTICS_NOT_FTP_T01')
    anchored=r127.verify_root_anchored(envelope=witness,pre=pre,post=post,now=now)
    need(type(anchored) is dict and
         anchored.get('external_root_trust_anchored') is True and
         anchored.get('physical_closure_claim_accepted') is True and
         anchored.get('crash_test_executed') is True and
         anchored.get('max_60s_met') is True and
         anchored.get('head')==candidate['head'] and
         anchored.get('session')==candidate['session'] and
         anchored.get('case_id')==candidate['case_id'] and
         anchored.get('signed_witness_sha256')==sha(witness),
         'ROOT_R127_WITNESS_NOT_ACCEPTED')
    out={'schema':SCHEMA+'-physical-admission',
         'head':candidate['head'],'session':candidate['session'],
         'case_id':candidate['case_id'],'family_id':'FTP-T01',
         'a5_sha256':candidate['sha256'],
         'independent_source_attestation_sha256':signed['source_sha256'],
         'independent_technical_verdict_sha256':signed['technical_sha256'],
         'independent_current_revocation_sha256':signed['revocation_sha256'],
         'independent_root_witness_sha256':signed['witness_sha256'],
         'root_b9_original_bytes_replayed':True,
         'root_r127_crash_restoration_verified':True,
         'technical_condition':'FTP_T01_CONTROL_CONNECTION_CONFIRMED',
         'interpretation':'NO_AUTHENTICATION_NO_FILE_ACCESS_NO_VULNERABILITY',
         'a6':'VERDADERO','a6_scope':'FTP_T01_CONTROL_CONNECTIVITY_ONLY',
         'a7_rf_confirmed':None,'a8_transition_applied':None,
         'a9_generation':None,'durable_store_opened':False,'p8':'NO-GO'}
    out['sha256']=sha(out)
    return out


def capabilities() -> dict:
    return {'schema':SCHEMA+'-capabilities',
            'b9_live_root_owned_sources_required':True,
            'r127_root_anchored_crash_test_required':True,
            'three_new_independent_ed25519_signers_required':True,
            'root_pinned_trust_path':str(TRUST),
            'independently_staged_exact_root_code_required':True,
            'fresh_revocation_max_age_seconds':MAX_REVOCATION_AGE,
            'technical_scope':'FTP_T01_CONTROL_CONNECTIVITY_ONLY',
            'automatic_vulnerability_claim':False,
            'a6_without_real_root_and_witness':'ND',
            'rf_without_calibration':None,
            'a8_transition_applied':False,
            'a9_global_generation_written':False,
            'network_connections':0,'vm_starts':0,'nft_writes':0,
            'p8':'NO-GO'}
