"""R127: cryptographically validate an INDEPENDENT physical closure receipt.

A signed testimonial is insufficient unless root-owned independent trust is
verified AND fresh root DENY is independently read. This component does NOT
create signatures, start timers, or inject failures into a live system.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import hashlib
import re
import time
import stat
from typing import Any

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r124_root_deny_readback as r124
from ardrec.coordination import r126_operational_controller as r126

SCHEMA = 'ARDREC-R127-FTP-T01-INDEPENDENT-ROOT-CLOSURE-v1'
PREFIX = b'ARDREC-R127-FTP-T01-ROOT-CLOSURE-v1\x00'
TRUST_PATH = Path('/etc/ardrec/r127-root-closure-witness-v1.json')
HASH = re.compile(r'[0-9a-f]{64}\Z')
SESSION = re.compile(r'[0-9a-f]{16}\Z')
FIELDS = {'schema','head','session','case_id','family_id','pre_readback_sha256',
          'post_readback_sha256','guard_sha256','boot_id','restoration_receipt_sha256',
          'arm_monotonic_ns','restore_monotonic_ns','verified_monotonic_ns',
          'target_seconds','maximum_seconds','crash_test_executed',
          'root_guard_recovered','post_deny_state','p8'}

class Stop(ValueError):
    """Fail-closed independent evidence rejection."""


def need(ok: bool, code: str) -> None:
    if not ok: raise Stop(code)


def _exact(obj: Any, keys: set, code: str) -> dict:
    need(type(obj) is dict and set(obj)==keys, code)
    return obj


def _trust_file(path: Path = TRUST_PATH) -> dict:
    """Accept only one root-owned path; no caller-selected trust on live host."""
    need(path == TRUST_PATH, 'UNTRUSTED_TRUST_PATH')
    for parent in (Path('/'),Path('/etc'),Path('/etc/ardrec')):
        st=parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and
             not(st.st_mode & 0o022), 'ROOT_TRUST_PARENT_INVALID')
    st=path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
         not(st.st_mode & 0o022) and 0<st.st_size<=8192,
         'ROOT_TRUST_FILE_INVALID')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        check=os.fstat(fd)
        need((check.st_dev,check.st_ino,check.st_size,check.st_uid)==
             (st.st_dev,st.st_ino,st.st_size,st.st_uid),
             'ROOT_TRUST_FILE_RACE')
        raw=os.read(fd,8193)
        need(len(raw)==st.st_size,'ROOT_TRUST_FILE_SHORT')
    finally:os.close(fd)
    return f1.load(raw)


def _trust_info(document: dict) -> dict:
    _exact(document,{'schema','witness_signer','scope_signer_key_id',
                     'revocation_signer_key_id'},'WITNESS_TRUST_FIELDS')
    need(document['schema']==SCHEMA+'-external-trust',
         'WITNESS_TRUST_SCHEMA')
    signer=_exact(document['witness_signer'],{'key_id','public_key_pem'},
                  'WITNESS_SIGNER_FIELDS')
    need(type(signer['key_id']) is str and f1.ID.fullmatch(signer['key_id']) and
         type(document['scope_signer_key_id']) is str and
         type(document['revocation_signer_key_id']) is str and
         len({signer['key_id'],document['scope_signer_key_id'],
              document['revocation_signer_key_id']})==3,
         'WITNESS_SIGNER_MUST_BE_INDEPENDENT')
    try:
        encoded=signer['public_key_pem'].encode('ascii')
    except (AttributeError,UnicodeError) as exc:
        raise Stop('WITNESS_PEM_INVALID') from exc
    need(encoded.startswith(b'-----BEGIN PUBLIC KEY-----\n') and
         encoded.endswith(b'-----END PUBLIC KEY-----\n') and
         len(encoded)<=1024,'WITNESS_PEM_INVALID')
    return signer


def validate(*, envelope: dict, pre: dict, post: dict,
             trust: dict, now: datetime) -> dict:
    """Check signature, chronology, source identity, post-DENY and freshness.

    Test-supplied `trust` is not host anchored. The output cannot claim
    physical verification unless `verify_root_anchored` opens the pinned file.
    """
    need(type(now) is datetime and now.tzinfo is not None and
         now.utcoffset() is not None, 'CLOCK_INVALID')
    signer=_trust_info(trust)
    _exact(envelope,{'statement','signer_key_id','signature_b64'},
           'WITNESS_ENVELOPE_FIELDS')
    stmt=_exact(envelope['statement'],FIELDS,'WITNESS_STATEMENT_FIELDS')
    need(stmt['schema']==SCHEMA and stmt['family_id']=='FTP-T01' and
         stmt['guard_sha256']==r124.PIN and stmt['p8']=='PILOT_ONLY' and
         type(stmt['head']) is str and r124.GIT.fullmatch(stmt['head']) and
         type(stmt['session']) is str and SESSION.fullmatch(stmt['session']) and
         type(stmt['case_id']) is str and 1<=len(stmt['case_id'])<=128 and
         type(stmt['boot_id']) is str and 1<=len(stmt['boot_id'])<=128,
         'WITNESS_IDENTITY_INVALID')
    for key in ('pre_readback_sha256','post_readback_sha256','restoration_receipt_sha256'):
        need(type(stmt[key]) is str and HASH.fullmatch(stmt[key]),
             'WITNESS_SOURCE_HASH')
    need(type(pre) is dict and type(post) is dict and
         pre.get('head')==post.get('head')==stmt['head'] and
         pre.get('sha256')==stmt['pre_readback_sha256'] and
         post.get('sha256')==stmt['post_readback_sha256'] and
         pre.get('schema')==post.get('schema')==r124.SCHEMA,
         'WITNESS_SOURCE_NOT_BOUND')
    # Source readbacks have their own SHA and establish post-hoc DENY, not P8.
    for item in (pre,post):
        need(item.get('root_guard_sha256')==r124.PIN and
             item.get('root_guard')=='PINNED_INSTALLED_DENY_CHECK_OK' and
             item.get('denied') is True and item.get('p8')=='NO-GO' and
             item.get('sha256')==r126.sha({k:v for k,v in item.items() if k!='sha256'}),
             'WITNESS_ROOT_READBACK_DRIFT')
    need(pre['host']['stage']=='FIVE_ONE_DENY_MATCH' and
         pre['host']['active_count']==5 and
         pre['session_marker_consumed'] is True and
         pre['session_timer_state']=='active' and
         post['host']['stage'] in ('OFFLINE_DENY_MATCH','FIVE_ONE_DENY_MATCH') and
         post['host']['active_count'] in (0,5) and
         stmt['post_deny_state']==post['host']['stage'],
         'WITNESS_PRE_POST_TOPOLOGY_INVALID')
    nums=('arm_monotonic_ns','restore_monotonic_ns','verified_monotonic_ns')
    need(all(type(stmt[k]) is int and 0<=stmt[k]<2**63 for k in nums) and
         stmt['arm_monotonic_ns'] < stmt['restore_monotonic_ns'] <=
         stmt['verified_monotonic_ns'], 'WITNESS_MONOTONIC_ORDER')
    elapsed_ns=stmt['verified_monotonic_ns']-stmt['arm_monotonic_ns']
    need(stmt['target_seconds']==45 and stmt['maximum_seconds']==60 and
         elapsed_ns<=60_000_000_000 and
         stmt['root_guard_recovered'] is True and
         stmt['crash_test_executed'] is True,
         'ROOT_CLOSURE_DEADLINE_OR_PROVENANCE')
    when=datetime.strptime(post['observed_at_utc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    age=(now.astimezone(timezone.utc)-when).total_seconds()
    need(-2<=age<=60,'POST_DENY_READBACK_NOT_FRESH')
    try:
        f3.verified_signature(envelope,stmt,signer,PREFIX)
    except (f3.Stop, ValueError, TypeError, KeyError) as exc:
        raise Stop('ROOT_WITNESS_SIGNATURE_REJECTED') from exc
    result={'schema':SCHEMA+'-verification',
            'head':stmt['head'],'session':stmt['session'],
            'case_id':stmt['case_id'],
            'signed_witness_sha256':r126.sha(envelope),
            'restoration_receipt_sha256':stmt['restoration_receipt_sha256'],
            'pre_readback_sha256':pre['sha256'],
            'post_readback_sha256':post['sha256'],
            'elapsed_ns':elapsed_ns,
            'target_45s_met':elapsed_ns<=45_000_000_000,
            'max_60s_met':True,'crash_test_executed':stmt['crash_test_executed'],
            'external_root_trust_anchored':False,
            'physical_closure_claim_accepted':False,
            'p8':'NO-GO','a6':'ND','a9':None,
            'dispatch':False}
    result['sha256']=r126.sha(result)
    return result


def verify_root_anchored(*, envelope: dict, pre: dict, post: dict,
                         now: datetime) -> dict:
    """Only live API: loads exactly the root-owned externally supplied key."""
    verified=validate(envelope=envelope,pre=pre,post=post,
                      trust=_trust_file(),now=now)
    # Cryptographic statement alone is never a physical restoration receipt.
    # R116 stores restore-<digest-prefix>.json and does NOT bind its basename
    # to the arm session, hence compare full bytes and post-DENY policy.
    target=envelope['statement']['restoration_receipt_sha256']
    root=Path('/var/lib/ardrec/r116-f1-five-one-deny-v1')
    st=root.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and
         not (st.st_mode & 0o077), 'ROOT_RECOVERY_DIRECTORY_NOT_TRUSTED')
    matches=0
    for path in root.iterdir():
        if re.fullmatch(r'restore-[0-9a-f]{16}\.json',path.name) is None:
            continue
        info=path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and
             info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600 and
             0<info.st_size<=8192,'ROOT_RECOVERY_RECEIPT_UNSAFE')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            opened=os.fstat(fd)
            need((opened.st_dev,opened.st_ino,opened.st_size,opened.st_uid)==
                 (info.st_dev,info.st_ino,info.st_size,info.st_uid),
                 'ROOT_RECOVERY_RECEIPT_RACE')
            raw=os.read(fd,8193)
            need(len(raw)==info.st_size,'ROOT_RECOVERY_RECEIPT_TRUNCATED')
            again=os.fstat(fd)
            need((again.st_dev,again.st_ino,again.st_size,again.st_mtime_ns)==
                 (opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns),
                 'ROOT_RECOVERY_RECEIPT_CHANGED')
        finally:os.close(fd)
        full_hash=hashlib.sha256(raw).hexdigest()
        need(path.name=='restore-'+full_hash[:16]+'.json',
             'ROOT_RECOVERY_RECEIPT_FILENAME_DRIFT')
        if full_hash!=target:
            continue
        receipt=f1.load(raw)
        need(raw==f1.canonical(receipt) and
             receipt.get('status')=='DENY_RESTORED' and
             receipt.get('traffic_allowed') is False and
             receipt.get('p8')=='NO-GO' and
             receipt.get('states')==post['host']['states'],
             'ROOT_RECOVERY_RECEIPT_CONTENT_INVALID')
        matches+=1
    need(matches==1,'ROOT_RECOVERY_RECEIPT_MISSING_OR_AMBIGUOUS')
    current_boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(current_boot==envelope['statement']['boot_id'],
         'ROOT_WITNESS_BOOT_CHANGED')
    age_ns=time.monotonic_ns()-envelope['statement']['verified_monotonic_ns']
    need(0<=age_ns<=60_000_000_000,'ROOT_WITNESS_MONOTONIC_STALE')
    verified['external_root_trust_anchored']=True
    verified['physical_closure_claim_accepted']=True
    verified['sha256']=r126.sha({k:v for k,v in verified.items() if k!='sha256'})
    return verified


def capabilities() -> dict:
    return {'schema':SCHEMA+'-capabilities',
            'external_ed25519_root_witness_required':True,
            'root_owned_trust_required':True,
            'readback_pre_5_1_post_0_6':True,
            'monotonic_max_seconds':60,'restore_target_seconds':45,
            'physical_crash_executed_by_module':False,
            'network_connections':0,'vm_starts':0,'nft_writes':0,
            'p8':'NO-GO'}
