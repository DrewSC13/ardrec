"""R116-F2: current-HEAD independent authority and physical DENY preflight.

Source-only preflight, never a root traffic grant. Unlike R115-F6 (historically
pinned to an R115 commit), this version checks the *current* signed case HEAD.
An external signer and a second independent revocation signer remain mandatory.

No guest boot, socket, nftables writes, systemd timer writes, P7 calibration,
A6 admission, or P8 production approval is performed here.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r115_f6_signed_scope_and_activation as f6
from ardrec.coordination import r115_f15_p7_independent_pilot as f15
from ardrec.coordination import r115_f16_physical_pilot_controller as f16

SCHEMA='ARDREC-R116-F2-CURRENT-PILOT-PHYSICAL-DENY-GATE-v1'
CATALOG_SHA='5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
MAX_SCOPE_REVOCATION_AGE=30
GUARD_SCHEMA='ARDREC-R116-F1-FIVE-ONE-DENY-GUARD-v1-check'
STAGE_KEYS=('ftp','runner','smb','ssh')

class Stop(ValueError):
    """Stable fail-closed refusal."""

def need(ok,code):
    if not ok:raise Stop(code)

def clock(now):
    need(type(now) is datetime and now.tzinfo is not None and
         now.utcoffset() is not None, 'UTC_AWARE_CLOCK_REQUIRED')
    return now.astimezone(timezone.utc)

def current_scope_review(contract_raw, scope_authorization_raw, *, catalog_raw,
                         now, head, root_loader=f6.secure_root_file):
    """Verify real Ed25519 scope/revocation with root-pinned keys, current HEAD.

    Compatibility repair: F6.scope requires the 2026-11 R115 static BASE.
    F15 requires contract.source_commit==HEAD, so F6 cannot be used for R116.
    We version the review without changing either signed historical module.
    """
    clock(now)
    need(type(head) is str and f1.GIT_SHA.fullmatch(head),'CURRENT_HEAD_INVALID')
    need(type(contract_raw) is bytes and type(scope_authorization_raw) is bytes,
         'SCOPE_RAW_BYTES_REQUIRED')
    need(type(catalog_raw) is bytes and f1.digest(catalog_raw)==CATALOG_SHA,
         'CATALOG_PIN_MISMATCH')
    need(callable(root_loader),'ROOT_POLICY_LOADER_INVALID')
    try:
        contract=f1.load(contract_raw)
        f1.validate(contract,f1.load(catalog_raw),catalog_raw)
        need(contract['source_commit']==head, 'SCOPE_CONTRACT_NOT_CURRENT_HEAD')
        auth=f1.load(scope_authorization_raw)
        trust=f1.load(root_loader(f6.TRUST))
        revoke=f1.load(root_loader(f6.REVOCATION))
        # No injected trust or approval from caller in production: root_loader
        # defaults to the fixed, root-owned, O_NOFOLLOW policy reader.
        report=f3.auth_review(contract,auth,revoke,trust,now=clock(now).isoformat())
        need(type(report) is dict and report.get('crypto_verified') is True and
             report.get('authorization_sha256')==f1.digest(f1.canonical(auth)),
             'SCOPE_CRYPTO_OR_BINDING_NOT_VERIFIED')
        if report.get('status')=='FALSO':
            return 'FALSO','SCOPE_SIGNED_REVOCATION',report['authorization_sha256']
        need(report.get('status')=='ND' and
             report.get('reason')=='CRYPTO_VALID_BUT_HOST_AUTHORITY_NOT_PINNED',
             'SCOPE_WINDOW_OR_SIGNATURE_NOT_CURRENT')
        issued=f1._instant(revoke['statement']['issued_at'],'REVOCATION_ISSUED')
        until=f1._instant(revoke['statement']['valid_until'],'REVOCATION_UNTIL')
        start=f1._instant(contract['valid_from'],'SCOPE_FROM')
        stop=f1._instant(contract['valid_until'],'SCOPE_TO')
        age=(clock(now)-issued).total_seconds()
        need(0 <= age <= MAX_SCOPE_REVOCATION_AGE and
             start <= clock(now)<min(stop,until),
             'SCOPE_REVOCATION_OR_WINDOW_STALE')
        return 'VERDADERO','R116_CURRENT_HEAD_ROOT_SCOPE_AT_REVIEW_ONLY',report['authorization_sha256']
    except (f1.Rejected,f3.Stop,KeyError,ValueError,TypeError,OSError) as exc:
        if isinstance(exc,Stop):raise
        raise Stop('CURRENT_SCOPE_REJECTED_'+type(exc).__name__) from exc

def signed_pilot(contract_raw,auth_raw,pilot_raw,*,head,catalog_raw,now,
                 scope_loader=f6.secure_root_file,pilot_loader=f15._root_read):
    """Wire F15's real signed review to the versioned current-HEAD F6 repair.

    Injected loaders exist for isolated tests only; CLI never exposes them.
    """
    clock(now)
    def reviewer(c,a,*,catalog_raw,now):
        return current_scope_review(c,a,catalog_raw=catalog_raw,now=now,
                                    head=head,root_loader=scope_loader)
    need(callable(pilot_loader),'PILOT_POLICY_LOADER_INVALID')
    doc=f15.signed_pilot_review(contract_raw,auth_raw,pilot_raw,now=now,
          head=head,catalog_raw=catalog_raw,scope_reviewer=reviewer,loader=pilot_loader)
    need(doc['document_status']=='DOCUMENT_SIGNED' and
         doc['head']==head and doc['family_id']=='FTP-T01' and
         doc['authorized_to_connect_by_module'] is False and
         doc['physical_pilot_session_attested'] is False and
         doc['p8']=='NO-GO' and doc['a6']=='ND',
         'PILOT_NOT_SIGNED_OR_REVOCATION_PRESENT')
    return doc

def check_root_guard(doc):
    """Validate data returned by the *staged* F1 root --check command.

    These bytes are a readback, NOT cryptographic authority: the operational
    privileged controller must independently invoke staged F1 before traffic.
    """
    need(type(doc) is dict and set(doc)=={'schema','states','policy','deny',
                                       'host_writes','p8'},'F1_READBACK_FIELDS')
    need(doc['schema']==GUARD_SCHEMA and doc['deny']=='MATCH' and
         doc['host_writes']==0 and doc['p8']=='NO-GO','F1_READBACK_NOT_DENY')
    expected={'ssh':'RUNNING','runner':'RUNNING','ftp':'RUNNING','smb':'OFF'}
    need(doc['states']==expected,'F1_GUEST_SET_NOT_FTP_ONLY')
    p=doc['policy']
    need(type(p) is dict and set(p)=={'running','active','absent',
                       'active_count','absent_count','allow_traffic','p8'},
         'F1_TOPOLOGY_FIELDS')
    need(p['running']==['ftp','runner','ssh'] and
         p['active']==['ftp','runner_ftp','runner_smb','runner_ssh','ssh'] and
         p['absent']==['smb'] and type(p['active_count']) is int and
         p['active_count']==5 and type(p['absent_count']) is int and
         p['absent_count']==1 and p['allow_traffic'] is False and
         p['p8']=='NO-GO','F1_FIVE_ONE_DENY_NOT_ATTESTED')
    return doc

def preflight(*,head,catalog_raw,now,capture,contract_raw,authorization_raw,
              pilot_raw,ftp_plan_dir,ftp_boot_dir,root_guard_readback,
              scope_loader=f6.secure_root_file,pilot_loader=f15._root_read,
              physical_checker=f16.physical_deny_stage,
              boot_checker=f16.boot_chain):
    """Strict cumulative signed+physical checks, still never a traffic permit."""
    clock(now)
    need(type(head) is str and f1.GIT_SHA.fullmatch(head),'HEAD_REQUIRED')
    need(type(catalog_raw) is bytes and f1.digest(catalog_raw)==CATALOG_SHA,
         'CATALOG_PIN_INVALID')
    need(isinstance(ftp_plan_dir,Path) and isinstance(ftp_boot_dir,Path),
         'BOOT_RECEIPT_PATH_REQUIRED')
    check_root_guard(root_guard_readback)
    try:
        physical=physical_checker(capture,now=now)
        need(type(physical) is dict and
             physical.get('active_deny_bindings')==5 and
             physical.get('offline_absent_bindings')==1 and
             physical.get('root_window_open') is False and
             physical.get('traffic_authorized') is False,
             'PHYSICAL_DENY_NOT_PROVEN')
        boot=boot_checker(ftp_plan_dir,ftp_boot_dir)
        need(type(boot) is dict and
             boot.get('ftp_boot_attributed_to_ssh_runner_ftp_replay') is True and
             boot.get('traffic_authorized') is False,
             'BOOT_CHAIN_NOT_PROVEN')
        signed=signed_pilot(contract_raw,authorization_raw,pilot_raw,
                           head=head,catalog_raw=catalog_raw,now=now,
                           scope_loader=scope_loader,pilot_loader=pilot_loader)
    except (f16.Stop,f15.Stop,f1.Rejected,KeyError,TypeError,ValueError,OSError) as exc:
        if isinstance(exc,Stop):raise
        raise Stop('PILOT_PRECONDITIONS_REJECTED_'+type(exc).__name__) from exc
    return {'schema':SCHEMA+'-review','head':head,'catalog_sha256':CATALOG_SHA,
            'pilot_sha256':signed['pilot_sha256'],
            'scope_authorization_sha256':signed['scope_authorization_sha256'],
            'f5_capture_sha256':physical['capture_sha256'],
            'boot_receipt_sha256':boot['boot_receipt_sha256'],
            'root_denies':'FIVE_ACTIVE_ONE_OFF_MATCH',
            'scope_and_pilot_document':'SIGNED_AT_REVIEW_ONLY',
            'physical_preconditions_at_review':True,
            'opens_socket':False,'starts_vm':False,'changes_firewall':False,
            'arms_watchdog':False,'root_window_open':False,
            'physical_a5_attested':False,'a6':'ND','p8':'NO-GO',
            'ready_for_separate_root_session_review':True,
            'root_execution_permit_issued':False}

def capabilities():
    return {'schema':SCHEMA+'-capabilities','family_id':'FTP-T01',
            'current_head_scope_validation':True,
            'independent_scope_pilot_and_revocation_required':True,
            'five_active_one_absent_root_readback':True,
            'real_ssh_runner_ftp_replay_required':True,
            'offline_tests_only':True,'root_execution_permit_issued':False,
            'opens_socket':False,'starts_vm':False,'changes_firewall':False,
            'p7':'DRAFT_NOT_CALIBRATED','a6':'ND','p8':'NO-GO'}
