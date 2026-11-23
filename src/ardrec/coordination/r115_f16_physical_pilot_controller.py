"""R115-F16: live pilot-boundary orchestrator for FTP-T01, fail closed.

Reuses R115-F15 signed pilot, F6 signed scope and R115-F7/F8 physical boot
receipt replay; verifies the actual five-active/one-offline F11 DENY lifecycle
using a fresh F5 root readback. Never confuses documentary approval, boot
proof, or a clean deny snapshot with an nftables traffic window. The separate
root-only permit-enforced 60s transition+autonomous deny rollback must be
implemented and independently audited before any connection can be dispatched.

No host writes, no sockets, no process spawning except explicit F5 read-only
capturing when invoked by the inspect CLI. No P7 mutation or A6 promotion.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f5_lifecycle_readiness as f5
from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_f8_runner_ftp_boot as f8
from ardrec.coordination import r115_f15_p7_independent_pilot as f15

SCHEMA='ARDREC-R115-F16-P7-LIVE-BOOT-BINDING-BOUNDARY-v1'
ROOT=Path('/home/cicada/ardrec-lab/r115-f16-physical-pilot-review-v1')
CATALOG=Path('lab/operational-catalog-v1/catalog.json')
MAX_READBACK_AGE_SECONDS=60
STAGE='ftp'
TARGET={'ip':'10.203.31.2','port':21}

class Stop(ValueError):
    """Non-operational, stable fail-closed gate rejection."""

def need(ok,code):
    if not ok: raise Stop(code)

def _time(now):
    need(type(now) is datetime and now.tzinfo is not None and
         now.utcoffset() is not None,'UTC_AWARE_CLOCK_REQUIRED')
    return now.astimezone(timezone.utc)

def _fresh(capture, now):
    f5.validate(capture)
    end=f1._instant(capture['end'],'F16_END')
    age=(_time(now)-end).total_seconds()
    need(-2<=age<=MAX_READBACK_AGE_SECONDS,'F5_READBACK_NOT_FRESH')
    return f1.digest(f1.canonical(capture))

def physical_deny_stage(capture, *, now):
    """A genuinely live DENY stage is five bound DENY + one absent while SMB target OFF.

    This is not equivalent to the historical R113-F6 `--attest-deny` 6/6
    all-on mode, which is inappropriate while SMB remains shut off.
    """
    capture_sha=_fresh(capture,now)
    try:
        proof=f7.state_gate(capture,STAGE,after=True)
    except (f7.Stop,f5.Stop,ValueError,TypeError,KeyError) as exc:
        raise Stop('CURRENT_FTP_STAGE_NOT_ATTESTED') from exc
    report=f5.report(capture)
    need(report['states']=={'ssh':'RUNNING','runner':'RUNNING','ftp':'RUNNING','smb':'OFF'},
         'WRONG_LIVE_GUEST_SET')
    want={'runner_ssh':'DENY_MATCH','ssh':'DENY_MATCH',
          'runner_ftp':'DENY_MATCH','ftp':'DENY_MATCH',
          'runner_smb':'DENY_MATCH','smb':'ABSENT_WHILE_OFF'}
    need(report['bindings']==want,'FIVE_DENY_ONE_OFF_BINDING_REQUIRED')
    need(report['nft']=='MATCH' and report['helper']=='MATCH' and
         report['f11_hook']=='MATCH','F11_R34_NOT_ATTESTED')
    need(proof['f5_capture_sha256']==capture_sha,'CAPTURE_HASH_NOT_BOUND')
    return {'schema':SCHEMA+'-deny-proof','role':'ftp',
            'capture_sha256':capture_sha,'nft':'MATCH','f11':'MATCH',
            'active_deny_bindings':5,'offline_absent_bindings':1,
            'guest_states':report['states'],
            'f11_r34_deny_proven_at_capture_only':True,
            'root_window_open':False,'traffic_authorized':False,
            'p8':'NO-GO','a6':'ND'}

def boot_chain(ftp_plan_dir, ftp_boot_dir, *, replay=f8.replay):
    """Replay physical F8 FTP proof; F8 recursively replays runner + F7 SSH."""
    need(isinstance(ftp_plan_dir,Path) and ftp_plan_dir.is_absolute() and
         isinstance(ftp_boot_dir,Path) and ftp_boot_dir.is_absolute(),
         'BOOT_PROVENANCE_PATH_REQUIRED')
    # Only the exact pre-existing F8 receipt root can be used.
    need(ftp_plan_dir.parent==f8.ROOT and
         ftp_boot_dir.parent==f8.ROOT and
         ftp_plan_dir.name.startswith('plan-') and
         ftp_boot_dir.name.startswith('boot-'),'F8_BOOT_PATH_OUT_OF_SCOPE')
    receipt=replay(ftp_plan_dir,ftp_boot_dir)
    need(type(receipt) is dict and receipt.get('role')=='ftp' and
         receipt.get('state')=='FTP_RUNNING_DENY_ATTESTED' and
         receipt.get('vm_starts')==1 and
         receipt.get('traffic_authorized') is False and
         receipt.get('p8')=='NO-GO' and receipt.get('a6')=='ND',
         'F8_FTP_BOOT_NOT_ATTESTED')
    return {'schema':SCHEMA+'-boot-proof','boot_receipt_sha256':f1.digest(f1.canonical(receipt)),
            'ftp_boot_attributed_to_ssh_runner_ftp_replay':True,
            'traffic_authorized':False,'p8':'NO-GO'}

def assess(*,head,catalog_raw,capture,now,contract_raw=None,authorization_raw=None,
           pilot_raw=None,ftp_plan_dir=None,ftp_boot_dir=None,
           pilot_review=f15.signed_pilot_review,
           boot_replay=f8.replay):
    """Independent preconditions are cumulative; no success path returns GO.

    The expected current lab state is OFFLINE. Reports blockers without
    prematurely reading root trust or claiming boot provenance when absent.
    """
    _time(now)
    need(type(head) is str and f1.GIT_SHA.fullmatch(head),'GIT_HEAD_REQUIRED')
    need(type(catalog_raw) is bytes and f1.digest(catalog_raw)==
         '5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e',
         'P7_CATALOG_SHA_CHANGED')
    require_docs=(contract_raw is not None,authorization_raw is not None,pilot_raw is not None)
    need(require_docs in ((False,False,False),(True,True,True)),
         'PARTIAL_SIGNED_DOCUMENT_INPUTS')
    require_boot=(ftp_plan_dir is not None,ftp_boot_dir is not None)
    need(require_boot in ((False,False),(True,True)),'PARTIAL_BOOT_RECEIPT_INPUTS')
    f5.validate(capture)
    snapshot=f5.report(capture)
    blockers=[]
    physical=None
    try: physical=physical_deny_stage(capture,now=now)
    except (Stop,f5.Stop,ValueError,TypeError,KeyError):
        blockers.append('FTP_RUNNING_FIVE_DENY_ONE_OFF_NOT_ATTESTED')
    boot=None
    if all(require_boot):
        try: boot=boot_chain(ftp_plan_dir,ftp_boot_dir,replay=boot_replay)
        except (Stop,f8.Stop,f7.Stop,f5.Stop,ValueError,TypeError,KeyError,OSError):
            blockers.append('F7_F8_REAL_BOOT_REPLAY_REJECTED')
    else: blockers.append('F7_F8_SIGNED_PHYSICAL_BOOT_RECEIPTS_MISSING')
    signed=None
    if all(require_docs):
        try:
            signed=pilot_review(contract_raw,authorization_raw,pilot_raw,
                now=now,head=head,catalog_raw=catalog_raw)
            need(type(signed) is dict and
                 signed.get('document_status')=='DOCUMENT_SIGNED' and
                 signed.get('authorized_to_connect_by_module') is False and
                 signed.get('physical_pilot_session_attested') is False and
                 signed.get('p8')=='NO-GO','PILOT_DOCUMENT_NOT_CURRENT')
        except (Stop,f15.Stop,f1.Rejected,ValueError,TypeError,KeyError,OSError):
            blockers.append('INDEPENDENT_SCOPE_PILOT_OR_REVOCATION_NOT_VERIFIED')
            signed=None
    else: blockers.append('INDEPENDENT_SCOPE_PILOT_AND_REVOCATION_MISSING')
    # No root-owned 60s autonomous guardian with 5/1 lifecycle-compatible
    # rollback is part of F16. This is a mandatory unresolved blocker.
    blockers.append('ROOT_60S_LIFECYCLE_COMPATIBLE_WINDOW_NOT_IMPLEMENTED')
    blockers.append('A3_CLIENT_AND_FTP_SERVICE_NOT_INDEPENDENTLY_ATTESTED')
    # Neither a perfect matched snapshot nor signed documents turn the
    # uncalibrated P7 into a general P8 release.
    return {'schema':SCHEMA+'-assessment','head':head,
            'catalog_sha256':f1.digest(catalog_raw),
            'capture_sha256':f1.digest(f1.canonical(capture)),
            'physical_deny':physical,'boot_chain':boot,
            'independent_pilot_document':(
                {'status':signed['document_status'],
                 'pilot_sha256':signed['pilot_sha256']}
                if signed is not None else {'status':'ND'}),
            'observed_vm_states':snapshot['states'],
            'blockers':sorted(set(blockers)),
            'pilot_release':False,'root_window_open':False,
            'ordinary_p8':'NO-GO','p7_pilot_completed':False,
            'a5':'NO-GO','a6':'ND','a7':None,'a8':None,'a9':None,'a10':None,
            'guest_starts_by_module':0,'network_connections_by_module':0,
            'firewall_mutations_by_module':0}

def persist(report, *, root=ROOT):
    need(os.geteuid()!=0,'ROOT_SHELL_FORBIDDEN')
    need(type(report) is dict and report.get('schema')==SCHEMA+'-assessment' and
         report.get('pilot_release') is False and
         report.get('ordinary_p8')=='NO-GO' and
         report.get('root_window_open') is False,'UNSAFE_REPORT')
    folder=f7._create(root,'inspect-')
    raw=f1.canonical(report)
    f2.exclusive(folder/'report.json',raw)
    f2.exclusive(folder/'manifest.json',f1.canonical({
        'schema':SCHEMA+'-manifest',
        'report_sha256':f1.digest(raw),
        'scope':'LIVE_READONLY_NOT_A_TRAFFIC_PERMIT'}))
    return folder

def capabilities():
    return {'schema':SCHEMA+'-capabilities','family_id':'FTP-T01',
            'live_five_deny_one_off_lifecycle_check':True,
            'replay_ssh_runner_ftp_physical_receipts':True,
            'verify_independent_signed_pilot':True,
            'opens_sockets':False,'starts_vm':False,
            'changes_firewall':False,'issues_signature':False,
            'physical_p7_pilot_executed':False,'p8':'NO-GO','a6':'ND'}
