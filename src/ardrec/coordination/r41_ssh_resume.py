"""P14-R41: receipt-bound explicit SSH-only libvirt resume.

Default preflight is read-only. Explicit resume is a *separate* command, guarded
by a fresh authenticated R41 preflight, storage revalidation and an intent written
BEFORE the sole allowed `virsh start`. Never runs guest probes or traffic tests.
"""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
from typing import Any

from ardrec.coordination import r35_inactive_deployment as r35
from ardrec.coordination import r365_first_boot as r365
from ardrec.coordination import r39_ssh_reconciliation as r39
from ardrec.coordination import r40_ssh_resume_preflight as r40
from ardrec.coordination.r36_readonly_dashboard import verified_directory

SCHEMA='ardrec-p14-r41-ssh-explicit-resume-v1'
R40_PIN='4666328583d16c8be5d9be15250be98779a3e6868bd7b0a2c91bca450e56bda7'
SSH_START=['/usr/bin/virsh','-c','qemu:///system','start',r365.SSH_DOMAIN]
PREFLIGHT_STATUS='READY_FOR_SEPARATE_EXPLICIT_SSH_RESUME'
STARTED_STATUS='SSH_RESUMED_DENY_FIRST_UNTESTED'
PARTIAL_STATUS='PARTIAL_NO_GO_REVIEW_REQUIRED'
PREFLIGHT_FILES=frozenset({'r41_preflight.json'})
R40_FILES=frozenset({'r40_preflight.json'})
MIN_AVAILABLE_MIB=2816  # 768 MiB SSH guest + 2048 MiB host reserve
MAX_PREFLIGHT_AGE_SECONDS=1200

class R41Error(ValueError):
    """Stable, fail-closed contract error."""

def need(condition: bool, code: str)->None:
    if not condition: raise R41Error(code)

def canon(x:Any)->bytes: return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def sha(raw:bytes)->str: return hashlib.sha256(raw).hexdigest()
def now_utc()->str: return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def parse_utc(raw:str)->datetime:
    try:
        dt=datetime.strptime(raw,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except (TypeError,ValueError) as exc: raise R41Error('timestamp_invalid') from exc
    need(dt.strftime('%Y-%m-%dT%H:%M:%SZ')==raw,'timestamp_not_canonical')
    return dt

def _verify_r40_source(path:Path, r39_dir:Path, r365_preflight_dir:Path,
                       r365_boot_dir:Path)->dict[str,Any]:
    """Pin the exact *observed* R40 receipt; local hash is not external proof."""
    docs=verified_directory(path,R40_FILES)
    raw=docs['r40_preflight.json']
    doc=r365.read_json(raw)
    r40.verify_report(doc)
    need(doc['sha256']==R40_PIN,'r40_source_report_pin_drift')
    chain=r40.verify_r39_source(r39_dir,r365_preflight_dir,r365_boot_dir)
    need(doc.get('source_r39_report_sha256')==chain['r39_report_sha256'] and
         doc.get('source_r39_file_sha256')==chain['r39_file_sha256'] and
         doc.get('source_r365_first_boot_report_sha256')==chain['r365_first_boot_report_sha256'] and
         doc.get('source_r365_preflight_report_sha256')==chain['r365_preflight_report_sha256'] and
         doc.get('source_r365_first_boot_commands_sha256')==chain['r365_first_boot_commands_sha256'] and
         doc.get('source_archive_sha256')==r35.ARCHIVE_SHA256,
         'r40_historical_chain_drift')
    return {'r40_report_sha256':doc['sha256'], 'r40_file_sha256':sha(raw),
            'r39_report_sha256':chain['r39_report_sha256'],
            'r365_first_boot_report_sha256':chain['r365_first_boot_report_sha256'],
            'r40_host_readback':doc['host_readback_after'],
            'r40_storage':doc['storage']}

class ReadOnlyHost(r40.ReadOnlyHost):
    """No activation in R41 preflight."""
    def activate_ssh_network(self)->None: raise R41Error('network_activation_forbidden')
    def activate_ssh_domain(self)->None: raise R41Error('preflight_activation_forbidden')
    def virsh_write(self,args:list[str])->bytes: raise R41Error('arbitrary_write_forbidden')

class AuthorizedSSHHost(ReadOnlyHost):
    """One narrow operation, never a generic libvirt write surface."""
    def activate_ssh_domain(self)->None:
        need(self.bin['virsh']=='/usr/bin/virsh','virsh_binary_mismatch')
        self.run([self.bin['sudo'],'-n','--',*SSH_START],timeout=180)

def verify_storage_and_live(source_archive:Path, host:ReadOnlyHost,
                            source:dict[str,Any])->tuple[dict[str,Any],dict[str,Any]]:
    """Read-only current scope and full postboot storage (not stale R40 hashes)."""
    before=r39.capture_current(host)
    need(before==source['r40_host_readback'],'host_drift_since_r40')
    with tempfile.TemporaryDirectory(prefix='ardrec-r41-source-') as tmp:
        root=Path(tmp)
        root.chmod(0o700)
        bundle=r35.verify_source_bundle(source_archive,root)
        r35.t33.verify_r32(bundle['r32'])
        storage=r40.verify_storage_postboot(host,bundle['r32'])
    after=r39.capture_current(host)
    r40.verify_live_unchanged(before,after)
    # R40 full inventory is the historical reference: SSH runtime was already mutable,
    # but it must not silently change *between* the R40 and R41 preflight.
    need(storage==source['r40_storage'],'storage_drift_since_r40')
    return after,storage

def _common_report(mode:str,status:str,source:dict[str,Any],live:dict[str,Any],
                   storage:dict[str,Any],timestamp:str,attempt_id:str)->dict[str,Any]:
    need(mode in ('PREFLIGHT_ONLY','EXPLICIT_SSH_RESUME'),'mode_invalid')
    need(status in (PREFLIGHT_STATUS,STARTED_STATUS,PARTIAL_STATUS),'status_invalid')
    need(len(attempt_id)==32 and all(c in '0123456789abcdef' for c in attempt_id),'attempt_id_invalid')
    parse_utc(timestamp)
    r40.verify_live_unchanged(live,live)
    need(storage==source['r40_storage'],'storage_binding_invalid')
    report={'schema':SCHEMA,'mode':mode,'status':status,
            'captured_at_utc':timestamp,'attempt_id':attempt_id,
            'source_r40_report_sha256':source['r40_report_sha256'],
            'source_r40_file_sha256':source['r40_file_sha256'],
            'source_r39_report_sha256':source['r39_report_sha256'],
            'source_r365_first_boot_report_sha256':source['r365_first_boot_report_sha256'],
            'source_archive_sha256':r35.ARCHIVE_SHA256,
            'host_state_before':live,
            'storage':storage,
            'minimum_available_memory_mib':MIN_AVAILABLE_MIB,
            'permission_from_prior_receipt':False,
            'isolation_tested':False,'real_service_testing':'NOT_EXECUTED',
            'guest_identity_attested':False,'technical_truth_accredited':False,
            'operational_dispatch':False,'published_generation':None,
            'final_risk':None,'p8_operational':'NO-GO',
            'experimental_validation':'NOT_RUN','automatic_rollback':False,
            'network_started_by_r41':False,
            'vm_started_by_r41':status==STARTED_STATUS,
            'attempted_mutations':([] if mode=='PREFLIGHT_ONLY' else [SSH_START]),
            'host_mutations':([] if status!=STARTED_STATUS else [SSH_START]),
            'outcome_uncertain':status==PARTIAL_STATUS,
            'guest_isolation_next_gate':'SEPARATE_BOUNDED_TRAFFIC_VALIDATION',
            'host_state_after':None,'failure_code':None,
            'source_r41_preflight_sha256':None}
    report['sha256']=sha(canon(report))
    if mode=='PREFLIGHT_ONLY':
        verify_report(report)
    return report

def verify_report(doc:dict[str,Any])->bool:
    need(type(doc) is dict and type(doc.get('sha256')) is str and
         len(doc['sha256'])==64 and doc['sha256']==sha(canon({k:v for k,v in doc.items() if k!='sha256'})),
         'r41_digest_invalid')
    need(doc.get('schema')==SCHEMA and
         doc.get('mode') in ('PREFLIGHT_ONLY','EXPLICIT_SSH_RESUME') and
         doc.get('status') in (PREFLIGHT_STATUS,STARTED_STATUS,PARTIAL_STATUS) and
         doc.get('source_r40_report_sha256')==R40_PIN and
         all(r40.valid_hex(doc.get(k)) for k in ('source_r40_file_sha256',
             'source_r39_report_sha256','source_r365_first_boot_report_sha256')) and
         doc.get('source_archive_sha256')==r35.ARCHIVE_SHA256 and
         doc.get('permission_from_prior_receipt') is False and
         doc.get('isolation_tested') is False and
         doc.get('real_service_testing')=='NOT_EXECUTED' and
         doc.get('guest_identity_attested') is False and
         doc.get('technical_truth_accredited') is False and
         doc.get('operational_dispatch') is False and
         doc.get('published_generation') is None and doc.get('final_risk') is None and
         doc.get('p8_operational')=='NO-GO' and
         doc.get('experimental_validation')=='NOT_RUN' and
         doc.get('automatic_rollback') is False and
         doc.get('network_started_by_r41') is False and
         doc.get('minimum_available_memory_mib')==MIN_AVAILABLE_MIB and
         doc.get('guest_isolation_next_gate')=='SEPARATE_BOUNDED_TRAFFIC_VALIDATION',
         'r41_false_authority_claim')
    parse_utc(doc.get('captured_at_utc'))
    need(type(doc.get('attempt_id')) is str and len(doc['attempt_id'])==32 and
         all(ch in '0123456789abcdef' for ch in doc['attempt_id']), 'r41_id_invalid')
    need(type(doc.get('storage')) is dict and doc['storage'].get('verified_roles')==4 and
         doc['storage'].get('source_images_mutated_by_r40') is False and
         doc['storage'].get('non_ssh_runtime_preboot_hash_enforced') is True,
         'r41_storage_invalid')
    before=doc.get('host_state_before')
    r40.verify_live_unchanged(before,before)
    mode,status=doc['mode'],doc['status']
    if mode=='PREFLIGHT_ONLY':
        need(status==PREFLIGHT_STATUS and doc.get('vm_started_by_r41') is False and
             doc.get('attempted_mutations')==[] and doc.get('host_mutations')==[] and
             doc.get('outcome_uncertain') is False and doc.get('host_state_after') is None and
             doc.get('source_r41_preflight_sha256') is None and doc.get('failure_code') is None,
             'preflight_report_claim_invalid')
    else:
        need(status in (STARTED_STATUS,PARTIAL_STATUS) and
             doc.get('attempted_mutations')==[SSH_START] and
             r40.valid_hex(doc.get('source_r41_preflight_sha256')),
             'resume_report_claim_invalid')
        if status==STARTED_STATUS:
            need(doc.get('vm_started_by_r41') is True and
                 doc.get('host_mutations')==[SSH_START] and
                 doc.get('outcome_uncertain') is False and
                 doc.get('host_state_after',{}).get('phase')=='SSH_RUNNING' and
                 doc.get('host_state_after',{}).get('active_domains')==[r365.SSH_DOMAIN] and
                 doc.get('host_state_after',{}).get('reserved_links')==sorted([
                     r365.t33.NET_BRIDGE['ssh'],'a33d30t']) and
                 doc.get('failure_code') is None,'resume_success_claim_invalid')
        else:
            need(doc.get('vm_started_by_r41') is False and
                 doc.get('host_mutations')==[] and
                 doc.get('outcome_uncertain') is True and
                 doc.get('host_state_after') is None and
                 type(doc.get('failure_code')) is str and 0<len(doc['failure_code'])<=160,
                 'resume_partial_claim_invalid')
    return True

def _make_dir(path:Path)->None:
    need(isinstance(path,Path) and path.is_absolute() and not path.exists() and
         all(not x.is_symlink() for x in (path,*path.parents)), 'receipt_path_invalid')
    parent=path.parent
    st=parent.stat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and
         stat.S_IMODE(st.st_mode)==0o700,'receipt_parent_not_private')
    path.mkdir(mode=0o700,parents=False,exist_ok=False)

def _write_once(path:Path,data:bytes)->None:
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

def _seal_receipt(path:Path, name:str,doc:dict[str,Any],intent:bytes|None=None)->None:
    verify_report(doc)
    body=canon(doc)+b'\n'
    _write_once(path/name,body)
    sums=[sha(body)+'  '+name]
    if intent is not None: sums.insert(0,sha(intent)+'  r41_intent.json')
    _write_once(path/'SHA256SUMS', ('\n'.join(sums)+'\n').encode('ascii'))

def _validate_fresh_memory()->int:
    available=r365.memory_available_mib()
    need(type(available) is int and available>=MIN_AVAILABLE_MIB,'insufficient_available_memory')
    return available

def preflight(*, source_archive:Path,r39_dir:Path,r40_dir:Path,
              r365_preflight_dir:Path,r365_boot_dir:Path,
              receipt_dir:Path,host:ReadOnlyHost|None=None)->dict[str,Any]:
    source=_verify_r40_source(r40_dir,r39_dir,r365_preflight_dir,r365_boot_dir)
    h=host if host is not None else ReadOnlyHost()
    before,storage=verify_storage_and_live(source_archive,h,source)
    _validate_fresh_memory()
    result=_common_report('PREFLIGHT_ONLY',PREFLIGHT_STATUS,source,before,storage,
                          now_utc(),secrets.token_hex(16))
    _make_dir(receipt_dir)
    _seal_receipt(receipt_dir,'r41_preflight.json',result)
    return result

def _verify_prior_preflight(path:Path,source:dict[str,Any])->dict[str,Any]:
    docs=verified_directory(path,PREFLIGHT_FILES)
    doc=r365.read_json(docs['r41_preflight.json'])
    verify_report(doc)
    need(doc['mode']=='PREFLIGHT_ONLY' and doc['status']==PREFLIGHT_STATUS,
         'r41_preflight_receipt_not_ready')
    need(doc['source_r40_report_sha256']==source['r40_report_sha256'] and
         doc['source_r40_file_sha256']==source['r40_file_sha256'] and
         doc['source_r39_report_sha256']==source['r39_report_sha256'] and
         doc['source_r365_first_boot_report_sha256']==source['r365_first_boot_report_sha256'] and
         doc['storage']==source['r40_storage'] and
         doc['host_state_before']==source['r40_host_readback'],
         'r41_preflight_source_drift')
    elapsed=(datetime.now(timezone.utc)-parse_utc(doc['captured_at_utc'])).total_seconds()
    need(0<=elapsed<=MAX_PREFLIGHT_AGE_SECONDS,'r41_preflight_expired_or_future')
    return doc

def resume(*,source_archive:Path,r39_dir:Path,r40_dir:Path,
           r365_preflight_dir:Path,r365_boot_dir:Path,prior_r41_dir:Path,
           receipt_dir:Path,authorized:bool=False,
           host:AuthorizedSSHHost|None=None)->dict[str,Any]:
    need(authorized is True,'explicit_authorization_missing')
    source=_verify_r40_source(r40_dir,r39_dir,r365_preflight_dir,r365_boot_dir)
    prior=_verify_prior_preflight(prior_r41_dir,source)
    h=host if host is not None else AuthorizedSSHHost()
    before,storage=verify_storage_and_live(source_archive,h,source)
    need(before==prior['host_state_before'] and storage==prior['storage'],
         'live_drift_since_r41_preflight')
    _validate_fresh_memory()
    # Stop if state drifted between storage validation and intent creation.
    need(r39.capture_current(h)==before,'last_instant_host_drift')
    _make_dir(receipt_dir)
    stamp=now_utc()
    aid=secrets.token_hex(16)
    intent={'schema':SCHEMA+'-intent','attempt_id':aid,'captured_at_utc':stamp,
            'source_r41_preflight_sha256':prior['sha256'],
            'source_r40_report_sha256':source['r40_report_sha256'],
            'exact_command':SSH_START,
            'authorization':'EXPLICIT_R41_SSH_ONLY',
            'no_automatic_retry':True,'p8_operational':'NO-GO'}
    intent['sha256']=sha(canon(intent))
    raw=canon(intent)+b'\n'
    _write_once(receipt_dir/'r41_intent.json',raw)
    # Only deliberate stateful operation. No auto rollback, no retry.
    try:
        h.activate_ssh_domain()
        final=r365.current(h,phase='SSH_RUNNING')
    except (Exception,KeyboardInterrupt) as exc:
        result=_common_report('EXPLICIT_SSH_RESUME',PARTIAL_STATUS,source,before,storage,stamp,aid)
        result['source_r41_preflight_sha256']=prior['sha256']
        result['failure_code']=type(exc).__name__+':'+str(exc)[:120]
        result['sha256']=sha(canon({k:v for k,v in result.items() if k!='sha256'}))
        _seal_receipt(receipt_dir,'r41_result.json',result,intent=raw)
        return result
    result=_common_report('EXPLICIT_SSH_RESUME',STARTED_STATUS,source,before,storage,stamp,aid)
    result['source_r41_preflight_sha256']=prior['sha256']
    result['host_state_after']=final
    result['sha256']=sha(canon({k:v for k,v in result.items() if k!='sha256'}))
    _seal_receipt(receipt_dir,'r41_result.json',result,intent=raw)
    return result
