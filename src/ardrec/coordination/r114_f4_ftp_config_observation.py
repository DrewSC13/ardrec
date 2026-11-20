"""R114-F4: bounded FTP guest configuration-source attestation, NOT effective config.

A physical QGA guest-exec of /usr/bin/cat /etc/vsftpd.conf is independently
recorded, not promoted to A5 execution or to A6 support. The actual FTP
response from F10R is only historical context, never a new A5 observation.
"""
from __future__ import annotations
import base64
import hashlib
import json
import re
from typing import Any

from ardrec.coordination import r114_f3_asset_anchor as f3
from ardrec.coordination import r59d_a5_result_intake as a5

SCHEMA='ARDREC-R114-F4-FTP-CONFIG-SOURCE-OBSERVATION-v1'
F3_MANIFEST_PIN='9a216b641f01fdeba5c5e559bb4819393212ecc6c5bbc6f7d90e79f8663f2acf'
F3_REPORT_PIN='4f2132be53f2c700199ce6fe2d12f1d95008781f3283f6fd5db19e26200a9a9c'
F3_DIR='/home/cicada/ardrec-lab/r114-f3-physical-asset-anchors-v1/anchors-79002bed'
VM='ardrec-r33-dev-ftp'
CONFIG='/etc/vsftpd.conf'
CMD=['/usr/bin/cat',CONFIG]
CASE='FTP-T01-S01-01'
SESSION='R114_F4_FTP_T01'
ATTEMPT='ATT_R114_F4_FTP_T01'
EXPECTED_MAC='52:54:00:ad:31:02'
EXPECTED_CIDR='10.203.31.2/28'
EXPECTED_PORT=21
MAX_DATA=65536

class Guard(ValueError): pass

def need(ok:bool,why:str)->None:
    if not ok: raise Guard(why)

def canonical(obj:Any)->bytes:
    return (json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')

def sha(raw:bytes)->str: return hashlib.sha256(raw).hexdigest()

def validate_f3(report:dict,manifest:dict,*,msha:str,rsha:str)->tuple[dict,dict]:
    need(msha==F3_MANIFEST_PIN and rsha==F3_REPORT_PIN,'F3_RECEIPT_NOT_PINNED')
    need(type(manifest) is dict and manifest.get('schema')=='ARDREC-R114-F3-PRIVATE-REPLAY-v1' and
         manifest.get('report_sha256')==F3_REPORT_PIN and
         manifest.get('a5_starts')==0 and manifest.get('a6_admitted')==0 and
         manifest.get('p8')=='NO-GO', 'F3_MANIFEST_AUTHORITY_CHANGED')
    need(type(report) is dict and report.get('schema')==f3.SCHEMA and
         report.get('asset_count')==3 and report.get('candidate_count')==29 and
         report.get('a5_starts')==0 and report.get('a6_admitted_conditions')==0 and
         report.get('a7_risk_recalculated') is False and report.get('p8')=='NO-GO' and
         report.get('sha256')==sha(canonical({k:v for k,v in report.items() if k!='sha256'})),
         'F3_REPORT_AUTHORITY_CHANGED')
    assets=[a for a in report.get('assets',[]) if type(a) is dict and a.get('role')=='ftp']
    candidates=[x for x in report.get('case_planning_candidates',[]) if type(x) is dict
                and x.get('family_id')=='FTP-T01' and x.get('variant') is None]
    need(len(assets)==1 and len(candidates)==1,'FTP_ASSET_OR_FAMILY_MISSING')
    asset,candidate=assets[0],candidates[0]
    need(asset.get('target_vm')==VM and asset.get('target_mac')==EXPECTED_MAC and
         asset.get('target_ipv4_cidr')==EXPECTED_CIDR and asset.get('tcp_port')==21 and
         asset.get('tcp_real_observed') is True and
         asset.get('a5_case_binding_accredited') is False and
         asset.get('a6_condition')=='ND' and asset.get('confirmed_rf') is None and
         candidate.get('asset_anchor_id')==asset.get('asset_anchor_id') and
         candidate.get('case_id_a5') is None and candidate.get('a5_attempt_started') is False and
         candidate.get('a6_classification')=='ND' and candidate.get('confirmed_rf') is None and
         'CONTROL_CHANNEL_RESPONSE' in candidate.get('catalogue_required_supports_not_admitted',[]),
         'FTP_T01_PHYSICAL_SCOPE_OR_A5_DRIFT')
    return asset,candidate

def plan(report:dict,manifest:dict,*,msha:str,rsha:str)->dict:
    asset,candidate=validate_f3(report,manifest,msha=msha,rsha=rsha)
    return {
      'schema':'ARDREC-R114-F4-FTP-SINGLE-GUEST-CONFIG-INTENT-v1',
      'original_f3_receipt_sha256':msha,'original_f3_report_sha256':rsha,
      'source_asset_anchor_id':asset['asset_anchor_id'],
      'source_candidate_planning_id':candidate['candidate_planning_id'],
      'vm':VM,'mac':EXPECTED_MAC,'ipv4_cidr':EXPECTED_CIDR,
      'family':'FTP-T01','case_id_proposed':CASE,'assessment_index':0,
      'guest_exec_path':CMD[0], 'guest_exec_args':[CMD[1]],
      'guest_operation':'READ_STATIC_VSFTPD_CONFIGURATION_FILE',
      'method_id':'FTP_EFFECTIVE_CONFIG_READONLY',
      'method_completed':False,'effective_configuration_accredited':False,
      'physical_attempt_authorized':False,'a5_operational_case_accredited':False,
      'a6_conditions_admitted':0,'risk_recalculated':False,
      'new_tcp_connections':0,'host_firewall_mutations':0,'p8':'NO-GO',
    }

def classify(plan_doc:dict, guest_completion_raw:bytes, config_raw:bytes,
             *, f6_before_raw:bytes,f6_after_raw:bytes,
             f3_report:dict,f3_manifest:dict,msha:str,rsha:str)->dict:
    need(plan_doc==plan(f3_report,f3_manifest,msha=msha,rsha=rsha), 'INTENT_CHANGED')
    try:
      completion=json.loads(guest_completion_raw)
      f6_before=json.loads(f6_before_raw)
      f6_after=json.loads(f6_after_raw)
    except (ValueError,UnicodeError,RecursionError) as exc: raise Guard('SOURCE_JSON_INVALID') from exc
    for value in (f6_before,f6_after):
      need(type(value) is dict and value.get('result')=='SIX_BINDING_DENY_ATTESTED'
           and value.get('bindings')==6 and value.get('p8')=='NO-GO' and
           value.get('host_writes')==0,'F6_DENY_NOT_ATTESTED')
    need(type(completion) is dict and set(completion)=={'return'} and
         type(completion['return']) is dict,'QGA_COMPLETION_INVALID')
    obj=completion['return']
    need(obj.get('exited') is True and type(obj.get('exitcode')) is int and obj['exitcode']==0,
         'GUEST_EXIT_NOT_ZERO')
    try:
      out=base64.b64decode(obj['out-data'],validate=True)
      err=base64.b64decode(obj.get('err-data',''),validate=True)
    except (KeyError,ValueError,TypeError) as exc: raise Guard('QGA_BASE64_INVALID') from exc
    need(not err and out==config_raw and 0<len(out)<=MAX_DATA and b'\0' not in out,
         'GUEST_OUTPUT_INVALID_OR_MISMATCH')
    # The observation is of FILE BYTES, not effective parsed settings, a live
    # authentication, a successful A5 family attempt or an A6 technical fact.
    intent=a5.build_intent(service_id='FTP_DEV',session_id=SESSION,
        family_id='FTP-T01',derived_case_id=CASE,assessment_index=0,
        attempt_id=ATTEMPT,configuration_sha256=sha(out),
        method_id='FTP_EFFECTIVE_CONFIG_READONLY')
    a5.verify_intent(intent)
    return {
      'schema':SCHEMA,'mode':'REAL_GUEST_CONFIG_FILE_OBSERVED_NOT_EFFECTIVE_OR_A5_FAMILY_COMPLETED',
      'source_f3_manifest_sha256':msha,'source_f3_report_sha256':rsha,
      'asset_anchor_id':plan_doc['source_asset_anchor_id'],
      'planning_candidate_id':plan_doc['source_candidate_planning_id'],
      'vm':VM,'mac':EXPECTED_MAC,'ipv4_cidr':EXPECTED_CIDR,
      'observed_file':CONFIG,'guest_exec':CMD,
      'config_file_bytes':len(out),'config_file_sha256':sha(out),
      'qga_completion_sha256':sha(guest_completion_raw),
      'f6_before_sha256':sha(f6_before_raw),'f6_after_sha256':sha(f6_after_raw),
      'case_intent':intent,'case_binding_status':'CASE_INTENT_DECLARED_WITH_REAL_FILE_SOURCE',
      'guest_file_read_accredited':True,'effective_configuration_accredited':False,
      'a5_case_start_independently_accredited':False,
      'a5_family_execution_completed':False,
      'a6_classification':'ND','a6_supports_admitted':[],
      'confirmed_vulnerability':False,'a7_rf':None,'a8_transitions':0,
      'a9_published_generation':None,'network_probes':0,'new_tcp_connections':0,
      'firewall_mutations':0,'p8':'NO-GO',
    }

def verify_report(report:dict,plan_doc:dict,completion:bytes,configuration:bytes,
                  *,f6_before:bytes,f6_after:bytes,f3_report:dict,f3_manifest:dict,
                  msha:str,rsha:str)->bool:
    need(report==classify(plan_doc,completion,configuration,f6_before_raw=f6_before,
                         f6_after_raw=f6_after,f3_report=f3_report,
                         f3_manifest=f3_manifest,msha=msha,rsha=rsha),
         'REPORT_SEMANTICS_OR_PROVENANCE_CHANGED')
    return True
