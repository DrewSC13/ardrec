"""R114-F2: 25-family evidence gap register from authentic R114-F1 intake.

Maps a *real service observation* to a catalogued protocol, not to an A5
attempt, a derived case, or an A6 truth value. This module does no I/O beyond
reading the byte-pinned existing P7 catalog through the three P7 engines.
No family rule engine is executed on a fake case and no Rf is calculated.
"""
from __future__ import annotations
from typing import Any
import hashlib
import json

from ardrec.coordination import r114_f1_real_receipt as f1
from ardrec.evidence import r58h_ssh_family_logic as ssh
from ardrec.evidence import r58i_ftp_family_logic as ftp
from ardrec.evidence import r58j_smb_family_logic as smb

SCHEMA='ARDREC-R114-F2-PHYSICAL-FAMILY-EVIDENCE-GAPS-v1'
F1_MANIFEST_PIN='923d8dda4d7e94f0d9173719d43c835fef68c33d8696cb3096c042ca35df680f'
F1_SESSION='/home/cicada/ardrec-lab/r114-f1-real-protocol-intake-v1/intake-d4371c00'
F1_MANIFEST_SCHEMA='ARDREC-R114-F1-PRIVATE-INTEGRITY-v1'
EXPECTED_FACTS={
    'ssh':'SSH_IDENTIFICATION_BANNER_OBSERVED',
    'ftp':'FTP_220_CONTROL_GREETING_OBSERVED',
    'smb':'SMB_TCP_CONNECTED_NO_SMB2_RESPONSE_VERIFIED',
}
CASELESS='NO_A5_CASE_ID_NO_ATTEMPT_OR_SUPPORT_ATTESTATION'
FAMILY_COUNT=25
VARIANT_OPTIONS={
    'FTP-T02':('CONTROL','DATA'),
    'FTP-T08':('READ','WRITE'),
    'SMB-T03':('SIGNING','ENCRYPTION'),
    'SMB-T09':('READ','WRITE'),
}
class GapError(ValueError):pass

def need(ok:bool,code:str):
    if not ok:raise GapError(code)

def canonical(doc:Any)->bytes:
    return (json.dumps(doc,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')

def digest(raw:bytes)->str:return hashlib.sha256(raw).hexdigest()

def _families()->list[tuple[str,str,dict,str|None]]:
    """Load all three original SHA-pinned P7 family engines, not test fixtures."""
    need(ssh.CATALOG_SHA256==ftp.CATALOG_SHA256==smb.CATALOG_SHA256,
         'PINNED_FAMILY_CATALOG_DRIFT')
    groups=(('ssh','SSH_DEV',ssh.load_pinned_catalog()),
            ('ftp','FTP_DEV',ftp.load_pinned_ftp_catalog()),
            ('smb','SMB_DEV',smb.load_pinned_smb_catalog()))
    need([len(x[2]) for x in groups]==[8,8,9], 'CATALOG_25_REQUIRED')
    rows=[]
    for protocol,service,details in groups:
        for definition in details:
            for variant in VARIANT_OPTIONS.get(definition['id'],(None,)):
                rows.append((protocol,service,definition,variant))
    need(len({r[2]['id'] for r in rows})==25 and len(rows)==29,
         'CATALOG_FAMILY_VARIANT_SCOPE_CHANGED')
    return rows

def validate_f1_report(report:dict)->dict[str,dict]:
    need(type(report) is dict and report.get('schema')==f1.SCHEMA and
         report.get('origin')=='REAL_F10R_QGA_RUNNER_AND_ROOT_CLOSURE' and
         report.get('root_receipt_sha256')==f1.F10R_RECEIPT_SHA and
         report.get('counts')=={'tcp_connections':3,'verified_banners':2,'verified_smb2':0,
                                'a5_case_bound':0,'a6_conditions_admitted':0} and
         report.get('final_f6_restore')=='SIX_BINDING_DENY_RESTORED' and
         report.get('final_f6_attest')=='SIX_BINDING_DENY_ATTESTED' and
         report.get('watchdog_armed_at_open') is True and
         report.get('no_new_network_traffic') is True and
         report.get('no_new_guest_exec') is True and
         report.get('operational_dispatch') is False and
         report.get('risk_recalculation_performed') is False and
         report.get('confirmed_final_risk') is None and
         report.get('p8')=='NO-GO', 'F1_AUTHORITY_OR_STATUS_DRIFT')
    observations=report.get('observations')
    need(type(observations) is list and len(observations)==3,
         'F1_OBSERVATIONS_NOT_THREE')
    found={}
    for value,(role,src,dst,port) in zip(observations,f1.ROLES):
        need(type(value) is dict and value.get('role')==role and
             value.get('source_ip')==src and value.get('target_ip')==dst and
             type(value.get('target_port')) is int and value['target_port']==port and
             value.get('tcp')=='CONNECTED' and
             value.get('protocol_observation')==EXPECTED_FACTS[role] and
             value.get('case_identity') is None and
             value.get('a5_case_binding')=='NOT_ACCREDITED' and
             value.get('a6_condition')=='ND_NO_DECLARED_FAMILY_CONDITION' and
             value.get('verified_vulnerability') is False and
             value.get('smb2_negotiation_accredited') is False and
             type(value.get('response_length')) is int and
             value['response_length']>=0 and
             type(value.get('raw_response_sha256')) is str and
             len(value['raw_response_sha256'])==64,
             'F1_REAL_EVIDENCE_OR_CASE_DRIFT_'+role)
        if role=='smb':need(value['response_length']==0,'F1_SMB2_MUST_REMAIN_ND')
        else:need(value['response_length']>0,'F1_BANNER_LOST_'+role)
        found[role]=value
    return found

def make_report(f1_report:dict, *, f1_report_sha256:str,
                f1_manifest_sha256:str)->dict:
    need(f1_manifest_sha256==F1_MANIFEST_PIN,'F1_MANIFEST_NOT_PINNED')
    need(type(f1_report_sha256) is str and len(f1_report_sha256)==64,
         'F1_REPORT_SHA_INVALID')
    obs=validate_f1_report(f1_report)
    flat=[]
    for role,service,spec,variant in _families():
        fid=spec['id']
        if role=='ssh':
            prec=list(spec['preconditions'])
            supports=list(spec['required_supports'])
            acceptance=list(spec['acceptance_supports'])
            cleanup=spec['cleanup']!='NO_MUTATION'
        else:
            engine=ftp if role=='ftp' else smb
            prec,supports,acceptance,_,cleanup=engine._requirements(spec,variant)
            prec,supports,acceptance=list(prec),list(supports),list(acceptance)
        need(bool(prec) and bool(supports) and bool(acceptance) and
             set(acceptance)<=set(supports) and len(set(supports))==len(supports),
             'CATALOG_REQUIREMENTS_INVALID_'+fid)
        physical=obs[role]
        flat.append({
            'family_id':fid,'service_id':service,'variant':variant,
            'real_source_ip':physical['source_ip'],
            'real_target_ip':physical['target_ip'],
            'real_target_port':physical['target_port'],
            'real_protocol_observation':physical['protocol_observation'],
            'raw_response_sha256':physical['raw_response_sha256'],
            'real_response_bytes':physical['response_length'],
            'catalogue_preconditions':prec,
            'catalogue_required_supports':supports,
            'catalogue_acceptance_supports':acceptance,
            'cleanup_required_for_family':cleanup,
            'preconditions_uncredited_for_A5':prec,
            'required_supports_uncredited_for_A6':supports,
            'candidate_fact_only_no_support_claim':True,
            'derived_case_id':None,'assessment_index':None,
            'a5_start_attested':False,'a5_case_binding':CASELESS,
            'a6_classification':'ND',
            'a6_technical_truth_accredited':False,
            'technical_contribution':None,
            'risk_final':None,
        })
    need(len(flat)==29 and len({x['family_id'] for x in flat})==25,
         'MATRIX_ROW_COUNT_INVALID')
    report={
        'schema':SCHEMA,
        'mode':'PHYSICAL_SOURCE_FAMILY_GAP_REGISTER_NO_A5_OR_A6',
        'source_f1_session':F1_SESSION,
        'source_f1_manifest_sha256':f1_manifest_sha256,
        'source_f1_report_sha256':f1_report_sha256,
        'source_f10r_receipt_sha256':f1.F10R_RECEIPT_SHA,
        'source_catalog_sha256':ssh.CATALOG_SHA256,
        'source_thesis_sha256':ssh.THESIS_SHA256,
        'catalog_status':'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE',
        'real_observations':[{
            'role':r,'source_ip':obs[r]['source_ip'],
            'target_ip':obs[r]['target_ip'],'target_port':obs[r]['target_port'],
            'classification':obs[r]['protocol_observation'],
            'response_sha256':obs[r]['raw_response_sha256'],
            'response_bytes':obs[r]['response_length'],
            'evidence_level':'SERVICE_OBSERVATION_ONLY',
        } for r in ('ssh','ftp','smb')],
        'family_requirements':flat,
        'family_count':25,'variant_path_count':29,
        'required_case_bindings_accredited':0,
        'a5_attempts_started_from_this_intake':0,
        'a6_technical_conditions_admitted':0,
        'blocked_reason':CASELESS,
        'priority_for_independent_evidence_planning':['SSH-T01','FTP-T01','SMB-T01'],
        'network_operations':0,'guest_exec':0,'root_operations':0,
        'technical_truth_accredited':False,
        'confirmed_final_risk':None,
        'risk_recalculation_performed':False,
        'state_transition_applied':False,
        'operational_dispatch':False,'published_generation':None,
        'p8':'NO-GO',
    }
    report['sha256']=digest(canonical(report))
    return report

def verify(report:dict,f1_report:dict,*,f1_report_sha256:str,f1_manifest_sha256:str):
    need(type(report) is dict and type(report.get('sha256')) is str,
         'REPORT_HASH_MISSING')
    need(report==make_report(f1_report,f1_report_sha256=f1_report_sha256,
                             f1_manifest_sha256=f1_manifest_sha256),
         'REPORT_NOT_REPRODUCIBLE')
    return True
