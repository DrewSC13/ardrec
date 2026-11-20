"""R114-F3: three *real* asset anchors and 29 non-operational family candidates.

Source is a replay-verified R114-F2 matrix and a separately SHA-pinned 2026
R113-F2 QGA IPv4/MAC proof. Candidate identifiers are not thesis case IDs,
not A5 attempts and not A6 facts; risk is deliberately uncomputed.
"""
from __future__ import annotations
import hashlib
import json
import re
from typing import Any
from ardrec.coordination import r113_f2_agent_ip_identity as identity_core
from ardrec.coordination import r114_f2_family_gap as gap

SCHEMA='ARDREC-R114-F3-REAL-ASSET-ANCHORS-CASE-PLANNING-v1'
F2_MATRIX_MANIFEST_PIN='8c8b06bd79828db5fb150ae8219ed3dd97a7f10ade0c19cbebb27c7e956fa57e'
F2_MATRIX_REPORT_PIN='05d3f2415228386a250f7a8f38cc77d86c3bead5de0f6550226fe916d21a1c85'
R113_F2_IDENTITY_MANIFEST_PIN='84e81025cac7180619edd530765052576a6726efe304ec3247bab68075df810b'
MATRIX_RECEIPT='/home/cicada/ardrec-lab/r114-f2-family-evidence-gaps-v1/matrix-b7f856d1'
IDENTITY_RECEIPT='/home/cicada/ardrec-lab/r113-f2-agent-ip-identity-v1/proof-c40akbko'
ROWS_BY_ROLE={'ssh':8,'ftp':10,'smb':11}
SERVICE_BY_ROLE={'ssh':'SSH_DEV','ftp':'FTP_DEV','smb':'SMB_DEV'}
TCP_PORTS={'ssh':22,'ftp':21,'smb':445}
ALGORITHM_CODES=tuple('A'+str(n) for n in range(1,11))
ALGORITHM_BOUNDARIES={
 'A1':'SOURCE_OBSERVATION_REGISTERED_NO_A5',
 'A2':'PINNED_CATALOG_REQUIREMENTS_ONLY',
 'A3':'NO_APPLIED_STATE_TRANSITION',
 'A4':'NO_FAMILY_EXECUTION_DISPATCH',
 'A5':'NO_ATTEMPT_RESERVED_OR_STARTED',
 'A6':'ND_NO_ADMITTED_CONDITION',
 'A7':'NO_CONFIRMED_RF_OR_RISK_RECALCULATION',
 'A8':'NO_APPLIED_TRANSITION',
 'A9':'NO_PUBLISHED_GENERATION',
 'A10':'PRIVATE_REPLAY_AVAILABLE_NOT_ALGORITHM_EXECUTED',
}

class AnchorError(ValueError):pass

def need(ok:bool, reason:str)->None:
 if not ok:raise AnchorError(reason)

def canonical(value:Any)->bytes:
 return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')

def digest(raw:bytes)->str:return hashlib.sha256(raw).hexdigest()

def _is_hex(value:Any)->bool:
 return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None

def _fingerprint(label:str,parts:list[str])->str:
 return label+'_'+digest(canonical(parts))[:32].upper()

def validate_identity(ident:dict)->dict:
 need(type(ident) is dict and ident.get('schema')==identity_core.SCHEMA and
      ident.get('verified_interface_count')==6 and
      ident.get('verified_network_count')==3 and
      ident.get('source')=='real_qemu_guest_agent_mac_bound' and
      ident.get('services_tested') is False and
      ident.get('traffic_authorized') is False and
      ident.get('p8_operational')=='NO-GO','PHYSICAL_IDENTITY_AUTHORITY_OR_SCHEMA_DRIFT')
 expected={role:{net:{'mac':mac,'ipv4_cidr':cidr,'bridge':identity_core.BRIDGES[net]}
                 for net,(mac,cidr) in nets.items()}
           for role,nets in identity_core.EXPECTED.items()}
 need(ident.get('endpoints')==expected,'PHYSICAL_MAC_IP_NETWORK_DRIFT')
 return expected

def validate_matrix(matrix:dict)->dict[str,list[dict]]:
 need(type(matrix) is dict and matrix.get('schema')==gap.SCHEMA and
      matrix.get('mode')=='PHYSICAL_SOURCE_FAMILY_GAP_REGISTER_NO_A5_OR_A6' and
      matrix.get('source_f1_manifest_sha256')==gap.F1_MANIFEST_PIN and
      matrix.get('source_f10r_receipt_sha256')==gap.f1.F10R_RECEIPT_SHA and
      matrix.get('source_catalog_sha256')==gap.ssh.CATALOG_SHA256 and
      matrix.get('source_thesis_sha256')==gap.ssh.THESIS_SHA256 and
      matrix.get('family_count')==25 and matrix.get('variant_path_count')==29 and
      matrix.get('required_case_bindings_accredited')==0 and
      matrix.get('a5_attempts_started_from_this_intake')==0 and
      matrix.get('a6_technical_conditions_admitted')==0 and
      matrix.get('technical_truth_accredited') is False and
      matrix.get('risk_recalculation_performed') is False and
      matrix.get('confirmed_final_risk') is None and
      matrix.get('state_transition_applied') is False and
      matrix.get('published_generation') is None and
      matrix.get('operational_dispatch') is False and
      matrix.get('p8')=='NO-GO', 'MATRIX_AUTHORITY_OR_CATALOG_CHANGED')
 need(matrix.get('sha256')==digest(canonical({k:v for k,v in matrix.items() if k!='sha256'})),
      'MATRIX_INNER_SHA256_INVALID')
 rows=matrix.get('family_requirements')
 need(type(rows) is list and len(rows)==29,'MATRIX_ROWS_NOT_29')
 by_role={r:[] for r in ROWS_BY_ROLE}
 unique=set()
 obs={o.get('role'):o for o in matrix.get('real_observations',[]) if type(o) is dict}
 need(set(obs)==set(ROWS_BY_ROLE) and len(matrix.get('real_observations'))==3,
      'MATRIX_REAL_OBSERVATIONS_INVALID')
 for row in rows:
  need(type(row) is dict,'MATRIX_ROW_NOT_OBJECT')
  service=row.get('service_id')
  need(service in SERVICE_BY_ROLE.values(),'MATRIX_UNEXPECTED_SERVICE')
  role=next(r for r,s in SERVICE_BY_ROLE.items() if s==service)
  family=row.get('family_id');variant=row.get('variant')
  need(type(family) is str and re.fullmatch(role.upper()+'-T[0-9]{2}',family) is not None and
       (variant is None or type(variant) is str), 'FAMILY_VARIANT_ID_INVALID')
  key=(family,variant)
  need(key not in unique,'FAMILY_VARIANT_DUPLICATE')
  unique.add(key)
  o=obs[role]
  need(row.get('real_source_ip')==o.get('source_ip') and
       row.get('real_target_ip')==o.get('target_ip') and
       row.get('real_target_port')==o.get('target_port') and
       row.get('real_protocol_observation')==o.get('classification') and
       row.get('raw_response_sha256')==o.get('response_sha256') and
       row.get('real_response_bytes')==o.get('response_bytes') and
       row.get('derived_case_id') is None and
       row.get('assessment_index') is None and
       row.get('a5_start_attested') is False and
       row.get('a6_classification')=='ND' and
       row.get('a6_technical_truth_accredited') is False and
       row.get('technical_contribution') is None and
       row.get('risk_final') is None and
       row.get('candidate_fact_only_no_support_claim') is True and
       row.get('a5_case_binding')==gap.CASELESS,
       'MATRIX_PHYSICAL_FACT_OR_CASE_PROMOTION_'+role)
  for a,b in [('catalogue_preconditions','preconditions_uncredited_for_A5'),
              ('catalogue_required_supports','required_supports_uncredited_for_A6')]:
   need(type(row.get(a)) is list and len(row[a])>0 and row[a]==row.get(b),
        'REQUIREMENT_CLAIMED_WITHOUT_EVIDENCE_'+role)
  by_role[role].append(row)
 need({r:len(v) for r,v in by_role.items()}==ROWS_BY_ROLE,'FAMILY_VARIANT_COUNTS_DRIFT')
 expected_obs={
    'ssh':('10.203.30.1','10.203.30.2',22,'SSH_IDENTIFICATION_BANNER_OBSERVED',True),
    'ftp':('10.203.31.1','10.203.31.2',21,'FTP_220_CONTROL_GREETING_OBSERVED',True),
    'smb':('10.203.32.1','10.203.32.2',445,'SMB_TCP_CONNECTED_NO_SMB2_RESPONSE_VERIFIED',False),
 }
 for role,(src,dst,port,cls,nonzero) in expected_obs.items():
  o=obs[role]
  need((o.get('source_ip'),o.get('target_ip'),o.get('target_port'),o.get('classification'))==
       (src,dst,port,cls) and _is_hex(o.get('response_sha256')) and
       type(o.get('response_bytes')) is int and
       (o['response_bytes']>0 if nonzero else o['response_bytes']==0) and
       o.get('evidence_level')=='SERVICE_OBSERVATION_ONLY',
       'SOURCE_OBSERVATION_CHANGED_'+role)
 return by_role

def make_report(matrix:dict, ident:dict, *, matrix_manifest_sha256:str,
                identity_manifest_sha256:str, matrix_report_sha256:str)->dict:
 need(matrix_manifest_sha256==F2_MATRIX_MANIFEST_PIN and
      matrix_report_sha256==F2_MATRIX_REPORT_PIN and
      identity_manifest_sha256==R113_F2_IDENTITY_MANIFEST_PIN,
      'PINNED_SOURCE_RECEIPT_SHA256_INVALID')
 expected=validate_identity(ident)
 by_role=validate_matrix(matrix)
 service=[];candidates=[]
 for role in ('ssh','ftp','smb'):
  net=role
  guest=expected[role][net]
  runner=expected['runner'][net]
  mrows=by_role[role]
  first=mrows[0]
  need(first['real_source_ip']+'/28'==runner['ipv4_cidr'] and
       first['real_target_ip']+'/28'==guest['ipv4_cidr'],
       'IP_PROOF_NOT_THE_OBSERVED_SERVICE_'+role)
  anchor_id=_fingerprint('ASSET',[matrix_report_sha256,identity_manifest_sha256,
                                  role,guest['mac'],guest['ipv4_cidr']])
  service.append({
    'asset_anchor_id':anchor_id,'role':role,'service_id':SERVICE_BY_ROLE[role],
    'runner_vm':'ardrec-r33-dev-runner',
    'target_vm':'ardrec-r33-dev-'+role,
    'runner_mac':runner['mac'],'runner_ipv4_cidr':runner['ipv4_cidr'],
    'target_mac':guest['mac'],'target_ipv4_cidr':guest['ipv4_cidr'],
    'bridge':guest['bridge'],'tcp_port':TCP_PORTS[role],
    'tcp_real_observed':True,
    'protocol_fact':first['real_protocol_observation'],
    'response_sha256':first['raw_response_sha256'],
    'response_bytes':first['real_response_bytes'],
    'protocol_negotiation_admitted':False,
    'a5_case_binding_accredited':False,
    'a6_condition':'ND','confirmed_rf':None,'p8':'NO-GO'
  })
  for row in mrows:
   candidate_id=_fingerprint('PLAN',[anchor_id,row['family_id'],
            row['variant'] if row['variant'] is not None else 'NONE',matrix_report_sha256])
   candidates.append({
    'candidate_planning_id':candidate_id,
    'asset_anchor_id':anchor_id,
    'family_id':row['family_id'],'service_id':row['service_id'],
    'variant':row['variant'],
    'catalogue_preconditions_not_attested':row['catalogue_preconditions'],
    'catalogue_required_supports_not_admitted':row['catalogue_required_supports'],
    'catalogue_acceptance_supports_not_admitted':row['catalogue_acceptance_supports'],
    'cleanup_required_if_future_authorized_attempt':row['cleanup_required_for_family'],
    'case_id_a5':None,'derived_case_id':None,'assessment_index':None,
    'attempt_id':None,'a5_attempt_started':False,'a6_classification':'ND',
    'confirmed_rf':None,'operational_dispatch':False,
    'source_observation_only':True,
   })
 need(len(service)==3 and len(candidates)==29 and
      len({x['asset_anchor_id'] for x in service})==3 and
      len({x['candidate_planning_id'] for x in candidates})==29,
      'ANCHOR_OR_CANDIDATE_COLLISION')
 report={
  'schema':SCHEMA,
  'mode':'REAL_PHYSICAL_ASSETS_AND_NONOPERATIONAL_CASE_PLANNING',
  'source_matrix_receipt':MATRIX_RECEIPT,
  'source_matrix_manifest_sha256':matrix_manifest_sha256,
  'source_matrix_report_sha256':matrix_report_sha256,
  'source_identity_receipt':IDENTITY_RECEIPT,
  'source_identity_manifest_sha256':identity_manifest_sha256,
  'source_f1_manifest_sha256':matrix['source_f1_manifest_sha256'],
  'source_f10r_root_sha256':matrix['source_f10r_receipt_sha256'],
  'source_catalog_sha256':matrix['source_catalog_sha256'],
  'source_thesis_sha256':matrix['source_thesis_sha256'],
  'assets':service,'case_planning_candidates':candidates,
  'asset_count':3,'candidate_count':29,'catalogue_family_count':25,
  'family_variants_count':29,
  'a1_to_a10_authority_boundaries':ALGORITHM_BOUNDARIES.copy(),
  'algorithms_operationally_executed':[],
  'a5_case_bindings_accredited':0,'a5_starts':0,
  'a6_admitted_conditions':0,'a6_classification':'ND',
  'a7_risk_recalculated':False,'confirmed_final_risk':None,
  'a8_transitions_applied':0,'a9_published_generation':None,
  'new_guest_exec':0,'new_network_calls':0,'new_root_calls':0,
  'p8':'NO-GO'
 }
 report['sha256']=digest(canonical(report))
 return report

def verify(report:dict,matrix:dict,identity:dict,*,matrix_manifest_sha256:str,
           identity_manifest_sha256:str,matrix_report_sha256:str)->bool:
 need(type(report) is dict and _is_hex(report.get('sha256')),
      'F3_REPORT_SHA256_MISSING')
 need(report==make_report(matrix,identity,
      matrix_manifest_sha256=matrix_manifest_sha256,
      identity_manifest_sha256=identity_manifest_sha256,
      matrix_report_sha256=matrix_report_sha256),
      'F3_REPORT_NOT_REPRODUCIBLE')
 return True
