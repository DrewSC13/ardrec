"""R58-F: bind cryptographically attributable witness statements to R58-E.

Ed25519 attribution is not independent physical truth. Keep all A7 units
UNRESOLVED, all A8 decisions advisory and all A9 generations unpublished.
"""
from __future__ import annotations

import re
from typing import Any

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.coordination.r58e_evidence_risk_bridge import build_unit_bridge,verify_unit_bridge
from ardrec.evidence.r58f_signed_witness import admit_signed_witness,verify_signed_witness

SCHEMA='ardrec-r58f-a6-signed-witness-a7-a8-conservative-bridge-v1'
HEX=re.compile(r'[0-9a-f]{64}\Z',re.ASCII)
MAX_BUNDLES=16

class SignedBridgeError(ValueError):
    pass

def need(ok:bool,reason:str):
    if not ok:raise SignedBridgeError(reason)

def _key(u:dict)->tuple[str,str,int]:
    return u['service_id'],u['case_id'],u['assessment_index']

def build_signed_bridge(units:list[dict[str,Any]],bundles:list[dict[str,Any]],*,
                        configuration_hashes:dict[tuple[str,str,int],str],
                        trusted_authorities:dict[str,Any],as_of_utc:str)->dict[str,Any]:
    """Do not turn signed statements into risk, status or dispatch authority."""
    base=build_unit_bridge(units,[])
    verify_unit_bridge(base)
    source=base['inputs']
    allowed={_key(u) for u in source}
    need(type(configuration_hashes) is dict and set(configuration_hashes)==allowed,
         'CONFIGURATION_SCOPE_INCOMPLETE')
    need(all(type(v) is str and HEX.fullmatch(v) for v in configuration_hashes.values()),
         'CONFIGURATION_HASH_INVALID')
    need(type(bundles) is list and len(bundles)<=MAX_BUNDLES,'SIGNED_BUNDLE_COUNT')
    witnessed={}; record_ids=set(); summaries=[]
    for b in bundles:
        need(type(b) is dict and set(b)=={'statement','signatures','support'},
             'BUNDLE_SCHEMA')
        statement=b['statement']
        need(type(statement) is dict and
             {'service_id','case_id','assessment_index'} <= set(statement),'BUNDLE_IDENTITY')
        key=_key(statement)
        need(key in allowed, 'UNBOUND_SIGNED_STATEMENT')
        need(key not in witnessed, 'DUPLICATE_UNIT_WITNESS')
        rid=statement.get('record_id')
        need(type(rid) is str and rid not in record_ids,'DUPLICATE_RECORD_ID')
        expect={'session_id':'DEV_TUTOR_001',
                'service_id':key[0],'case_id':key[1],
                'assessment_index':key[2],
                'configuration_sha256':configuration_hashes[key]}
        review=admit_signed_witness(statement,b['signatures'],trusted_authorities,b['support'],
                                    expected=expect,as_of_utc=as_of_utc)
        verify_signed_witness(review,b['signatures'],trusted_authorities,b['support'],expected=expect)
        witnessed[key]=review
        record_ids.add(rid)
        summaries.append({'service_id':key[0],'case_id':key[1],
                          'assessment_index':key[2],
                          'record_id':rid,'witness_review_sha256':review['sha256'],
                          'statement_sha256':review['statement_sha256'],
                          'support_sha256_verified':review['support_sha256_verified'],
                          'verified_public_keys':[r['public_key_sha256'] for r in review['roles']],
                          'observed_claim_not_accredited':statement['observed_claim'],
                          'attribution_verified':True,'technical_truth_accredited':False})
    summaries.sort(key=lambda x:(x['service_id'],x['case_id'],x['assessment_index']))
    decisions=[]
    for dec in base['decisions']:
        key=_key(dec)
        witness=witnessed.get(key)
        decisions.append({'service_id':key[0],'case_id':key[1],
                          'assessment_index':key[2],
                          'signed_witness_review_sha256':witness['sha256'] if witness else None,
                          'a6_status':('SIGNED_WITNESS_FOR_REVIEW_NOT_ACCREDITED'
                                       if witness else 'NO_SIGNED_WITNESS'),
                          'a6_classification':'ND',
                          'a7_rf_lower':dec['a7_rf_lower'],
                          'a7_rf_upper':dec['a7_rf_upper'],
                          'a7_source':'FULL_UNRESOLVED',
                          'a8_recommendation':dec['a8_recommendation'],
                          'a8_applied_transition':None,
                          'confirmed_rf':None,'confirmed_phase':None})
    doc={'schema':SCHEMA,'source_kind':'SIGNED_DOCUMENTARY_REVIEW_ONLY',
         'as_of_utc':as_of_utc,'r58e_bridge_sha256':base['sha256'],
         'configuration_bindings':[{'service_id':k[0],'case_id':k[1],
                                    'assessment_index':k[2],
                                    'configuration_sha256':configuration_hashes[k]}
                                   for k in sorted(allowed)],
         'witness_reviews':summaries,'decisions':decisions,
         'unit_count':len(source),'signed_witness_count':len(summaries),
         'a7':base['a7'], 'all_a6_nd':True,'technical_truth_accredited':False,
         'signer_independence_physically_attested':False,
         'confirmed_final_risk':None,'published_generation':None,
         'applied_state_transition':None,'operational_dispatch':False,
         'vm_checks_executed':False,'p8_operational':'NO-GO'}
    need(len(canonical(doc))<=262144,'BRIDGE_TOO_LARGE')
    doc['sha256']=digest(doc)
    return doc

def verify_signed_bridge(report:dict[str,Any],units:list[dict[str,Any]],
                         bundles:list[dict[str,Any]],*,
                         configuration_hashes:dict[tuple[str,str,int],str],
                         trusted_authorities:dict[str,Any],as_of_utc:str)->bool:
    need(type(report) is dict and type(report.get('sha256')) is str and
         HEX.fullmatch(report['sha256']) is not None,'REPORT_SCHEMA')
    expected=build_signed_bridge(units,bundles,configuration_hashes=configuration_hashes,
                                 trusted_authorities=trusted_authorities,as_of_utc=as_of_utc)
    need(canonical(report)==canonical(expected),'REPORT_NOT_REPRODUCIBLE')
    return True
