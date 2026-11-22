"""R129-B12: signed FTP-T01 A7 calibration + native A9 *in-memory* preflight.

Follows B11: a copied A6 dict, even if self-consistent, is NOT an independently
attested physical source. Signed calibration authorizes only a mathematical
candidate until an exact root-installed A6 verifier and native state transaction
exist. Never opens a store, publishes, signs, dispatches, or changes host policy.

The A9 structural preflight deliberately invokes the native immutable reducer,
not a second state machine. It is an in-memory rehearsal, NOT a generation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import hashlib
import re

from ardrec.analytics.exact_preview import preview_bounds, verify_bounds, canonical as math_canonical
from ardrec.analytics.r58d_interval_kernel import build_intervals, verify_intervals
from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r129_b11_independent_a6 as b11
from ardrec.persistence import _publish
from ardrec.state import GlobalState, Truth

SCHEMA='ARDREC-R129-B12-FTP-T01-CALIBRATION-A9-PREFLIGHT-v1'
CALIBRATION_SCHEMA=SCHEMA+'-calibration'
REVOCATION_SCHEMA=SCHEMA+'-revocation'
TRUST_SCHEMA=SCHEMA+'-trust'
CALIBRATION_PREFIX=(CALIBRATION_SCHEMA+'\x00').encode('ascii')
REVOCATION_PREFIX=(REVOCATION_SCHEMA+'\x00').encode('ascii')
MAX_SECONDS=60
MAX_REVOCATION_AGE_SECONDS=30
HEX=re.compile('[0-9a-f]{64}\\Z',re.ASCII)
FIELDS_CAL=frozenset(('schema','calibration_id','head','session','case_id',
    'family_id','service_id','assessment_index','a6_sha256','catalog_sha256',
    'measurement_provenance_sha256','initial_risk','criticality',
    'replacement_risk','evidence_contribution','weights','valid_from',
    'valid_until','interpretation_boundary','a9_publication_authorized'))
FIELDS_REV=frozenset(('schema','calibration_sha256','issued_at','valid_until',
                       'revoked','reason_code'))

class Stop(ValueError):
    """Fail-closed constraint violation."""

def need(ok:bool,reason:str)->None:
    if not ok:raise Stop(reason)

def sha(value:dict)->str:
    return f1.digest(f1.canonical(value))

def _utc(raw:Any)->datetime:
    try: t=f1._instant(raw,'B12_TIME')
    except (ValueError,TypeError,f1.Rejected) as exc:
        raise Stop('INVALID_UTC_TIMESTAMP') from exc
    need(t.tzinfo is not None and t.utcoffset() is not None,'CLOCK_NAIVE')
    return t.astimezone(timezone.utc)

def _signer(key:Any)->tuple[str,str]:
    need(type(key) is dict and set(key)=={'key_id','public_key_pem'},
         'SIGNER_FIELDS')
    kid,pem=key['key_id'],key['public_key_pem']
    need(type(kid) is str and f1.ID.fullmatch(kid) and type(pem) is str,
         'SIGNER_ID_OR_PEM')
    try: raw=pem.encode('ascii')
    except UnicodeError as exc: raise Stop('SIGNER_NONASCII') from exc
    need(raw.startswith(b'-----BEGIN PUBLIC KEY-----\n') and
         raw.endswith(b'-----END PUBLIC KEY-----\n') and len(raw)<=1024,
         'SIGNER_PEM_INVALID')
    return kid,hashlib.sha256(raw).hexdigest()

def _trust(trust:dict,b11_trust:dict)->tuple[dict,dict]:
    need(type(trust) is dict and set(trust)=={
        'schema','calibration_signer','revocation_signer'},'TRUST_FIELDS')
    need(trust['schema']==TRUST_SCHEMA,'TRUST_SCHEMA')
    b11.trust_check(b11_trust)
    keys=[_signer(trust[k]) for k in ('calibration_signer','revocation_signer')]
    keys.extend(_signer(b11_trust[k]) for k in (
        'source_signer','technical_signer','revocation_signer'))
    need(len({k[0] for k in keys})==5 and
         len({k[1] for k in keys})==5,'SIGNERS_NOT_DISTINCT_FROM_A6')
    return trust['calibration_signer'],trust['revocation_signer']

def _wrapper(value:Any,fields:frozenset[str],reason:str)->dict:
    need(type(value) is dict and set(value)=={
        'statement','signer_key_id','signature_b64'},reason+'_WRAPPER')
    statement=value['statement']
    need(type(statement) is dict and set(statement)==fields,reason+'_FIELDS')
    return statement

def preview_signed(*,admission:dict,calibration:dict,revocation:dict,
                   trust:dict,b11_trust:dict,now:datetime,
                   catalog_sha256:str)->dict:
    """Verify signatures and recompute A7; always label provenance documentary.

    Even an authentic B11 dict can be copied and supplied by an adversary.
    This function has no root-readback, and must NEVER return confirmed Rf.
    """
    need(type(now) is datetime and now.tzinfo is not None and
         now.utcoffset() is not None,'CLOCK_REQUIRED')
    now=now.astimezone(timezone.utc)
    need(type(catalog_sha256) is str and HEX.fullmatch(catalog_sha256),
         'CATALOG_DIGEST_REQUIRED')
    need(type(admission) is dict and
         admission.get('schema')==b11.SCHEMA+'-physical-admission' and
         admission.get('sha256')==sha({k:v for k,v in admission.items() if k!='sha256'}) and
         admission.get('a6')=='VERDADERO' and
         admission.get('a6_scope')=='FTP_T01_CONTROL_CONNECTIVITY_ONLY' and
         admission.get('technical_condition')=='FTP_T01_CONTROL_CONNECTION_CONFIRMED' and
         admission.get('root_b9_original_bytes_replayed') is True and
         admission.get('root_r127_crash_restoration_verified') is True and
         admission.get('a7_rf_confirmed') is None and
         admission.get('a8_transition_applied') is None and
         admission.get('a9_generation') is None and
         admission.get('p8')=='NO-GO','A6_DOCUMENT_NOT_VALID_SHAPE')
    signer,rev_signer=_trust(trust,b11_trust)
    stmt=_wrapper(calibration,FIELDS_CAL,'CALIBRATION')
    need(stmt['schema']==CALIBRATION_SCHEMA and
         type(stmt['calibration_id']) is str and f1.ID.fullmatch(stmt['calibration_id']) and
         type(stmt['head']) is str and f1.GIT_SHA.fullmatch(stmt['head']) and
         stmt['head']==admission['head'] and
         stmt['session']==admission['session'] and
         stmt['case_id']==admission['case_id'] and
         stmt['a6_sha256']==admission['sha256'] and
         stmt['family_id']=='FTP-T01' and
         stmt['service_id']=='FTP_DEV' and
         type(stmt['assessment_index']) is int and 0<=stmt['assessment_index']<2**31 and
         stmt['catalog_sha256']==catalog_sha256 and
         type(stmt['measurement_provenance_sha256']) is str and
         HEX.fullmatch(stmt['measurement_provenance_sha256']) and
         stmt['interpretation_boundary']=='CONTROL_CONNECTIVITY_ONLY_NO_VULNERABILITY' and
         stmt['a9_publication_authorized'] is False,
         'CALIBRATION_SCOPE_OR_IDENTITY_MISMATCH')
    start,end=_utc(stmt['valid_from']),_utc(stmt['valid_until'])
    need(start<=now<end and 0<(end-start).total_seconds()<=MAX_SECONDS,
         'CALIBRATION_NOT_CURRENT')
    rw=_wrapper(revocation,FIELDS_REV,'REVOCATION')
    need(rw['schema']==REVOCATION_SCHEMA and
         rw['calibration_sha256']==sha(calibration) and
         type(rw['revoked']) is bool and rw['revoked'] is False and
         type(rw['reason_code']) is str and f1.ID.fullmatch(rw['reason_code']),
         'REVOCATION_SCOPE_OR_STATUS')
    rstart,rend=_utc(rw['issued_at']),_utc(rw['valid_until'])
    need(rstart<=now<rend and rend>rstart and
         0<=(now-rstart).total_seconds()<=MAX_REVOCATION_AGE_SECONDS,
         'REVOCATION_STALE')
    try:
        f3.verified_signature(calibration,stmt,signer,CALIBRATION_PREFIX)
        f3.verified_signature(revocation,rw,rev_signer,REVOCATION_PREFIX)
    except (f3.Stop,ValueError,TypeError,KeyError) as exc:
        raise Stop('CALIBRATION_SIGNATURE_REJECTED') from exc
    try:
        values=(stmt['initial_risk'],stmt['criticality'],
                stmt['replacement_risk'],stmt['evidence_contribution'])
        need(type(stmt['weights']) is list and len(stmt['weights'])==3,
             'WEIGHTS_SCHEMA')
        exact=preview_bounds(values[0],values[1],[values[3]],values[2],
                             weights=tuple(stmt['weights']))
        verify_bounds(exact)
        interval=build_intervals([{
           'service_id':'FTP_DEV','case_id':stmt['case_id'],
           'assessment_index':stmt['assessment_index'],
           'initial_risk':values[0], 'normalized_criticality':values[1],
           'replacement_risk':values[2],
           'evidence':[{'evidence_id':'FTP_T01_SIGNED_CALIBRATION',
                        'kind':'SYNTHETIC_FIXED','lower':values[3],
                        'upper':values[3]}],
           }],weights=tuple(stmt['weights']))
        verify_intervals(interval)
    except (ValueError,TypeError,KeyError) as exc:
        raise Stop('CALIBRATION_MATHEMATICAL_CONTRACT_REJECTED') from exc
    proof=interval['results'][0]
    need(proof['point_identified'] is True and
         proof['rf_lower']==proof['rf_upper']==exact['hypothetical_rf'],
         'A7_ORACLES_DISAGREE')
    report={'schema':SCHEMA+'-documentary-a7-review',
        'head':stmt['head'],'session':stmt['session'],'case_id':stmt['case_id'],
        'service_id':'FTP_DEV','family_id':'FTP-T01',
        'assessment_index':stmt['assessment_index'],
        'a6_copy_sha256':admission['sha256'],
        'calibration_sha256':sha(calibration),
        'revocation_sha256':sha(revocation),
        'catalog_sha256':catalog_sha256,
        'measurement_provenance_sha256':stmt['measurement_provenance_sha256'],
        'calibration_signatures_verified':True,
        'exact_preview_sha256':exact['sha256'],
        'exact_interval_sha256':interval['sha256'],
        'a7_math_candidate':exact['hypothetical_rf'],
        'a7_point_candidate_not_proven':True,
        'a6':'ND','confirmed_rf':None,
        'a8_transition_applied':None,'a9_generation':None,
        'a9_native_transaction_executed':False,
        'physical_provenance_reverified_here':False,
        'source_kind':'SIGNED_DOCUMENTARY_CALIBRATION_AND_MATH_ONLY',
        'p8':'NO-GO'}
    report['sha256']=sha(report)
    need(len(math_canonical(report))<=16384,'REPORT_TOO_LARGE')
    return report

def native_publish_preflight(*,state:GlobalState,expected_generation:int,
                             reference:str,event:str)->dict:
    """Apply the native immutable A9 reducer without a durable write.

    No external signer's assurance and no technical risk is conferred.
    Only a subsequent independent native transaction can make a generation.
    """
    need(type(state) is GlobalState,'NATIVE_STATE_REQUIRED')
    need(state.authority is Truth.VERDADERO and state.simulation is False,
         'NATIVE_AUTHORITATIVE_STATE_REQUIRED')
    need(type(expected_generation) is int,'GENERATION_TYPE')
    try: candidate=_publish(state,expected_generation,reference,event)
    except (ValueError,TypeError,KeyError) as exc:
        raise Stop('NATIVE_A9_PUBLICATION_GUARD_REJECTED') from exc
    need(candidate.confirmed.generation==expected_generation+1 and
         candidate.confirmed.generation_reference==reference and
         candidate.confirmed.incorporated_events[-1]==event,
         'NATIVE_PREVIEW_RESULT_INVALID')
    return {'schema':SCHEMA+'-native-a9-inmemory-preflight',
        'record_id':state.confirmed.record_id,
        'expected_generation':expected_generation,
        'candidate_generation':candidate.confirmed.generation,
        'candidate_reference':reference,'event_reference':event,
        'native_reducer_checked':True,
        'durable_store_opened':False,'generation_written':False,
        'technical_risk_published':False,'p8':'NO-GO'}

def capabilities()->dict:
    return {'schema':SCHEMA+'-capabilities',
       'independent_calibration_and_revocation_signers':True,
       'requires_distinct_from_three_b11_signers':True,
       'maximum_calibration_seconds':MAX_SECONDS,
       'maximum_revocation_age_seconds':MAX_REVOCATION_AGE_SECONDS,
       'a7_math_r58d_and_exact_preview_crosscheck':True,
       'documentary_a6_is_not_live_root_attestation':True,
       'synthetic_fixed_interval_is_not_physical_measurement':True,
       'native_durable_store_reducer_preflight':True,
       'native_a9_generation_written':False,
       'actual_a8_transition_applied':False,
       'risk_without_live_calibration_confirmed':None,
       'network_connections':0,'vm_starts':0,'nft_writes':0,
       'a6':'ND','a9':None,'p8':'NO-GO'}
