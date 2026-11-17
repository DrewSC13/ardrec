"""R59-G: bind Ed25519 documentary witness signatures to an immutable A5-v2 receipt.

The signatures bind *what was declared*, not whether the attempt ran or the
technical finding is true. An external trust-registry SHA-256 pin is mandatory.
No guest I/O, authority escalation, A6 promotion, A7, A9, or P8 transition.
"""
from __future__ import annotations

from datetime import timedelta
import json
import os
from pathlib import Path
from typing import Any

from ardrec.coordination import r59d_a5_result_intake as d
from ardrec.coordination import r59f_variant_origin as v2
from ardrec.evidence import r58f_signed_witness as witness
from ardrec.evidence import r58g_trust_registry as registry

SCHEMA_STATEMENT = 'ardrec-r59g-a5-v2-signed-declaration-v1'
SCHEMA_REVIEW = 'ardrec-r59g-a5-v2-two-signature-documentary-review-v1'
PREFIX = b'ARDREC-R59G-A5-V2-DECLARED-RESULT-V1\x00'
STATEMENT_FIELDS = frozenset({
    'schema','v2_report_sha256','legacy_candidate_sha256','a6_bridge_sha256',
    'v2_intent_sha256','service_id','session_id','family_id','derived_case_id',
    'assessment_index','attempt_id','variant','configuration_sha256','method_id',
    'declared_outcome','declared_started_at_utc','declared_finished_at_utc',
    'support_sha256','support_bytes','source_catalog_sha256','p8_operational',
})
REVIEW_FIELDS = frozenset({
    'schema','decision','statement','statement_signed_sha256',
    'signatures','registry_sha256_pinned','registry_campaign_id',
    'review_at_utc','verified_roles','cryptographic_attribution_verified',
    'independent_physical_origin_attested','a5_physical_start_accredited',
    'a5_case_binding_physically_attested','technical_truth_accredited',
    'a6_classification','confirmed_final_risk','published_generation',
    'operational_dispatch','p8_operational','sha256',
})
MAX_REPORT = 65536
MAX_REVIEW_AGE = timedelta(hours=24)

class SignedA5Error(ValueError):
    """Failure of exact case, signature, registry, timestamp or source binding."""

def need(ok: bool, reason: str) -> None:
    if not ok:
        raise SignedA5Error(reason)

def _roots(*roots: Path) -> None:
    for root in roots:
        d._private_root(root)
    need(len({(p.stat().st_dev,p.stat().st_ino) for p in roots})==len(roots),
         'SOURCE_AND_OUTPUT_DIRECTORIES_MUST_DIFFER')

def _v2(v2_root: Path,a5_root: Path,a6_root: Path, attempt_id: str) -> dict[str,Any]:
    _roots(v2_root,a5_root,a6_root)
    doc=v2.verify_stored(v2_root,a5_root,a6_root,attempt_id)
    need(doc['schema']==v2.SCHEMA_REPORT and
         doc['a5_start_independently_attested'] is False and
         doc['technical_truth_accredited'] is False and
         doc['a6_classification']=='ND' and
         doc['published_generation'] is None and
         doc['p8_operational']=='NO-GO', 'V2_UPSTREAM_AUTHORITY_INVALID')
    return doc

def statement_for(doc: dict[str,Any]) -> dict[str,Any]:
    """Domain-separated statement covers full v2 identity, variant and support."""
    need(type(doc) is dict and doc.get('schema')==v2.SCHEMA_REPORT and
         d._hex(doc.get('sha256')) and
         doc.get('p8_operational')=='NO-GO' and
         doc.get('a6_classification')=='ND' and
         doc.get('a5_start_independently_attested') is False,
         'V2_REPORT_INVALID')
    i=doc['intent'];r=doc['receipt']
    need(r['declared_outcome']!='NO_START' and
         r['source_kind']=='EXTERNAL_UNVERIFIED' and
         type(r['support_bytes']) is int and r['support_bytes']>0,
         'UNSIGNED_OR_NO_START_CANNOT_BE_A_WITNESS_RESULT')
    need(r['physical_authority_receipt_sha256'] is None and
         i['sha256']==r['v2_intent_sha256'] and i['variant']==r['variant'],
         'ORIGIN_VARIANT_OR_AUTHORITY_INVALID')
    for key in v2.IDENTITY:
        need(i[key]==r[key], 'V2_IDENTITY_RECEIPT_DRIFT:'+key)
    doc_fields={
        'schema':SCHEMA_STATEMENT,
        'v2_report_sha256':doc['sha256'],
        'legacy_candidate_sha256':doc['legacy_candidate_sha256'],
        'a6_bridge_sha256':doc['source_bridge_sha256'],
        'v2_intent_sha256':i['sha256'],
        **{key:i[key] for key in v2.IDENTITY},
        'variant':i['variant'],
        'declared_outcome':r['declared_outcome'],
        'declared_started_at_utc':r['declared_started_at_utc'],
        'declared_finished_at_utc':r['declared_finished_at_utc'],
        'support_sha256':r['support_sha256'],
        'support_bytes':r['support_bytes'],
        'source_catalog_sha256':i['source_catalog_sha256'],
        'p8_operational':'NO-GO',
    }
    need(set(doc_fields)==STATEMENT_FIELDS,'SIGNED_STATEMENT_SCHEMA_INTERNAL')
    need(len(d.canonical(doc_fields))<=8192,'SIGNED_STATEMENT_TOO_LARGE')
    return doc_fields

def signing_bytes(statement: dict[str,Any]) -> bytes:
    need(type(statement) is dict and set(statement)==STATEMENT_FIELDS and
         statement.get('schema')==SCHEMA_STATEMENT and
         statement.get('p8_operational')=='NO-GO' and
         statement.get('declared_outcome') in d.OUTCOMES-{'NO_START'} and
         d._hex(statement.get('v2_report_sha256')),
         'SIGNED_STATEMENT_FIELDS')
    return PREFIX+d.canonical(statement)

def _registry_scope(reg:dict[str,Any], doc:dict[str,Any]) -> None:
    intent=doc['intent']
    need(reg['session_id']==intent['session_id'], 'REGISTRY_SESSION_MISMATCH')
    expected={key:intent[key] for key in (
        'service_id','derived_case_id','assessment_index',
        'configuration_sha256','method_id')}
    expected['case_id']=expected.pop('derived_case_id')
    matches=[row for row in reg['scope'] if row==expected]
    need(len(matches)==1,'REGISTRY_CASE_SCOPE_NOT_PINNED')

def build_review(v2_root:Path,a5_root:Path,a6_root:Path,attempt_id:str,*,
                 signatures:dict[str,Any],registry_document:dict[str,Any],
                 registry_pin_sha256:str,review_at_utc:str) -> dict[str,Any]:
    """Verify source replay and two Ed25519 signatures with independent pin.

    Does not infer physical execution or case truth from keys or signed claims.
    """
    doc=_v2(v2_root,a5_root,a6_root,attempt_id)
    statement=statement_for(doc)
    registry.validate_registry(registry_document,pinned_sha256=registry_pin_sha256)
    _registry_scope(registry_document,doc)
    started=registry.utc(statement['declared_started_at_utc'])
    finished=registry.utc(statement['declared_finished_at_utc'])
    review=registry.utc(review_at_utc)
    need(started<=finished<=review and review-finished<=MAX_REVIEW_AGE,
         'REVIEW_OUTSIDE_DECLARED_FINISH_WINDOW')
    # Require the entire declared attempt window inside the pinned campaign.
    need(registry.utc(registry_document['window_start_utc'])<=started and
         finished<=registry.utc(registry_document['window_end_utc']),
         'DECLARED_ATTEMPT_OUTSIDE_CAMPAIGN')
    trust=registry.trusted_for_capture(registry_document,
                                      pinned_sha256=registry_pin_sha256,
                                      captured_at_utc=statement['declared_finished_at_utc'],
                                      review_at_utc=review_at_utc)
    signed=signing_bytes(statement)
    roles=witness._signature_data(signatures,trust,signed)
    need(len(roles)==2 and [r['role'] for r in roles]==list(witness.ROLES),
         'SIGNATURE_ROLE_COUNT')
    report={
        'schema':SCHEMA_REVIEW,
        'decision':'SIGNED_DECLARATION_BOUND_TO_VERIFIED_A5_V2_ONLY',
        'statement':statement,
        'statement_signed_sha256':d.sha(signed),
        'signatures':signatures,
        'registry_sha256_pinned':registry_pin_sha256,
        'registry_campaign_id':registry_document['campaign_id'],
        'review_at_utc':review_at_utc,
        'verified_roles':roles,
        'cryptographic_attribution_verified':True,
        'independent_physical_origin_attested':False,
        'a5_physical_start_accredited':False,
        'a5_case_binding_physically_attested':False,
        'technical_truth_accredited':False,
        'a6_classification':'ND',
        'confirmed_final_risk':None,
        'published_generation':None,
        'operational_dispatch':False,
        'p8_operational':'NO-GO',
    }
    need(set(report)|{'sha256'}==REVIEW_FIELDS,'SIGNED_REVIEW_SCHEMA_INTERNAL')
    need(len(d.canonical(report)) < MAX_REPORT-100,'SIGNED_REVIEW_TOO_LARGE')
    report['sha256']=d.digest(report)
    return report

def _file(attempt_id:str) -> str:
    need(type(attempt_id) is str and d.ATTEMPT.fullmatch(attempt_id) is not None,
         'ATTEMPT_ID_INVALID')
    return 'r59g-signed-'+d.sha(b'ARDREC-R59G-SIGNED-ATTEMPT-V1\0'+attempt_id.encode('ascii'))+'.json'

def _load(root:Path,attempt_id:str) -> dict[str,Any]:
    raw=d._read_private(root/_file(attempt_id),MAX_REPORT)
    try:doc=json.loads(raw,object_pairs_hook=d._pairs)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise SignedA5Error('SIGNED_RECORD_INVALID_JSON') from exc
    need(type(doc) is dict and raw==d.canonical(doc)+b'\n' and
         set(doc)==REVIEW_FIELDS,'SIGNED_RECORD_NOT_CANONICAL_OR_SCHEMA')
    return doc

def verify_stored(output_root:Path,v2_root:Path,a5_root:Path,a6_root:Path,
                  attempt_id:str,*,registry_path:Path,
                  registry_pin_sha256:str) -> dict[str,Any]:
    _roots(output_root,v2_root,a5_root,a6_root)
    doc=_load(output_root,attempt_id)
    need(doc['registry_sha256_pinned']==registry_pin_sha256,
         'EXTERNAL_REGISTRY_PIN_CHANGED')
    reg=registry.read_pinned_registry(registry_path,pinned_sha256=registry_pin_sha256)
    expected=build_review(v2_root,a5_root,a6_root,attempt_id,
                          signatures=doc['signatures'],registry_document=reg,
                          registry_pin_sha256=registry_pin_sha256,
                          review_at_utc=doc['review_at_utc'])
    need(d.canonical(doc)==d.canonical(expected),
         'SIGNED_REVIEW_OR_PERSISTED_SOURCE_CHANGED')
    return doc

def persist(output_root:Path,v2_root:Path,a5_root:Path,a6_root:Path,
            attempt_id:str,*,signatures:dict[str,Any],registry_path:Path,
            registry_pin_sha256:str,review_at_utc:str) -> dict[str,Any]:
    """Private, immutable signed review; readback with external registry pin."""
    _roots(output_root,v2_root,a5_root,a6_root)
    reg=registry.read_pinned_registry(registry_path,pinned_sha256=registry_pin_sha256)
    doc=build_review(v2_root,a5_root,a6_root,attempt_id,
                     signatures=signatures,registry_document=reg,
                     registry_pin_sha256=registry_pin_sha256,
                     review_at_utc=review_at_utc)
    action=d._store_once(output_root/_file(attempt_id),d.canonical(doc)+b'\n',MAX_REPORT)
    fd=os.open(output_root,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
    try:os.fsync(fd)
    finally:os.close(fd)
    verify_stored(output_root,v2_root,a5_root,a6_root,attempt_id,
                  registry_path=registry_path,registry_pin_sha256=registry_pin_sha256)
    return {'status':action,'signed_review_sha256':doc['sha256'],
            'cryptographic_attribution_verified':True,
            'a5_physical_start_accredited':False,
            'a6_classification':'ND','p8_operational':'NO-GO'}
