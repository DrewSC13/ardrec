"""R59-E — strict, read-only R59-D A5 candidate -> P7/R58-H/I/J A6 preview.

No independent physical attestation, no A5 start, no A6 accreditation, no
final risk, no state transition, no A9 publication and no P8 authorization.
A declared variant is a frozen REVIEW sidecar, not part of original A5 intent.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json
import os
from typing import Any

from ardrec.coordination import r59d_a5_result_intake as a5

SCHEMA = 'ardrec-r59e-a5-to-p7-family-a6-conservative-bridge-v1'
REVIEW_SCHEMA = 'ardrec-r59e-unattested-family-review-v1'
MODE = 'DECLARED_A5_TO_SYNTHETIC_A6_NO_TECHNICAL_AUTHORITY'
FAMILY_COUNTS = {'SSH_DEV': 8, 'FTP_DEV': 8, 'SMB_DEV': 9}
REVIEW_FIELDS = frozenset({'schema','candidate_sha256','variant','preconditions',
                           'supports','integrity','provenance','cleanup','source_mode'})
REPORT_FIELDS = frozenset({
    'schema','mode','source_candidate_sha256','source_intent_sha256',
    'source_support_sha256','source_catalog_sha256','family_count',
    'identity','variant','variant_in_original_a5_intent',
    'source_kind','declared_outcome','source_has_support','review_declaration',
    'family_requirements','unresolved_preconditions','unresolved_supports',
    'hypothetical_family_class','hypothetical_family_reason','rule_report_sha256',
    'rule_catalog_source','a5_physical_start_accredited',
    'a5_case_binding_independently_attested','a6_classification',
    'technical_truth_accredited','confirmed_rf','applied_transition',
    'published_generation','operational_dispatch','p8_operational','sha256',
})
VARIANT_OPTIONS = {
    'FTP-T02': ('CONTROL', 'DATA'),
    'FTP-T08': ('READ', 'WRITE'),
    'SMB-T03': ('SIGNING', 'ENCRYPTION'),
    'SMB-T09': ('READ', 'WRITE'),
}
TRUTH = frozenset(('VERDADERO','FALSO','ND'))
MAX_BRIDGE = 65536
MAX_REVIEW = 16384


class FamilyBridgeError(ValueError):
    """Refuse case drift, unpinned catalogue, forged authority or replay conflict."""


def need(condition: bool, code: str) -> None:
    if not condition:
        raise FamilyBridgeError(code)


def _sources():
    # Production imports the EXISTING rule engines, not a reimplementation.
    from ardrec.evidence import r58h_ssh_family_logic as ssh
    from ardrec.evidence import r58i_ftp_family_logic as ftp
    from ardrec.evidence import r58j_smb_family_logic as smb
    need(ssh.CATALOG_SHA256 == ftp.CATALOG_SHA256 == smb.CATALOG_SHA256,
         'CATALOG_PIN_MISMATCH_ACROSS_ENGINES')
    ssh_specs = ssh.load_pinned_catalog()
    ftp_specs = ftp.load_pinned_ftp_catalog()
    smb_specs = smb.load_pinned_smb_catalog()
    need([len(x) for x in (ssh_specs,ftp_specs,smb_specs)] == [8,8,9],
         'CATALOG_25_FAMILIES_REQUIRED')
    families = {
        'SSH_DEV': (ssh, ssh_specs, ssh.build_ssh_simulation, ssh.verify_ssh_simulation),
        'FTP_DEV': (ftp, ftp_specs, ftp.build_ftp_simulation, ftp.verify_ftp_simulation),
        'SMB_DEV': (smb, smb_specs, smb.build_smb_simulation, smb.verify_smb_simulation),
    }
    for service, (engine, specs, _, _) in families.items():
        prefix = service.split('_')[0]
        need({x['id'] for x in specs} ==
             {f'{prefix}-T{i:02d}' for i in range(1, FAMILY_COUNTS[service]+1)},
             'CATALOG_FAMILY_IDS_INVALID')
    return ssh.CATALOG_SHA256, families


def _requirements(service: str, family_id: str, variant: str | None,
                  specs: list[dict[str, Any]], engine: Any) -> dict[str, Any]:
    found = [s for s in specs if s['id'] == family_id]
    need(len(found)==1, 'FAMILY_NOT_IN_PINNED_CATALOG')
    need(variant in VARIANT_OPTIONS[family_id] if family_id in VARIANT_OPTIONS
         else variant is None, 'VARIANT_EXPLICIT_REQUIRED_OR_UNEXPECTED')
    spec = found[0]
    if service == 'SSH_DEV':
        pre = list(spec['preconditions'])
        supports = list(spec['required_supports'])
        acceptance = list(spec['acceptance_supports'])
        cleanup_required = spec['cleanup'] != 'NO_MUTATION'
    else:
        pre, supports, acceptance, _, cleanup_required = engine._requirements(spec, variant)
        pre, supports, acceptance = list(pre), list(supports), list(acceptance)
    need(pre and supports and acceptance and set(acceptance) <= set(supports),
         'FAMILY_REQUIREMENTS_INVALID')
    need(len(set(pre)) == len(pre) and len(set(supports)) == len(supports),
         'FAMILY_REQUIREMENTS_DUPLICATED')
    return {'preconditions':pre, 'required_supports':supports,
            'acceptance_supports':acceptance, 'cleanup_required':cleanup_required}


def _review(candidate_sha: str, variant: str | None,
            requirements: dict[str, Any], supplied: dict[str, Any] | None,
            outcome: str) -> dict[str, Any]:
    if supplied is None:
        return {'schema':REVIEW_SCHEMA, 'candidate_sha256':candidate_sha,
                'variant':variant,
                'preconditions':{k:'ND' for k in requirements['preconditions']},
                'supports':{k:'ND' for k in requirements['required_supports']},
                'integrity':'ND','provenance':'ND',
                'cleanup':'ND' if requirements['cleanup_required'] else 'NO_APLICA',
                'source_mode':'DEFAULT_ALL_UNRESOLVED'}
    need(outcome!='NO_START', 'NO_START_CANNOT_HAVE_REVIEW_ASSERTIONS')
    need(type(supplied) is dict and set(supplied)==REVIEW_FIELDS,
         'REVIEW_FIELDS_INVALID')
    need(supplied['schema']==REVIEW_SCHEMA and
         supplied['candidate_sha256']==candidate_sha and
         supplied['variant']==variant and
         supplied['source_mode']=='UNATTESTED_REVIEW_DECLARATION',
         'REVIEW_CASE_OR_SOURCE_DRIFT')
    need(type(supplied['preconditions']) is dict and
         set(supplied['preconditions'])==set(requirements['preconditions']) and
         type(supplied['supports']) is dict and
         set(supplied['supports'])==set(requirements['required_supports']),
         'REVIEW_REQUIREMENTS_NOT_EXACT')
    need(all(type(v) is str and v in TRUTH for v in
             (*supplied['preconditions'].values(), *supplied['supports'].values(),
              supplied['integrity'],supplied['provenance'])),
         'REVIEW_TRIVALENT_INVALID')
    need(supplied['cleanup'] in TRUTH if requirements['cleanup_required']
         else supplied['cleanup']=='NO_APLICA', 'REVIEW_CLEANUP_INVALID')
    need(len(a5.canonical(supplied))<=MAX_REVIEW,'REVIEW_SIZE_LIMIT')
    return deepcopy(supplied)


def build_bridge(source_root: Path, candidate_sha256: str,
                 *, variant: str | None = None,
                 review: dict[str, Any] | None = None) -> dict[str, Any]:
    """Reopen R59-D's ORIGINAL private receipt, evaluate P7 rules conservatively."""
    need(a5._hex(candidate_sha256), 'CANDIDATE_DIGEST_INVALID')
    candidate = a5.verify_stored_candidate(source_root, candidate_sha256)
    a5.need(candidate['a5_physical_start_accredited'] is False and
            candidate['a5_case_binding_independently_attested'] is False and
            candidate['a6_classification']=='ND' and
            candidate['a6_technical_truth_accredited'] is False and
            candidate['a7_confirmed_rf'] is None and
            candidate['a9_published_generation'] is None and
            candidate['operational_dispatch'] is False and
            candidate['p8_operational']=='NO-GO',
            'UPSTREAM_AUTHORITY_INVALID')
    intent, receipt = candidate['intent'], candidate['receipt']
    svc, fid = intent['service_id'], intent['family_id']
    catalogue_sha, engines = _sources()
    need(svc in engines,'SERVICE_UNKNOWN')
    engine, specs, run_rule, verify_rule = engines[svc]
    requirements = _requirements(svc, fid, variant, specs, engine)
    rv = _review(candidate_sha256, variant, requirements, review,
                 receipt['declared_outcome'])
    no_start = receipt['declared_outcome']=='NO_START'
    rule_sha = None
    rule_source = None
    hypothetical_class = 'NO_INTENTO_NO_CLASIFICACION'
    hypothetical_reason = 'NO_START_HAS_NO_EVIDENCE'
    if not no_start:
        unit = {
            'family_id':fid, 'derived_case_id':intent['derived_case_id'],
            'assessment_index':intent['assessment_index'],
            'session_id':intent['session_id'], 'phase':'PENDIENTE',
            'preconditions':rv['preconditions'], 'supports':rv['supports'],
            'integrity':rv['integrity'], 'provenance':rv['provenance'],
            'cleanup':rv['cleanup'], 'outcome':receipt['declared_outcome'],
        }
        if svc!='SSH_DEV':
            unit['variant']=variant
        result = run_rule([unit])
        need(verify_rule(result) is True and
             result['source_catalog_sha256']==catalogue_sha and
             result['catalog_source']=='FULL_FILE_SHA256_PINNED' and
             result['unit_count']==1 and
             result['a6_classification']=='ND' and
             result['technical_truth_accredited'] is False and
             result['confirmed_final_risk'] is None and
             result['published_generation'] is None and
             result['operational_dispatch'] is False and
             result['p8_operational']=='NO-GO',
             'RULE_ENGINE_AUTHORITY_OR_CATALOG')
        decision=result['decisions'][0]
        need(all(decision[k]==intent[k] for k in ('family_id','derived_case_id',
              'assessment_index','session_id')) and
             decision['a6_classification']=='ND' and
             decision['technical_truth_accredited'] is False and
             decision['confirmed_rf'] is None,
             'RULE_ENGINE_CASE_OR_AUTHORITY_DRIFT')
        rule_sha=result['sha256']
        rule_source=result['catalog_source']
        hypothetical_class=decision['hypothetical_result_class']
        hypothetical_reason=decision['hypothetical_reason']
    identity={k:intent[k] for k in ('service_id','session_id','family_id',
               'derived_case_id','assessment_index','attempt_id',
               'configuration_sha256','method_id')}
    doc={
        'schema':SCHEMA, 'mode':MODE,
        'source_candidate_sha256':candidate_sha256,
        'source_intent_sha256':intent['sha256'],
        'source_support_sha256':receipt['support_sha256'],
        'source_catalog_sha256':catalogue_sha,'family_count':25,
        'identity':identity,'variant':variant,
        'variant_in_original_a5_intent':False,
        'source_kind':receipt['source_kind'],
        'declared_outcome':receipt['declared_outcome'],
        'source_has_support':receipt['support_bytes']>0,
        'review_declaration':rv,
        'family_requirements':requirements,
        'unresolved_preconditions':sorted(k for k,v in rv['preconditions'].items() if v!='VERDADERO'),
        'unresolved_supports':sorted(k for k,v in rv['supports'].items() if v!='VERDADERO'),
        'hypothetical_family_class':hypothetical_class,
        'hypothetical_family_reason':hypothetical_reason,
        'rule_report_sha256':rule_sha,
        'rule_catalog_source':rule_source,
        'a5_physical_start_accredited':False,
        'a5_case_binding_independently_attested':False,
        'a6_classification':'ND',
        'technical_truth_accredited':False,
        'confirmed_rf':None,'applied_transition':None,
        'published_generation':None,'operational_dispatch':False,
        'p8_operational':'NO-GO',
    }
    need(len(a5.canonical(doc))<MAX_BRIDGE-200,'BRIDGE_REPORT_TOO_LARGE')
    doc['sha256']=a5.digest(doc)
    need(set(doc)==REPORT_FIELDS,'BRIDGE_REPORT_SCHEMA_DRIFT')
    return doc


def verify_bridge(doc: dict[str, Any], source_root: Path) -> bool:
    need(type(doc) is dict and set(doc)==REPORT_FIELDS and
         a5._hex(doc.get('sha256')),'BRIDGE_REPORT_SCHEMA')
    expected=build_bridge(source_root,doc['source_candidate_sha256'],
                          variant=doc['variant'],
                          review=(doc['review_declaration'] if
                                  doc['review_declaration'].get('source_mode')!=
                                  'DEFAULT_ALL_UNRESOLVED' else None))
    need(a5.canonical(doc)==a5.canonical(expected),
         'BRIDGE_REPORT_NOT_REPRODUCIBLE')
    return True


def _filename(candidate_sha256: str) -> str:
    return 'r59e-a6-'+candidate_sha256+'.json'


def persist_bridge(output_root: Path, source_root: Path, candidate_sha256: str,
                   *, variant: str | None = None,
                   review: dict[str, Any] | None = None) -> dict[str, Any]:
    """One frozen variant/review per A5 candidate, immutable and source-bound."""
    a5._private_root(output_root)
    a5._private_root(source_root)
    need(output_root.stat().st_dev!=source_root.stat().st_dev or
         output_root.stat().st_ino!=source_root.stat().st_ino,
         'SOURCE_AND_OUTPUT_ROOT_MUST_DIFFER')
    doc=build_bridge(source_root,candidate_sha256,variant=variant,review=review)
    action=a5._store_once(output_root/_filename(candidate_sha256),
                          a5.canonical(doc)+b'\n',MAX_BRIDGE)
    fd=os.open(output_root,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
    try:os.fsync(fd)
    finally:os.close(fd)
    verify_stored_bridge(output_root,source_root,candidate_sha256)
    return {'status':action,'bridge_sha256':doc['sha256'],
            'source_candidate_sha256':candidate_sha256,
            'a6_classification':'ND','p8_operational':'NO-GO'}


def verify_stored_bridge(output_root: Path,source_root: Path,
                         candidate_sha256: str) -> dict[str, Any]:
    a5._private_root(output_root)
    a5._private_root(source_root)
    need(a5._hex(candidate_sha256),'CANDIDATE_SHA_INVALID')
    raw=a5._read_private(output_root/_filename(candidate_sha256),MAX_BRIDGE)
    try: doc=json.loads(raw,object_pairs_hook=a5._pairs)
    except (ValueError,UnicodeError,RecursionError) as exc:
        raise FamilyBridgeError('STORED_BRIDGE_INVALID_JSON') from exc
    need(type(doc) is dict and raw==a5.canonical(doc)+b'\n',
         'STORED_BRIDGE_NOT_CANONICAL')
    need(doc.get('source_candidate_sha256')==candidate_sha256,
         'STORED_BRIDGE_SOURCE_DRIFT')
    verify_bridge(doc,source_root)
    return doc
