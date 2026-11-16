"""R58-I: thesis-grounded FTP/FTPS A6 trivalent *synthetic* evaluations.

Never executes FTP, never treats a declared result as technical evidence, and
never applies A7 risk, A8 transitions, A9 publication or P8 dispatch.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.evidence.r58h_ssh_family_logic import (
    CATALOG_SHA256, THESIS_SHA256, CATALOG_PATH, _reject_dupes,
    _guard, TRUTH, OUTCOMES, CLASSES, SESSION,
)

SCHEMA = 'ardrec-r58i-a6-ftp-family-trivalent-preview-v1'
FAMILY_IDS = tuple(f'FTP-T{i:02}' for i in range(1, 9))
DERIVED = re.compile(r'FTP-T0[1-8]-S\d{2}-\d{2}\Z', re.ASCII)
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
MAX_UNITS = 54
MAX_BYTES = 262144
UNIT_FIELDS = frozenset(('family_id','derived_case_id','assessment_index','session_id',
                         'phase','variant','preconditions','supports',
                         'integrity','provenance','cleanup','outcome'))
VARIANTS = {'FTP-T02': ('CONTROL','DATA'), 'FTP-T08': ('READ','WRITE')}
VARIANT_PRECONDITIONS = {
    ('FTP-T02','DATA'): ('CONTROL_CHANNEL_VERIFIED','SESSION_AUTHENTICATED'),
    ('FTP-T08','WRITE'): ('WRITE_FIXTURE_PREPARED','CLEANUP_VERIFIABLE'),
}
VARIANT_SUPPORTS = {
    ('FTP-T08','WRITE'): ('MARKER_CREATED','MARKER_VERIFIED','CLEANUP_CONFIRMED'),
}
CLEANUP_FAMILIES = frozenset(('FTP-T07',))

class FTPFamilyError(ValueError):
    """Stable fail-closed input and report rejection."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise FTPFamilyError(code)


def _specs(families: Any) -> list[dict[str, Any]]:
    need(type(families) is list, 'FAMILIES_NOT_LIST')
    chosen = []
    for f in families:
        need(type(f) is dict, 'FAMILY_NOT_DICT')
        if f.get('protocol') != 'ftp':
            continue
        need(type(f.get('id')) is str and f['id'] in FAMILY_IDS, 'FTP_FAMILY_UNKNOWN')
        for field in ('preconditions','required_supports','acceptance_supports'):
            sequence = f.get(field)
            need(type(sequence) is list and len(sequence)>0 and
                 len(sequence)==len(set(sequence)) and
                 all(type(x) is str and re.fullmatch(r'[A-Z0-9_]{2,80}',x,re.ASCII)
                     for x in sequence), 'CATALOG_'+field.upper())
        need(set(f['acceptance_supports']) <= set(f['required_supports']),
             'CATALOG_ACCEPTANCE_NOT_REQUIRED')
        fid = f['id']
        cleanup = f.get('cleanup')
        if fid == 'FTP-T07':
            need(cleanup == 'VERIFY_THEN_REMOVE_MARKER', 'CATALOG_T07_CLEANUP')
        elif fid == 'FTP-T08':
            need(cleanup == 'CONDITIONAL_WRITE_MARKER_CLEANUP', 'CATALOG_T08_CLEANUP')
        else:
            need(cleanup == 'NO_MUTATION','CATALOG_CLEANUP')
        variants = f.get('variants')
        precedence = f.get('precedence')
        if fid in VARIANTS:
            need(type(variants) is dict and
                 variants.get('dimension') == ('channel' if fid=='FTP-T02' else 'operation_class')
                 and type(variants.get('precedence_by_option')) is dict and
                 set(variants['precedence_by_option']) == set(VARIANTS[fid]),
                 'CATALOG_VARIANTS')
            expected = {'CONTROL':1,'DATA':3} if fid=='FTP-T02' else {'READ':3,'WRITE':4}
            need(variants['precedence_by_option'] == expected and
                 precedence == list(expected.values()), 'CATALOG_VARIANT_PRECEDENCE')
            variant_precedence = expected
        else:
            need(variants is None and type(precedence) is int and
                 precedence in (1,2,3,4), 'CATALOG_PRECEDENCE')
            variant_precedence = {None:precedence}
        chosen.append({
            'id':fid,'preconditions':list(f['preconditions']),
            'required_supports':list(f['required_supports']),
            'acceptance_supports':list(f['acceptance_supports']),
            'cleanup':cleanup,'precedence_by_variant':variant_precedence,
        })
    chosen.sort(key=lambda s:s['id'])
    need([f['id'] for f in chosen]==list(FAMILY_IDS), 'FTP_FAMILIES_NOT_EXACTLY_EIGHT')
    return chosen


def load_pinned_ftp_catalog() -> list[dict[str, Any]]:
    """Use original SHA-pinned thesis catalogue, never an editable proposal."""
    need(CATALOG_PATH.is_file() and not CATALOG_PATH.is_symlink(), 'CATALOG_NOT_REGULAR')
    try:
        data = CATALOG_PATH.read_bytes()
    except OSError as exc:
        raise FTPFamilyError('CATALOG_UNREADABLE') from exc
    need(0 < len(data) <= 131072, 'CATALOG_SIZE')
    need(hashlib.sha256(data).hexdigest() == CATALOG_SHA256, 'CATALOG_PIN_MISMATCH')
    try:
        doc = json.loads(data,object_pairs_hook=_reject_dupes)
    except (ValueError,UnicodeError,RecursionError) as exc:
        raise FTPFamilyError('CATALOG_JSON_INVALID') from exc
    need(type(doc) is dict and doc.get('thesis_sha256') == THESIS_SHA256 and
         doc.get('counts') == {'ssh':8,'ftp':8,'smb':9,'total':25} and
         doc.get('status') == 'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE' and
         doc.get('execution_enabled') is False,'CATALOG_METADATA_MISMATCH')
    return _specs(doc.get('families'))


def _requirements(f:dict[str,Any], variant: str|None):
    fid = f['id']
    if fid in VARIANTS:
        need(type(variant) is str and variant in VARIANTS[fid], 'VARIANT_EXPLICIT_REQUIRED')
    else:
        need(variant is None, 'UNEXPECTED_VARIANT')
    need(variant in f['precedence_by_variant'],'VARIANT_PRECEDENCE_MISSING')
    extra_pc = VARIANT_PRECONDITIONS.get((fid,variant),())
    extra_s = VARIANT_SUPPORTS.get((fid,variant),())
    pre = tuple(dict.fromkeys([*f['preconditions'],*extra_pc]))
    # FTP control-channel TLS is not evidence about the data channel.  The
    # generic catalogue names correlation, but only the DATA variant needs it.
    base_supports = ([x for x in f['required_supports'] if x!='CONTROL_DATA_CORRELATION']
                     if fid=='FTP-T02' and variant=='CONTROL'
                     else f['required_supports'])
    supports = tuple(dict.fromkeys([*base_supports,*extra_s]))
    added_accept = ('CONTROL_DATA_CORRELATION',) if (fid,variant)==('FTP-T02','DATA') else ()
    accept = tuple(dict.fromkeys([*f['acceptance_supports'],*extra_s,*added_accept]))
    need(set(accept).issubset(supports),'VARIANT_ACCEPTANCE_INVALID')
    cleanup_required = fid == 'FTP-T07' or (fid=='FTP-T08' and variant=='WRITE')
    return pre,supports,accept,f['precedence_by_variant'][variant],cleanup_required


def _unit(value:Any, f:dict[str,Any]) -> tuple[dict[str,Any],dict[str,Any]]:
    need(type(value) is dict and set(value)==UNIT_FIELDS, 'UNIT_SCHEMA')
    fid = value['family_id']
    need(fid == f['id'], 'FAMILY_BINDING')
    cid = value['derived_case_id']
    need(type(cid) is str and DERIVED.fullmatch(cid) is not None and
         cid.startswith(fid+'-'), 'DERIVED_CASE_ID')
    index=value['assessment_index']
    need(type(index) is int and 0<=index<2**31,'ASSESSMENT_INDEX')
    session=value['session_id']
    need(type(session) is str and SESSION.fullmatch(session) is not None,'SESSION_ID')
    need(type(value['phase']) is str and value['phase'] in ('PREPARADO','PENDIENTE',
         'ACTIVO','VALIDACION','ACTUALIZADO','PAUSADO','CERRADO','DETENIDO'),'PHASE')
    variant=value['variant']
    pre,requirements,accept,precedence,cleanup_required=_requirements(f,variant)
    pc=value['preconditions'];supports=value['supports']
    need(type(pc) is dict and set(pc)==set(pre),'PRECONDITION_SCHEMA')
    need(type(supports) is dict and set(supports)<=set(requirements), 'SUPPORT_SCHEMA')
    for mapping in (pc,supports):
        need(all(type(x) is str and x in TRUTH for x in mapping.values()),
             'TRIVALENT_VALUES')
    for key in ('integrity','provenance'):
        need(type(value[key]) is str and value[key] in TRUTH,key.upper()+'_VALUE')
    cleanup=value['cleanup']
    need(type(cleanup) is str and
         (cleanup in TRUTH if cleanup_required else cleanup=='NO_APLICA'),
         'CLEANUP_VALUE')
    need(type(value['outcome']) is str and value['outcome'] in OUTCOMES,'OUTCOME')
    normalized={**value,'preconditions':{k:pc[k] for k in sorted(pc)},
                'supports':{k:supports[k] for k in sorted(supports)}}
    guard=_guard([pc[k] for k in pre])
    absent=[k for k in requirements if k not in supports]
    unknown=[k for k in requirements if supports.get(k,'ND')=='ND']
    contradict=[k for k in requirements if supports.get(k)=='FALSO']
    # Supports express verifiability of an observation, not its sign.  An
    # observed negative is only valid when a complete negative response exists.
    if value['phase']!='PENDIENTE':
        cls='NO_ADMITIDO';reason='SERVICE_NOT_PENDING'
    elif guard!='VERDADERO':
        cls='NO_ADMITIDO';reason=('PRECONDITION_FALSE' if guard=='FALSO' else 'PRECONDITION_ND')
    elif value['integrity']=='FALSO' or value['provenance']=='FALSO':
        cls='INVALIDO';reason='INTEGRITY_OR_PROVENANCE_CONTRADICTED'
    elif value['integrity']=='ND' or value['provenance']=='ND':
        cls='INCONCLUSO';reason='INTEGRITY_OR_PROVENANCE_UNRESOLVED'
    elif cleanup_required and cleanup!='VERDADERO':
        if supports.get('CLEANUP_CONFIRMED')=='VERDADERO':
            cls='INVALIDO';reason='CLEANUP_SUPPORT_CONTRADICTS_STATUS'
        elif cleanup=='FALSO':
            cls='INCIDENCIA';reason='MARKER_CLEANUP_FAILED'
        else:
            cls='INCONCLUSO';reason='MARKER_CLEANUP_UNRESOLVED'
    elif cleanup_required and supports.get('CLEANUP_CONFIRMED')=='FALSO':
        cls='INVALIDO';reason='CLEANUP_STATUS_CONTRADICTS_SUPPORT'
    elif contradict:
        cls='INVALIDO';reason='REQUIRED_SUPPORT_CONTRADICTED'
    elif unknown:
        cls='INCONCLUSO';reason='REQUIRED_SUPPORT_UNRESOLVED'
    elif value['outcome']=='INCIDENCIA':
        cls='INCIDENCIA';reason='SIMULATED_OPERATIONAL_INCIDENT'
    elif value['outcome']=='INCONCLUSO':
        cls='INCONCLUSO';reason='SIMULATED_OUTCOME_UNRESOLVED'
    elif value['outcome']=='OBSERVADO_POSITIVO':
        cls='POSITIVO_VALIDO';reason='HYPOTHETICAL_POSITIVE_ALL_SUPPORTS'
    else:
        cls='NEGATIVO_VALIDO';reason='HYPOTHETICAL_NEGATIVE_EXPLICITLY_OBSERVED'
    need(cls in CLASSES,'CLASS_UNKNOWN')
    return normalized,{
        'family_id':fid,'derived_case_id':cid,'session_id':session,
        'assessment_index':index,'variant':variant,'precedence':precedence,
        'service_id':'FTP_DEV','phase_assumed':value['phase'],
        'required_preconditions':list(pre),'required_supports':list(requirements),
        'acceptance_supports':list(accept),
        'missing_required_supports':absent,
        'unresolved_required_supports':unknown,
        'contradicted_required_supports':contradict,
        'cleanup_required':cleanup_required,
        'guard_simulated':guard,
        'hypothetical_result_class':cls,'hypothetical_reason':reason,
        'hypothetical_condition_truth':('VERDADERO' if cls=='POSITIVO_VALIDO' else
                                        'FALSO' if cls=='NEGATIVO_VALIDO' else 'ND'),
        'a6_classification':'ND','technical_truth_accredited':False,
        'technical_contribution':None,'confirmed_rf':None,
        'applied_transition':None,'published_generation':None,
    }


def build_ftp_simulation(units:list[dict[str,Any]],*,
                         _test_families:list[dict[str,Any]]|None=None) -> dict[str,Any]:
    """Deterministic FTP rule preview; injected family specs are test-only."""
    families = load_pinned_ftp_catalog() if _test_families is None else _specs(_test_families)
    need(type(units) is list and 0<len(units)<=MAX_UNITS,'UNIT_COUNT')
    by_id={f['id']:f for f in families}
    normalized=[];decisions=[];seen=set();variant_case_ids=set()
    for row in units:
        need(type(row) is dict,'UNIT_NOT_DICT')
        fid=row.get('family_id')
        need(type(fid) is str and fid in by_id,'FAMILY_OUT_OF_SCOPE')
        unit,decision=_unit(row,by_id[fid])
        key=(unit['session_id'],unit['derived_case_id'],unit['assessment_index'],unit['variant'])
        # Each variant is an independently derived case, not two claims about
        # a reused case identifier.  Prevent ambiguous A6/A9 case binding.
        case_key=(unit['session_id'],unit['derived_case_id'],unit['assessment_index'])
        need(key not in seen,'DUPLICATE_CASE_VARIANT_WINDOW')
        need(case_key not in variant_case_ids,'CASE_ID_REUSED_ACROSS_VARIANTS')
        seen.add(key);variant_case_ids.add(case_key)
        normalized.append(unit);decisions.append(decision)
    order=lambda x:(x['session_id'],x['derived_case_id'],x['assessment_index'],x['variant'] or '')
    normalized.sort(key=order);decisions.sort(key=order)
    doc={'schema':SCHEMA,'mode':'SYNTHETIC_RULE_EVALUATION_ONLY',
         'source_catalog_sha256':CATALOG_SHA256 if _test_families is None else None,
         'source_thesis_sha256':THESIS_SHA256,
         'catalog_source':'FULL_FILE_SHA256_PINNED' if _test_families is None else 'TEST_FIXTURE_NOT_PINNED',
         'ftp_family_ids':list(FAMILY_IDS),
         'inputs':normalized,'decisions':decisions,'unit_count':len(normalized),
         'a6_classification':'ND','technical_truth_accredited':False,
         'confirmed_final_risk':None,'published_generation':None,
         'applied_state_transition':None,'operational_dispatch':False,
         'host_mutations':0,'p8_operational':'NO-GO'}
    need(len(canonical(doc))<=MAX_BYTES,'REPORT_TOO_LARGE')
    doc['sha256']=digest(doc)
    return doc


def verify_ftp_simulation(report:dict[str,Any],*,
                          _test_families:list[dict[str,Any]]|None=None)->bool:
    need(type(report) is dict and type(report.get('sha256')) is str and
         HEX.fullmatch(report['sha256']) is not None,'REPORT_SCHEMA')
    expected=build_ftp_simulation(report.get('inputs'),_test_families=_test_families)
    need(canonical(report)==canonical(expected),'REPORT_NOT_REPRODUCIBLE')
    return True
