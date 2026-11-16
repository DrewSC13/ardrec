"""R58-H A6: eight thesis-grounded SSH family rule previews, strictly offline.

No factual admission is made: even a simulated POSITIVO_VALIDO is not A6 truth.
Only a byte-for-byte SHA-pinned P7 catalogue is accepted in production mode.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

from ardrec.analytics.exact_preview import canonical, digest

SCHEMA = 'ardrec-r58h-a6-ssh-family-trivalent-preview-v1'
REPO = Path(__file__).resolve().parents[3]
CATALOG_PATH = REPO / 'lab/operational-catalog-v1/catalog.json'
CATALOG_SHA256 = '5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
THESIS_SHA256 = '6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72'
FAMILY_IDS = tuple(f'SSH-T{i:02}' for i in range(1,9))
TRUTH = frozenset(('VERDADERO','FALSO','ND'))
OUTCOMES = frozenset(('OBSERVADO_POSITIVO','OBSERVADO_NEGATIVO','INCONCLUSO','INCIDENCIA'))
CLASSES = frozenset(('POSITIVO_VALIDO','NEGATIVO_VALIDO','INCONCLUSO',
                     'INCIDENCIA','INVALIDO','NO_ADMITIDO'))
HEX = re.compile(r'[0-9a-f]{64}\Z',re.ASCII)
DERIVED = re.compile(r'SSH-T0[1-8]-S\d{2}-\d{2}\Z',re.ASCII)
SESSION = re.compile(r'[A-Za-z0-9_:-]{1,80}\Z',re.ASCII)
MAX_UNITS = 54
MAX_BYTES = 262144
KEYS = frozenset(('family_id','derived_case_id','assessment_index','session_id',
                  'phase','preconditions','supports','integrity','provenance',
                  'cleanup','outcome'))
SPEC_FIELDS = frozenset(('id','precedence','preconditions','required_supports',
                         'acceptance_supports','cleanup'))

class FamilyError(ValueError):
    """Fail-closed validation for simulated family classification."""


def need(condition: bool, code: str) -> None:
    if not condition:
        raise FamilyError(code)


def _reject_dupes(pairs: list[tuple[str, Any]]) -> dict[str,Any]:
    out: dict[str,Any] = {}
    for k,v in pairs:
        need(k not in out,'CATALOG_DUPLICATE_JSON_KEY')
        out[k]=v
    return out


def load_pinned_catalog() -> list[dict[str,Any]]:
    """Read authoritative P7 source after checking its full-file SHA-256."""
    need(CATALOG_PATH.is_file() and not CATALOG_PATH.is_symlink(), 'CATALOG_NOT_REGULAR')
    try:
        data=CATALOG_PATH.read_bytes()
    except OSError as exc:
        raise FamilyError('CATALOG_UNREADABLE') from exc
    need(0<len(data)<=131072,'CATALOG_SIZE')
    need(hashlib.sha256(data).hexdigest()==CATALOG_SHA256,'CATALOG_PIN_MISMATCH')
    try:
        doc=json.loads(data,object_pairs_hook=_reject_dupes)
    except (ValueError,UnicodeError,RecursionError) as exc:
        raise FamilyError('CATALOG_JSON_INVALID') from exc
    need(type(doc) is dict and doc.get('thesis_sha256')==THESIS_SHA256 and
         doc.get('status')=='P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE' and
         doc.get('counts')=={'ssh':8,'ftp':8,'smb':9,'total':25} and
         doc.get('execution_enabled') is False,'CATALOG_METADATA_MISMATCH')
    return _specs(doc.get('families'))


def _specs(families: Any) -> list[dict[str,Any]]:
    need(type(families) is list, 'FAMILIES_NOT_LIST')
    chosen=[]
    for f in families:
        need(type(f) is dict,'FAMILY_NOT_DICT')
        if f.get('protocol')!='ssh':
            continue
        need(type(f.get('id')) is str and f['id'] in FAMILY_IDS,'SSH_FAMILY_UNKNOWN')
        prec=f.get('preconditions'); supports=f.get('required_supports')
        accept=f.get('acceptance_supports')
        need(type(prec) is list and type(supports) is list and type(accept) is list,
             'CATALOG_LIST_TYPES')
        for seq in (prec,supports,accept):
            need(seq and all(type(x) is str and
                 re.fullmatch(r'[A-Z0-9_]{2,80}',x,re.ASCII) for x in seq) and
                 len(seq)==len(set(seq)),'CATALOG_VOCAB_INVALID')
        need(set(accept)<=set(supports),'CATALOG_ACCEPTANCE_NOT_REQUIRED')
        need(type(f.get('precedence')) is int and 1<=f['precedence']<=4,
             'CATALOG_PRECEDENCE_INVALID')
        cleanup=f.get('cleanup')
        need(cleanup in ('NO_MUTATION','VERIFY_THEN_REMOVE_MARKER'),'CATALOG_CLEANUP')
        need((f['id']=='SSH-T07') == (cleanup=='VERIFY_THEN_REMOVE_MARKER'),
             'CATALOG_CLEANUP_MISMATCH')
        chosen.append({'id':f['id'],'precedence':f['precedence'],
                       'preconditions':prec,'required_supports':supports,
                       'acceptance_supports':accept,'cleanup':cleanup})
    chosen.sort(key=lambda x:x['id'])
    need([x['id'] for x in chosen]==list(FAMILY_IDS),'SSH_FAMILIES_NOT_EXACTLY_EIGHT')
    return chosen


def _guard(states: list[str]) -> str:
    if 'FALSO' in states:
        return 'FALSO'
    if 'ND' in states:
        return 'ND'
    return 'VERDADERO'


def _unit(value: Any, f: dict[str,Any]) -> tuple[dict[str,Any],dict[str,Any]]:
    need(type(value) is dict and set(value)==KEYS,'UNIT_SCHEMA')
    fid=value['family_id']
    need(fid==f['id'],'FAMILY_BINDING')
    cid=value['derived_case_id']
    need(type(cid) is str and DERIVED.fullmatch(cid) is not None and
         cid.startswith(fid+'-'),'DERIVED_CASE_ID')
    need(type(value['assessment_index']) is int and
         0<=value['assessment_index']<2**31,'ASSESSMENT_INDEX')
    need(type(value['session_id']) is str and SESSION.fullmatch(value['session_id']) is not None,
         'SESSION_ID')
    need(type(value['phase']) is str and
         value['phase'] in ('PREPARADO','PENDIENTE','ACTIVO','VALIDACION','ACTUALIZADO',
                            'PAUSADO','CERRADO','DETENIDO'),'PHASE')
    pc=value['preconditions']; supports=value['supports']
    need(type(pc) is dict and set(pc)==set(f['preconditions']),'PRECONDITION_SCHEMA')
    need(type(supports) is dict and set(supports)<=set(f['required_supports']),
         'SUPPORT_SCHEMA')
    for mapping in (pc,supports):
        need(all(type(v) is str and v in TRUTH for v in mapping.values()),
             'TRIVALENT_VALUES')
    for k in ('integrity','provenance'):
        need(type(value[k]) is str and value[k] in TRUTH,k.upper()+'_VALUE')
    cleanup=value['cleanup']
    need(type(cleanup) is str,'CLEANUP_VALUE')
    if f['cleanup']=='NO_MUTATION':
        need(cleanup=='NO_APLICA','CLEANUP_EXPECTED_NO_MUTATION')
    else:
        need(cleanup in TRUTH,'CLEANUP_REQUIRED')
    need(type(value['outcome']) is str and value['outcome'] in OUTCOMES,'OUTCOME')
    norm={**value,'preconditions':{k:pc[k] for k in sorted(pc)},
          'supports':{k:supports[k] for k in sorted(supports)}}
    guard=_guard([pc[k] for k in f['preconditions']])
    absent=[k for k in f['required_supports'] if k not in supports]
    unknown=[k for k in f['required_supports'] if supports.get(k,'ND')=='ND']
    contradictions=[k for k in f['required_supports'] if supports.get(k)=='FALSO']
    if value['phase']!='PENDIENTE':
        cls='NO_ADMITIDO';reason='SERVICE_NOT_PENDING'
    elif guard!='VERDADERO':
        cls='NO_ADMITIDO';reason='PRECONDITION_FALSE' if guard=='FALSO' else 'PRECONDITION_ND'
    elif value['integrity']=='FALSO' or value['provenance']=='FALSO':
        cls='INVALIDO';reason='INTEGRITY_OR_PROVENANCE_CONTRADICTED'
    elif value['integrity']=='ND' or value['provenance']=='ND':
        cls='INCONCLUSO';reason='INTEGRITY_OR_PROVENANCE_UNRESOLVED'
    elif f['id']=='SSH-T07' and cleanup!='VERDADERO':
        if supports.get('CLEANUP_CONFIRMED')=='VERDADERO':
            cls='INVALIDO';reason='CLEANUP_SUPPORT_CONTRADICTS_CLEANUP_STATUS'
        elif cleanup=='FALSO':
            cls='INCIDENCIA';reason='MARKER_CLEANUP_FAILED'
        else:
            cls='INCONCLUSO';reason='MARKER_CLEANUP_UNRESOLVED'
    elif contradictions:
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
    need(cls in CLASSES,'CLASS_NOT_RECOGNIZED')
    return norm,{
        'family_id':fid,'derived_case_id':cid,
        'session_id':value['session_id'], 'assessment_index':value['assessment_index'],
        'service_id':'SSH_DEV','phase_assumed':value['phase'],
        'precedence':f['precedence'],'required_supports':list(f['required_supports']),
        'acceptance_supports':list(f['acceptance_supports']),
        'missing_required_supports':absent,
        'unresolved_required_supports':unknown,
        'contradicted_required_supports':contradictions,
        'guard_simulated':guard,
        'hypothetical_result_class':cls,'hypothetical_reason':reason,
        'hypothetical_condition_truth':('VERDADERO' if cls=='POSITIVO_VALIDO' else
                                        'FALSO' if cls=='NEGATIVO_VALIDO' else 'ND'),
        'a6_classification':'ND','technical_truth_accredited':False,
        'technical_contribution':None,'confirmed_rf':None,
        'applied_transition':None,'published_generation':None,
    }


def build_ssh_simulation(units: list[dict[str,Any]], *,
                         _test_families: list[dict[str,Any]] | None = None)->dict[str,Any]:
    """Exact SSH decision previews; _test_families is non-authoritative test injection."""
    families=(load_pinned_catalog() if _test_families is None
              else _specs(_test_families))
    need(type(units) is list and 0<len(units)<=MAX_UNITS,'UNIT_COUNT')
    by_id={f['id']:f for f in families}
    normalized=[]; results=[]; seen=set()
    for unit in units:
        need(type(unit) is dict,'UNIT_NOT_DICT')
        fid=unit.get('family_id')
        need(type(fid) is str and fid in by_id,'FAMILY_OUT_OF_SCOPE')
        u,d=_unit(unit,by_id[fid])
        key=(u['session_id'],u['derived_case_id'],u['assessment_index'])
        need(key not in seen,'DUPLICATE_CASE_WINDOW')
        seen.add(key);normalized.append(u);results.append(d)
    normalized.sort(key=lambda x:(x['session_id'],x['derived_case_id'],x['assessment_index']))
    results.sort(key=lambda x:(x['session_id'],x['derived_case_id'],x['assessment_index']))
    report={'schema':SCHEMA,'mode':'SYNTHETIC_RULE_EVALUATION_ONLY',
            'source_catalog_sha256':(CATALOG_SHA256 if _test_families is None else None),
            'source_thesis_sha256':THESIS_SHA256,
            'catalog_source':('FULL_FILE_SHA256_PINNED' if _test_families is None
                              else 'TEST_FIXTURE_NOT_PINNED'),
            'ssh_family_ids':list(FAMILY_IDS),
            'inputs':normalized,'decisions':results,'unit_count':len(normalized),
            'a6_classification':'ND','technical_truth_accredited':False,
            'confirmed_final_risk':None,'published_generation':None,
            'operational_dispatch':False,'applied_state_transition':None,
            'host_mutations':0,'p8_operational':'NO-GO'}
    need(len(canonical(report))<=MAX_BYTES,'REPORT_TOO_LARGE')
    report['sha256']=digest(report)
    return report


def verify_ssh_simulation(doc:dict[str,Any],*,
                          _test_families:list[dict[str,Any]]|None=None)->bool:
    need(type(doc) is dict and type(doc.get('sha256')) is str and
         HEX.fullmatch(doc['sha256']) is not None,'REPORT_SCHEMA')
    expected=build_ssh_simulation(doc.get('inputs'),_test_families=_test_families)
    need(canonical(doc)==canonical(expected),'REPORT_NOT_REPRODUCIBLE')
    return True
