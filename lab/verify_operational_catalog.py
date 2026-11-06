#!/usr/bin/env python3
"""ARDREC P7: deterministic, read-only catalogue verifier; no networking or executions.

This module validates 25 *family specifications* and constructs unapproved case
DESCRIPTORS ONLY when a separately recorded service-scenario is supplied. It is
not an executor, credential reader, applicability evaluator or A6 classifier.
"""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = 'f803ba28af310f3c08dc33dddbd0c22522d2377f'
THESIS = '6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72'
CATALOG_SHA256 = '5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
REL = 'lab/operational-catalog-v1/catalog.json'
TRACE = 'docs/traceability/operational-catalog-v1.json'
STAGES = ('dev','pilot','exp')
NAMES = {'ssh':tuple(f'SSH-T{i:02d}' for i in range(1,9)),
         'ftp':tuple(f'FTP-T{i:02d}' for i in range(1,9)),
         'smb':tuple(f'SMB-T{i:02d}' for i in range(1,10))}
LEVELS = {'SSH-T01':1,'SSH-T02':1,'SSH-T03':2,'SSH-T04':2,'SSH-T05':3,'SSH-T06':3,'SSH-T07':4,'SSH-T08':4,
          'FTP-T01':1,'FTP-T02':[1,3],'FTP-T03':2,'FTP-T04':2,'FTP-T05':3,'FTP-T06':3,'FTP-T07':4,'FTP-T08':[3,4],
          'SMB-T01':1,'SMB-T02':1,'SMB-T03':3,'SMB-T04':2,'SMB-T05':2,'SMB-T06':3,'SMB-T07':3,'SMB-T08':4,'SMB-T09':[3,4]}
VARIANTS = {
    'FTP-T02':{'dimension':'channel','precedence_by_option':{'CONTROL':1,'DATA':3}},
    'FTP-T08':{'dimension':'operation_class','precedence_by_option':{'READ':3,'WRITE':4}},
    'SMB-T03':{'dimension':'protection','precedence_by_option':{'SIGNING':3,'ENCRYPTION':3}},
    'SMB-T09':{'dimension':'operation_class','precedence_by_option':{'READ':3,'WRITE':4}},
}
MARKERS = {'SSH-T07','FTP-T07','SMB-T08'}
COMPARES = {'FTP-T08','SMB-T09'}
CRITICAL = {
    'SSH-T01':{'HOST_KEY_MATCH'}, 'SSH-T03':{'AUTH_COMPLETION'}, 'SSH-T04':{'AUTH_COMPLETION'},
    'SSH-T06':{'KNOWN_CONTENT_DIGEST'}, 'FTP-T02':{'TLS_CHANNEL_PROTECTION'},
    'FTP-T06':{'KNOWN_CONTENT_DIGEST'}, 'SMB-T02':{'SMBV1_RESPONSE'},
    'SMB-T06':{'DIRECTORY_LISTING'},'SMB-T07':{'KNOWN_CONTENT_DIGEST'},
}
SENTINEL = re.compile(r'^ref:[a-zA-Z0-9][a-zA-Z0-9._:/-]{2,127}$')
SCENARIO_CODE = re.compile(r'^S[0-9]{2,4}$')


def require(pred, reason):
    if not pred:
        raise ValueError(reason)


def keys(obj, required, where):
    require(type(obj) is dict and set(obj)==set(required), f'{where}: campos obligatorios inesperados')


def read(root, rel):
    root=Path(root).resolve(strict=True)
    p=root/rel
    require(p.is_file() and p.resolve().is_relative_to(root) and
            not any(x.is_symlink() for x in (p,*list(p.parents)[:len(p.relative_to(root).parts)-1])),
            f'{rel}: archivo ausente o ruta vinculada')
    def obj_pairs(pairs):
        o={}
        for k,v in pairs:
            require(k not in o, f'{rel}: clave JSON duplicada {k}')
            o[k]=v
        return o
    return json.loads(p.read_text(encoding='utf-8'), object_pairs_hook=obj_pairs)


def canonical_sha(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,
                    separators=(',',':')).encode('utf-8')).hexdigest()


def validate(root=ROOT, *, require_empty=True):
    root=Path(root).resolve(strict=True)
    file=root/REL
    require(file.is_file() and not file.is_symlink(), 'Catálogo ausente/vinculado')
    require(hashlib.sha256(file.read_bytes()).hexdigest()==CATALOG_SHA256,
            'Catálogo P7 modificado respecto a revisión documental fijada')
    c=read(root,REL)
    keys(c,['schema_version','status','baseline_commit','thesis_sha256','source_sections','source_tables',
            'stage_registry','counts','execution_enabled','catalog_frozen','pilot_completed','derived_real_cases',
            'type_vocabulary','interpretation','budget','prohibitions','execution_profile','families'],'catalog')
    require(c['schema_version']=='1.0' and c['status']=='P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE', 'Catálogo indebidamente habilitado')
    require(c['baseline_commit']==BASE and c['thesis_sha256']==THESIS and
            c['source_sections']==['3.7','3.7.1','3.7.2','3.7.3','3.7.4','3.7.5'] and
            c['source_tables']==['3.7','3.8','3.9','3.10','3.11','3.12'], 'Referencia de tesis incorrecta')
    require(c['stage_registry']=='lab/scenario-separation-v1/registry.json' and
            c['counts']=={'ssh':8,'ftp':8,'smb':9,'total':25}, 'Etapas o cantidades diferentes')
    require(c['execution_enabled'] is False and c['catalog_frozen'] is False and
            c['pilot_completed'] is False and c['derived_real_cases']==0 and
            c['execution_profile']=='P8_NOT_DEFINED', 'Se pretende autorizar o congelar antes de tiempo')
    keys(c['type_vocabulary'],['preconditions','parameter_slots','supports'],'type_vocabulary')
    keys(c['interpretation'],['logic_values','technical_result_classes','technical_result_is_evidence',
            'negative_is_not_unobserved','admissibility_requires_independent_A6'],'interpretation')
    i=c['interpretation']
    require(i=={'logic_values':['VERDADERO','FALSO','ND'],
           'technical_result_classes':['POSITIVO_VALIDO','NEGATIVO_VALIDO','INCONCLUSO','INCIDENCIA','INVALIDO','NO_ADMITIDO'],
           'technical_result_is_evidence':False,'negative_is_not_unobserved':True,
           'admissibility_requires_independent_A6':True}, 'Resultados/evidencia confundidos')
    b=c['budget']
    keys(b,['ordinary_attempts','additional_attempts','timeout_seconds','operation_count',
           'transfer_bytes','output_bytes','memory_mib','request_count','limits_status'],'budget')
    require(type(b['ordinary_attempts']) is int and b['ordinary_attempts']==1 and
            b['additional_attempts']=='PREAUTHORIZED_ONLY_NO_HIDDEN_RETRY' and
            b['limits_status']=='PILOT_REQUIRED_BEFORE_FREEZE' and
            all(b[k] is None for k in ('timeout_seconds','operation_count','transfer_bytes','output_bytes','memory_mib','request_count')),
            'Presupuesto inferido antes del piloto o repetición no autorizada')
    require(set(c['prohibitions'])=={'FORCE_BRUTE','PASSWORD_SPRAYING','UNBOUNDED_ENUMERATION',
      'EXTERNAL_TARGETS','DESTRUCTIVE_ACTIONS','MALWARE','PERSISTENCE',
      'ALTER_EXISTING_USERS_PERMISSIONS_KEYS_OR_FILES','AUTOMATIC_MATERIAL_CHANGE',
      'HIDDEN_RETRIES','UNAUTHORIZED_FALLBACK','RUN_WITHOUT_CLEANUP_OR_TRACE'}, 'Prohibiciones ausentes')
    require(type(c['families']) is list and len(c['families'])==25, 'No hay 25 familias')
    ids=[r['id'] for r in c['families']]
    require(len(ids)==len(set(ids)) and set(ids)==set(LEVELS), 'Familias duplicadas/ajenas/ausentes')
    pre,slots,support=set(),set(),set()
    for f in c['families']:
        keys(f,['id','protocol','source_table','condition_es','minimum_action_es','precedence','variants',
                'preconditions','parameter_slots','required_supports','acceptance_supports','cleanup',
                'interpretation_boundary_es'],'family')
        id_=f['id'];proto=id_.split('-')[0].lower()
        require(f['protocol']==proto and id_ in NAMES[proto] and
                f['source_table']=={'ssh':'3.9','ftp':'3.10','smb':'3.11'}[proto], 'Familia/protocolo/tabla incongruente')
        require(f['precedence']==LEVELS[id_] and f['variants']==VARIANTS.get(id_), 'Precedencia/variantes alteradas')
        require(all(type(f[k]) is str and len(f[k].strip())>=12 for k in
                    ['condition_es','minimum_action_es','interpretation_boundary_es']), 'Definición sin detalle')
        for name in ['preconditions','parameter_slots','required_supports','acceptance_supports']:
            arr=f[name]
            require(type(arr) is list and len(arr)>0 and len(arr)==len(set(arr)) and
                    all(type(s) is str and re.fullmatch('[a-z0-9_]+' if name=='parameter_slots' else '[A-Z0-9_]+',s) for s in arr),
                    f'{id_}: {name} inválido')
        require(set(['SCOPE_APPROVED','LAB_ISOLATION_CONFIRMED','DESTINATION_AUTHORIZED','CLIENT_COMPATIBLE'])<=set(f['preconditions']), 'Guardas comunes ausentes')
        require(set(['authorization_ref','target_ref'])<=set(f['parameter_slots']), 'Referencias de autorización o destino ausentes')
        require(set(['TARGET_ATTESTATION','INTEGRITY_PROVENANCE'])<=set(f['required_supports']), 'Soportes de identidad/procedencia ausentes')
        require(set(f['acceptance_supports'])<=set(f['required_supports']) and
                CRITICAL.get(id_,set())<=set(f['acceptance_supports']), 'Aceptación sin soporte crítico')
        cleanup=('VERIFY_THEN_REMOVE_MARKER' if id_ in MARKERS else
                'CONDITIONAL_WRITE_MARKER_CLEANUP' if id_ in COMPARES else 'NO_MUTATION')
        require(f['cleanup']==cleanup, 'Política de limpieza incompatible')
        if id_ in MARKERS:
            require({'MARKER_CREATED','MARKER_VERIFIED','CLEANUP_CONFIRMED'}<=set(f['acceptance_supports']),
                    'Marcador: escritura y limpieza no acreditadas separadamente')
            require('CLEANUP_VERIFIABLE' in f['preconditions'], 'Marcador sin limpieza prevista')
        if id_ in COMPARES:
            require('ACCESS_COMPARISON' in f['acceptance_supports'], 'Comparación sin soportes equivalentes')
        pre.update(f['preconditions']);slots.update(f['parameter_slots']);support.update(f['required_supports'])
    require(c['type_vocabulary']=={'preconditions':sorted(pre),'parameter_slots':sorted(slots),'supports':sorted(support)},
            'Vocabulario/tipos no coincide con familias')
    reg=read(root,c['stage_registry'])
    require(reg['status']=='LOGICAL_SEPARATION_PREPARED_NOT_DEPLOYED' and
            reg['baseline_commit']=='cc0d7486b0bcf06ef7dd68e8f9511c1e8ddc1b4d' and
            reg['experimental_design']['sample_frozen'] is False and
            reg['experimental_design']['pilot_completed'] is False and
            reg['experimental_design']['planned_units']==54 and
            reg['open_findings']==['AL-06','AL-07'] and reg['open_obligations']==7,
            'Registro P6 no preservado')
    for stage in STAGES:
        m=read(root,'lab/scenario-separation-v1/'+stage+'.json')
        require(m['stage']==stage and m['status']=='RESERVED_NOT_DEPLOYED' and
                m['units']==[] and m['cases']==[] and m['executions']==[] and
                m['attempts']==[] and m['artifacts']==[] and
                (not require_empty or (m['services']==[] and m['scenarios']==[])),
                'Casos reales o muestra experimental inesperados para P7')
    trace=read(root,TRACE)
    keys(trace,['schema_version','status','roadmap_step','source_sha256','baseline_commit','catalog_path',
                'catalog_sha256','count_by_protocol','declared_case_count','implemented_executor',
                'pilot_limits','physical_isolation','functional_acceptance','experimental_validation',
                'open_findings','open_obligations','requirements','source_sections','artifacts'], 'trace')
    require(trace['schema_version']=='1.0' and trace['status']=='P7_SPECIFICATIONS_PREPARED_NOT_EXECUTABLE' and
            trace['roadmap_step']==7 and trace['source_sha256']==THESIS and trace['baseline_commit']==BASE and
            trace['catalog_path']==REL and trace['catalog_sha256']==CATALOG_SHA256 and
            trace['count_by_protocol']==c['counts'] and trace['declared_case_count']==0 and
            trace['implemented_executor'] is False and trace['pilot_limits']=='PENDING' and
            trace['physical_isolation']=='NOT_VERIFIED' and trace['functional_acceptance']=='PENDING' and
            trace['experimental_validation']=='NOT_RUN' and
            trace['open_findings']==['AL-06','AL-07'] and trace['open_obligations']==7,
            'Trazabilidad P7 sobreatribuye resultados')
    require(trace['source_sections']==c['source_sections'] and
            set(trace['requirements'])=={'AC-24','AC-25','AC-27','MET-09','MET-10','MET-12','MET-13'},
            'Trazabilidad de requisitos inconsistente')
    for file in trace['artifacts']:
        require(type(file) is str and not Path(file).is_absolute() and '..' not in Path(file).parts
                and (root/file).is_file(), 'Artefacto de trazabilidad P7 ausente o traversal')
    return {'status':'PASS_P7_FAMILY_SPECIFICATIONS_ONLY','families':len(ids),
            'ssh':8,'ftp':8,'smb':9,'real_derived_cases':0,'executable_profiles':'P8_NOT_DEFINED',
            'pilot_limits':'PENDING','experimental_validation':'NOT_RUN'}


def derive_case(root, request):
    """Create an IN-MEMORY, non-executable descriptor; never create sessions or files.

    As the current P6 manifests contain zero scenarios, this is used only by synthetic
    oracle tests until real, pre-identified service-scenarios are registered separately.
    """
    validate(root, require_empty=False)
    keys(request,['stage','scenario_id','family_id','scenario_code','ordinal','variant','parameter_refs'],'request')
    stage=request['stage']
    require(stage in STAGES, 'Etapa fuera de P6')
    m=read(root,'lab/scenario-separation-v1/'+stage+'.json')
    services={s['id']:s for s in m['services']}
    scenarios={s['id']:s for s in m['scenarios']}
    require(request['scenario_id'] in scenarios, 'Escenario real no registrado para derivación')
    scenario=scenarios[request['scenario_id']]
    require(scenario['service_id'] in services, 'Escenario sin servicio registrado')
    service=services[scenario['service_id']]
    keys(service,['id','protocol','network_id','instance_ref'],'service P6')
    keys(scenario,['id','service_id','profile','technical_fingerprint','prior_use','origin_scenario_ids'],'scenario P6')
    require(service['id'].startswith(stage+'-svc-') and
            service['network_id']==f"ardrec-{stage}-{service['protocol']}" and
            scenario['id'].startswith(stage+'-scn-') and
            type(service['instance_ref']) is str and service['instance_ref'].strip(),
            'Origen P6 fuera de namespace o instancia inválida')
    profile=scenario['profile']
    keys(profile,['version','configuration_sha256','exposure','authentication',
                  'controls_sha256','initial_state_sha256','context_sha256'],'profile P6')
    for field in ('configuration_sha256','controls_sha256','initial_state_sha256','context_sha256'):
        require(type(profile[field]) is str and re.fullmatch('[a-f0-9]{64}',profile[field]),
                'Perfil de escenario sin huella válida')
    require(scenario['technical_fingerprint']==canonical_sha({'protocol':service['protocol'],'profile':profile}),
            'Huella técnica de escenario inconsistente')
    require(type(scenario['prior_use']) is list and type(scenario['origin_scenario_ids']) is list and
            all(type(x) is str and x.startswith(stage+'-scn-') and x in scenarios and x!=scenario['id']
                for x in scenario['origin_scenario_ids']),
            'Linaje de escenario fuera de etapa')
    c=read(root,REL)
    matches=[f for f in c['families'] if f['id']==request['family_id']]
    require(len(matches)==1, 'Familia ausente en 25')
    f=matches[0]
    require(services[scenario['service_id']]['protocol']==f['protocol'], 'Familia incompatible con servicio')
    require(type(request['scenario_code']) is str and SCENARIO_CODE.fullmatch(request['scenario_code']),
            'Código id_i fuera del formato de derivación provisional Snn')
    ordinal=request['ordinal']
    require(type(ordinal) is int and 1<=ordinal<=99, 'Ordinal nn inválido')
    v=request['variant']
    if f['variants'] is None:
        require(v is None, 'Variante no definida para familia')
        precedence=f['precedence']
    else:
        require(type(v) is str and v in f['variants']['precedence_by_option'], 'Variante no aprobada')
        precedence=f['variants']['precedence_by_option'][v]
    slots=request['parameter_refs']
    require(type(slots) is dict and set(slots)==set(f['parameter_slots']), 'Parámetros materiales incompletos/adicionales')
    for name,value in slots.items():
        require(type(value) is str and SENTINEL.fullmatch(value) and '..' not in value,
                'Parámetro no es referencia simbólica permitida: '+name)
    cleanup=f['cleanup']
    if cleanup=='CONDITIONAL_WRITE_MARKER_CLEANUP':
        cleanup='VERIFY_THEN_REMOVE_MARKER' if v=='WRITE' else 'NO_MUTATION'
    acceptance=list(f['acceptance_supports'])
    required_supports=list(f['required_supports'])
    preconditions=list(f['preconditions'])
    if f['id']=='SMB-T03':
        selected={'SIGNING':'SMB_SIGNATURE','ENCRYPTION':'SMB_ENCRYPTION'}[v]
        excluded={'SIGNING':'SMB_ENCRYPTION','ENCRYPTION':'SMB_SIGNATURE'}[v]
        required_supports.remove(excluded)
        acceptance.append(selected)
    if f['id']=='FTP-T02':
        if v=='DATA':
            preconditions.extend(['SESSION_AUTHENTICATED','DATA_CHANNEL_PREDEFINED'])
            acceptance.append('CONTROL_DATA_CORRELATION')
        else:
            required_supports.remove('CONTROL_DATA_CORRELATION')
    if f['id'] in COMPARES and v=='WRITE':
        preconditions.extend(['WRITE_FIXTURE_PREPARED','CLEANUP_VERIFIABLE'])
        required_supports.extend(['MARKER_CREATED','MARKER_VERIFIED','CLEANUP_CONFIRMED'])
        acceptance.extend(['MARKER_CREATED','MARKER_VERIFIED','CLEANUP_CONFIRMED'])
    return {
      'case_id':f"{f['id']}-{request['scenario_code']}-{ordinal:02d}",
      'source_family':f['id'],'stage':stage,'scenario_id':request['scenario_id'],
      'variant':v,'precedence':precedence,'parameter_refs':dict(slots),
      'material_parameter_sha256':canonical_sha(slots),
      'preconditions':preconditions, 'preconditions_value':'ND',
      'required_supports':required_supports, 'acceptance_supports':acceptance,
      'cleanup':cleanup, 'limit_status':'PILOT_REQUIRED_BEFORE_FREEZE',
      'status':'DRAFT_NOT_AUTHORIZED', 'execution_enabled':False,
      'not_an_experimental_unit':True,
    }


def derive_batch(root, requests):
    require(type(requests) is list and len(requests)>0,
            'Se requieren declaraciones explícitas para cada caso')
    cases=[derive_case(root,r) for r in requests]
    ids=[c['case_id'] for c in cases]
    require(len(set(ids))==len(ids),'Identidad de caso derivado duplicada')
    return cases


if __name__=='__main__':
    try:
        print(json.dumps(validate(),sort_keys=True,ensure_ascii=False))
        print('ARDREC_POINT7_FAMILY_CATALOG=PASS_25_DRAFT_ONLY')
    except (ValueError,OSError,KeyError,TypeError,json.JSONDecodeError) as exc:
        print('ARDREC_POINT7_FAMILY_CATALOG=FAIL: '+str(exc))
        raise SystemExit(1)
