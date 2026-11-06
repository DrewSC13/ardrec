"""ARDREC P6: comprobación documental de dominios y procedencia (sin desplegar VM).

ES: No autoriza operaciones técnicas ni valida aislamiento físico.
EN: Document and reference validation only; neither execution authorization nor physical isolation.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
BASE = 'cc0d7486b0bcf06ef7dd68e8f9511c1e8ddc1b4d'
THESIS = '6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72'
STAGES = ('dev', 'pilot', 'exp')
PROTOCOLS = ('ssh', 'ftp', 'smb')
COLLECTIONS = ('services', 'scenarios', 'cases', 'executions', 'attempts', 'artifacts', 'units')
CATEGORIES = ('configurations', 'inventories', 'credential_refs', 'mutable_resources', 'logs', 'evidence', 'results')
HASH = re.compile(r'^[0-9a-f]{64}$')
IDENT = re.compile(r'^[a-z0-9][a-z0-9-]{1,127}$')
FAMILY_COUNTS = {'ssh': 8, 'ftp': 8, 'smb': 9}


def require(predicate: bool, reason: str) -> None:
    if not predicate:
        raise ValueError(reason)


def keys(obj, required, where):
    require(isinstance(obj, dict), f'{where}: objeto esperado')
    require(set(obj) == set(required), f'{where}: campos ausentes o desconocidos: {sorted(set(obj) ^ set(required))}')


def read(root: Path, rel: str):
    path = root / rel
    require(not any(p.is_symlink() for p in (path, *path.parents) if p != root.parent), f'{rel}: symlink no permitido')
    require(path.is_file(), f'{rel}: archivo ausente')
    def pairs(seq):
        d = {}
        for k, v in seq:
            require(k not in d, f'{rel}: clave JSON duplicada {k}')
            d[k] = v
        return d
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=pairs)


def stage_id(value, stage, kind):
    require(isinstance(value, str) and bool(IDENT.fullmatch(value)), f'{kind}: identidad inválida')
    require(value.startswith(stage + '-' + kind + '-'), f'{kind}: identidad incompatible con etapa {stage}')
    return value


def digest(value, where):
    require(isinstance(value, str) and bool(HASH.fullmatch(value)), f'{where}: SHA256 inválido')


def canonical_sha(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')).hexdigest()


def protected_path(path, prefix, where):
    require(isinstance(path, str) and '\\' not in path and '\x00' not in path, f'{where}: ruta inválida')
    p = PurePosixPath(path)
    require(not p.is_absolute() and '..' not in p.parts and '.' not in path.split('/') and
            len(p.parts) >= 4 and str(p) == path and path.startswith(prefix + '/'), f'{where}: ruta ajena o traversal')
    return path


def unique_objects(manifest, name, stage):
    arr = manifest[name]
    require(isinstance(arr, list), f'{stage}.{name}: colección no válida')
    found = {}
    for obj in arr:
        require(isinstance(obj, dict) and 'id' in obj, f'{stage}.{name}: entidad sin identidad')
        id_ = stage_id(obj['id'], stage, {'services':'svc','scenarios':'scn','cases':'case',
                         'executions':'exec','attempts':'att','artifacts':'art','units':'unit'}[name])
        require(id_ not in found, f'{stage}.{name}: identidad duplicada {id_}')
        found[id_] = obj
    return found


def validate(root: Path = ROOT):
    root = Path(root).resolve(strict=True)
    base = 'lab/scenario-separation-v1/'
    reg = read(root, base + 'registry.json')
    keys(reg, ['schema_version','status','baseline_commit','thesis_sha256','roadmap_step',
               'source_sections','requirements','open_findings','open_obligations',
               'experimental_design','stages','separation_policies','limitations'], 'registry')
    require(reg['schema_version'] == '1.0' and reg['status'] == 'LOGICAL_SEPARATION_PREPARED_NOT_DEPLOYED', 'Registro P6 sobreatribuido')
    require(reg['baseline_commit'] == BASE and reg['thesis_sha256'] == THESIS and reg['roadmap_step'] == 6, 'Procedencia de la especificación distinta')
    require(set(reg['source_sections']) >= {'1.9.3','1.9.4','3.2.1','3.3.1'}, 'Fuentes metodológicas ausentes')
    require(set(reg['requirements']) == {'AC-24','AC-25','AC-27','MET-09','MET-10','MET-12','MET-13'}, 'Trazabilidad P6 alterada')
    require(reg['open_findings'] == ['AL-06','AL-07'] and reg['open_obligations'] == 7, 'Obligaciones residuales perdidas')
    d = reg['experimental_design']
    keys(d, ['planned_units','by_protocol','sample_frozen','pilot_completed','functional_acceptance','experimental_validation'], 'experimental_design')
    require(d == {'planned_units':54,'by_protocol':{'ssh':18,'ftp':18,'smb':18},'sample_frozen':False,
                  'pilot_completed':False,'functional_acceptance':'PENDING','experimental_validation':'NOT_RUN'}, 'Cierre experimental anticipado')
    require(set(reg['stages']) == set(STAGES), 'Etapas ausentes o adicionales')
    require(reg['separation_policies'] == {
        'cross_stage_references':'REJECT', 'shared_generic_bases':'ALLOW_ONLY_WITH_PROVENANCE_NO_PRIOR_OBSERVATIONS',
        'record_promotion':'REJECT', 'pilot_in_experiment':'REJECT',
        'repeat_is_new_unit':'REJECT', 'physical_isolation':'NOT_VERIFIED',
        'real_execution':'NOT_AUTHORIZED_BY_P6'}, 'Política P6 reducida')
    require(isinstance(reg['limitations'], list) and len(reg['limitations']) >= 5, 'Límites no declarados')

    trace_p6 = read(root, 'docs/traceability/scenario-separation-v1.json')
    keys(trace_p6, ['schema_version','status','roadmap_step','source_sha256','source_sections',
                    'requirements','open_findings','open_obligations','artifacts','verification',
                    'safety_gates','unit_count_plan','unit_count_frozen',
                    'pilot_units_reused_in_experiment','historical_records_preserved'], 'trace_p6')
    require(trace_p6['schema_version']=='1.0' and
            trace_p6['status']=='P6_LOGICAL_SEPARATION_PREPARED_LOCAL_REVIEW_PENDING' and
            trace_p6['roadmap_step']==6 and trace_p6['source_sha256']==THESIS and
            trace_p6['requirements']==reg['requirements'] and
            trace_p6['open_findings']==reg['open_findings'] and
            trace_p6['open_obligations']==7 and trace_p6['unit_count_plan']==54 and
            trace_p6['unit_count_frozen']==0 and trace_p6['pilot_units_reused_in_experiment'] is False,
            'Trazabilidad P6 con promoción o discrepancia')
    require(trace_p6['verification']=={'document_and_reference_guards':'LOCAL_TEST_PENDING',
            'ci':'NOT_RUN','physical_stage_isolation':'NOT_VERIFIED','pilot':'NOT_RUN',
            'experiment':'NOT_RUN'}, 'Verificación no realizada declarada como cerrada')
    require(trace_p6['safety_gates']=={'AL-06':'OPEN','AL-07':'OPEN',
            'real_executor':'BLOCKED_BY_RESIDUAL_OBLIGATIONS'}, 'Puertas de seguridad prematuramente cerradas')
    require(set(trace_p6['historical_records_preserved']) >=
            {'lab/topology-v1.json','lab/services-v1/evidence.json',
             'lab/restoration-isolation-v1/record.json',
             'docs/traceability/development-v2.json'}, 'Antecedentes históricos no preservados')
    for name in trace_p6['artifacts']:
        require(isinstance(name,str) and '..' not in PurePosixPath(name).parts and
                not PurePosixPath(name).is_absolute() and (root/name).is_file(), 'Artefacto P6 de trazabilidad ausente')

    topo = read(root, 'lab/topology-v1.json')
    require(topo['status']=='DESIGN_ONLY_NOT_DEPLOYED' and topo['max_active_environments']==1, 'Topología histórica modificada')
    require(len(topo['networks']) == 9, 'Topología incompleta')
    topology = {x['id']:x for x in topo['networks']}
    require(len(topology)==9, 'ID de red duplicado')
    for n in topo['networks']:
        require(n['environment'] in STAGES and n['protocol'] in PROTOCOLS, 'Red de otra etapa/protocolo')
        require(n['id']==f"ardrec-{n['environment']}-{n['protocol']}", 'Red sin namespace')
        require(n['status']=='RESERVED_DESIGN_RECHECK_BEFORE_DEPLOYMENT', 'Red presentada como desplegada')
        require(ipaddress.ip_address(n['runner']) in ipaddress.ip_network(n['cidr']) and
                ipaddress.ip_address(n['target']) in ipaddress.ip_network(n['cidr']), 'Red o direcciones inconsistentes')
    svc = read(root, 'lab/services-v1/evidence.json')
    require(svc['environment']=='dev' and svc['experimental_data'] is False, 'Evidencia histórica reclasificada')
    restoration = read(root, 'lab/restoration-isolation-v1/record.json')
    require(restoration['limits']['environment']=='development_only' and
            restoration['limits']['pilot_and_experiment_deployed'] is False and
            restoration['limits']['experimental_validation']=='NOT_RUN', 'Restauración histórica reclasificada')
    trace = read(root, 'docs/traceability/development-v2.json')
    req_ids = {r['id'] for r in trace['requirements']}
    require(set(reg['requirements']) <= req_ids, 'ID de requisito no registrado')

    all_records = {}
    all_fingerprints = {}
    all_instance_refs = {}
    all_experimental_artifact_hashes = {}
    manifests = {}
    for stage in STAGES:
        s = reg['stages'][stage]
        keys(s, ['purpose','status','private_root','data_paths','network_ids','public_manifest'], stage)
        require(s['purpose']=={'dev':'DEVELOPMENT','pilot':'PILOT','exp':'EXPERIMENT'}[stage], 'Propósito intercambiado')
        require(s['status']=='RESERVED_NOT_DEPLOYED' and s['private_root']==f'private/{stage}', 'Ruta/estado de etapa alterado')
        require(s['public_manifest']==f'{stage}.json', 'Ruta de manifiesto cruzada')
        require(s['data_paths']=={x:f'private/{stage}/{x}' for x in CATEGORIES}, 'Categorías de datos cruzadas')
        require(sorted(s['network_ids'])==sorted(f'ardrec-{stage}-{p}' for p in PROTOCOLS), 'Referencias de red cruzadas')
        for ref in s['network_ids']:
            require(ref in topology and topology[ref]['environment']==stage, 'Red de etapa ajena')
        m = read(root, base + s['public_manifest'])
        keys(m, ['schema_version','stage','purpose','status','network_ids','shared_bases',*COLLECTIONS], stage+'.manifest')
        require(m['schema_version']=='1.0' and m['stage']==stage and m['purpose']==s['purpose'] and
                m['status']=='RESERVED_NOT_DEPLOYED' and sorted(m['network_ids'])==sorted(s['network_ids']), 'Cabecera de manifiesto inconsistente')
        require(isinstance(m['shared_bases'],list), 'Bases compartidas inválidas')
        for item in m['shared_bases']:
            keys(item,['id','sha256','provenance','purpose','contains_prior_observations'], 'shared_base')
            digest(item['sha256'],'shared_base')
            require(item['purpose']=='GENERIC_TOOL_OR_OS_BASE' and item['contains_prior_observations'] is False and
                    isinstance(item['provenance'],str) and bool(item['provenance']), 'Base con datos o uso anterior')
        maps = {name:unique_objects(m, name, stage) for name in COLLECTIONS}
        for collection in maps.values():
            for obj_id in collection:
                require(obj_id not in all_records, 'Identidad global reutilizada')
                all_records[obj_id] = stage
        manifests[stage] = (m,maps)
        services, scenarios, cases, executions, attempts, artifacts, units = (maps[x] for x in COLLECTIONS)

        for r in services.values():
            keys(r,['id','protocol','network_id','instance_ref'], 'service')
            require(r['protocol'] in PROTOCOLS and r['network_id']==f"ardrec-{stage}-{r['protocol']}" and
                    isinstance(r['instance_ref'],str) and bool(r['instance_ref'].strip()), 'Instancia/red inválida')
            require(r['instance_ref'] not in all_instance_refs or all_instance_refs[r['instance_ref']]==stage,
                    'Instancia de servicio física reutilizada entre etapas')
            all_instance_refs[r['instance_ref']]=stage
        for r in scenarios.values():
            keys(r,['id','service_id','profile','technical_fingerprint','prior_use','origin_scenario_ids'], 'scenario')
            require(r['service_id'] in services, 'Servicio de escenario ajeno')
            profile = r['profile']
            keys(profile,['version','configuration_sha256','exposure','authentication','controls_sha256','initial_state_sha256','context_sha256'], 'profile')
            for p in ['configuration_sha256','controls_sha256','initial_state_sha256','context_sha256']:
                digest(profile[p],p)
            require(all(isinstance(profile[p],str) and bool(profile[p].strip()) for p in ['version','exposure','authentication']), 'Caracterización incompleta')
            digest(r['technical_fingerprint'],'technical_fingerprint')
            require(r['technical_fingerprint']==canonical_sha({'protocol':services[r['service_id']]['protocol'],'profile':profile}), 'Huella de unidad mal calculada')
            require(isinstance(r['origin_scenario_ids'],list) and all(x in scenarios and x!=r['id'] for x in r['origin_scenario_ids']), 'Linaje cruzado o circular')
            require(isinstance(r['prior_use'],list), 'Historial de uso ausente')
            for event in r['prior_use']:
                keys(event,['stage','purpose','record_id'], 'prior_use')
                require(event['stage']==stage and event['purpose']==s['purpose'] and isinstance(event['record_id'],str) and event['record_id'], 'Uso anterior de otra etapa')
            all_fingerprints.setdefault(r['technical_fingerprint'], set()).add(stage)
        for r in cases.values():
            keys(r,['id','scenario_id','family_id'], 'case')
            require(r['scenario_id'] in scenarios, 'Caso de escenario ajeno')
            p = services[scenarios[r['scenario_id']]['service_id']]['protocol']
            require(r['family_id'] in {f'{p.upper()}-T{k:02d}' for k in range(1,FAMILY_COUNTS[p]+1)}, 'Familia fuera del catálogo de tesis')
        for r in executions.values():
            keys(r,['id','scenario_id','unit_id'], 'execution')
            require(r['scenario_id'] in scenarios, 'Ejecución de escenario ajeno')
            require(r['unit_id'] is None or (stage=='exp' and r['unit_id'] in units and units[r['unit_id']]['scenario_id']==r['scenario_id']), 'Unidad de ejecución ajena')
        for r in attempts.values():
            keys(r,['id','execution_id','case_id','repetition_of'], 'attempt')
            require(r['execution_id'] in executions and r['case_id'] in cases, 'Intento con ejecución/caso ajenos')
            require(cases[r['case_id']]['scenario_id']==executions[r['execution_id']]['scenario_id'], 'Intento que mezcla escenarios')
            require(r['repetition_of'] is None or (r['repetition_of'] in attempts and r['repetition_of']!=r['id']), 'Repetición cruzada')
        for r in artifacts.values():
            keys(r,['id','scenario_id','execution_id','attempt_id','category','path','sha256','origin_stage','prior_use'], 'artifact')
            require(r['category'] in CATEGORIES and r['origin_stage']==stage, 'Procedencia o categoría ajena')
            require(r['scenario_id'] in scenarios and r['execution_id'] in executions and
                    executions[r['execution_id']]['scenario_id']==r['scenario_id'], 'Artefacto de otra ejecución')
            require(r['attempt_id'] is None or (r['attempt_id'] in attempts and
                    attempts[r['attempt_id']]['execution_id']==r['execution_id']), 'Artefacto de intento ajeno')
            protected_path(r['path'], s['data_paths'][r['category']], 'artifact.path')
            digest(r['sha256'],'artifact.sha256')
            require(isinstance(r['prior_use'],list) and all(u==stage for u in r['prior_use']), 'Artefacto utilizado en otra etapa')
            if r['category'] in ('evidence','results','logs'):
                all_experimental_artifact_hashes.setdefault(r['sha256'],set()).add(stage)
        for r in units.values():
            keys(r,['id','scenario_id','protocol','status'], 'unit')
            require(stage=='exp' and r['status']=='PLANNED_NOT_FROZEN', 'Unidad experimental anticipada')
            require(r['scenario_id'] in scenarios and r['protocol']==services[scenarios[r['scenario_id']]['service_id']]['protocol'], 'Unidad de otra unidad/servicio')
        require(len({r['scenario_id'] for r in units.values()})==len(units), 'Una unidad duplicada por intentos/repeticiones')
        if stage != 'exp': require(len(units)==0, 'Dev/piloto confundido con unidad experimental')
        # P6 is a planning increment: no experimental samples or collections are frozen/collected.
        if stage=='exp':
            require(len({r['technical_fingerprint'] for r in scenarios.values()})==len(scenarios),
                    'Duplicación técnica dentro de la muestra experimental')
        if stage=='exp': require(len(units)==0 and len(executions)==0 and len(attempts)==0 and len(artifacts)==0, 'Exp muestra/resultado creado prematuramente')

    for fp, stages in all_fingerprints.items():
        require(not ('exp' in stages and len(stages)>1), 'Huella técnica reutilizada en desarrollo/piloto y experimento: '+fp)
    for hash_, stages in all_experimental_artifact_hashes.items():
        require(not ('exp' in stages and len(stages)>1), 'Resultado/evidencia promovido por copia: '+hash_)
    # An object can never be promoted by changing stage only: prefix, private path,
    # source references and observed-use history are checked jointly.
    return {'status':'PASS_LOGICAL_SEPARATION_ONLY','stages':list(STAGES),
            'reserved_networks':len(topology),'registered_scenarios':sum(len(m['scenarios']) for m,_ in manifests.values()),
            'frozen_experimental_units':0,'physical_isolation':'NOT_VERIFIED',
            'experimental_validation':'NOT_RUN','real_execution':'NOT_AUTHORIZED_BY_P6'}


if __name__ == '__main__':
    try:
        print(json.dumps(validate(),ensure_ascii=False,sort_keys=True))
        print('ARDREC_POINT6_DOCUMENT_AND_REFERENCE_GUARDS=PASS')
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print('ARDREC_POINT6_DOCUMENT_AND_REFERENCE_GUARDS=FAIL: '+str(exc))
        raise SystemExit(1)
