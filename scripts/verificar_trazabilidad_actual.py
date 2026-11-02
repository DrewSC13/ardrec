"""Validar trazabilidad vigente y separar cobertura de aceptación / Current traceability."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASE = '228bdedf09d06906ddfa184525e9a7c60f4e2dc6'
SOURCE = '6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72'
REGISTRY = 'docs/traceability/development-v2.json'
EVIDENCE = 'docs/traceability/evidence-v2.json'
NOTE = 'docs/traceability/development-v2.md'
TOOL_TEST = 'test_traceability_current'
# Reviewed requirement/component associations; update through an explicit source review.
COMPONENT_REQUIREMENTS = {'NUMERIC': ['AC-02', 'AC-15'], 'PROTOCOL': ['AC-02', 'AC-04'], 'TRANSPORT': ['AC-03'], 'STATE': ['AC-01', 'AC-10', 'AC-11', 'AC-18', 'AC-19', 'AC-22', 'AC-24'], 'RECONCILIATION': ['AC-05', 'AC-10', 'AC-11', 'AC-21', 'AC-27'], 'PERSISTENCE': ['AC-20', 'AC-21', 'AC-27'], 'JOURNAL': ['AC-05', 'AC-10', 'AC-11', 'AC-21'], 'SOCKET_RECONCILIATION': ['AC-03', 'AC-05', 'AC-11', 'AC-21'], 'MAGNITUDES': ['AC-02', 'AC-15', 'AC-16', 'AC-20'], 'TEMPORAL': ['AC-04', 'AC-10', 'AC-11', 'AC-21'], 'PROJECTION': ['AC-02', 'AC-07', 'AC-15', 'AC-16', 'AC-17', 'AC-19'], 'REFERENCES': ['AC-04', 'AC-14', 'AC-19'], 'ARCHIVE': ['AC-14', 'AC-20', 'AC-21', 'AC-27'], 'ANCHOR': ['AC-07', 'AC-19', 'AC-20', 'AC-21', 'AC-27'], 'COUNTERS': ['AC-10', 'AC-19', 'AC-20', 'AC-21'], 'PEER': ['AC-01', 'AC-03'], 'REFERENCE_AUDIT': ['AC-06', 'AC-07', 'AC-09', 'AC-13', 'AC-14', 'AC-15', 'AC-16'], 'TRACEABILITY_AUDIT': ['AC-27']}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read(root, name):
    return json.loads((root / name).read_text(encoding='utf-8'))


def indexed(items):
    require(isinstance(items, list), 'Se requiere una lista')
    ids = [x['id'] for x in items]
    require(len(ids) == len(set(ids)), 'Identificador duplicado')
    return {x['id']: x for x in items}


def relative(root, name):
    require(isinstance(name, str) and bool(name), 'Ruta vacía')
    p = PurePosixPath(name)
    require(not p.is_absolute() and '..' not in p.parts and '\\' not in name,
            'Ruta externa: ' + name)
    target = root / name
    require(target.resolve().is_relative_to(root.resolve()) and target.is_file()
            and not any(x.is_symlink() for x in [target, *target.parents]), 'Ruta no regular: ' + name)
    return target


def bilingual(value):
    require(isinstance(value, dict) and set(value) == {'es', 'en'}
            and all(isinstance(v, str) and v.strip() for v in value.values()), 'Texto bilingüe incompleto')


def discover(root):
    """Discover real methods, including dynamically installed tests; never run them."""
    saved = sys.path[:]
    try:
        sys.path.insert(0, str(root / 'src'))
        sys.path.insert(0, str(root / 'tests/unit'))
        loader = unittest.TestLoader()
        suite = loader.discover(str(root / 'tests/unit'), pattern='test_*.py')
        require(not loader.errors, 'Error al descubrir pruebas: ' + str(loader.errors))
        def flatten(items):
            for item in items:
                if isinstance(item, unittest.TestSuite):
                    yield from flatten(item)
                else:
                    yield item.id()
        ids = list(flatten(suite))
        require(len(ids) == len(set(ids)), 'Identidades de pruebas duplicadas')
        return sorted(ids)
    finally:
        sys.path[:] = saved


def render(registry):
    lines = ['# Trazabilidad vigente / Current traceability', '',
             '## Español', '',
             'Base revisada: `' + registry['baseline_commit'] + '`. Fuente: `' + SOURCE + '`.', '',
             registry['scope']['es'], '',
             '**Lectura:** requisito → algoritmo o responsable → componente → módulo y comprobaciones → evidencia → trabajo pendiente.', '',
             'Una asociación a una suite identifica soporte parcial del componente; no afirma que cada método pruebe todo el requisito. Los 405 métodos Python incluyen métodos generados dinámicamente. Los 73 métodos Rust y los siete verificadores tienen identidades separadas. La evidencia recibida se atribuye a las suites de la base, no a esta nueva versión ni a resultados individuales.', '',
             'Los planes TF/TE/TM conservan estado pendiente. Los 51 casos son oráculos de referencia; no son ejecuciones de A1–A10. AL-06 y AL-07 y las siete obligaciones residuales conservan sus condiciones de entrada.', '',
             '## English', '', registry['scope']['en'], '',
             'Read requirement → algorithm or owner → component → modules/checks → evidence → pending work. Component-suite links indicate partial support, not assertion-level or full-requirement coverage. Baseline suite evidence does not establish execution of this new version or individual tests. Verification plans and full acceptance remain pending; 51 reference oracles are not A1–A10 executions.', '',
             '## Requisitos / Requirements', '',
             '| ID | Fuente / Source | Algoritmos / Algorithms | Componentes / Components | Pasos / Steps | Verificación prevista / Planned verification |',
             '| --- | --- | --- | --- | --- | --- |']
    for row in registry['requirements']:
        alg = ', '.join(row['algorithms']) or 'Responsable metodológico / Methodological owner'
        lines.append('| ' + ' | '.join([row['id'], ', '.join(row['source_sections']), alg,
                    ', '.join(row['components']) or 'Pendiente / Pending',
                    ', '.join(map(str, row['roadmap_steps'])), row['planned_verification']['id']]) + ' |')
    for row in registry['requirements']:
        lines += ['', '### ' + row['id'], '', row['requirement']['es'], '', row['requirement']['en'], '',
                  '- Pendiente: ' + row['remaining_work']['es'],
                  '- Pending: ' + row['remaining_work']['en'],
                  '- Verificación prevista / Planned verification: `' + row['planned_verification']['id'] + '` — ' + row['planned_verification']['es'],
                  '- Planned check: ' + row['planned_verification']['en'],
                  '- Obligaciones / Obligations: ' + (', '.join(row['development_obligations']) or 'Plan específico del requisito / Requirement verification plan'),
                  '- Evidencia / Evidence: ' + ('EV-MAIN26-CI: suites de componentes / component suites' if row['components'] else 'Sin ejecución acreditada / No execution evidence')]
    lines += ['', '## Componentes y comprobaciones / Components and checks', '']
    for comp in registry['components']:
        lines += ['### ' + comp['id'], '', comp['scope']['es'], '', comp['scope']['en'], '',
                  '- Requisitos / Requirements: ' + ', '.join(comp['requirements']),
                  '- Módulos / Modules: ' + ', '.join('`' + x + '`' for x in comp['modules']),
                  '- Comprobaciones / Checks: ' + str(len(comp['checks'])) + '; identidades y comandos en `development-v2.json`.',
                  '- Evidencia de base / Baseline evidence: ' + ', '.join(comp['evidence_ids']), '']
    lines += ['## Mantenimiento / Maintenance', '',
              'Español: al cambiar un requisito o componente, actualizar sus vínculos, huellas, pruebas y evidencia en una revisión identificable. Registrar una comprobación pendiente cuando aún no exista. Conservar v1 y el cierre del punto 1. Ejecutar `python3 scripts/verificar_trazabilidad_actual.py` y la suite Python; CI repite la validación.', '',
              'English: when a requirement or component changes, update links, hashes, checks and evidence in an identifiable revision. Keep missing checks explicitly planned. Preserve v1 and point 1 closure. Run the current traceability checker and Python suite; CI repeats validation.', '']
    return '\n'.join(lines)


def validate(root=ROOT, registry=None, evidence=None, *, discovered=None, check_note=True):
    registry = read(root, REGISTRY) if registry is None else registry
    evidence = read(root, EVIDENCE) if evidence is None else evidence
    old = read(root, 'docs/traceability/development-v1.json')
    closure = read(root, 'docs/traceability/point-1-closure-v1.json')
    coverage = indexed(read(root, 'docs/acceptance/current-coverage-v2.json')['criteria'])
    for doc in (registry, evidence):
        require(doc['schema_version'] == '2.0' and doc['baseline_commit'] == BASE, 'Base/version incorrecta')
        require(doc['source'] == {'label': 'TESIS ARDREC', 'sha256': SOURCE}, 'Fuente alterada')
    require(registry['status'] == 'REGISTERED_REQUIREMENTS_TRACED_NOT_SYSTEM_ACCEPTANCE', 'Alcance incorrecto')
    bilingual(registry['scope'])
    for key, expected in [('system_functional_acceptance', 'PENDING'), ('full_specification_alignment', 'PENDING'),
                          ('full_analytical_state', 'PENDING'), ('experimental_validation', 'NOT_RUN'),
                          ('algorithm_implementation', 'NOT_STARTED'), ('operational_prototype', 'NOT_STARTED'),
                          ('before_real_executor_gate', 'BLOCKED_BY_RESIDUAL_OBLIGATIONS')]:
        require(registry[key] == expected, 'Promoción sin evidencia: ' + key)
    require(registry['open_findings'] == closure['open_findings'] == ['AL-06', 'AL-07'], 'Hallazgos abiertos alterados')
    require(registry['scoped_closures'] == closure['scoped_closures'], 'Cierres acotados alterados')
    reqs = indexed(registry['requirements']); original = indexed(old['requirements'])
    require(set(reqs) == set(original) and len(reqs) == 44, 'Inventario de requisitos incompleto')
    components = indexed(registry['components']); checks = indexed(registry['test_inventory'])
    require({c['id']:c['requirements'] for c in components.values()} == COMPONENT_REQUIREMENTS, 'Asociación revisada de componentes alterada')
    ev = indexed(evidence['items'])
    require(set(ev) == {'EV-MAIN26-CI'}, 'Inventario de evidencia incorrecto')
    e = ev['EV-MAIN26-CI']
    require((e['kind'], e['commit'], e['run_id'], e['event'], e['branch'], e['workflow'], e['reported_conclusion']) ==
            ('USER_SUPPLIED_INTEGRATION_OUTPUT', BASE, 41358531943, 'push', 'main', '.github/workflows/ci.yml', 'success'), 'Identidad CI incorrecta')
    require(e['url'] == 'https://github.com/DrewSC13/ardrec/actions/runs/41358531943', 'URL CI incorrecta')
    require((e['python_tests'], e['rust_tests'], e['peer_scenarios']) == (405, 73, 7), 'Conteo CI incorrecto')
    require(e['reported_log_hashes'] == [
        {'job_id':125003719173,'sha256':'06c2e412f622652c71d3959d467eddd04254f31bd8e719010593f56f7dcdad07'},
        {'job_id':125003719260,'sha256':'985fdaeaee6bacbaa45fadc0b2be2508262202342a0361f8a8f990dd8446f0dd'}], 'Huellas recibidas alteradas')
    for key in ['independently_queried','per_test_results_available','raw_logs_archived_in_repository','proves_system_acceptance','proves_experimental_validation']:
        require(e[key] is False, 'Evidencia sobreatribuida: ' + key)
    bilingual(e['provenance'])
    require(evidence['new_increment_execution'] == 'PENDING_LOCAL_AND_REMOTE_VERIFICATION', 'Evidencia de esta revisión inventada')
    sources = registry['source_files']
    for path, digest in sources.items():
        require(hashlib.sha256(relative(root, path).read_bytes()).hexdigest() == digest, 'Fuente modificada: ' + path)
    required_sources = {c['path'] for c in checks.values()} | {p for c in components.values() for p in c['modules']}
    required_sources |= {'docs/traceability/development-v1.json','docs/traceability/evidence-v1.json','docs/traceability/alignment-current-v1.json','docs/traceability/point-1-closure-v1.json','docs/acceptance/system-v1.json','docs/acceptance/current-coverage-v1.json','docs/acceptance/current-coverage-v2.json','tests/fixtures/model-reference-v1.json'}
    require(set(sources) == required_sources, 'Procedencia incompleta o ajena')
    observed = discover(root) if discovered is None else discovered
    baseline = sorted(x for x in observed if not x.startswith(TOOL_TEST + '.'))
    declared = sorted(c['unittest_id'] for c in checks.values() if c['kind'] == 'PYTHON_UNIT')
    require(baseline == declared and len(baseline) == 405, 'Métodos Python ausentes, nuevos o renombrados')
    rust_observed = {}
    for path in (root / 'crates/ardrec-executor/src').rglob('*.rs'):
        for name in re.findall(r'#\[test\]\s*fn\s+(\w+)\s*\(', path.read_text()):
            rust_observed[path.relative_to(root).as_posix() + '::' + name] = name
    require({c['id']:c['symbol'] for c in checks.values() if c['kind']=='RUST_UNIT'} == rust_observed
            and len(rust_observed)==73, 'Inventario Rust incompleto')
    require(sum(c['kind']=='INTEGRATION_SCRIPT' for c in checks.values())==7, 'Faltan verificadores de integración')
    require((registry['baseline_python_tests'],registry['baseline_rust_tests'],registry['integration_scripts'])==(405,73,7), 'Conteos de base alterados')
    for cid, c in components.items():
        bilingual(c['scope'])
        require(c['full_requirement_fulfillment'] is False and c['evidence_ids']==['EV-MAIN26-CI'], 'Componente sobreatribuido')
        require(c['verification_level']==('DOCUMENT_OR_REFERENCE_AUDIT_ONLY' if 'AUDIT' in cid else 'BASELINE_COMPONENT_SUITE_REPORTED'), 'Oráculo confundido con producción')
        require(c['checks'] and len(c['checks'])==len(set(c['checks'])) and all(t in checks for t in c['checks']), 'Vínculo de prueba roto')
        require(set(c['checks'])=={t['id'] for t in checks.values() if t['component']==cid}, 'Asignación de comprobaciones incoherente')
        require(c['requirements']==[r['id'] for r in reqs.values() if cid in r['components']] and c['requirements'], 'Índice de componente incoherente')
        for p in c['modules']:relative(root,p)
    for c in checks.values():
        require(c['component'] in components and c['fulfills_full_requirement'] is False
                and c['execution_attribution']=='BASELINE_SUITE_ONLY', 'Comprobación sobreatribuida')
        if c['kind']=='PYTHON_UNIT':
            mod,cls,method=c['unittest_id'].split('.')
            require(c['path']=='tests/unit/'+mod+'.py' and c['id']==c['path']+'::'+cls+'.'+method
                    and c['symbol']==cls+'.'+method, 'Identidad Python incoherente')
            require(c['command']==['python3','-m','unittest','discover','-s','tests/unit','-p',mod+'.py','-v'] and c['environment']=={'PYTHONPATH':'src'}, 'Comando Python incorrecto')
        elif c['kind']=='RUST_UNIT':
            require(c['id']==c['path']+'::'+c['symbol'] and c['command']==['cargo','test','--locked','--workspace','--lib'] and c['environment']=={}, 'Comando Rust incorrecto')
        else:
            require(c['kind']=='INTEGRATION_SCRIPT' and c['command']==['python3',c['path']] and c['environment']=={} and c['symbol'] is None, 'Comando integración incorrecto')
    obligations = indexed(registry['development_obligations'])
    originals = indexed(closure['development_obligations'])
    require(set(obligations)==set(originals) and len(obligations)==7, 'Obligaciones perdidas')
    for ident,o in obligations.items():
        require({k:v for k,v in o.items() if k!='requirements'}==originals[ident], 'Condición de entrada o residual alterada')
        require(o['requirements'] and len(o['requirements'])==len(set(o['requirements'])) and all(x in reqs for x in o['requirements']), 'Obligación sin seguimiento')
    for ident,r in reqs.items():
        base=original[ident]
        for key in ['kind','source_sections','requirement','algorithms','invariants','planned_modules','planned_verification','reference_cases','acceptance_status','system_functional_verification','experimental_validation']:
            require(r[key]==base[key], 'Requisito/aceptación histórica alterada: '+ident+'/'+key)
        require(r['test_links_inherited']==base['tests'], 'Enlaces históricos perdidos')
        require(all(t['test_id'] in checks for t in r['test_links_inherited']), 'Prueba heredada inexistente')
        require(r['open_findings']==[x for x in base['open_findings'] if x in registry['open_findings']], 'Hallazgo desligado de requisito')
        require(r['scoped_closed_findings']==[x for x in base['open_findings'] if x in registry['scoped_closures']], 'Cierre sin procedencia')
        require(r['components']==list(dict.fromkeys(r['components'])) and all(c in components for c in r['components']), 'Componente de requisito inválido')
        require(r['current_component_modules']==sorted({p for cid in r['components'] for p in components[cid]['modules']}), 'Módulos de requisito incoherentes')
        require(r['roadmap_steps'] and r['roadmap_steps']==sorted(set(r['roadmap_steps'])) and all(type(x) is int and 3<=x<=46 for x in r['roadmap_steps']), 'Plan de desarrollo inválido')
        require(r['development_obligations']==[o['id'] for o in obligations.values() if ident in o['requirements']], 'Obligación desvinculada')
        require(r['traceability_status']=='LINKED_WITH_EXPLICIT_PENDING_WORK', 'Estado de trazabilidad incorrecto')
        require(r['verification_relation']==('COMPONENT_SUITE_PARTIAL_SUPPORT' if r['components'] else 'PLANNED_ONLY_NO_EXECUTION_EVIDENCE'), 'Relación de verificación incorrecta')
        require(r['evidence_links']==([{'evidence_id':'EV-MAIN26-CI','claim':'COMPONENT_SUITES_ONLY_NOT_REQUIREMENT_ACCEPTANCE'}] if r['components'] else []), 'Evidencia incompatible con alcance')
        if ident.startswith('AC-'):
            require(r['implementation']==coverage[ident]['implementation'] and r['remaining_work']==coverage[ident]['remaining_work'], 'Cobertura del punto 1 alterada')
        else:
            require(not r['components'] and not r['algorithms'] and not r['test_links_inherited'] and r['non_algorithmic_owner']==base['non_algorithmic_owner']
                    and r['related_acceptance_criteria']==base['related_acceptance_criteria'] and r['implementation']=='NOT_ASSESSED' and r['remaining_work']==base['remaining_work'], 'Metodología presentada como ejecutada')
    for key in ['algorithms','invariants','reference_cases']:
        require(registry[key]==old[key], 'Algoritmos, invariantes u oráculos promovidos o modificados')
    expected={'modules':{p:[r['id'] for r in reqs.values() if p in r['current_component_modules']] for p in sorted({p for c in components.values() for p in c['modules']})},
              'checks':{t['id']:components[t['component']]['requirements'] for t in checks.values()},
              'evidence':{'EV-MAIN26-CI':[r['id'] for r in reqs.values() if r['components']]}}
    require(registry['reverse_indexes']==expected, 'Índices inversos incoherentes')
    workflow=(root/'.github/workflows/ci.yml').read_text()
    require(workflow.count('run: python3 scripts/verificar_trazabilidad_actual.py')==1, 'CI no ejecuta una sola validación vigente')
    if check_note:require((root/NOTE).read_text()==render(registry), 'Markdown desactualizado respecto de JSON')
    return {'requirements':44,'system_criteria':27,'methodological_obligations':17,'algorithms':10,'invariants':15,
            'reference_oracles':51,'components':len(components),'baseline_python_tests':405,'baseline_rust_tests':73,'integration_scripts':7,
            'development_obligations':7,'open_findings':['AL-06','AL-07'],'traceability':'PASS_REGISTERED_REQUIREMENTS',
            'system_functional_acceptance':'PENDING','experimental_validation':'NOT_RUN'}


if __name__=='__main__':
    try:
        result=validate()
        print(json.dumps(result,ensure_ascii=False,indent=2))
        print('ARDREC_CURRENT_TRACEABILITY=PASS')
    except (ValueError,KeyError,TypeError,OSError,SyntaxError) as error:
        print('ARDREC_CURRENT_TRACEABILITY=FAIL: '+str(error),file=sys.stderr)
        sys.exit(1)
