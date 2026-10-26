"""Comprobar vínculos de trazabilidad sin declarar conformidad del sistema."""

import ast
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = 'e72830432bc1c26cf5f8679752eddf28077e82a0'
SOURCE = '6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(root, name):
    return json.loads((root / name).read_text(encoding='utf-8'))


def index(items, label):
    require(isinstance(items, list), f'Lista inválida: {label}')
    identifiers = [item['id'] for item in items]
    require(len(identifiers) == len(set(identifiers)), f'Identificadores duplicados: {label}')
    return {item['id']: item for item in items}


def relative(root, name, *, exists=False):
    require(isinstance(name, str) and bool(name), 'Ruta vacía')
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts and '\\' not in name,
            f'Ruta fuera del proyecto: {name}')
    local = root / name
    require(local.resolve().is_relative_to(root.resolve()), f'Ruta externa: {name}')
    if exists:
        require(local.is_file() and not local.is_symlink(), f'Archivo no disponible: {name}')
    return local


def bilingual(value):
    require(set(value) == {'es', 'en'} and all(isinstance(v, str) and v.strip() for v in value.values()),
            'Texto bilingüe incompleto')


def validate(root=ROOT, registry=None, evidence=None):
    """Validar el registro histórico y las identidades actuales de sus enlaces."""
    registry = read(root, 'docs/traceability/development-v1.json') if registry is None else registry
    evidence = read(root, 'docs/traceability/evidence-v1.json') if evidence is None else evidence
    historical = read(root, 'docs/acceptance/system-v1.json')
    review = read(root, 'docs/traceability/alignment-current-v1.json')
    coverage = read(root, 'docs/acceptance/current-coverage-v1.json')
    catalog = read(root, 'tests/fixtures/model-reference-v1.json')
    for record in (registry, evidence):
        require(record['schema_version'] == '1.0' and record['baseline_commit'] == BASE,
                'Base o versión de trazabilidad inesperada')
        require(record['source'] == {'label': 'TESIS ARDREC', 'sha256': SOURCE},
                'Fuente vigente incorrecta')
    require(registry['status'] == 'TRACEABILITY_FOR_REGISTERED_REQUIREMENTS_NOT_CONFORMITY',
            'La matriz no acredita conformidad')
    for field, expected in [('system_functional_acceptance', 'PENDING'),
                            ('full_specification_alignment', 'PENDING'),
                            ('experimental_validation', 'NOT_RUN'),
                            ('operational_prototype', 'NOT_STARTED')]:
        require(registry[field] == expected, f'Estado sin evidencia: {field}')
    for key, source in [('matrix', historical), ('reference_catalog', catalog)]:
        item = registry['historical_sources'][key]
        relative(root, item['path'], exists=True)
        require(item['source_sha256'] == source['source']['sha256']
                and item['source_sha256'] != SOURCE, 'Procedencia histórica sobrescrita')
        require(re.fullmatch('[0-9a-f]{64}', item['sha256']), 'Huella histórica inválida')
    relative(root, registry['historical_sources']['current_review']['path'], exists=True)
    criteria = index(historical['criteria'], 'criterios históricos')
    current = index(coverage['criteria'], 'cobertura actual')
    methodological = index(review['methodological_requirements'], 'metodología')
    requirements = index(registry['requirements'], 'requisitos')
    require(set(requirements) == set(criteria) | set(methodological) and len(requirements) == 44,
            'Faltan requisitos registrados o aparecen identificadores ajenos')
    tests = index(registry['test_inventory'], 'pruebas')
    evidences = index(evidence['items'], 'evidencias')
    require(set(evidences) == {'EV-PR14-CI', 'EV-MAIN14-CI'}, 'Evidencias inesperadas')
    for key, commit, run, event in [('EV-PR14-CI', '714cb4cddfb0e5b51f5ddf9b910d4760feade92e', 40388033084, 'pull_request'),
                                    ('EV-MAIN14-CI', BASE, 40389092388, 'push')]:
        item = evidences[key]
        require(item['kind'] == 'USER_REPORTED_CI' and item['commit'] == commit
                and item['run_id'] == run and item['event'] == event
                and item['url'] == f'https://github.com/DrewSC13/ardrec/actions/runs/{run}',
                'Identidad de evidencia alterada')
        require(item['reported_conclusion'] == 'success'
                and item['proof_level'] == 'BASELINE_WORKFLOW_ONLY'
                and all(item[k] is False for k in ('independently_queried', 'raw_logs_archived_in_repository',
                        'per_test_results_available', 'proves_system_acceptance', 'proves_experimental_validation')),
                'Se atribuye a la evidencia un alcance no demostrado')
    trees = {}
    for item in tests.values():
        path = relative(root, item['path'], exists=True)
        require(re.fullmatch('[0-9a-f]{64}', item['source_sha256_at_baseline']), 'Huella de prueba inválida')
        require(item['baseline_evidence'] == ['EV-MAIN14-CI'], 'Evidencia de prueba desconocida')
        require(isinstance(item['command'], list) and item['command'][0] == 'python', 'Comando inválido')
        if item['kind'] == 'PYTHON_UNIT_METHOD':
            require(item['path'].startswith('tests/unit/test_') and item['path'].endswith('.py'), 'Ruta de método inválida')
            if item['path'] not in trees:
                tree = ast.parse(path.read_text(encoding='utf-8'))
                trees[item['path']] = {c.name + '.' + f.name for c in tree.body if isinstance(c, ast.ClassDef)
                                     for f in c.body if isinstance(f, ast.FunctionDef) and f.name.startswith('test_')}
            require(item['symbol'] in trees[item['path']], f'Método inexistente: {item["id"]}')
            require(item['id'] == item['path'] + '::' + item['symbol'], 'Identidad del método incoherente')
            require(item['execution_attribution'] == 'SUITE_LEVEL_ONLY_NOT_INDIVIDUAL_RESULT'
                    and item['command_scope'] == 'WHOLE_FILE_NOT_SINGLE_METHOD'
                    and item['command_environment'] == {'PYTHONPATH': 'src'}, 'Alcance individual no acreditado')
            require(item['command'] == ['python', '-m', 'unittest', 'discover', '-s', 'tests/unit',
                                        '-p', path.name, '-v'], 'Comando de descubrimiento incorrecto')
        else:
            require(item['kind'] == 'INTEGRATION_SCRIPT' and item['symbol'] is None
                    and item['path'].startswith('scripts/') and item['command'] == ['python', item['path']],
                    'Integración inválida')
            require(item['execution_attribution'] == 'WORKFLOW_STEP_REPORTED_NOT_RAW_LOG_REVIEW',
                    'Atribución de integración no acreditada')
            bilingual(item['scope'])
    require(sum(t['kind'] == 'PYTHON_UNIT_METHOD' for t in tests.values()) == 210
            and sum(t['kind'] == 'INTEGRATION_SCRIPT' for t in tests.values()) == 4,
            'Inventario de la base incompleto')
    cases = index(registry['reference_cases'], 'casos')
    originals = index(catalog['cases'], 'oráculos originales')
    require(set(cases) == set(originals) and len(cases) == 51, 'Casos de referencia incompletos')
    findings = index(registry['open_findings'], 'hallazgos abiertos')
    source_findings = {f['id']: f for f in review['findings'] if f['status'] == 'OPEN'}
    require(set(findings) == set(source_findings), 'Se omitió un hallazgo abierto')
    for ident, req in requirements.items():
        bilingual(req['requirement'])
        bilingual(req['remaining_work'])
        require(req['acceptance_status'] == 'PENDING', 'No se puede declarar aceptación por trazabilidad')
        planned = req['planned_verification']
        require(planned['status'] == 'NOT_IMPLEMENTED' and not planned['execution_evidence'],
                'Un plan no es una prueba ejecutada')
        require(set(req['open_findings']) <= set(findings), 'Hallazgo inexistente')
        for name in req['planned_modules']:
            relative(root, name)
        for name in req['current_component_modules']:
            relative(root, name, exists=True)
        require(len({t['test_id'] for t in req['tests']}) == len(req['tests']), 'Vínculo de prueba duplicado')
        for link in req['tests']:
            require(link['test_id'] in tests and link['fulfills_requirement'] is False, 'Prueba inexistente o cumplimiento no acreditado')
            audit = tests[link['test_id']]['path'] in {'tests/unit/test_model_references.py', 'tests/unit/test_reference_alignment.py'}
            require(link['coverage_kind'] == ('REFERENCE_AUDIT_ONLY' if audit else 'COMPONENT_ONLY'),
                    'Auditoría de referencias confundida con implementación')
        for link in req['evidence_links']:
            require(link['evidence_id'] in evidences and link['claim'] == 'BASELINE_COMPONENT_SUITE_ONLY',
                    'Evidencia ajena o conclusión excesiva')
        require(bool(req['tests']) == bool(req['evidence_links']), 'Vínculo de evidencia sin pruebas asociadas')
        expected_refs = [c['id'] for c in catalog['cases'] if ident in c['acceptance_criteria']]
        require(req['reference_cases'] == expected_refs, 'Asociación de oráculos incorrecta')
        if ident in criteria:
            old = criteria[ident]
            require(req['kind'] == 'SYSTEM_CRITERION', 'Tipo de requisito incorrecto')
            for key in ('source_sections', 'algorithms', 'invariants'):
                require(req[key] == old[key], f'Enlace histórico alterado: {ident}/{key}')
            require(req['requirement'] == old['acceptance'] and planned == old['planned_test'],
                    'Criterio o plan histórico alterado')
            require(req['planned_modules'] == old['modules'], 'Módulos previstos alterados')
            require(req['implementation'] == current[ident]['implementation']
                    and req['remaining_work'] == current[ident]['remaining_work']
                    and req['system_functional_verification'] == 'PENDING'
                    and req['experimental_validation'] == current[ident]['experimental_validation'],
                    'Cobertura convertida en cumplimiento')
        else:
            met = methodological[ident]
            require(req['kind'] == 'METHODOLOGICAL_OBLIGATION' and not req['algorithms']
                    and not req['tests'] and not req['evidence_links'] and not req['current_component_modules'],
                    'La metodología no tiene ejecución acreditada')
            require(req['requirement'] == met['requirement'] and req['source_sections'] == [met['source_section']]
                    and req['related_acceptance_criteria'] == met['acceptance_criteria']
                    and planned['id'] == 'TM-' + ident[4:]
                    and {k: planned[k] for k in ('es', 'en')} == met['required_evidence']
                    and req['implementation'] == 'NOT_ASSESSED'
                    and req['experimental_validation'] == 'NOT_RUN', 'Obligación metodológica alterada')
            bilingual(req['non_algorithmic_owner'])
    for ident, case in cases.items():
        original = originals[ident]
        require(case['group'] == original['group'] and case['algorithms'] == original['algorithms']
                and case['requirements'] == original['acceptance_criteria']
                and case['production_verification'] == 'NOT_RUN', 'Oráculo presentado como ejecución del modelo')
    algorithms = index(registry['algorithms'], 'algoritmos')
    require(set(algorithms) == set(historical['algorithm_modules']), 'Mapa de algoritmos incompleto')
    invariants = index(registry['invariants'], 'invariantes')
    require(set(invariants) == {i['id'] for i in historical['invariants']}, 'Invariantes incompletos')
    # Los índices inversos deben reproducir los enlaces de cada requisito.
    for collection, key in ((algorithms, 'algorithms'), (invariants, 'invariants'), (findings, 'open_findings')):
        for ident, node in collection.items():
            expected = [r['id'] for r in requirements.values() if ident in r[key]]
            require(node['requirements'] == expected and expected, f'Índice inverso incoherente: {ident}')
    for ident, node in algorithms.items():
        require(node['module'] == historical['algorithm_modules'][ident] and node['implementation'] == 'NOT_STARTED',
                'Algoritmo presentado como implementado')
    for node in invariants.values():
        require(node['verification'] == 'PENDING', 'Invariante sin aceptación integral')
    for ident, node in findings.items():
        require(node['gate'] == source_findings[ident]['gate']
                and node['closure_evidence_required'] == source_findings[ident]['closure_evidence_required'],
                'Condición de cierre del hallazgo alterada')
    linked = {t['test_id'] for r in requirements.values() for t in r['tests']}
    return {'requirements': len(requirements), 'system_criteria': len(criteria),
            'methodological_obligations': len(methodological), 'algorithms': len(algorithms),
            'invariants': len(invariants), 'reference_cases': len(cases),
            'python_methods_at_baseline': 210, 'integration_scripts': 4,
            'distinct_linked_checks': len(linked), 'inventory_checks_not_linked': len(tests) - len(linked),
            'open_findings': sorted(findings), 'system_functional_acceptance': 'PENDING',
            'experimental_validation': 'NOT_RUN', 'full_specification_alignment': 'PENDING'}


if __name__ == '__main__':
    try:
        print(json.dumps(validate(), ensure_ascii=False, indent=2))
        print('ARDREC_TRACEABILITY_LINKS=PASS')
        print('ARDREC_TRACEABILITY_SCOPE=REGISTERED_REQUIREMENTS_ONLY')
    except (ValueError, KeyError, TypeError, OSError, SyntaxError) as error:
        print(f'ARDREC_TRACEABILITY=FAIL: {error}', file=sys.stderr)
        sys.exit(1)
