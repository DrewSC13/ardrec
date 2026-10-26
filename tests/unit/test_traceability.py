"""Rechazar enlaces rotos y afirmaciones de cumplimiento sin evidencia."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ardrec_traceability_checker', ROOT / 'scripts/verificar_trazabilidad.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class TraceabilityTests(unittest.TestCase):
    """Mantener separadas referencia, implementación y evidencia experimental."""

    def setUp(self):
        self.registry = json.loads((ROOT / 'docs/traceability/development-v1.json').read_text())
        self.evidence = json.loads((ROOT / 'docs/traceability/evidence-v1.json').read_text())

    def reject(self):
        with self.assertRaises(ValueError):
            checker.validate(ROOT, self.registry, self.evidence)

    def test_registered_links_and_reverse_indexes(self):
        result = checker.validate(ROOT, self.registry, self.evidence)
        self.assertEqual((result['requirements'], result['reference_cases']), (44, 51))
        self.assertEqual(len(result['open_findings']), 5)

    def test_missing_and_duplicate_requirements(self):
        original = deepcopy(self.registry)
        self.registry['requirements'].pop()
        self.reject()
        self.registry = original
        self.registry['requirements'].append(deepcopy(self.registry['requirements'][0]))
        self.reject()

    def test_unknown_test_and_renamed_method(self):
        original = deepcopy(self.registry)
        self.registry['requirements'][0]['tests'][0]['test_id'] = 'missing'
        self.reject()
        self.registry = original
        self.registry['test_inventory'][0]['symbol'] += '_missing'
        self.reject()

    def test_reference_audit_cannot_be_production_test(self):
        req = next(r for r in self.registry['requirements'] if r['id'] == 'AC-06')
        req['tests'][0]['coverage_kind'] = 'COMPONENT_ONLY'
        self.reject()

    def test_workflow_evidence_cannot_claim_individual_results(self):
        self.evidence['items'][1]['per_test_results_available'] = True
        self.reject()

    def test_changed_evidence_commit_and_run(self):
        original = deepcopy(self.evidence)
        self.evidence['items'][1]['commit'] = '0' * 40
        self.reject()
        self.evidence = original
        self.evidence['items'][1]['run_id'] += 1
        self.reject()

    def test_no_promotion_to_system_or_experimental_acceptance(self):
        original = deepcopy(self.registry)
        self.registry['system_functional_acceptance'] = 'PASS'
        self.reject()
        self.registry = original
        self.registry['requirements'][-1]['experimental_validation'] = 'PASS'
        self.reject()

    def test_reverse_index_and_open_finding_cannot_disappear(self):
        original = deepcopy(self.registry)
        self.registry['algorithms'][0]['requirements'] = []
        self.reject()
        self.registry = original
        self.registry['open_findings'].pop()
        self.reject()

    def test_historical_source_is_not_relabelled(self):
        self.registry['historical_sources']['matrix']['source_sha256'] = checker.SOURCE
        self.reject()

    def test_external_path_and_oracle_execution_are_rejected(self):
        original = deepcopy(self.registry)
        self.registry['requirements'][0]['current_component_modules'] = ['../outside.py']
        self.reject()
        self.registry = original
        self.registry['reference_cases'][0]['production_verification'] = 'PASS'
        self.reject()


if __name__ == '__main__':
    unittest.main()
