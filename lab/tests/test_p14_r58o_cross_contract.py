"""R58-O: 10-stage synthetic cross-contract trace and refusal invariants."""
from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src'))
from ardrec.coordination import r58o_a1_a10_cross_contract_trace as o

SHA = lambda v: (v * 64)[:64]
ROOT = Path('/tmp/ardrec-r58o-contract-tests')


class FakeSession:
    def __init__(self):
        self.sha256 = SHA('a')
        self.document = {
            'events': [{'algorithm': 'A1'}] * 9,
            'sources_sha256': {'rules': SHA('1'), 'integrated': SHA('2'),
                               'guard': SHA('3')},
        }

    def verify(self):
        return True


class TraceTests(unittest.TestCase):
    def setUp(self):
        self.scenario = {'session_id': 'DEV_TUTOR_001'}
        self.session = FakeSession()
        self.cycle = {
            'schema': 'synthetic', 'session_id': 'DEV_TUTOR_001',
            'session_sha256': SHA('a'), 'sha256': SHA('b'),
            'r26_event_count': 9, 'r26_units': [1, 2, 3],
            'r27': {'selected_actual': None},
            'a7': {'confirmed_rf': None},
            'a8': {'sha256': SHA('4')},
            'a9': {'durable_local_receipt': False,
                   'technical_generation_published': False},
            'a10': {'stages': [{'algorithm': 'A' + str(i)} for i in range(1, 11)]},
            'operational_dispatch': False, 'vm_checks_executed': False,
            'final_risk': None, 'p8_operational': 'NO-GO',
        }
        self.selected = {'service_id':'FTP_DEV', 'session_id':'DEV_TUTOR_001',
                         'derived_case_id':'FTP-T02-S01-01', 'assessment_index':0}
        self.rid = 'ATT_R58O_DEMO_001'
        self.review = {
            'session_id': 'DEV_TUTOR_001', 'source_catalog_sha256': SHA('c'),
            'source_thesis_sha256': SHA('d'), 'sha256': SHA('e'),
            'unit_count': 29, 'covered_family_count': 25,
            'a4': {'sha256': SHA('5')},
            'a4_selected_identity': self.selected,
            'a4_operational_selection': None,
            'a5': {'actual_attempts_started': 0,
                   'actual_attempt_reservations': 0},
            'attempt_intent': {**self.selected, 'attempt_id': self.rid,
                               'action': 'SYNTHETIC_REVIEW_ONLY'},
            'a6_classification': 'ND', 'technical_truth_accredited': False,
            'confirmed_final_risk': None, 'applied_state_transition': None,
            'published_generation': None, 'operational_dispatch': False,
            'p8_operational': 'NO-GO',
            'unified': {
                'sha256': SHA('f'), 'source_catalog_sha256': SHA('c'),
                'source_thesis_sha256': SHA('d'),
                'a6_a7_a8_bridge': {'sha256': SHA('6'),
                                    'confirmed_final_risk': None},
                'decisions': [{
                    'a8_recommendation': 'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA',
                    'a6_classification': 'ND', 'confirmed_rf': None,
                    'applied_transition': None,
                }],
            },
        }
        self.binding = {
            'sha256': SHA('7'), 'declared_request_id': self.rid,
            'a4_selected_identity': self.selected,
            'identity_declaration_independently_attested': False,
            'physical_case_binding_accredited': False,
            'technical_truth_accredited': False, 'a6_classification': 'ND',
            'confirmed_final_risk': None, 'applied_state_transition': None,
            'published_generation': None, 'operational_dispatch': False,
            'p8_operational': 'NO-GO',
            'a5_fixture_journal_sha256': SHA('8'),
            'a5_fixture_state': 'ACCEPTED',
            'a5_fixture_start_intent_count': 0,
        }
        self.persisted = {
            'receipt_sha256': SHA('7'),
            'persisted_verification': 'PASS_DECLARED_ONLY_NO_AUTHORITY',
            'retry_allowed': False,
        }

    def _context(self):
        stack = ExitStack()
        stack.enter_context(patch.object(o, 'normalize_scenario',
                                         side_effect=lambda x: x))
        stack.enter_context(patch.object(o, 'build_development_session',
                                         return_value=self.session))
        stack.enter_context(patch.object(o, 'build_development_cycle',
                                         return_value=self.cycle))
        stack.enter_context(patch.object(o, 'verify_development_cycle',
                                         return_value=True))
        stack.enter_context(patch.object(o, 'verify_a4_a5_review',
                                         return_value=True))
        stack.enter_context(patch.object(o, 'verify_persisted',
                                         return_value=self.persisted))
        stack.enter_context(patch.object(o, 'build_binding',
                                         return_value=self.binding))
        return stack

    def build(self):
        with self._context():
            return o.build_cross_contract_trace(
                self.scenario, self.review, ROOT, ROOT, self.rid)

    def verify(self, report):
        with self._context():
            return o.verify_cross_contract_trace(
                report, self.scenario, self.review, ROOT, ROOT, self.rid)

    def test_ten_ordered_stages(self):
        doc = self.build()
        self.assertEqual([x['algorithm'] for x in doc['stage_ledger']],
                         ['A' + str(x) for x in range(1, 11)])

    def test_all_statuses_exact(self):
        self.assertEqual([x['status'] for x in self.build()['stage_ledger']],
                         list(o.STAGE_STATUSES))

    def test_ledger_chained(self):
        doc = self.build()
        prev = None
        for item in doc['stage_ledger']:
            self.assertEqual(item['previous_stage_sha256'], prev)
            self.assertEqual(item['event_sha256'],
                             o.digest({k:v for k,v in item.items()
                                       if k != 'event_sha256'}))
            prev = item['event_sha256']
        self.assertEqual(doc['ledger_head_sha256'], prev)

    def test_all_stage_evidence_false(self):
        for entry in self.build()['stage_ledger']:
            self.assertIs(entry['technical_truth_accredited'], False)
            self.assertIs(entry['operational_dispatch'], False)
            self.assertIsNone(entry['published_generation'])

    def test_full_report_not_full_algorithm(self):
        doc = self.build()
        self.assertFalse(doc['a1_a10_implementation_complete'])
        self.assertFalse(doc['experimental_hypothesis_validated'])
        self.assertFalse(doc['a1_a3_to_family_case_binding_attested'])
        self.assertFalse(doc['independent_physical_case_binding_attested'])

    def test_source_scopes_separate(self):
        doc = self.build()
        self.assertIn('R26_THREE', doc['source_scopes']['a1_a3'])
        self.assertIn('25_FAMILY', doc['source_scopes']['a4_a8'])
        self.assertNotEqual(doc['stage_ledger'][2]['scope'],
                            doc['stage_ledger'][3]['scope'])

    def test_counts(self):
        d = self.build()
        self.assertEqual((d['a1_a3_service_count'], d['a1_a3_event_count']), (3,9))
        self.assertEqual((d['a4_a8_case_count'], d['a4_a8_family_count']), (29,25))

    def test_zero_real_starts(self):
        self.assertEqual(self.build()['a5_real_operational_attempts'], 0)

    def test_unknown_a6(self):
        self.assertEqual(self.build()['a6_classification'], 'ND')

    def test_unresolved_a7(self):
        self.assertIs(self.build()['a7_uncertainty_only'], True)

    def test_a8_pause(self):
        self.assertEqual(self.build()['a8_recommendation'],
                         'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA')

    def test_a9_receipt_not_generation(self):
        r = self.build()
        self.assertTrue(r['a9_local_declared_receipt_verified'])
        self.assertIsNone(r['published_generation'])

    def test_report_reproducibility(self):
        self.assertTrue(self.verify(self.build()))

    def test_report_permutation_and_repeat_stable(self):
        self.assertEqual(self.build(), self.build())

    def test_tamper_digest_refused(self):
        report = self.build()
        report['a6_classification'] = 'POSITIVO_VALIDO'
        with self.assertRaises(o.CrossContractError):
            self.verify(report)

    def test_tamper_rehashed_refused(self):
        report = self.build()
        report['a1_a10_implementation_complete'] = True
        report['sha256'] = o.digest({k:v for k,v in report.items() if k != 'sha256'})
        with self.assertRaises(o.CrossContractError):
            self.verify(report)

    def test_tamper_rehashed_stage_refused(self):
        report = self.build()
        report['stage_ledger'][8]['status'] = 'PUBLISHED'
        report['stage_ledger'][8]['event_sha256'] = o.digest({
            k:v for k,v in report['stage_ledger'][8].items() if k != 'event_sha256'})
        report['sha256'] = o.digest({k:v for k,v in report.items() if k != 'sha256'})
        with self.assertRaises(o.CrossContractError):
            self.verify(report)

    def test_wrong_session_refused(self):
        self.review['session_id'] = 'OTHER'
        with self.assertRaises(o.CrossContractError): self.build()

    def test_wrong_r28_sha_refused(self):
        self.cycle['session_sha256'] = SHA('f')
        with self.assertRaises(o.CrossContractError): self.build()

    def test_wrong_service_count_refused(self):
        self.cycle['r26_units'] = [1,2]
        with self.assertRaises(o.CrossContractError): self.build()

    def test_55_cases_refused(self):
        self.review['unit_count'] = 55
        with self.assertRaises(o.CrossContractError): self.build()

    def test_catalog_mismatch_refused(self):
        self.review['source_catalog_sha256'] = SHA('0')
        with self.assertRaises(o.CrossContractError): self.build()

    def test_a4_confirmed_selection_refused(self):
        self.cycle['r27']['selected_actual'] = {'case_id':'CASE'}
        with self.assertRaises(o.CrossContractError): self.build()

    def test_r28_unexpected_receipt_refused(self):
        self.cycle['a9']['durable_local_receipt'] = True
        with self.assertRaises(o.CrossContractError): self.build()

    def test_r28_execution_refused(self):
        self.cycle['operational_dispatch'] = True
        with self.assertRaises(o.CrossContractError): self.build()

    def test_wrong_identity_refused(self):
        self.binding['a4_selected_identity'] = {'service_id':'SSH_DEV'}
        with self.assertRaises(o.CrossContractError): self.build()

    def test_wrong_persisted_receipt_refused(self):
        self.persisted['receipt_sha256'] = SHA('f')
        with self.assertRaises(o.CrossContractError): self.build()

    def test_retry_allowed_refused(self):
        self.persisted['retry_allowed'] = True
        with self.assertRaises(o.CrossContractError): self.build()

    def test_forged_binding_authority_refused(self):
        self.binding['physical_case_binding_accredited'] = True
        with self.assertRaises(o.CrossContractError): self.build()

    def test_forged_risk_refused(self):
        self.review['confirmed_final_risk'] = '0'
        with self.assertRaises(o.CrossContractError): self.build()

    def test_forged_a7_interval_refused(self):
        self.review['unified']['a6_a7_a8_bridge']['confirmed_final_risk'] = '0'
        with self.assertRaises(o.CrossContractError): self.build()

    def test_forged_a8_decision_refused(self):
        self.review['unified']['decisions'][0]['a8_recommendation'] = 'CERRAR'
        with self.assertRaises(o.CrossContractError): self.build()

    def test_forged_a6_decision_refused(self):
        self.review['unified']['decisions'][0]['a6_classification'] = 'VERDADERO'
        with self.assertRaises(o.CrossContractError): self.build()

    def test_forged_a9_generation_refused(self):
        self.binding['published_generation'] = 1
        with self.assertRaises(o.CrossContractError): self.build()

    def test_forged_p8_go_refused(self):
        self.review['p8_operational'] = 'GO'
        with self.assertRaises(o.CrossContractError): self.build()

    def test_false_started_counter_refused(self):
        self.review['a5']['actual_attempts_started'] = 1
        with self.assertRaises(o.CrossContractError): self.build()

    def test_missing_receipt_intent_refused(self):
        self.review['attempt_intent'] = None
        with self.assertRaises(o.CrossContractError): self.build()

    def test_relative_journal_refused(self):
        with self._context():
            with self.assertRaises(o.CrossContractError):
                o.build_cross_contract_trace(self.scenario, self.review,
                                             Path('relative'), ROOT, self.rid)

    def test_relative_receipts_refused(self):
        with self._context():
            with self.assertRaises(o.CrossContractError):
                o.build_cross_contract_trace(self.scenario, self.review,
                                             ROOT, Path('relative'), self.rid)

    def test_report_schema_not_dict_refused(self):
        with self.assertRaises(o.CrossContractError): self.verify([])


if __name__ == '__main__':
    unittest.main()
