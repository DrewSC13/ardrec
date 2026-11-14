"""Oráculos independientes del escenario P14-R26; sin operaciones de red o VM."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.coordination.demo_session import (
    SCENARIO_FORMAT, SessionError, build_development_session,
    read_fixed_scenario, verify_session_document,
)
from ardrec.initialization.rule_preflight import (
    FORMAT as RULE_FORMAT, preflight_rule_configuration,
)
from ardrec.initialization.initial_preview import (
    FORMAT as INITIAL_FORMAT, InitialPreviewError, prepare_initial_preview,
)

FIXTURE = ROOT / 'lab' / 'p14-r26-session-v1' / 'scenario.json'
ORACLE = ROOT / 'lab' / 'p14-r26-session-v1' / 'oracle.json'


class DevelopmentSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = read_fixed_scenario(FIXTURE)
        self.oracle = json.loads(ORACLE.read_text(encoding='utf-8'))
        self.session = build_development_session(self.fixture)
        self.doc = self.session.document

    def test_three_real_module_stages_against_prior_oracle(self):
        expected = self.oracle['expected']
        self.assertEqual(set(expected), {u['service_id'] for u in self.doc['units']})
        for unit in self.doc['units']:
            wanted = expected[unit['service_id']]
            self.assertEqual(unit['a1']['status'], wanted['a1'])
            self.assertEqual(unit['a1']['selected_rule'], wanted['selected_rule'])
            self.assertEqual(unit['a3']['table_status'], wanted['a3'])
            for control in unit['a3']['controls']:
                self.assertIn(wanted['primary_blocker'], control['blockers'])
                self.assertIn('AUTORIDAD_OPERACIONAL_NO_ACREDITADA',
                              control['blockers'])
            self.assertEqual(unit['a2']['initial_phase'], 'PREPARADO')
            self.assertEqual(unit['a2']['initial_risk'], '1/4')
            self.assertEqual(unit['a2']['accumulated_evidence'], '0')
            self.assertEqual(len(unit['a2']['cases']), 2)
            self.assertEqual(len(unit['a3']['controls']), 2)

    def test_no_unearned_operational_claims(self):
        self.assertEqual(self.doc['source_kind'], 'SYNTHETIC_FIXTURE')
        self.assertEqual(self.doc['p8_operational'], 'NO-GO')
        self.assertFalse(self.doc['operational_dispatch'])
        self.assertIsNone(self.doc['published_generation'])
        self.assertIsNone(self.doc['final_risk'])
        self.assertFalse(self.doc['a1_full'])
        self.assertFalse(self.doc['a2_full'])
        self.assertFalse(self.doc['a3_full'])
        self.assertFalse(self.doc['a4_a10_executed'])
        self.assertEqual(len(self.doc['events']), 9)
        self.assertTrue(self.session.verify())

    def test_identical_input_identical_bytes_and_event_chain(self):
        again = build_development_session(copy.deepcopy(self.fixture))
        self.assertEqual(self.session.json_bytes(), again.json_bytes())
        self.assertEqual(self.session.sha256, again.sha256)
        self.assertTrue(verify_session_document(json.loads(self.session.json_bytes())))

    def test_permutation_does_not_change_decision_or_digest(self):
        reverse = copy.deepcopy(self.fixture)
        reverse['services'].reverse()
        self.assertEqual(self.session.json_bytes(),
                         build_development_session(reverse).json_bytes())

    def test_digest_detects_event_tampering(self):
        changed = copy.deepcopy(self.doc)
        changed['events'][0]['decision']['status'] = 'FALSO'
        with self.assertRaises(SessionError) as error:
            verify_session_document(changed)
        self.assertEqual(error.exception.code, 'event_digest')

    def test_digest_detects_unearned_final_risk(self):
        changed = copy.deepcopy(self.doc)
        changed['final_risk'] = '1/2'
        with self.assertRaises(SessionError) as error:
            verify_session_document(changed)
        self.assertEqual(error.exception.code, 'session_false_authority')

    def test_rejects_operational_source_disguised_as_fixture(self):
        changed = copy.deepcopy(self.fixture)
        changed['services'][0]['source_kind'] = 'LIVE_VM'
        with self.assertRaises(SessionError):
            build_development_session(changed)

    def test_rejects_duplicate_target(self):
        changed = copy.deepcopy(self.fixture)
        changed['services'][0]['id'] = changed['services'][1]['id']
        with self.assertRaises(SessionError):
            build_development_session(changed)

    def test_rejects_noncanonical_risk(self):
        changed = copy.deepcopy(self.fixture)
        changed['services'][0]['initial_risk'] = '2/4'
        with self.assertRaises(SessionError):
            build_development_session(changed)

    def test_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / 'scenario.json'
            target.write_text('{"format":"' + SCENARIO_FORMAT + '",'
                              '"format":"' + SCENARIO_FORMAT + '",'
                              '"session_id":"DEV_TUTOR_001","services":[]}',
                              encoding='utf-8')
            with self.assertRaises(SessionError):
                read_fixed_scenario(target)

    def test_reference_mismatch_fails_closed_in_existing_a2(self):
        sid = 'SSH_DEV'
        rules = preflight_rule_configuration({
            'format': RULE_FORMAT, 'fields': {}, 'services': [{
                'id': sid, 'initial_state': 'PREPARADO', 'rules': [{
                    'id': 'NEVER', 'condicion': {'op': 'CONSTANTE',
                        'tipo': 'LOGICO', 'valor': 'FALSO'}}]}]})
        wrong = '0' * 64 if rules.sha256 != '0' * 64 else '1' * 64
        with self.assertRaises(InitialPreviewError):
            prepare_initial_preview(rules, {
                'format': INITIAL_FORMAT, 'rule_source_sha256': wrong,
                'services': [{'id': sid, 'initial_risk': '1/4',
                              'normalized_criticality': '1/2',
                              'cases': [{'id': 'CASE_POLICY',
                                         'max_repetitions': 0}]}],
            })


if __name__ == '__main__':
    unittest.main()
