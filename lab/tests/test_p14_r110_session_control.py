"""R110: execute A1-A3 on 54 case controls and reject operational T1."""
from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / 'src'), str(REPO / 'scripts'), str(REPO / 'lab/tests')]

from ardrec.coordination import r59d_a5_result_intake as a5
from ardrec.coordination import r110_session_control as r110
from ardrec.coordination.demo_session import read_fixed_scenario
import ardrec_p14_r110_session_control as cli
import test_p14_r109_executable_decision_chain as fixture_tests


class R110ControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_tests.R109DecisionTests.setUpClass()
        original = fixture_tests.R109DecisionTests
        cls.unified = original.unified
        cls.trace = original.trace
        cls.model = original.model
        cls.decisions = original.result
        cls.scenario = read_fixed_scenario(cli.SCENARIO_PATH)
        cls.report = r110.build(cls.unified, cls.trace,
                                cls.model, cls.decisions, cls.scenario)

    def test_all_54_unique_cases(self):
        self.assertEqual(self.report['case_count'], 54)
        self.assertEqual(len({x['case_id_a7'] for x in self.report['cases']}), 54)
        self.assertEqual(self.report['family_count'], 25)

    def test_two_synthetic_sessions_only(self):
        self.assertEqual(self.report['session_ids'], ['DEV_TUTOR_001','DEV_TUTOR_002'])
        self.assertFalse(self.report['r26_second_session_observed'])
        self.assertFalse(self.report['a1_a3_independent_session_authority'])

    def test_all_three_services_counted(self):
        self.assertEqual(self.report['counts_by_service'], r110.COUNTS)

    def test_actual_r17_r22_guard_outputs(self):
        self.assertEqual(self.report['a3_truth_counts'],
                         {'VERDADERO':16,'FALSO':18,'ND':20})
        self.assertEqual(len(self.report['a1_a3_source_hashes']), 6)
        self.assertTrue(all(len(x) == 64 for x in self.report['a1_a3_source_hashes'].values()))

    def test_all_guards_retain_auth_blocker(self):
        self.assertTrue(all('AUTORIDAD_OPERACIONAL_NO_ACREDITADA' in x['a3_blockers']
                            for x in self.report['cases']))

    def test_t1_counterfactual_candidates_exactly_16(self):
        self.assertEqual(self.report['t1_counterfactual_candidates'], 16)
        for x in self.report['cases']:
            self.assertEqual(x['t1_counterfactual_candidate_sha256'] is not None,
                             x['a3_guard_truth'] == 'VERDADERO')

    def test_real_state_transition_denied_in_all_54(self):
        self.assertEqual(self.report['t1_denied_by_authority'], 54)
        self.assertEqual(self.report['operational_t1_transitions'], 0)
        self.assertEqual({x['t1_rejected_reason'] for x in self.report['cases']},
                         {'authority_unverified'})

    def test_no_p8_a5_a6_a9_promotion(self):
        self.assertEqual(self.report['p8_operational'], 'NO-GO')
        self.assertEqual(self.report['a6_classification'], 'ND')
        self.assertFalse(self.report['operational_dispatch'])
        self.assertFalse(self.report['a1_a10_operational_implementation_complete'])
        for key in ('operational_t1_transitions','a5_operational_starts',
                    'a8_operational_transitions','a9_published_generations',
                    'host_mutations','vm_starts'):
            self.assertEqual(self.report[key], 0)

    def test_r109_source_identity(self):
        self.assertEqual(self.report['r109_decision_sha256'], self.decisions['sha256'])
        self.assertEqual({x['r109_case_sha256'] for x in self.report['cases']},
                         {x['sha256'] for x in self.decisions['cases']})

    def test_deterministic_reexecution(self):
        self.assertEqual(self.report, r110.build(
            self.unified,self.trace,self.model,self.decisions,self.scenario))
        self.assertTrue(r110.verify(self.report,self.unified,self.trace,
                                    self.model,self.decisions,self.scenario))

    def test_case_chain_integrity(self):
        previous = None
        for item in self.report['cases']:
            self.assertEqual(item['previous_case_sha256'], previous)
            self.assertEqual(item['sha256'],a5.digest({k:v for k,v in item.items() if k!='sha256'}))
            previous = item['sha256']
        self.assertEqual(previous,self.report['case_chain_head_sha256'])

    def test_changed_guard_even_if_rehashed_rejected(self):
        invalid = deepcopy(self.report)
        item = invalid['cases'][0]
        item['a3_guard_truth'] = 'VERDADERO'
        item['sha256'] = a5.digest({k:v for k,v in item.items() if k!='sha256'})
        invalid['sha256'] = a5.digest({k:v for k,v in invalid.items() if k!='sha256'})
        with self.assertRaises(ValueError):
            r110.verify(invalid,self.unified,self.trace,self.model,self.decisions,self.scenario)

    def test_synthetic_second_session_cannot_become_observed(self):
        invalid = deepcopy(self.report)
        invalid['r26_second_session_observed'] = True
        invalid['sha256'] = a5.digest({k:v for k,v in invalid.items() if k!='sha256'})
        with self.assertRaises(ValueError):
            r110.verify(invalid,self.unified,self.trace,self.model,self.decisions,self.scenario)

    def test_wrong_frozen_scenario_rejected(self):
        invalid = deepcopy(self.scenario)
        invalid['services'][0]['fact'] = 'VERDADERO' if invalid['services'][0]['fact'] != 'VERDADERO' else 'FALSO'
        with self.assertRaises(ValueError):
            r110.build(self.unified,self.trace,self.model,self.decisions,invalid)

    def test_wrong_upstream_r109_rejected(self):
        invalid = deepcopy(self.decisions)
        invalid['a9_published_generations'] = 1
        invalid['sha256'] = a5.digest({k:v for k,v in invalid.items() if k!='sha256'})
        with self.assertRaises(ValueError):
            r110.build(self.unified,self.trace,self.model,invalid,self.scenario)

    def test_private_durable_roundtrip(self):
        with TemporaryDirectory(prefix='ardrec-r110-safe-') as tmp:
            session, report, manifest = cli.persist(
                self.unified,self.trace,self.model,self.decisions,self.scenario,Path(tmp))
            self.assertEqual((report,manifest),cli.verify(
                session,self.unified,self.trace,self.model,self.decisions,self.scenario))
            self.assertEqual({p.name for p in session.iterdir()},cli.FILES)
            self.assertEqual({p.stat().st_mode & 0o777 for p in session.iterdir()}, {0o600})

    def test_private_tamper_rejected(self):
        with TemporaryDirectory(prefix='ardrec-r110-tamper-') as tmp:
            session,_,_=cli.persist(self.unified,self.trace,self.model,
                                    self.decisions,self.scenario,Path(tmp))
            target=session/'control.json'
            target.write_bytes(target.read_bytes()[:-1]+b' ')
            with self.assertRaises(ValueError):
                cli.verify(session,self.unified,self.trace,self.model,
                           self.decisions,self.scenario)

    def test_private_extra_file_rejected(self):
        with TemporaryDirectory(prefix='ardrec-r110-inventory-') as tmp:
            session,_,_=cli.persist(self.unified,self.trace,self.model,
                                    self.decisions,self.scenario,Path(tmp))
            (session/'rogue.json').write_text('{}')
            with self.assertRaises(ValueError):
                cli.verify(session,self.unified,self.trace,self.model,
                           self.decisions,self.scenario)

    def test_no_network_process_privilege_imports(self):
        for relative in ('src/ardrec/coordination/r110_session_control.py',
                         'scripts/ardrec_p14_r110_session_control.py'):
            tree=ast.parse((REPO/relative).read_text('utf-8'))
            imports={n.module.split('.')[0] for n in ast.walk(tree)
                     if isinstance(n,ast.ImportFrom) and n.module}
            imports|={a.name.split('.')[0] for n in ast.walk(tree)
                      if isinstance(n,ast.Import) for a in n.names}
            self.assertFalse({'subprocess','socket','libvirt','paramiko'}.intersection(imports))

if __name__ == '__main__':
    unittest.main()
