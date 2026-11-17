"""R62-R3: R26 and R58-P must share the exact A1 rule source and output semantics.

Pure synthetic fixtures only. No host, network, operational authority or VM execution.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT))

from ardrec.coordination.demo_session import build_development_session, read_fixed_scenario
from ardrec.coordination.r58l_a4_a5_family_review import build_a4_a5_review
from ardrec.coordination import r58p_a3_family_controls as p
from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries


class R26R58PBindingOracle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scenario = read_fixed_scenario(ROOT / 'lab/p14-r26-session-v1/scenario.json')
        cls.review = build_a4_a5_review(synthetic_entries())
        cls.r26 = build_development_session(cls.scenario)

    def test_rule_source_identity_and_29_family_case_controls(self):
        report = p.build_family_a3_projection(self.scenario, self.review)
        self.assertTrue(p.verify_family_a3_projection(report, self.scenario, self.review))
        self.assertEqual(report['a1_a3_source_sha256']['rules'],
                         self.r26.document['sources_sha256']['rules'])
        self.assertEqual(report['r26_session_sha256'], self.r26.sha256)
        self.assertEqual(report['control_reference_count'], 29)
        self.assertEqual(report['family_count'], 25)
        self.assertFalse(report['operational_dispatch'])
        self.assertEqual(report['p8_operational'], 'NO-GO')
        self.assertIsNone(report['published_generation'])
        self.assertIsNone(report['confirmed_final_risk'])

    def test_declared_outputs_agree_across_r26_and_r58p_diagnostics(self):
        captured = []
        original = p.diagnose_guards

        def observing(*args, **kwargs):
            result = original(*args, **kwargs)
            captured.append(result)
            return result

        with patch.object(p, 'diagnose_guards', side_effect=observing):
            report = p.build_family_a3_projection(self.scenario, self.review)

        self.assertEqual(len(captured), 1)
        r26_units = {u['service_id']: u for u in self.r26.document['units']}
        wanted = {
            'SSH_DEV': 'CASE_POLICY',
            'FTP_DEV': None,
            'SMB_DEV': 'CASE_REFERENCE',
        }
        for unit in captured[0].units:
            with self.subTest(service=unit.service_id):
                ref = r26_units[unit.service_id]
                self.assertEqual(unit.table_output, wanted[unit.service_id])
                self.assertEqual(unit.table_output, ref['a1']['selected_output'])
                self.assertEqual(unit.table_output, ref['a3']['table_output'])
                self.assertEqual(unit.table_status.name, ref['a1']['status'])
        self.assertEqual(report['a1_a3_source_sha256']['rules'],
                         self.r26.document['sources_sha256']['rules'])
        self.assertFalse(captured[0].operational_dispatch_allowed)
        self.assertIsNone(captured[0].published_generation)


if __name__ == '__main__':
    unittest.main()
