"""P14-R28: integración real con R26/R27; se ejecuta en Prometheus."""
from __future__ import annotations
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.development_cycle import (
    build_development_cycle,verify_development_cycle,CycleError)
from ardrec.coordination.terminal_view import render_text
from ardrec.persistence.development_receipt import FILE_NAME
from ardrec.analytics.exact_preview import canonical

FIXTURE=ROOT/'lab/p14-r26-session-v1/scenario.json'

class VerticalR28Tests(unittest.TestCase):
    def setUp(self):
        self.fixture=read_fixed_scenario(FIXTURE)
    def test_preview_contains_ten_stages_without_io(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'not_yet_created'
            o=build_development_cycle(self.fixture)
            self.assertTrue(verify_development_cycle(o))
            self.assertEqual([s['algorithm'] for s in o['a10']['stages']],
                             [f'A{i}' for i in range(1,11)])
            self.assertIsNone(o['r27']['a5_state'])
            self.assertIsNone(o['final_risk'])
            self.assertFalse(o['a9']['durable_local_receipt'])
            self.assertFalse(p.exists())
    def test_run_replay_and_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'journal'
            one=build_development_cycle(self.fixture,journal_root=p,run_local_benign=True)
            two=build_development_cycle(self.fixture,journal_root=p,run_local_benign=True)
            self.assertEqual(canonical(one),canonical(two))
            self.assertTrue((p/FILE_NAME).is_file())
            self.assertTrue(verify_development_cycle(one))
            self.assertEqual(one['r27']['a5_start_count'],1)
            self.assertEqual(one['r27']['a5_state'],'RECORDED_LIMITED')
            self.assertEqual(one['r27']['a6_classification'],'ND')
            self.assertIsNone(one['a7']['confirmed_rf'])
            self.assertIsNone(one['a8']['applied_transition'])
            self.assertIsNone(one['a9']['published_generation'])
            self.assertFalse(one['vm_checks_executed'])
            self.assertEqual(one['p8_operational'],'NO-GO')
            self.assertIn('PAGINA 10/10',render_text(one))
    def test_changed_scenario_same_receipt_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'journal'
            self.assertTrue(build_development_cycle(self.fixture,journal_root=p,run_local_benign=True))
            other={**self.fixture,'session_id':'DEV_TUTOR_002'}
            with self.assertRaises(Exception):
                build_development_cycle(other,journal_root=p,run_local_benign=True)
    def test_no_false_authority(self):
        o=build_development_cycle(self.fixture)
        o['operational_dispatch']=True
        with self.assertRaises(CycleError):verify_development_cycle(o)
    def test_preview_rejects_journal(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(CycleError):
                build_development_cycle(self.fixture,journal_root=Path(d))
    def test_local_requires_journal(self):
        with self.assertRaises(CycleError):
            build_development_cycle(self.fixture,run_local_benign=True)

if __name__=='__main__':unittest.main()
