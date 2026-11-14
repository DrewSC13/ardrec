"""R37: integración de admisión documental con el ciclo y la TUI existentes.

Se ejecuta en el worktree real donde están instalados A1-A10 de R28.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.development_cycle import build_development_cycle, verify_development_cycle
from ardrec.coordination.terminal_view import lines_for_page, render_text
from ardrec.evidence.defensive_import import admit_defensive_observation, SCHEMA

CONTENT=b'PasswordAuthentication no\nPermitRootLogin no\n'

class IntegrationR37Tests(unittest.TestCase):
    def test_a6_import_visible_without_false_authority(self):
        fixture=read_fixed_scenario(ROOT/'lab/p14-r26-session-v1/scenario.json')
        with tempfile.TemporaryDirectory() as tmp:
            support=Path(tmp)/'support.txt'
            support.write_bytes(CONTENT)
            receipt={
               'schema':SCHEMA,'record_id':'DEV-SSH-0001',
               'session_id':'DEV_TUTOR_001','service_id':'SSH_DEV',
               'case_id':'CASE_REFERENCE','source_kind':'SYNTHETIC_FIXTURE',
               'method_id':'SSH_EFFECTIVE_CONFIG_READONLY',
               'captured_at_utc':'2026-11-14T19:59:00Z',
               'configuration_sha256':'a'*64,
               'support_sha256':hashlib.sha256(CONTENT).hexdigest(),
               'support_bytes':len(CONTENT),'observed_claim':'INCONCLUSIVE'
            }
            raw=json.dumps(receipt,sort_keys=True).encode('utf-8')
            admitted=admit_defensive_observation(receipt,raw,support,
                          as_of_utc='2026-11-14T20:00:00Z')
            report=build_development_cycle(fixture,defensive_observation=admitted)
            self.assertTrue(verify_development_cycle(report))
            self.assertEqual(report['r27']['a6_classification'],'ND')
            self.assertEqual(report['a6_import']['classification'],'ND')
            self.assertEqual(report['a10']['stages'][5]['status'],'ND_DOCUMENTARY_ACCEPTED')
            self.assertIsNone(report['a7']['confirmed_rf'])
            self.assertIsNone(report['a9']['published_generation'])
            self.assertIsNone(report['final_risk'])
            self.assertEqual(report,build_development_cycle(fixture,defensive_observation=admitted))
            displayed='\n'.join(lines_for_page(report,5))
            self.assertIn('DEV-SSH-0001',displayed)
            self.assertIn('NO ACREDITADA',displayed)
            self.assertIn('A6 ADMISION DOCUMENTAL',render_text(report))

    def test_legacy_report_does_not_gain_import(self):
        fixture=read_fixed_scenario(ROOT/'lab/p14-r26-session-v1/scenario.json')
        report=build_development_cycle(fixture)
        self.assertNotIn('a6_import',report)
        self.assertTrue(verify_development_cycle(report))
        self.assertIsNone(report['final_risk'])

if __name__=='__main__':unittest.main()
