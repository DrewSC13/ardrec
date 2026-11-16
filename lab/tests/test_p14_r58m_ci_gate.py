"""Ensure R58-M is an unprivileged, direct-CLI, pinned development check."""
from __future__ import annotations

import ast
from pathlib import Path
import sys
import subprocess
import unittest

REPO=Path(__file__).resolve().parents[2]
CI=REPO/'.github/workflows/ci.yml'
SRC=REPO/'src/ardrec/coordination/r58m_durable_a5_audit.py'
DEMO=REPO/'scripts/ardrec_p14_r58m_durable_a5_demo.py'
TEST=REPO/'lab/tests/test_p14_r58m_durable_a5.py'
DOC=REPO/'docs/development/p14-r58m-a5-readonly-durable-audit.md'
TEST_STEP='Probar R58-M auditoria durable A5 offline / Test read-only journal contract'
DEMO_STEP='Demostrar R58-M diario A5 temporal / Check zero-start durable audit'
TEST_CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58m_*.py' -v"
DEMO_CMD='PYTHONPATH=src python3 -B scripts/ardrec_p14_r58m_durable_a5_demo.py --synthetic-offline'
PRIOR='Demostrar R58-L seleccion A4 y A5 sintetico / Check offline no-dispatch review'


class CIGate(unittest.TestCase):
    def setUp(self):self.ci=CI.read_text()

    def test_source_exists(self):self.assertTrue(SRC.is_file())
    def test_demo_exists(self):self.assertTrue(DEMO.is_file())
    def test_doc_exists(self):self.assertTrue(DOC.is_file())
    def test_tests_exist(self):self.assertTrue(TEST.is_file())
    def test_python_job(self):self.assertIn('Python - empaquetado / packaging',self.ci)
    def test_rust_job(self):self.assertIn('Rust - compilación / build',self.ci)
    def test_prior_l_step_unchanged(self):self.assertIn(PRIOR,self.ci)
    def test_prior_k_step_unchanged(self):self.assertIn('Demostrar R58-K 29 casos SSH FTP SMB',self.ci)
    def test_test_command_once(self):self.assertEqual(self.ci.count(TEST_CMD),1)
    def test_demo_command_once(self):self.assertEqual(self.ci.count(DEMO_CMD),1)
    def test_test_step_once(self):self.assertEqual(self.ci.count(TEST_STEP),1)
    def test_demo_step_once(self):self.assertEqual(self.ci.count(DEMO_STEP),1)
    def test_order(self):
        self.assertLess(self.ci.index(PRIOR),self.ci.index(TEST_STEP))
        self.assertLess(self.ci.index(TEST_STEP),self.ci.index(DEMO_STEP))
        self.assertLess(self.ci.index(DEMO_STEP),self.ci.index('Verificar diseño del laboratorio'))
    def test_no_privileged_ci_commands(self):
        for command in (TEST_CMD,DEMO_CMD):
            self.assertFalse(any(x in command for x in ('sudo ', 'virsh ', 'ssh ', 'nft ', 'systemctl ')))
    def test_read_only_sqlite(self):
        source=SRC.read_text()
        for needle in ('mode=ro&immutable=1','PRAGMA query_only=ON',
                       'LIVE_OR_UNCHECKPOINTED_JOURNAL_REFUSED',
                       'case_identity_binding_accredited',
                       'case_identity_stored_in_journal'):
            self.assertIn(needle,source)
    def test_no_pipeline_constructor_in_audit(self):
        self.assertNotIn('BenignPipeline(',SRC.read_text())
    def test_no_exec_apis_in_audit(self):
        tree=ast.parse(SRC.read_text())
        imported=set()
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):imported.update(alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node,ast.ImportFrom):imported.add((node.module or '').split('.')[0])
        self.assertFalse(imported & {'subprocess','socket','paramiko','asyncssh','fabric'})
    def test_demo_requires_offline(self):
        try:from ardrec.benign_pipeline import BenignPipeline
        except ImportError:self.skipTest('P9_SOURCE_ABSENT_IN_SMALL_TEST_FIXTURE')
        run=subprocess.run([sys.executable,'-B',str(DEMO)],cwd=REPO,
                 capture_output=True,text=True,timeout=15)
        self.assertEqual(run.returncode,23,run.stderr[-1000:])
    def test_demo_real_direct_subprocess(self):
        try:from ardrec.benign_pipeline import BenignPipeline
        except ImportError:self.skipTest('P9_SOURCE_ABSENT_IN_SMALL_TEST_FIXTURE')
        run=subprocess.run([sys.executable,'-B',str(DEMO),'--synthetic-offline'],
               cwd=REPO,env={'PYTHONPATH':'src','PATH':'/usr/bin:/bin'},
               capture_output=True,text=True,timeout=120)
        self.assertEqual(run.returncode,0,run.stderr[-1800:])
        import json
        doc=json.loads(run.stdout)
        self.assertEqual(doc['unit_count'],29)
        self.assertEqual(doc['journal_state'],'ACCEPTED')
        self.assertEqual(doc['local_fixture_start_intent_count'],0)
        self.assertFalse(doc['case_binding_accredited'])
        self.assertEqual(doc['p8_operational'],'NO-GO')


if __name__=='__main__':unittest.main()
