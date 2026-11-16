"""R58-N CI gate: pinned source-only, direct CLI and no privileged actions."""
from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
CI=ROOT/'.github/workflows/ci.yml'
SOURCE=ROOT/'src/ardrec/coordination/r58n_durable_case_binding.py'
DEMO=ROOT/'scripts/ardrec_p14_r58n_durable_binding_demo.py'
TEST=ROOT/'lab/tests/test_p14_r58n_durable_binding.py'
DOC=ROOT/'docs/development/p14-r58n-durable-declared-case-binding.md'
TEST_CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58n_*.py' -v"
DEMO_CMD="PYTHONPATH=src python3 -B scripts/ardrec_p14_r58n_durable_binding_demo.py --synthetic-offline"


class WorkflowTests(unittest.TestCase):
    def setUp(self):self.workflow=CI.read_text()
    def test_python_job(self):self.assertIn('Python - empaquetado / packaging',self.workflow)
    def test_rust_job(self):self.assertIn('Rust - compilación / build',self.workflow)
    def test_source(self):self.assertTrue(SOURCE.is_file())
    def test_demo(self):self.assertTrue(DEMO.is_file())
    def test_tests(self):self.assertTrue(TEST.is_file())
    def test_docs(self):self.assertTrue(DOC.is_file())
    def test_new_test_command_once(self):self.assertEqual(self.workflow.count(TEST_CMD),1)
    def test_new_demo_command_once(self):self.assertEqual(self.workflow.count(DEMO_CMD),1)
    def test_new_test_step_once(self):self.assertEqual(self.workflow.count('Probar R58-N vinculacion durable A4 A5'),1)
    def test_new_demo_step_once(self):self.assertEqual(self.workflow.count('Demostrar R58-N recibo declarado e idempotente'),1)
    def test_prior_m_step(self):self.assertIn('Demostrar R58-M diario A5 temporal',self.workflow)
    def test_prior_l_step(self):self.assertIn('Demostrar R58-L seleccion A4 y A5 sintetico',self.workflow)
    def test_prior_k_step(self):self.assertIn('Demostrar R58-K 29 casos SSH FTP SMB',self.workflow)
    def test_step_order(self):
        keys=('Demostrar R58-M diario A5 temporal','Probar R58-N vinculacion durable A4 A5',
              'Demostrar R58-N recibo declarado e idempotente','Verificar diseño del laboratorio')
        self.assertEqual(sorted(self.workflow.index(k) for k in keys),
                         [self.workflow.index(k) for k in keys])
    def test_no_privilege(self):
        for cmd in (TEST_CMD,DEMO_CMD):
            for disallowed in ('sudo ','systemctl ','virsh ','ssh ','nft ','docker ','nc '):
                self.assertNotIn(disallowed,cmd)
    def test_ast_no_network(self):
        tree=ast.parse(SOURCE.read_text())
        imported=set()
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):imported.update(a.name.split('.')[0] for a in node.names)
            if isinstance(node,ast.ImportFrom):imported.add((node.module or '').split('.')[0])
        self.assertFalse(imported & {'socket','subprocess','paramiko','asyncssh','fabric','requests'})
    def test_no_benign_pipeline_in_audit(self):
        self.assertNotIn('BenignPipeline(',SOURCE.read_text())
    def test_no_operational_grants(self):
        s=SOURCE.read_text()
        for needle in ("'physical_case_binding_accredited': False",
                       "'technical_truth_accredited': False",
                       "'operational_dispatch': False",
                       "'p8_operational': 'NO-GO'",
                       "'a6_classification': 'ND'",'os.O_EXCL','os.fsync'):
            self.assertIn(needle,s)
    def test_demo_needs_explicit_flag(self):
        try:from ardrec.benign_pipeline import BenignPipeline
        except ImportError:self.skipTest('ORIGINAL_BENIGN_PIPELINE_NOT_IN_TINY_FIXTURE')
        run=subprocess.run([sys.executable,'-B',str(DEMO)],cwd=ROOT,
                           capture_output=True,text=True,timeout=20)
        self.assertEqual(run.returncode,23)
    def test_direct_cli_real(self):
        try:from ardrec.benign_pipeline import BenignPipeline
        except ImportError:self.skipTest('ORIGINAL_BENIGN_PIPELINE_NOT_IN_TINY_FIXTURE')
        env=os.environ.copy();env['PYTHONPATH']='src'
        run=subprocess.run([sys.executable,'-B',str(DEMO),'--synthetic-offline'],
                           cwd=ROOT,env=env,capture_output=True,text=True,timeout=120)
        self.assertEqual(run.returncode,0,run.stderr[-2400:])
        import json
        d=json.loads(run.stdout)
        self.assertEqual(d['unit_count'],29)
        self.assertEqual(d['covered_family_count'],25)
        self.assertEqual(d['first_persist_status'],'CREATED')
        self.assertEqual(d['replay_persist_status'],'REPLAY_IDENTICAL')
        self.assertEqual(d['journal_state'],'ACCEPTED')
        self.assertFalse(d['physical_case_binding_accredited'])
        self.assertEqual(d['a6_classification'],'ND')
        self.assertEqual(d['p8_operational'],'NO-GO')

if __name__=='__main__':unittest.main()
