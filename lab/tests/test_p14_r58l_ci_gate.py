"""R58-L CI anchor, source-only boundary, and prior workflow preservation."""
from __future__ import annotations

import ast
import re
from pathlib import Path
import unittest

REPO=Path(__file__).resolve().parents[2]
CI=REPO/'.github/workflows/ci.yml'
SRC=REPO/'src/ardrec/coordination/r58l_a4_a5_family_review.py'
DEMO=REPO/'scripts/ardrec_p14_r58l_a4_a5_review_demo.py'
DOC=REPO/'docs/development/p14-r58l-a4-a5-a6-a8-synthetic-review.md'
TEST=REPO/'lab/tests/test_p14_r58l_coordination.py'
TEST_CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58l_*.py' -v"
DEMO_CMD='PYTHONPATH=src python3 -B scripts/ardrec_p14_r58l_a4_a5_review_demo.py --synthetic-offline'
TEST_STEP='Probar R58-L A4 A5 revision sin despacho / Test selection and attempt review'
DEMO_STEP='Demostrar R58-L seleccion A4 y A5 sintetico / Check offline no-dispatch review'
PRIOR='Demostrar R58-K 29 casos SSH FTP SMB sin ejecucion / Test unified synthetic preview'

class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text=CI.read_text()

    def test_workflow_exists(self):
        self.assertTrue(CI.is_file())

    def test_python_job_exists(self):
        self.assertIn('Python - empaquetado / packaging',self.text)

    def test_rust_job_preserved(self):
        self.assertIn('Rust - compilación / build',self.text)

    def test_prior_r58k_step_preserved(self):
        self.assertIn(PRIOR,self.text)

    def test_prior_r58k_demo_preserved(self):
        self.assertIn('scripts/ardrec_p14_r58k_unified_family_demo.py --synthetic-offline',self.text)

    def test_prior_ssh_ftp_smb(self):
        for stage in 'hij':
            self.assertIn(f"-p 'test_p14_r58{stage}_*.py' -v",self.text)

    def test_new_test_step_once(self):
        self.assertEqual(self.text.count(TEST_STEP),1)

    def test_new_demo_step_once(self):
        self.assertEqual(self.text.count(DEMO_STEP),1)

    def test_new_test_command_once(self):
        self.assertEqual(self.text.count(TEST_CMD),1)

    def test_new_demo_command_once(self):
        self.assertEqual(self.text.count(DEMO_CMD),1)

    def test_steps_order(self):
        self.assertLess(self.text.index(PRIOR),self.text.index(TEST_STEP))
        self.assertLess(self.text.index(TEST_STEP),self.text.index(DEMO_STEP))
        self.assertLess(self.text.index('Verificar trazabilidad vigente / Verify current traceability'),self.text.index(TEST_STEP))

    def test_no_privileged_actions(self):
        for cmd in (TEST_CMD,DEMO_CMD):
            self.assertNotRegex(cmd,r'\b(?:sudo|systemctl|virsh|ssh|iptables|nft)\b')

    def test_files_present(self):
        for p in (SRC,DEMO,DOC,TEST):self.assertTrue(p.is_file(),str(p))

    def test_source_imports_existing_a4_and_r58k(self):
        s=SRC.read_text()
        self.assertIn('select_development',s)
        self.assertIn('verify_selection',s)
        self.assertIn('build_unified_preview',s)
        self.assertIn('verify_unified_preview',s)

    def test_no_host_mutators_in_coordinator(self):
        tree=ast.parse(SRC.read_text())
        forbidden={'subprocess','socket','paramiko','fabric','asyncssh','pexpect'}
        used=set()
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):
                used.update(alias.name.split('.')[0] for alias in node.names)
            if isinstance(node,ast.ImportFrom) and node.module:
                used.add(node.module.split('.')[0])
        self.assertFalse(forbidden & used)

    def test_anti_accreditation_guards(self):
        src=SRC.read_text()
        for guard in ("'a6_classification': 'ND'", "'operational_dispatch': False",
                      "'actual_attempts_started': 0", "'published_generation': None",
                      "'p8_operational': 'NO-GO'",'INTENT_MUST_BE_REVIEW_ONLY',
                      'ORDINARY_BUDGET_EXCEEDED_NO_RETRY'):
            self.assertIn(guard,src)

    def test_source_base_pinned(self):
        self.assertIn('8aad0fd43e451de2c33a1e42fe9b6240fcd23c8f',SRC.read_text())


    def test_demo_subprocess_matches_ci(self):
        # Reproduce the actual GitHub Actions invocation.
        catalog = REPO / 'lab/operational-catalog-v1/catalog.json'
        if not catalog.is_file():
            self.skipTest('AUTHORITATIVE_CATALOG_NOT_AVAILABLE')

        import json
        import os
        import subprocess
        import sys

        env = {**os.environ, 'PYTHONPATH': 'src'}

        run = subprocess.run(
            [
                sys.executable,
                '-B',
                'scripts/ardrec_p14_r58l_a4_a5_review_demo.py',
                '--synthetic-offline',
            ],
            cwd=REPO,
            env=env,
            text=True,
            capture_output=True,
            timeout=45,
            check=False,
        )

        self.assertEqual(
            run.returncode,
            0,
            run.stderr[-2000:],
        )

        result = json.loads(run.stdout)

        self.assertEqual(result['unit_count'], 29)
        self.assertEqual(result['covered_family_count'], 25)
        self.assertEqual(result['a5_actual_starts'], 0)
        self.assertEqual(result['a6_classification'], 'ND')
        self.assertEqual(result['p8_operational'], 'NO-GO')


if __name__=='__main__':unittest.main()
