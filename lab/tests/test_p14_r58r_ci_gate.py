"""R58-R workflow, filesystem boundary and authentic CLI regression."""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

REPO=Path(__file__).resolve().parents[2]
SOURCE=REPO/'src/ardrec/coordination/r58r_durable_transition_proposal.py'
DEMO=REPO/'scripts/ardrec_p14_r58r_durable_transition_demo.py'
TEST=REPO/'lab/tests/test_p14_r58r_immutable_proposal.py'
DOC=REPO/'docs/development/p14-r58r-immutable-transition-proposal.md'
CI=REPO/'.github/workflows/ci.yml'
CATALOG=REPO/'lab/operational-catalog-v1/catalog.json'
CATALOG_SHA='5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
TEST_STEP='Probar R58-R recibo inmutable de propuesta A3 A4 / Test immutable transition proposal'
DEMO_STEP='Demostrar R58-R persistencia declarada sin transicion / Check private idempotent proposal receipt'
TEST_CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58r_*.py' -v"
DEMO_CMD='PYTHONPATH=src python3 -B scripts/ardrec_p14_r58r_durable_transition_demo.py --synthetic-offline'


class WorkflowGates(unittest.TestCase):
    def test_five_files_present(self):
        self.assertTrue(all(p.is_file() for p in (SOURCE,DEMO,TEST,DOC,CI)))

    def test_module_syntax(self):
        ast.parse(SOURCE.read_text(encoding='utf-8'))

    def test_cli_syntax(self):
        ast.parse(DEMO.read_text(encoding='utf-8'))

    def test_unit_tests_syntax(self):
        ast.parse(TEST.read_text(encoding='utf-8'))

    def test_ci_test_step_once(self):
        self.assertEqual(CI.read_text().count(TEST_STEP),1)

    def test_ci_demo_step_once(self):
        self.assertEqual(CI.read_text().count(DEMO_STEP),1)

    def test_ci_test_command_once(self):
        self.assertEqual(CI.read_text().count(TEST_CMD),1)

    def test_ci_demo_command_once(self):
        self.assertEqual(CI.read_text().count(DEMO_CMD),1)

    def test_ci_step_order(self):
        ci=CI.read_text()
        self.assertLess(ci.index('Demostrar R58-Q doble seleccion A4'),ci.index(TEST_STEP))
        self.assertLess(ci.index(TEST_STEP),ci.index(DEMO_STEP))
        self.assertLess(ci.index(DEMO_STEP),ci.index('Verificar diseño del laboratorio'))

    def test_prior_steps_preserved(self):
        ci=CI.read_text()
        for step in ('Probar R58-Q transicion PREPARADO PENDIENTE',
                     'Demostrar R58-Q doble seleccion A4',
                     'Probar R58-P referencias A2 y guardas A3 por caso',
                     'Probar R58-O trazabilidad A1 A10'):
            with self.subTest(step=step):
                self.assertEqual(ci.count(step),1)

    def test_python_rust_jobs_present(self):
        ci=CI.read_text()
        self.assertIn('Python - empaquetado / packaging',ci)
        self.assertIn('Rust - compilación / build',ci)

    def test_new_steps_have_no_privileged_calls(self):
        chunk=CI.read_text().split(TEST_STEP,1)[1].split('Verificar diseño del laboratorio',1)[0]
        for token in ('sudo ', 'nmap ', 'ssh ', 'ftp ', 'smbclient ', 'docker run',
                      'libvirt', '--privileged', 'curl ', 'apt install'):
            with self.subTest(token=token):
                self.assertNotIn(token,chunk.lower())

    def test_module_no_host_operational_imports(self):
        tree=ast.parse(SOURCE.read_text())
        imports=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):
                imports.extend(a.name for a in node.names)
            if isinstance(node,ast.ImportFrom):
                imports.append(node.module or '')
        for unsafe in ('subprocess','socket','sqlite3','ctypes','ardrec.benign_pipeline',
                       'ardrec.executor','ardrec.transport'):
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe,imports)

    def test_source_avoids_attempt_and_state_mutators(self):
        text=SOURCE.read_text()
        for token in ('.submit(','.accept(','.execute(','.recover(',
                      'Popen(','.start_vm(','.publish_generation(',
                      'os.system(','.transition_case(', '.apply_transition('):
            with self.subTest(token=token):
                self.assertNotIn(token,text)

    def test_real_r58q_verifier_imported(self):
        self.assertIn('verify_a3_a4_transition_audit',SOURCE.read_text())

    def test_source_explicit_no_authority(self):
        source=SOURCE.read_text()
        for token in ("'transition_authorized': False",
                      "'transitions_applied': 0",
                      "'confirmed_pending_case_count': 0",
                      "'technical_truth_accredited': False",
                      "'operational_dispatch': False",
                      "'p8_operational': 'NO-GO'"):
            self.assertIn(token,source)

    def test_canonical_persistence_protocol(self):
        source=SOURCE.read_text()
        for token in ('os.O_EXCL', 'os.fsync(', 'O_NOFOLLOW',
                      'REPLAY_IDENTICAL', 'RECEIPT_REPLAY_CONFLICT_OR_TAMPER'):
            self.assertIn(token,source)

    def test_catalog_sha_when_available(self):
        if not CATALOG.is_file():
            self.skipTest('ORIGINAL_CATALOG_NOT_AVAILABLE')
        self.assertEqual(hashlib.sha256(CATALOG.read_bytes()).hexdigest(),CATALOG_SHA)

    def test_cli_no_flag_deny_in_full_repo(self):
        if not (REPO/'src/ardrec/initialization/initial_preview.py').is_file():
            self.skipTest('FULL_REPO_REQUIRED')
        p=subprocess.run([sys.executable,'-B',str(DEMO)],cwd=REPO,
                         env={**os.environ,'PYTHONPATH':'src'},
                         text=True,capture_output=True,timeout=15,check=False)
        self.assertEqual(p.returncode,23)
        self.assertIn('R58R=BLOCKED',p.stderr)

    def test_authentic_direct_cli(self):
        if (not CATALOG.is_file() or not
            (REPO/'src/ardrec/initialization/initial_preview.py').is_file()):
            self.skipTest('FULL_PINNED_REPO_REQUIRED')
        p=subprocess.run([sys.executable,'-B',str(DEMO),'--synthetic-offline'],
                         cwd=REPO,env={**os.environ,'PYTHONPATH':'src'},
                         text=True,capture_output=True,timeout=150,check=False)
        self.assertEqual(p.returncode,0,p.stderr[-3000:])
        d=json.loads(p.stdout)
        self.assertEqual((d['case_count'],d['family_count']),(29,25))
        self.assertEqual((d['current_prepared_count'],d['counterfactual_pending_count']),(29,8))
        self.assertEqual(d['create_status'],'CREATED')
        self.assertEqual(d['replay_status'],'REPLAY_IDENTICAL')
        self.assertEqual(d['receipt_file_count'],1)
        self.assertEqual(d['transitions_applied'],0)
        self.assertIs(d['technical_truth_accredited'],False)
        self.assertEqual(d['p8_operational'],'NO-GO')


if __name__=='__main__':
    unittest.main()
