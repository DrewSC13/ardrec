"""R58-S: test workflow, permissions, direct CLI and pinned catalogue."""
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
SOURCE=REPO/'src/ardrec/coordination/r58s_transition_deny_gate.py'
DEMO=REPO/'scripts/ardrec_p14_r58s_transition_deny_demo.py'
TEST=REPO/'lab/tests/test_p14_r58s_transition_gate.py'
DOC=REPO/'docs/development/p14-r58s-deny-only-transition-assessment.md'
CI=REPO/'.github/workflows/ci.yml'
CATALOG=REPO/'lab/operational-catalog-v1/catalog.json'
CATALOG_SHA='5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
TEST_STEP='Probar R58-S decision durable denegada A3 A4 / Test deny-only transition assessment'
DEMO_STEP='Demostrar R58-S 29 denegaciones sin transicion / Check immutable no-commit gate'
TEST_CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58s_*.py' -v"
DEMO_CMD='PYTHONPATH=src python3 -B scripts/ardrec_p14_r58s_transition_deny_demo.py --synthetic-offline'


class R58SGates(unittest.TestCase):
    def test_all_files_present(self):
        self.assertTrue(all(p.is_file() for p in (SOURCE,DEMO,TEST,DOC,CI)))

    def test_source_syntax(self):
        ast.parse(SOURCE.read_text(encoding='utf-8'))

    def test_demo_syntax(self):
        ast.parse(DEMO.read_text(encoding='utf-8'))

    def test_test_command_once(self):
        self.assertEqual(CI.read_text().count(TEST_CMD),1)

    def test_demo_command_once(self):
        self.assertEqual(CI.read_text().count(DEMO_CMD),1)

    def test_test_step_once(self):
        self.assertEqual(CI.read_text().count(TEST_STEP),1)

    def test_demo_step_once(self):
        self.assertEqual(CI.read_text().count(DEMO_STEP),1)

    def test_ci_after_r58r_before_lab(self):
        text=CI.read_text()
        self.assertLess(text.index('Demostrar R58-R persistencia declarada'),
                        text.index(TEST_STEP))
        self.assertLess(text.index(TEST_STEP),text.index(DEMO_STEP))
        self.assertLess(text.index(DEMO_STEP),text.index('Verificar diseño del laboratorio'))

    def test_preserve_prior_steps(self):
        text=CI.read_text()
        for label in ('Probar R58-R recibo inmutable',
                      'Demostrar R58-R persistencia declarada',
                      'Probar R58-Q transicion PREPARADO',
                      'Demostrar R58-Q doble seleccion A4'):
            with self.subTest(label=label):self.assertEqual(text.count(label),1)

    def test_rust_and_python_jobs(self):
        text=CI.read_text()
        self.assertIn('Python - empaquetado / packaging',text)
        self.assertIn('Rust - compilación / build',text)

    def test_no_privileged_ci(self):
        text=CI.read_text().split(TEST_STEP,1)[1].split('Verificar diseño del laboratorio',1)[0]
        for forbidden in ('sudo ', 'docker run', 'nmap ', 'smbclient ',
                          'ssh ', 'libvirt', '--privileged', 'curl '):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden,text.lower())

    def test_source_does_not_execute_or_connect(self):
        tree=ast.parse(SOURCE.read_text())
        imported=[]
        for item in ast.walk(tree):
            if isinstance(item,ast.Import):imported.extend(x.name for x in item.names)
            if isinstance(item,ast.ImportFrom):imported.append(item.module or '')
        for forbidden in ('subprocess','socket','ctypes','sqlite3','ardrec.benign_pipeline'):
            self.assertNotIn(forbidden,imported)

    def test_persist_only_explicit_root(self):
        text=SOURCE.read_text()
        self.assertIn('os.O_EXCL',text)
        self.assertIn('_root(root)',text)
        self.assertIn('_read_private(target)',text)
        self.assertIn('os.fsync',text)

    def test_no_operational_promotions(self):
        text=SOURCE.read_text()
        for marker in ("'all_requests_denied': True",
                       "'review_outcome': 'DENIED'",
                       "'transitions_applied': 0",
                       "'confirmed_pending_case_count': 0",
                       "'a6_classification': 'ND'",
                       "'published_generation': None",
                       "'operational_dispatch': False",
                       "'p8_operational': 'NO-GO'"):
            self.assertIn(marker,text)

    def test_reuses_existing_r58r_private_primitives(self):
        text=SOURCE.read_text()
        for term in ('verify_persisted_proposal', 'build_proposal',
                     '_read_private', '_root'):
            self.assertIn(term,text)

    def test_rejects_executive_methods(self):
        text=SOURCE.read_text()
        for term in ('.execute(', '.recover(', '.submit(', '.accept(',
                     '.start_vm(', 'Popen(', 'os.system(', 'persist_binding('):
            with self.subTest(term=term):self.assertNotIn(term,text)

    def test_demo_requires_offline_flag(self):
        self.assertIn('--synthetic-offline',DEMO.read_text())

    def test_catalog_pinned_when_available(self):
        if not CATALOG.is_file():self.skipTest('PINNED_CATALOG_NOT_AVAILABLE')
        self.assertEqual(hashlib.sha256(CATALOG.read_bytes()).hexdigest(),CATALOG_SHA)

    def test_real_cli_denies_missing_flag(self):
        if not (REPO/'src/ardrec/initialization/initial_preview.py').is_file():
            self.skipTest('REAL_GITHUB_CHECKOUT_REQUIRED')
        run=subprocess.run([sys.executable,'-B',str(DEMO)],cwd=REPO,
                           env={**os.environ,'PYTHONPATH':'src'},
                           capture_output=True,text=True,timeout=20)
        self.assertEqual(run.returncode,23)
        self.assertIn('R58S=BLOCKED',run.stderr)

    def test_real_cli_with_catalog(self):
        if not CATALOG.is_file() or not (REPO/'src/ardrec/initialization/initial_preview.py').is_file():
            self.skipTest('REAL_PINNED_CHECKOUT_REQUIRED')
        run=subprocess.run([sys.executable,'-B',str(DEMO),'--synthetic-offline'],
                           cwd=REPO,env={**os.environ,'PYTHONPATH':'src'},
                           capture_output=True,text=True,timeout=180)
        self.assertEqual(run.returncode,0,run.stderr[-2000:])
        report=json.loads(run.stdout)
        self.assertEqual(report['case_count'],29)
        self.assertEqual(report['family_count'],25)
        self.assertEqual(report['logical_candidate_requests'],8)
        self.assertEqual(report['not_eligible_count'],21)
        self.assertEqual(report['gate_first'],'CREATED')
        self.assertEqual(report['gate_replay'],'REPLAY_IDENTICAL')
        self.assertEqual(report['transitions_applied'],0)
        self.assertFalse(report['signed_approval_attested'])
        self.assertFalse(report['state_machine_mutated'])
        self.assertFalse(report['operational_dispatch'])
        self.assertEqual(report['a6_classification'],'ND')
        self.assertEqual(report['p8_operational'],'NO-GO')


if __name__=='__main__':
    unittest.main()
