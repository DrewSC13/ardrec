"""R58-Q CI, source permissions and exact direct CLI regression."""
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
SOURCE=REPO/'src/ardrec/coordination/r58q_transition_guard_bridge.py'
DEMO=REPO/'scripts/ardrec_p14_r58q_a3_a4_transition_demo.py'
TEST=REPO/'lab/tests/test_p14_r58q_transition_bridge.py'
DOC=REPO/'docs/development/p14-r58q-a3-a4-transition-audit.md'
CI=REPO/'.github/workflows/ci.yml'
SCENARIO=REPO/'lab/p14-r26-session-v1/scenario.json'
CATALOG=REPO/'lab/operational-catalog-v1/catalog.json'
CATALOG_SHA='5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
TEST_STEP='Probar R58-Q transicion PREPARADO PENDIENTE / Test counterfactual A3 A4 mapping'
DEMO_STEP='Demostrar R58-Q doble seleccion A4 / Check zero actual and eight hypothetical SSH'
TEST_CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58q_*.py' -v"
DEMO_CMD='PYTHONPATH=src python3 -B scripts/ardrec_p14_r58q_a3_a4_transition_demo.py --synthetic-offline'


class WorkflowTests(unittest.TestCase):
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

    def test_step_order_and_prior_steps(self):
        ci=CI.read_text()
        self.assertLess(ci.index('Demostrar R58-P guardas de 29 casos'),ci.index(TEST_STEP))
        self.assertLess(ci.index(TEST_STEP),ci.index(DEMO_STEP))
        self.assertLess(ci.index(DEMO_STEP),ci.index('Verificar diseño del laboratorio'))

    def test_prior_r58o_r58p_preserved(self):
        ci=CI.read_text()
        for name in ('Probar R58-O trazabilidad A1 A10',
                     'Demostrar R58-O cadena A1 A10',
                     'Probar R58-P referencias A2 y guardas A3 por caso',
                     'Demostrar R58-P guardas de 29 casos'):
            self.assertEqual(ci.count(name),1)

    def test_python_and_rust_jobs(self):
        ci=CI.read_text()
        self.assertIn('Python - empaquetado / packaging',ci)
        self.assertIn('Rust - compilación / build',ci)

    def test_new_steps_no_privileged_commands(self):
        ci=CI.read_text().split(TEST_STEP,1)[1].split('Verificar diseño del laboratorio',1)[0]
        for token in ('sudo ','ssh ','ftp ','nmap ','smbclient ','docker run','libvirt','--privileged','curl '):
            with self.subTest(token=token):
                self.assertNotIn(token,ci.lower())

    def test_no_host_mutator_imports(self):
        tree=ast.parse(SOURCE.read_text())
        imported=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):
                imported.extend(alias.name for alias in node.names)
            if isinstance(node,ast.ImportFrom):
                imported.append(node.module or '')
        for name in ('subprocess','socket','sqlite3','os','pathlib','ctypes','ardrec.benign_pipeline'):
            with self.subTest(name=name):
                self.assertNotIn(name,imported)

    def test_no_execution_methods(self):
        source=SOURCE.read_text()
        for call in ('.execute(','.recover(','.submit(','.accept(','.persist(',
                     'Popen(','.system(','.start_vm(','.launch(','.persist_binding('):
            with self.subTest(call=call):
                self.assertNotIn(call,source)

    def test_real_a4_selector_imported(self):
        source=SOURCE.read_text()
        self.assertIn('from ardrec.selection.greedy_development import select_development, verify_selection',source)

    def test_r58p_source_reused(self):
        source=SOURCE.read_text()
        self.assertIn('verify_family_a3_projection',source)
        self.assertIn('verify_a4_a5_review',source)

    def test_explicit_denial(self):
        source=SOURCE.read_text()
        for code in ("'prepared_to_pending_transitions_applied': 0",
                     "'a3_to_a4_operational_authority_attested': False",
                     "'confirmed_pending_case_count': 0",
                     "'a6_classification': 'ND'",
                     "'operational_dispatch': False",
                     "'p8_operational': 'NO-GO'"):
            with self.subTest(code=code):
                self.assertIn(code,source)

    def test_cli_needs_explicit_flag_source(self):
        self.assertIn('--synthetic-offline',DEMO.read_text())

    def test_source_catalog_pinned_when_present(self):
        if not CATALOG.is_file():
            self.skipTest('PINNED_CATALOG_NOT_MOUNTED')
        self.assertEqual(hashlib.sha256(CATALOG.read_bytes()).hexdigest(),CATALOG_SHA)

    def test_cli_rejects_no_flag_real_checkout(self):
        if not (REPO/'src/ardrec/initialization/initial_preview.py').is_file():
            self.skipTest('FULL_REPO_REQUIRED')
        result=subprocess.run([sys.executable,'-B',str(DEMO)],cwd=REPO,
                              env={**os.environ,'PYTHONPATH':'src'},
                              capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,23,result.stderr[-2000:])
        self.assertIn('R58Q=BLOCKED',result.stderr)

    def test_cli_real_pinned_catalog(self):
        if not CATALOG.is_file() or not SCENARIO.is_file() or not (REPO/'src/ardrec/initialization/initial_preview.py').is_file():
            self.skipTest('FULL_PINNED_REPO_REQUIRED')
        result=subprocess.run([sys.executable,'-B',str(DEMO),'--synthetic-offline'],cwd=REPO,
                              env={**os.environ,'PYTHONPATH':'src'},
                              capture_output=True,text=True,timeout=120)
        self.assertEqual(result.returncode,0,result.stderr[-2000:])
        d=json.loads(result.stdout)
        self.assertEqual(d['case_count'],29)
        self.assertEqual(d['family_count'],25)
        self.assertEqual(d['a3_guard_truth_counts'],{'VERDADERO':8,'FALSO':11,'ND':10})
        self.assertEqual(d['actual_a4_eligible_count'],0)
        self.assertIsNone(d['actual_a4_selected'])
        self.assertEqual(d['hypothetical_a4_eligible_count'],8)
        self.assertEqual(d['hypothetical_a4_selected']['service_id'],'SSH_DEV')
        self.assertEqual(d['transitions_applied'],0)
        self.assertFalse(d['operational_authority_attested'])
        self.assertEqual(d['a6_classification'],'ND')
        self.assertEqual(d['p8_operational'],'NO-GO')


if __name__=='__main__':
    unittest.main()
