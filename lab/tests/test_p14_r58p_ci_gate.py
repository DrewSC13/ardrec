"""R58-P workflow, guard non-mutation and genuine direct-CLI regression."""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / 'src/ardrec/coordination/r58p_a3_family_controls.py'
DEMO = REPO / 'scripts/ardrec_p14_r58p_a3_family_demo.py'
TEST = REPO / 'lab/tests/test_p14_r58p_family_controls.py'
DOC = REPO / 'docs/development/p14-r58p-a3-family-controls.md'
CI = REPO / '.github/workflows/ci.yml'
CATALOG = REPO / 'lab/operational-catalog-v1/catalog.json'
CATALOG_SHA256 = '5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
TEST_STEP = 'Probar R58-P referencias A2 y guardas A3 por caso / Test typed family control projection'
DEMO_STEP = 'Demostrar R58-P guardas de 29 casos / Check A3 A4 discrepancies without dispatch'
TEST_CMD = "PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58p_*.py' -v"
DEMO_CMD = 'PYTHONPATH=src python3 -B scripts/ardrec_p14_r58p_a3_family_demo.py --synthetic-offline'


class WorkflowGates(unittest.TestCase):
    def test_files_present(self):
        self.assertTrue(all(p.is_file() for p in (SOURCE,DEMO,TEST,DOC,CI)))

    def test_ci_test_step_once(self):
        self.assertEqual(CI.read_text().count(TEST_STEP),1)

    def test_ci_demo_step_once(self):
        self.assertEqual(CI.read_text().count(DEMO_STEP),1)

    def test_ci_test_command_once(self):
        self.assertEqual(CI.read_text().count(TEST_CMD),1)

    def test_ci_demo_command_once(self):
        self.assertEqual(CI.read_text().count(DEMO_CMD),1)

    def test_ci_step_order(self):
        s=CI.read_text()
        self.assertLess(s.index('Demostrar R58-O cadena A1 A10'),s.index(TEST_STEP))
        self.assertLess(s.index(TEST_STEP),s.index(DEMO_STEP))
        self.assertLess(s.index(DEMO_STEP),s.index('Verificar diseño del laboratorio'))

    def test_prior_r58n_and_r58o_preserved(self):
        s=CI.read_text()
        for name in ('Probar R58-O trazabilidad A1 A10',
                     'Demostrar R58-O cadena A1 A10',
                     'Probar R58-N vinculacion durable A4 A5'):
            self.assertEqual(s.count(name),1)

    def test_python_and_rust_jobs_preserved(self):
        s=CI.read_text()
        self.assertIn('Python - empaquetado / packaging',s)
        self.assertIn('Rust - compilación / build',s)

    def test_no_privileged_new_ci(self):
        s=CI.read_text().split(TEST_STEP,1)[1].split('Verificar diseño del laboratorio',1)[0]
        for term in ('sudo ', 'docker run', 'nmap ', 'ssh ', 'smbclient ',
                     '--privileged', 'libvirt', 'curl ', 'apt install'):
            self.assertNotIn(term,s.lower())

    def test_source_no_host_apis(self):
        tree=ast.parse(SOURCE.read_text())
        imported=[]
        for n in ast.walk(tree):
            if isinstance(n,ast.Import):
                imported.extend(a.name for a in n.names)
            if isinstance(n,ast.ImportFrom):
                imported.append(n.module or '')
        for bad in ('subprocess','socket','sqlite3','os','ardrec.benign_pipeline'):
            self.assertNotIn(bad,imported)

    def test_source_not_rewriting_r26(self):
        t=SOURCE.read_text()
        for bad in ('persist_binding(','.execute(','.recover(','.submit(','.accept(',
                    'Popen(', 'os.system('):
            self.assertNotIn(bad,t)
        self.assertIn("'r26_a3_control_targets_replaced_in_source': False",t)

    def test_source_no_claim_authority(self):
        t=SOURCE.read_text()
        for expected in ("'operational_eligibility_attested': False",
                         "'a3_case_guard_is_operational_authority': False",
                         "'a1_a3_to_family_case_authority_attested': False",
                         "'a1_a10_implementation_complete': False",
                         "'experimental_hypothesis_validated': False",
                         "'p8_operational': 'NO-GO'"):
            self.assertIn(expected,t)

    def test_r17_r22_genuine_imports(self):
        t=SOURCE.read_text()
        for token in ('preflight_rule_configuration','prepare_initial_preview',
                      'prepare_dependency_preview','prepare_control_preview',
                      'assemble_integrated_preview','diagnose_guards'):
            self.assertIn(token,t)

    def test_one_control_per_case(self):
        t=SOURCE.read_text()
        self.assertIn("'guard_rule_id': 'ALLOW'",t)
        self.assertIn("'target_case_id': d['case_id_a7']",t)
        self.assertIn("'max_repetitions': 0",t)

    def test_pinned_catalog_when_present(self):
        if not CATALOG.is_file():
            self.skipTest('ORIGINAL_CATALOG_UNAVAILABLE')
        self.assertEqual(hashlib.sha256(CATALOG.read_bytes()).hexdigest(),CATALOG_SHA256)

    def test_cli_denies_no_flag(self):
        if not (REPO / 'src/ardrec/initialization/initial_preview.py').is_file():
            self.skipTest('FULL_GITHUB_CHECKOUT_REQUIRED')
        out=subprocess.run([sys.executable,'-B',str(DEMO)],cwd=REPO,
                           env={**os.environ,'PYTHONPATH':'src'},
                           capture_output=True,text=True,timeout=15)
        self.assertEqual(out.returncode,23)
        self.assertIn('R58P=BLOCKED',out.stderr)

    def test_cli_real_catalog_synthetic_only(self):
        if not CATALOG.is_file() or not (REPO / 'src/ardrec/initialization/initial_preview.py').is_file():
            self.skipTest('FULL_PINNED_GITHUB_CHECKOUT_REQUIRED')
        out=subprocess.run([sys.executable,'-B',str(DEMO),'--synthetic-offline'],
                           cwd=REPO,env={**os.environ,'PYTHONPATH':'src'},
                           capture_output=True,text=True,timeout=120)
        self.assertEqual(out.returncode,0,out.stderr[-2000:])
        d=json.loads(out.stdout)
        self.assertEqual(d['control_reference_count'],29)
        self.assertEqual(d['family_count'],25)
        self.assertEqual(d['a3_guard_truth_counts'],{'VERDADERO':8,'FALSO':11,'ND':10})
        self.assertEqual(d['a3_a4_guard_mismatch_count'],21)
        self.assertFalse(d['a3_case_guard_is_operational_authority'])
        self.assertFalse(d['a1_a3_to_family_case_authority_attested'])
        self.assertEqual(d['a6_classification'],'ND')
        self.assertEqual(d['p8_operational'],'NO-GO')

if __name__=='__main__':
    unittest.main()
