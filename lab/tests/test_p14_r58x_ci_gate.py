"""R58-X CI, safety, actual catalog and full CLI integration checks."""
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
SOURCE=REPO/'src/ardrec/coordination/r58x_no_start_a6_a7_envelope.py'
DEMO=REPO/'scripts/ardrec_p14_r58x_no_start_a6_a7_demo.py'
TEST=REPO/'lab/tests/test_p14_r58x_no_start_envelope.py'
DOC=REPO/'docs/development/p14-r58x-no-start-a6-a7-uncertainty.md'
CI=REPO/'.github/workflows/ci.yml'
CATALOG=REPO/'lab/operational-catalog-v1/catalog.json'
CATALOG_SHA='5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
TEST_STEP='Probar R58-X A5 sin inicio A6 ND y A7 exacto / Test no-start uncertainty bridge'
DEMO_STEP='Demostrar R58-X 29 intervalos sin Rf acreditado / Check exact no-start envelope'
TEST_CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58x_*.py' -v"
DEMO_CMD='PYTHONPATH=src python3 -B scripts/ardrec_p14_r58x_no_start_a6_a7_demo.py --synthetic-offline'

class R58XCIGates(unittest.TestCase):
    def test_01_files(self):self.assertTrue(all(f.is_file() for f in (SOURCE,DEMO,TEST,DOC,CI)))
    def test_02_source_syntax(self):ast.parse(SOURCE.read_text())
    def test_03_demo_syntax(self):ast.parse(DEMO.read_text())
    def test_04_ci_test_step_once(self):self.assertEqual(CI.read_text().count(TEST_STEP),1)
    def test_05_ci_demo_step_once(self):self.assertEqual(CI.read_text().count(DEMO_STEP),1)
    def test_06_ci_test_command_once(self):self.assertEqual(CI.read_text().count(TEST_CMD),1)
    def test_07_ci_demo_command_once(self):self.assertEqual(CI.read_text().count(DEMO_CMD),1)
    def test_08_ci_order(self):
        t=CI.read_text()
        self.assertLess(t.index('Demostrar R58-W A5 sin reserva ni evidencia A6'),t.index(TEST_STEP))
        self.assertLess(t.index(TEST_STEP),t.index(DEMO_STEP))
        self.assertLess(t.index(DEMO_STEP),t.index('Verificar diseño del laboratorio'))
    def test_09_prior_steps(self):
        t=CI.read_text()
        for term in ('Probar R58-W A5 intenciones sinteticas sin inicio',
                     'Demostrar R58-W A5 sin reserva ni evidencia A6',
                     'Probar R58-V entrega A5 A6 solo lectura',
                     'Probar R58-U pausas reanudaciones'):
            with self.subTest(term=term):self.assertEqual(t.count(term),1)
    def test_10_python_rust_jobs(self):
        t=CI.read_text();self.assertIn('Python - empaquetado / packaging',t)
        self.assertIn('Rust - compilación / build',t)
    def test_11_ci_timeout_capacity(self):
        t=CI.read_text()
        self.assertIn('timeout-minutes: 30',t.split('  python:',1)[1].split('  rust:',1)[0])
    def test_12_no_privileged_ci(self):
        t=CI.read_text().split(TEST_STEP,1)[1].split('Verificar diseño del laboratorio',1)[0].lower()
        for term in ('sudo ','docker run','ssh ','smbclient ','nmap ','libvirt','--privileged','curl ','wget '):
            with self.subTest(term=term):self.assertNotIn(term,t)
    def test_13_no_exec_imports(self):
        imports=[]
        for n in ast.walk(ast.parse(SOURCE.read_text())):
            if isinstance(n,ast.Import):imports.extend(a.name for a in n.names)
            if isinstance(n,ast.ImportFrom):imports.append(n.module or '')
        for bad in ('subprocess','socket','ctypes','ardrec.executor','ardrec.p8'):
            self.assertNotIn(bad,imports)
    def test_14_no_real_operations(self):
        s=SOURCE.read_text()
        for term in ('transition_service(','.submit(','.execute_attempt(','.launch(','.publish(',
                     '.dispatch(', 'Popen(', 'persist_binding('):
            self.assertNotIn(term,s)
    def test_15_existing_math_reused(self):
        t=SOURCE.read_text()
        for name in ('build_unit_bridge','verify_unit_bridge','normalize_scenario',
                     'inspect_model_ledger','_private_file_fingerprint','mode=ro'):
            self.assertIn(name,t)
    def test_16_no_evidence_import(self):
        t=SOURCE.read_text();self.assertIn("'evidence': []",t)
        self.assertIn('build_unit_bridge(unit_inputs, [])',t)
    def test_17_no_accredited_output(self):
        t=SOURCE.read_text()
        for name in ("'a6_classification':'ND'", "'confirmed_final_risk':None",
                     "'a5_attempts_started':0", "'p8_operational':'NO-GO'",
                     "'published_generation':None"):
            self.assertIn(name,t)
    def test_18_demo_flag(self):self.assertIn('--synthetic-offline',DEMO.read_text())
    def test_19_real_catalog(self):
        if not CATALOG.is_file():self.skipTest('REAL_CATALOG_NOT_MOUNTED')
        self.assertEqual(hashlib.sha256(CATALOG.read_bytes()).hexdigest(),CATALOG_SHA)
    def test_20_cli_requires_offline_flag(self):
        if not (REPO/'src/ardrec/initialization/initial_preview.py').is_file():
            self.skipTest('AUTHENTIC_GITHUB_CHECKOUT_REQUIRED')
        p=subprocess.run([sys.executable,'-B',str(DEMO)],cwd=REPO,
                         env={**os.environ,'PYTHONPATH':'src'},capture_output=True,text=True,timeout=25)
        self.assertEqual(p.returncode,23)
        self.assertIn('R58X=BLOCKED',p.stderr)
    def test_21_full_catalog_integration(self):
        if not CATALOG.is_file() or not (REPO/'src/ardrec/initialization/initial_preview.py').is_file():
            self.skipTest('AUTHENTIC_GITHUB_CHECKOUT_REQUIRED')
        p=subprocess.run([sys.executable,'-B',str(DEMO),'--synthetic-offline'],cwd=REPO,
                         env={**os.environ,'PYTHONPATH':'src'},capture_output=True,text=True,timeout=600)
        self.assertEqual(p.returncode,0,p.stderr[-2500:])
        d=json.loads(p.stdout)
        self.assertEqual((d['case_count'],d['family_count']),(29,25))
        self.assertEqual(d['model_event_count'],2)
        self.assertEqual(d['model_no_start_resolutions'],1)
        self.assertEqual(d['model_no_start_case_count'],1)
        self.assertEqual(d['a7_lower_values'],['1/4'])
        self.assertEqual(d['a7_upper_values'],['7/12'])
        self.assertEqual(d['mathematical_unit_count'],29)
        self.assertTrue(d['all_a6_nd'])
        self.assertTrue(d['all_risks_unconfirmed'])
        self.assertTrue(d['source_t1_unchanged'])
        self.assertTrue(d['source_overlay_unchanged'])
        self.assertTrue(d['source_denials_preserved'])
        self.assertEqual(d['a5_attempts_started'],0)
        self.assertEqual(d['a6_accredited_evidence_count'],0)
        self.assertIsNone(d['confirmed_final_risk'])
        self.assertEqual(d['p8_operational'],'NO-GO')

if __name__=='__main__':unittest.main()
