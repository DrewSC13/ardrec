"""R58-T CI gating, source safety and authentic pinned demo tests."""
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
SOURCE=REPO/'src/ardrec/coordination/r58t_counterfactual_state_store.py'
DEMO=REPO/'scripts/ardrec_p14_r58t_counterfactual_t1_demo.py'
TEST=REPO/'lab/tests/test_p14_r58t_simulation.py'
DOC=REPO/'docs/development/p14-r58t-private-counterfactual-t1-simulator.md'
CI=REPO/'.github/workflows/ci.yml'
CATALOG=REPO/'lab/operational-catalog-v1/catalog.json'
SCENARIO=REPO/'lab/p14-r26-session-v1/scenario.json'
CATALOG_SHA='5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
TEST_STEP='Probar R58-T simulador SQLite T1 aislado / Test atomic counterfactual state store'
DEMO_STEP='Demostrar R58-T dos T1 sinteticos sin autoridad / Check offline state replay'
TEST_CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58t_*.py' -v"
DEMO_CMD='PYTHONPATH=src python3 -B scripts/ardrec_p14_r58t_counterfactual_t1_demo.py --synthetic-offline'


class R58TCIGates(unittest.TestCase):
    def test_01_all_files_exist(self):
        self.assertTrue(all(p.is_file() for p in (SOURCE,DEMO,TEST,DOC,CI)))
    def test_02_source_ast(self):ast.parse(SOURCE.read_text(encoding='utf-8'))
    def test_03_demo_ast(self):ast.parse(DEMO.read_text(encoding='utf-8'))
    def test_04_ci_test_step_once(self):self.assertEqual(CI.read_text().count(TEST_STEP),1)
    def test_05_ci_demo_step_once(self):self.assertEqual(CI.read_text().count(DEMO_STEP),1)
    def test_06_ci_test_command_once(self):self.assertEqual(CI.read_text().count(TEST_CMD),1)
    def test_07_ci_demo_command_once(self):self.assertEqual(CI.read_text().count(DEMO_CMD),1)
    def test_08_step_order(self):
        ci=CI.read_text()
        self.assertLess(ci.index('Demostrar R58-S 29 denegaciones'),ci.index(TEST_STEP))
        self.assertLess(ci.index(TEST_STEP),ci.index(DEMO_STEP))
        self.assertLess(ci.index(DEMO_STEP),ci.index('Verificar diseño del laboratorio'))
    def test_09_previous_stages_retained(self):
        s=CI.read_text()
        for label in ('Probar R58-S decision durable denegada',
                      'Demostrar R58-S 29 denegaciones',
                      'Probar R58-R recibo inmutable',
                      'Demostrar R58-Q doble seleccion A4'):
            with self.subTest(label=label):self.assertEqual(s.count(label),1)
    def test_10_existing_jobs_retained(self):
        s=CI.read_text()
        self.assertIn('Python - empaquetado / packaging',s)
        self.assertIn('Rust - compilación / build',s)
    def test_11_no_privileged_steps(self):
        s=CI.read_text().split(TEST_STEP,1)[1].split('Verificar diseño del laboratorio',1)[0].lower()
        for token in ('sudo ','docker run','nmap ','ssh ','smbclient ','libvirt','--privileged','curl '):
            with self.subTest(token=token):self.assertNotIn(token,s)
    def test_12_no_operational_imports(self):
        tree=ast.parse(SOURCE.read_text(encoding='utf-8'))
        imported=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):imported.extend(x.name for x in node.names)
            if isinstance(node,ast.ImportFrom):imported.append(node.module or '')
        for forbidden in ('subprocess','socket','ctypes','ardrec.benign_pipeline','ardrec.p8'):
            with self.subTest(name=forbidden):self.assertNotIn(forbidden,imported)
    def test_13_no_operational_calls(self):
        s=SOURCE.read_text(encoding='utf-8')
        for token in ('transition_service(','.start_vm(','.launch(','.dispatch(','.submit(',
                      'Popen(','.run(','.check_call(','.publish(', 'persist_binding('):
            with self.subTest(token=token):self.assertNotIn(token,s)
    def test_14_source_requires_documentary_denial(self):
        s=SOURCE.read_text(encoding='utf-8')
        for token in ('verify_persisted_deny_gate','build_deny_gate','all_requests_denied',
                      "'review_outcome'",'DENIED',"'operational_transitions_applied':0",
                      "'operational_dispatch':False", "'p8_operational':'NO-GO'"):
            with self.subTest(token=token):self.assertIn(token,s)
    def test_15_private_sqlite_and_atomicity(self):
        s=SOURCE.read_text(encoding='utf-8')
        for token in ('sqlite3','BEGIN IMMEDIATE','PRAGMA integrity_check',
                      'PRAGMA foreign_key_check','PRAGMA synchronous=FULL',
                      'O_EXCL','conn.rollback()','conn.commit()','prev_sha256'):
            with self.subTest(token=token):self.assertIn(token,s)
    def test_16_mode_requires_flag(self):self.assertIn('--synthetic-offline',DEMO.read_text())
    def test_17_true_state_enums_reused(self):
        s=SOURCE.read_text()
        self.assertIn('from ardrec.state import ServicePhase, Transition',s)
        self.assertIn('Transition.PREPARAR.value',s)
    def test_18_pinned_catalog(self):
        if not CATALOG.is_file():self.skipTest('FULL_CATALOG_NOT_MOUNTED')
        self.assertEqual(hashlib.sha256(CATALOG.read_bytes()).hexdigest(),CATALOG_SHA)
    def test_19_cli_blocks_without_flag(self):
        if not (REPO/'src/ardrec/initialization/initial_preview.py').is_file():
            self.skipTest('FULL_GITHUB_CHECKOUT_REQUIRED')
        p=subprocess.run([sys.executable,'-B',str(DEMO)],cwd=REPO,
                         env={**os.environ,'PYTHONPATH':'src'},capture_output=True,text=True,timeout=20)
        self.assertEqual(p.returncode,23,p.stderr[-2000:])
        self.assertIn('R58T=BLOCKED',p.stderr)
    def test_20_full_real_catalog_demo(self):
        if not CATALOG.is_file() or not SCENARIO.is_file() or not (REPO/'src/ardrec/initialization/initial_preview.py').is_file():
            self.skipTest('FULL_PINNED_GITHUB_CHECKOUT_REQUIRED')
        p=subprocess.run([sys.executable,'-B',str(DEMO),'--synthetic-offline'],cwd=REPO,
                         env={**os.environ,'PYTHONPATH':'src'},capture_output=True,text=True,timeout=180)
        self.assertEqual(p.returncode,0,p.stderr[-1800:])
        d=json.loads(p.stdout)
        self.assertEqual((d['case_count'],d['family_count']),(29,25))
        self.assertEqual(d['logical_candidate_count'],8)
        self.assertEqual(d['simulated_t1_count'],2)
        self.assertEqual(d['simulated_prepared_count'],27)
        self.assertEqual(d['simulated_pending_count'],2)
        self.assertTrue(d['source_requests_all_denied'])
        self.assertTrue(d['ineligible_t1_rejected'])
        self.assertEqual(d['initial_replay_status'],'REPLAY_IDENTICAL')
        self.assertEqual(d['event_replay_status'],'REPLAY_IDENTICAL')
        self.assertFalse(d['operational_state_mutated'])
        self.assertEqual(d['operational_transitions_applied'],0)
        self.assertFalse(d['operational_dispatch'])
        self.assertEqual(d['a6_classification'],'ND')
        self.assertEqual(d['p8_operational'],'NO-GO')

if __name__=='__main__':unittest.main()
