"""R58-U source-only CI gate and authentic pinned CLI tests."""
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
SOURCE=REPO/'src/ardrec/coordination/r58u_counterfactual_pause_recovery.py'
DEMO=REPO/'scripts/ardrec_p14_r58u_pause_recovery_demo.py'
TEST=REPO/'lab/tests/test_p14_r58u_model_transitions.py'
DOC=REPO/'docs/development/p14-r58u-offline-pause-resume-stop.md'
CI=REPO/'.github/workflows/ci.yml'
CATALOG=REPO/'lab/operational-catalog-v1/catalog.json'
SCENARIO=REPO/'lab/p14-r26-session-v1/scenario.json'
CATALOG_SHA='5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
TEST_STEP='Probar R58-U pausas reanudaciones y detenciones sinteticas / Test offline state overlay'
DEMO_STEP='Demostrar R58-U T8 T9 T10 sin autoridad / Check private replay and terminal state'
TEST_CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58u_*.py' -v"
DEMO_CMD='PYTHONPATH=src python3 -B scripts/ardrec_p14_r58u_pause_recovery_demo.py --synthetic-offline'


class UGate(unittest.TestCase):
    def test_01_filenames(self):
        if not CI.exists():self.skipTest('FULL_GITHUB_CHECKOUT_REQUIRED')
        self.assertTrue(all(p.is_file() for p in (SOURCE,DEMO,TEST,DOC,CI)))
    def test_02_source_syntax(self):ast.parse(SOURCE.read_text(encoding='utf-8'))
    def test_03_demo_syntax(self):ast.parse(DEMO.read_text(encoding='utf-8'))
    def test_04_workflow_test_step_once(self):
        if not CI.exists():self.skipTest('FULL_GITHUB_CHECKOUT_REQUIRED')
        self.assertEqual(CI.read_text().count(TEST_STEP),1)
    def test_05_workflow_demo_step_once(self):
        if not CI.exists():self.skipTest('FULL_GITHUB_CHECKOUT_REQUIRED')
        self.assertEqual(CI.read_text().count(DEMO_STEP),1)
    def test_06_workflow_test_command_once(self):
        if not CI.exists():self.skipTest('FULL_GITHUB_CHECKOUT_REQUIRED')
        self.assertEqual(CI.read_text().count(TEST_CMD),1)
    def test_07_workflow_demo_command_once(self):
        if not CI.exists():self.skipTest('FULL_GITHUB_CHECKOUT_REQUIRED')
        self.assertEqual(CI.read_text().count(DEMO_CMD),1)
    def test_08_step_order(self):
        if not CI.exists():self.skipTest('FULL_GITHUB_CHECKOUT_REQUIRED')
        data=CI.read_text()
        self.assertLess(data.index('Demostrar R58-T dos T1 sinteticos'),data.index(TEST_STEP))
        self.assertLess(data.index(TEST_STEP),data.index(DEMO_STEP))
        self.assertLess(data.index(DEMO_STEP),data.index('Verificar diseño del laboratorio'))
    def test_09_previous_jobs(self):
        if not CI.exists():self.skipTest('FULL_GITHUB_CHECKOUT_REQUIRED')
        data=CI.read_text()
        for name in ('Probar R58-T simulador SQLite T1 aislado',
                     'Demostrar R58-T dos T1 sinteticos',
                     'Probar R58-S decision durable denegada',
                     'Demostrar R58-S 29 denegaciones'):
            self.assertEqual(data.count(name),1)
    def test_10_existing_python_rust(self):
        if not CI.exists():self.skipTest('FULL_GITHUB_CHECKOUT_REQUIRED')
        data=CI.read_text()
        self.assertIn('Python - empaquetado / packaging',data)
        self.assertIn('Rust - compilación / build',data)
    def test_11_no_host_invocations(self):
        tree=ast.parse(SOURCE.read_text())
        names=[]
        for x in ast.walk(tree):
            if isinstance(x,ast.Import):names.extend(y.name for y in x.names)
            elif isinstance(x,ast.ImportFrom):names.append(x.module or '')
        for forbidden in ('subprocess','socket','ctypes','ardrec.benign_pipeline',
                          'ardrec.p8_state_bridge'):
            self.assertNotIn(forbidden,names)
    def test_12_no_operational_methods(self):
        data=SOURCE.read_text()
        for term in ('transition_service(','.launch(','.dispatch(','.submit(',
                     'Popen(','.publish(', 'persist_binding('):
            self.assertNotIn(term,data)
    def test_13_only_synthetic_facts(self):
        data=SOURCE.read_text()
        for term in ('FIXTURE_ASSUMPTIONS_NEVER_ATTESTED','MODEL_FACT_REFERENCE_INVALID',
                     'operational_transitions_applied','p8_operational',
                     'source_t1_head_sha256'):
            self.assertIn(term,data)
    def test_14_sqlite_transactions(self):
        data=SOURCE.read_text()
        for term in ('BEGIN IMMEDIATE','PRAGMA integrity_check','PRAGMA synchronous=FULL',
                     'conn.rollback()','conn.commit()','O_EXCL','prev_sha'):
            self.assertIn(term,data)
    def test_15_source_reuses_t(self):
        self.assertIn('from ardrec.coordination import r58t_counterfactual_state_store as t',
                      SOURCE.read_text())
    def test_16_exact_true_state_enums(self):
        self.assertIn('from ardrec.state import ServicePhase, Transition',SOURCE.read_text())
    def test_17_cli_requires_flag(self):
        self.assertIn('--synthetic-offline',DEMO.read_text())
    def test_18_ci_not_privileged(self):
        if not CI.exists():self.skipTest('FULL_GITHUB_CHECKOUT_REQUIRED')
        data=CI.read_text().split(TEST_STEP,1)[1].split('Verificar diseño del laboratorio',1)[0].lower()
        for term in ('sudo ', 'docker run', 'nmap ', 'ssh ', 'libvirt','--privileged','curl '):
            self.assertNotIn(term,data)
    def test_19_pinned_catalog(self):
        if not CATALOG.is_file():self.skipTest('FULL_PINNED_CATALOG_REQUIRED')
        self.assertEqual(hashlib.sha256(CATALOG.read_bytes()).hexdigest(),CATALOG_SHA)
    def test_20_cli_missing_flag_rejected(self):
        if not (REPO/'src/ardrec/initialization/initial_preview.py').is_file():
            self.skipTest('AUTHENTIC_CHECKOUT_REQUIRED')
        p=subprocess.run([sys.executable,'-B',str(DEMO)],cwd=REPO,
                         env={**os.environ,'PYTHONPATH':'src'},capture_output=True,text=True,timeout=20)
        self.assertEqual(p.returncode,23,p.stderr)
        self.assertIn('R58U=BLOCKED',p.stderr)
    def test_21_authentic_integrated_demo(self):
        if not (CATALOG.is_file() and SCENARIO.is_file() and
                (REPO/'src/ardrec/initialization/initial_preview.py').is_file()):
            self.skipTest('AUTHENTIC_GITHUB_CHECKOUT_REQUIRED')
        p=subprocess.run([sys.executable,'-B',str(DEMO),'--synthetic-offline'],
                         cwd=REPO,env={**os.environ,'PYTHONPATH':'src'},
                         capture_output=True,text=True,timeout=180)
        self.assertEqual(p.returncode,0,p.stderr[-2200:])
        data=json.loads(p.stdout)
        self.assertEqual(data['simulated_phase_counts'],
                         {'PREPARADO':27,'PENDIENTE':1,'PAUSADO':0,'DETENIDO':1})
        self.assertEqual(data['simulated_event_count'],3)
        self.assertTrue(data['source_denials_preserved'])
        self.assertTrue(data['r58t_source_unchanged'])
        self.assertTrue(data['terminal_reentry_denied'])
        self.assertEqual(data['event_replay_status'],'REPLAY_IDENTICAL')
        self.assertEqual(data['operational_transitions_applied'],0)
        self.assertFalse(data['operational_dispatch'])
        self.assertEqual(data['p8_operational'],'NO-GO')

if __name__=='__main__':unittest.main()
