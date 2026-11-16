"""R58-W workflow, safety checks, and pinned actual checkout demo."""
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
SOURCE=REPO/'src/ardrec/coordination/r58w_declared_a5_model_ledger.py'
DEMO=REPO/'scripts/ardrec_p14_r58w_a5_model_intent_demo.py'
TEST=REPO/'lab/tests/test_p14_r58w_model_ledger.py'
DOC=REPO/'docs/development/p14-r58w-a5-model-intent-no-start-ledger.md'
CI=REPO/'.github/workflows/ci.yml'
CATALOG=REPO/'lab/operational-catalog-v1/catalog.json'
SCENARIO=REPO/'lab/p14-r26-session-v1/scenario.json'
CATALOG_SHA='5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
TEST_STEP='Probar R58-W A5 intenciones sinteticas sin inicio / Test private model intent ledger'
DEMO_STEP='Demostrar R58-W A5 sin reserva ni evidencia A6 / Check model no-start replay'
TEST_CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58w_*.py' -v"
DEMO_CMD='PYTHONPATH=src python3 -B scripts/ardrec_p14_r58w_a5_model_intent_demo.py --synthetic-offline'

class R58WCIGates(unittest.TestCase):
    def test_01_files(self):self.assertTrue(all(p.is_file() for p in (SOURCE,DEMO,TEST,DOC,CI)))
    def test_02_source_ast(self):ast.parse(SOURCE.read_text(encoding='utf-8'))
    def test_03_demo_ast(self):ast.parse(DEMO.read_text(encoding='utf-8'))
    def test_04_test_step_once(self):self.assertEqual(CI.read_text().count(TEST_STEP),1)
    def test_05_demo_step_once(self):self.assertEqual(CI.read_text().count(DEMO_STEP),1)
    def test_06_test_command_once(self):self.assertEqual(CI.read_text().count(TEST_CMD),1)
    def test_07_demo_command_once(self):self.assertEqual(CI.read_text().count(DEMO_CMD),1)
    def test_08_order(self):
        c=CI.read_text(encoding='utf-8')
        self.assertLess(c.index('Demostrar R58-V estado T1 U sin A5 real'),c.index(TEST_STEP))
        self.assertLess(c.index(TEST_STEP),c.index(DEMO_STEP))
        self.assertLess(c.index(DEMO_STEP),c.index('Verificar diseño del laboratorio'))
    def test_09_previous_steps(self):
        c=CI.read_text()
        for marker in ('Probar R58-V entrega A5 A6 solo lectura',
                       'Demostrar R58-V estado T1 U sin A5 real',
                       'Probar R58-U pausas reanudaciones',
                       'Probar R58-T simulador SQLite T1'):
            with self.subTest(marker=marker):self.assertEqual(c.count(marker),1)
    def test_10_existing_jobs(self):
        c=CI.read_text();self.assertIn('Python - empaquetado / packaging',c)
        self.assertIn('Rust - compilación / build',c)
    def test_11_steps_no_privileged(self):
        c=CI.read_text().split(TEST_STEP,1)[1].split('Verificar diseño del laboratorio',1)[0].lower()
        for word in ('sudo ','docker run','ssh ','nmap ','smbclient ',
                     'libvirt','--privileged','curl ','wget '):
            with self.subTest(word=word):self.assertNotIn(word,c)
    def test_12_source_no_network_or_executor(self):
        tree=ast.parse(SOURCE.read_text())
        imports=[]
        for item in ast.walk(tree):
            if isinstance(item,ast.Import):imports.extend(node.name for node in item.names)
            if isinstance(item,ast.ImportFrom):imports.append(item.module or '')
        for forbidden in ('subprocess','socket','ctypes','ardrec.benign_pipeline',
                          'ardrec.p8','ardrec.executor'):
            self.assertNotIn(forbidden,imports)
    def test_13_operational_calls_absent(self):
        s=SOURCE.read_text()
        for marker in ('transition_service(','.submit(','.execute_attempt(',
                       '.launch(','.publish(','.dispatch(', 'Popen(',
                       'persist_binding('):
            with self.subTest(marker=marker):self.assertNotIn(marker,s)
    def test_14_expected_source(self):
        s=SOURCE.read_text()
        for marker in ('verify_persisted_handoff','build_handoff',
                       'READONLY_HANDOFF_NOT_VERIFIED','MODEL_CASE_NOT_PENDING',
                       'MODEL_EVENT_CHAIN_INVALID','BEGIN IMMEDIATE','rollback()',
                       'PRAGMA integrity_check','PRAGMA synchronous=FULL'):
            self.assertIn(marker,s)
    def test_15_explicit_zero_authority(self):
        s=SOURCE.read_text()
        for marker in ("'a5_attempts_started':0", "'a6_classification':'ND'",
                       "'a6_accredited_evidence_count':0", "'p8_operational':'NO-GO'",
                       "'published_generation':None", "'operational_dispatch':False"):
            self.assertIn(marker,s)
    def test_16_private_db(self):
        s=SOURCE.read_text()
        for marker in ('O_EXCL','O_NOFOLLOW','os.fsync','0o600','_root'):
            self.assertIn(marker,s)
    def test_17_cli_flag(self):self.assertIn('--synthetic-offline',DEMO.read_text())
    def test_18_real_catalog_sha(self):
        if not CATALOG.is_file():self.skipTest('CATALOG_NOT_AVAILABLE')
        self.assertEqual(hashlib.sha256(CATALOG.read_bytes()).hexdigest(),CATALOG_SHA)
    def test_19_cli_no_flag(self):
        if not (REPO/'src/ardrec/initialization/initial_preview.py').is_file():
            self.skipTest('FULL_REPO_REQUIRED')
        p=subprocess.run([sys.executable,'-B',str(DEMO)],cwd=REPO,
                         env={**os.environ,'PYTHONPATH':'src'},
                         capture_output=True,text=True,timeout=25)
        self.assertEqual(p.returncode,23,p.stderr[-1000:])
        self.assertIn('R58W=BLOCKED',p.stderr)
    def test_20_cli_full_catalog(self):
        if not CATALOG.is_file() or not SCENARIO.is_file() or not (REPO/'src/ardrec/initialization/initial_preview.py').is_file():
            self.skipTest('FULL_PINNED_REPO_REQUIRED')
        p=subprocess.run([sys.executable,'-B',str(DEMO),'--synthetic-offline'],
                         cwd=REPO,env={**os.environ,'PYTHONPATH':'src'},
                         capture_output=True,text=True,timeout=240)
        self.assertEqual(p.returncode,0,p.stderr[-1500:])
        d=json.loads(p.stdout)
        self.assertEqual((d['case_count'],d['family_count']),(29,25))
        self.assertEqual(d['model_review_candidate_count'],1)
        self.assertEqual(d['model_intents_declared'],1)
        self.assertEqual(d['model_intents_open'],0)
        self.assertEqual(d['model_no_start_resolutions'],1)
        self.assertEqual(d['model_event_count'],2)
        self.assertEqual(d['initial_status'],'CREATED')
        self.assertEqual(d['declare_replay'],'REPLAY_IDENTICAL')
        self.assertEqual(d['resolution_replay'],'REPLAY_IDENTICAL')
        self.assertTrue(d['source_t1_unchanged'])
        self.assertTrue(d['source_overlay_unchanged'])
        self.assertTrue(d['source_denials_preserved'])
        self.assertEqual(d['a5_operational_reservations'],0)
        self.assertEqual(d['a5_attempts_started'],0)
        self.assertEqual(d['a6_accredited_evidence_count'],0)
        self.assertEqual(d['a6_classification'],'ND')
        self.assertEqual(d['p8_operational'],'NO-GO')

if __name__=='__main__':unittest.main()
