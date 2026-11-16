"""R58-V CI gating, safe source-only read and authentic catalog CLI checks."""
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
SOURCE=REPO/'src/ardrec/coordination/r58v_a5_a6_readonly_handoff.py'
DEMO=REPO/'scripts/ardrec_p14_r58v_a5_a6_handoff_demo.py'
TEST=REPO/'lab/tests/test_p14_r58v_handoff.py'
DOC=REPO/'docs/development/p14-r58v-readonly-a5-a6-handoff.md'
CI=REPO/'.github/workflows/ci.yml'
CATALOG=REPO/'lab/operational-catalog-v1/catalog.json'
CATALOG_SHA='5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
TEST_STEP='Probar R58-V entrega A5 A6 solo lectura / Test offline handoff with no starts'
DEMO_STEP='Demostrar R58-V estado T1 U sin A5 real / Check immutable A6 ND report'
TEST_CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58v_*.py' -v"
DEMO_CMD='PYTHONPATH=src python3 -B scripts/ardrec_p14_r58v_a5_a6_handoff_demo.py --synthetic-offline'


class R58VCIGates(unittest.TestCase):
    def test_01_files(self):self.assertTrue(all(x.is_file() for x in (SOURCE,DEMO,TEST,DOC,CI)))
    def test_02_ast_source(self):ast.parse(SOURCE.read_text(encoding='utf-8'))
    def test_03_ast_demo(self):ast.parse(DEMO.read_text(encoding='utf-8'))
    def test_04_test_step_once(self):self.assertEqual(CI.read_text().count(TEST_STEP),1)
    def test_05_demo_step_once(self):self.assertEqual(CI.read_text().count(DEMO_STEP),1)
    def test_06_test_command_once(self):self.assertEqual(CI.read_text().count(TEST_CMD),1)
    def test_07_demo_command_once(self):self.assertEqual(CI.read_text().count(DEMO_CMD),1)
    def test_08_step_order(self):
        text=CI.read_text()
        self.assertLess(text.index('Demostrar R58-U T8 T9 T10'),text.index(TEST_STEP))
        self.assertLess(text.index(TEST_STEP),text.index(DEMO_STEP))
        self.assertLess(text.index(DEMO_STEP),text.index('Verificar diseño del laboratorio'))
    def test_09_preserve_old_steps(self):
        text=CI.read_text()
        for label in ('Probar R58-U pausas reanudaciones',
                      'Demostrar R58-U T8 T9 T10',
                      'Probar R58-T simulador SQLite T1',
                      'Demostrar R58-T dos T1 sinteticos'):
            with self.subTest(label=label):self.assertEqual(text.count(label),1)
    def test_10_python_rust_retained(self):
        text=CI.read_text()
        self.assertIn('Python - empaquetado / packaging',text)
        self.assertIn('Rust - compilación / build',text)
    def test_11_no_privileged_ci(self):
        text=CI.read_text().split(TEST_STEP,1)[1].split('Verificar diseño del laboratorio',1)[0].lower()
        for val in ('sudo ','docker run','nmap ','ssh ','smbclient ','libvirt',
                    '--privileged','curl ','wget '):
            with self.subTest(name=val):self.assertNotIn(val,text)
    def test_12_no_execution_imports(self):
        tree=ast.parse(SOURCE.read_text())
        names=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):names.extend(x.name for x in node.names)
            if isinstance(node,ast.ImportFrom):names.append(node.module or '')
        for bad in ('subprocess','socket','ctypes','ardrec.benign_pipeline'):
            self.assertNotIn(bad,names)
    def test_13_no_operational_actions(self):
        text=SOURCE.read_text()
        for token in ('transition_service(','.submit(','.accept(','.execute_attempt(',
                      'Popen(','.run(','.dispatch(','.launch(','.publish(',
                      'persist_binding('):
            with self.subTest(token=token):self.assertNotIn(token,text)
    def test_14_sqlite_readonly(self):
        text=SOURCE.read_text()
        for marker in ('mode=ro','PRAGMA query_only=ON','_rows_read_only','inspect_overlay'):
            self.assertIn(marker,text)
    def test_15_source_verification(self):
        text=SOURCE.read_text()
        for marker in ('u._context','u.inspect_overlay','t.inspect_simulator',
                       "'SOURCE_SNAPSHOT_DRIFT'", "'SOURCE_GATE_NOT_DENY_ONLY'"):
            self.assertIn(marker,text)
    def test_16_denial_and_a6_nd(self):
        text=SOURCE.read_text()
        for marker in ("'all_source_requests_denied': True", "'a6_classification': 'ND'",
                       "'a5_attempts_started': 0", "'a6_accredited_evidence_count': 0",
                       "'p8_operational': 'NO-GO'", "'operational_dispatch': False"):
            self.assertIn(marker,text)
    def test_17_private_receipt(self):
        text=SOURCE.read_text()
        for marker in ('O_EXCL','O_NOFOLLOW','os.fsync','_read_private','_root'):
            self.assertIn(marker,text)
    def test_18_cli_requires_flag(self):self.assertIn('--synthetic-offline',DEMO.read_text())
    def test_19_pinned_catalog(self):
        if not CATALOG.is_file():self.skipTest('AUTHENTIC_CATALOG_NOT_AVAILABLE')
        self.assertEqual(hashlib.sha256(CATALOG.read_bytes()).hexdigest(),CATALOG_SHA)
    def test_20_missing_flag_denied(self):
        if not (REPO/'src/ardrec/initialization/initial_preview.py').is_file():
            self.skipTest('AUTHENTIC_GITHUB_CHECKOUT_REQUIRED')
        run=subprocess.run([sys.executable,'-B',str(DEMO)],cwd=REPO,
                           env={**os.environ,'PYTHONPATH':'src'},
                           capture_output=True,text=True,timeout=20)
        self.assertEqual(run.returncode,23)
        self.assertIn('R58V=BLOCKED',run.stderr)
    def test_21_offline_end_to_end_cli(self):
        if not CATALOG.is_file() or not (REPO/'src/ardrec/initialization/initial_preview.py').is_file():
            self.skipTest('AUTHENTIC_PINNED_CHECKOUT_REQUIRED')
        run=subprocess.run([sys.executable,'-B',str(DEMO),'--synthetic-offline'],
                           cwd=REPO,env={**os.environ,'PYTHONPATH':'src'},
                           capture_output=True,text=True,timeout=180)
        self.assertEqual(run.returncode,0,run.stderr[-2000:])
        d=json.loads(run.stdout)
        self.assertEqual((d['case_count'],d['family_count']),(29,25))
        self.assertEqual(d['source_t1_event_count'],2)
        self.assertEqual(d['source_overlay_event_count'],3)
        self.assertEqual(d['simulated_phase_counts'],
                         {'PREPARADO':27,'PENDIENTE':1,'PAUSADO':0,'DETENIDO':1})
        self.assertEqual(d['a5_model_review_candidates'],1)
        self.assertEqual(d['handoff_first'],'CREATED')
        self.assertEqual(d['handoff_replay'],'REPLAY_IDENTICAL')
        self.assertEqual(d['handoff_verification'],'PASS_READONLY_MODEL_HANDOFF_NO_A5_OR_A6')
        self.assertTrue(d['source_t1_unchanged'])
        self.assertTrue(d['source_overlay_unchanged'])
        self.assertEqual(d['a5_attempts_started'],0)
        self.assertEqual(d['a6_accredited_evidence_count'],0)
        self.assertEqual(d['a6_classification'],'ND')
        self.assertFalse(d['operational_dispatch'])
        self.assertEqual(d['p8_operational'],'NO-GO')

if __name__=='__main__':unittest.main()
