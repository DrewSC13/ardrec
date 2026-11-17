"""R69.1: oráculos nuevos del puente durable R69 a la TUI original R38."""
from __future__ import annotations

import copy
from dataclasses import replace
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.durable_dev import open_or_create_dev
from ardrec.coordination.durable_dashboard_bridge import (
    DurableViewError, VIEW_SCHEMA, build_durable_dashboard,
)
from ardrec.coordination.dashboard_tui import (
    DashboardError, DashboardState, detail_rows, handle_key, render_dashboard_frame,
    summary_rows, validate_dashboard_report,
)
from ardrec.persistence.codec import canonical, digest

FIXTURE = ROOT / 'lab/p14-r26-session-v1/scenario.json'
R28 = ROOT / 'scripts/demo_p14_r28_a1_a10_tui.py'


@unittest.skipIf(os.geteuid() == 0, 'El almacen R69 rechaza root; CI/Prometheus no-root')
class R691DashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ardrec-r691-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'store'
        self.fixture = read_fixed_scenario(FIXTURE)
        self.source = open_or_create_dev(self.path, self.fixture)
        self.view = build_durable_dashboard(self.source, self.fixture)

    def test_01_existing_r38_three_panels_are_reused(self):
        frame = '\n'.join(render_dashboard_frame(self.view, DashboardState(), 132, 30))
        for label in ('ALGORITMOS', 'DETALLE', 'ESTADO / AUDITORIA',
                      'GEN 0 RECUPERADA', 'A1 / DETALLE', 'P8:NO-GO'):
            self.assertIn(label, frame)
        self.assertNotIn('TUI DEV de solo lectura', frame)

    def test_02_real_a1_choices_are_visible_without_r28_substitution(self):
        rows = '\n'.join(detail_rows(self.view, 0))
        for label in ('SSH_DEV: VERDADERO', 'SMB_DEV: VERDADERO', 'FTP_DEV: ND',
                      'REGLA: ALLOW', 'REGLA: DENY', 'SALIDA: CASE_POLICY'):
            self.assertIn(label, rows)
        self.assertIn('CONTEXTO (7)', rows)
        self.assertNotIn('EXECUTED_IN_R26', rows)

    def test_03_a9_generation_zero_and_no_subsequent_publication(self):
        rows = '\n'.join(detail_rows(self.view, 8))
        self.assertIn('GENERACION 0 INICIALIZADA DURABLEMENTE', rows)
        self.assertIn('PUBLICACION ANALITICA POSTERIOR: NO', rows)
        self.assertIn(self.source['store_head_sha256'], rows)
        self.assertIsNone(self.view['a9']['published_generation'])

    def test_04_reopen_keeps_same_bytes_and_no_new_journal(self):
        root = self.path / 'generational-store' / 'journal'
        before = sorted(x.read_bytes() for x in root.glob('*.json'))
        doc = open_or_create_dev(self.path, self.fixture)
        view = build_durable_dashboard(doc, self.fixture)
        self.assertEqual(canonical(view), canonical(self.view))
        self.assertEqual(before, sorted(x.read_bytes() for x in root.glob('*.json')))

    def test_05_unchanged_r38_keyboard_and_help_navigation(self):
        for index, key in enumerate('1234567890'):
            self.assertEqual(handle_key(self.view, DashboardState(), key).selected, index)
        a = handle_key(self.view, DashboardState(), 'F1')
        self.assertIn('AYUDA', '\n'.join(render_dashboard_frame(self.view, a)))
        b = handle_key(self.view, DashboardState(), 'F2')
        self.assertTrue(b.compact)
        c = handle_key(self.view, DashboardState(), 'TAB')
        self.assertEqual(c.focus, 'DETAIL')

    def test_06_layout_is_responsive_and_no_false_authority(self):
        for w, h in ((132, 30), (90, 24), (58, 18), (40, 10)):
            for index in (0, 8, 9):
                frame = render_dashboard_frame(self.view, DashboardState(selected=index), w, h)
                self.assertEqual(len(frame), h)
                self.assertTrue(all(len(x) == w for x in frame))
                self.assertIn('P8:NO-GO', '\n'.join(frame))
                self.assertIn('RF:ND', '\n'.join(frame))
        self.assertFalse(self.view['operational_dispatch'])
        self.assertIsNone(self.view['final_risk'])

    def test_07_source_receipt_modified_rejected_even_with_unchanged_pin(self):
        modified = copy.deepcopy(self.source)
        modified['record_id'] = 'OTHER'
        with self.assertRaisesRegex(DurableViewError, 'r69_receipt_digest_mismatch'):
            build_durable_dashboard(modified, self.fixture)

    def test_08_r68_decision_modified_rehashed_doc_still_rejected(self):
        modified = copy.deepcopy(self.source)
        modified['a1_decisions']['SSH_DEV']['r68']['selected_rule'] = 'FORGED'
        modified['sha256'] = digest(canonical({k:v for k,v in modified.items() if k!='sha256'}))
        with self.assertRaisesRegex(DurableViewError, 'a1_receipt_binding_invalid'):
            build_durable_dashboard(modified, self.fixture)

    def test_09_no_physical_go_even_with_rehashed_document(self):
        modified = copy.deepcopy(self.source)
        modified['operational_dispatch'] = True
        modified['sha256'] = digest(canonical({k:v for k,v in modified.items() if k!='sha256'}))
        with self.assertRaisesRegex(DurableViewError, 'unsupported_operational_claim'):
            build_durable_dashboard(modified, self.fixture)

    def test_10_view_rejects_forged_a9_publication_and_report_tamper(self):
        mod = copy.deepcopy(self.view)
        mod['a9']['published_generation'] = 3
        mod['sha256'] = digest(canonical({k:v for k,v in mod.items() if k!='sha256'}))
        with self.assertRaises(DashboardError):
            validate_dashboard_report(mod)
        mod = copy.deepcopy(self.view)
        mod['r69_durable']['store_head_sha256'] = 'f' * 64
        with self.assertRaisesRegex(DashboardError, 'invalid_durable_view_binding'):
            validate_dashboard_report(mod)

    def test_11_only_generation_zero_a9_status_is_used(self):
        self.assertEqual(self.view['schema'], VIEW_SCHEMA)
        self.assertEqual([x['algorithm'] for x in self.view['a10']['stages']],
                         [f'A{i}' for i in range(1, 11)])
        for i in range(2, 8):
            self.assertIn(self.view['a10']['stages'][i]['source'], ('NOT_EXECUTED',))
        self.assertEqual(self.view['a10']['stages'][8]['status'], 'INITIAL_GEN0_ONLY')
        self.assertIn('A9: GEN 0 DURABLE', '\n'.join(summary_rows(self.view)))

    def test_12_render_is_pure_and_keeps_stored_receipts(self):
        initial = canonical(self.view)
        receipt = (self.path / 'a1-generation-0.json').read_bytes()
        for i in range(10):
            render_dashboard_frame(self.view, DashboardState(selected=i), 120, 32)
        self.assertEqual(canonical(self.view), initial)
        self.assertEqual((self.path / 'a1-generation-0.json').read_bytes(), receipt)

    def test_13_normal_entrypoints_keep_identical_document_json(self):
        env = dict(os.environ, PYTHONPATH=str(ROOT/'src'))
        args = ['--durable-dev-root',str(self.path),'--json']
        first = subprocess.run([sys.executable, '-B', '-m', 'ardrec', *args],
                               cwd=ROOT, env=env, capture_output=True, timeout=25)
        second = subprocess.run([sys.executable, '-B', str(R28), *args],
                                cwd=ROOT, env=env, capture_output=True, timeout=25)
        self.assertEqual((first.returncode, second.returncode),(0,0),(first.stderr,second.stderr))
        self.assertEqual(first.stdout, second.stdout)
        self.assertIn(self.source['sha256'].encode(), first.stdout)

    def test_14_real_curses_r38_launches_from_normal_entrypoint_and_q_exits(self):
        # PTY real: no se acepta un mock de run_dashboard_tui ni un frame de texto plano.
        master, slave = pty.openpty()
        self.addCleanup(lambda: os.close(master))
        env = dict(os.environ, PYTHONPATH=str(ROOT/'src'), TERM='xterm-256color')
        proc = subprocess.Popen(
            [sys.executable, '-B', '-m', 'ardrec', '--durable-dev-root', str(self.path), '--tui'],
            cwd=ROOT, env=env, stdin=slave, stdout=slave, stderr=slave,
            start_new_session=True,
        )
        os.close(slave)
        try:
            found = b''
            deadline = time.monotonic()+12
            while time.monotonic()<deadline and proc.poll() is None:
                r,_,_=select.select([master], [], [], 0.2)
                if r:
                    try: found += os.read(master, 65536)
                    except OSError: break
                if b'ALGORITMOS' in found and b'A9' in found:
                    break
            self.assertIn(b'ALGORITMOS',found,found[:250])
            self.assertIn(b'ESTADO', found)
            os.write(master,b'9q')
            self.assertEqual(proc.wait(timeout=8),0)
        finally:
            if proc.poll() is None:
                proc.kill(); proc.wait(timeout=5)


if __name__=='__main__':
    unittest.main()
