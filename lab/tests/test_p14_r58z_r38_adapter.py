"""R58-Z-R2: contratos del tablero oficial R38 consumiendo R58-Z documental."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import dashboard_tui as r38
from ardrec.coordination import r58y_observation_register as y
from ardrec.coordination import r58z_verified_workspace as z
from ardrec.coordination import r58z_r38_dashboard_adapter as a


class R58ZR38AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.db = self.base / 'registry.sqlite3'
        self.r422 = self.base / 'r422'
        self.r423 = self.base / 'r423'
        self.r422.mkdir()
        self.r423.mkdir()
        physical = {
            'source_kind': 'REAL_READONLY_SSH_SNAPSHOT',
            'r422_report_sha256': y.r424.R422_PIN,
            'r423_report_sha256': y.r424.R423_PIN,
            'route': 'DIRECT_ENS3_EXPECTED',
            'arp': 'ABSENT',
            'tx_snapshot': 0,
            'rx_snapshot': 15,
            'tap_frames_r422': 0,
            'bridge_frames_r422': 0,
            'guest_ping_reported_transmitted_r422': 1,
            'isolation_proven': False,
            'p8_operational': 'NO-GO',
        }
        mock = patch.object(y, 'verify_sources', return_value={
            'physical': physical,
            'captured_at_utc': {'r422': '2026-11-15T00:46:36Z',
                                'r423': '2026-11-15T01:05:07Z'},
        })
        mock.start()
        self.addCleanup(mock.stop)
        y.initialize_database(self.db)
        self.doc_empty = z.from_database(self.db)
        y.import_ssh(self.db, self.r422, self.r423)
        self.doc = z.from_database(self.db)

    def test_preserves_original_r38_contract(self):
        for service in range(3):
            self.assertIsNone(r38.validate_dashboard_report(
                a.project_report(self.doc, service)))

    def test_no_operational_authority_in_projection(self):
        for service in range(3):
            report = a.project_report(self.doc, service)
            self.assertIs(report['operational_dispatch'], False)
            self.assertIs(report['vm_checks_executed'], False)
            self.assertIsNone(report['final_risk'])
            self.assertIsNone(report['a9']['published_generation'])
            self.assertEqual(report['r27']['a6_classification'], 'ND')
            self.assertEqual(report['r27']['a5_start_count'], 0)
            self.assertEqual(report['sha256'], self.doc['sha256'])

    def test_three_panels_r38_large_terminal(self):
        frame = a.render_frame(self.doc, 0, width=140, height=35)
        body = '\n'.join(frame)
        self.assertIn('ALGORITMOS', body)
        self.assertIn('DETALLE', body)
        self.assertIn('ESTADO / AUDITORIA', body)
        self.assertIn('MONITOR R38', frame[0])
        self.assertEqual(len(frame), 35)
        self.assertTrue(all(len(line) == 140 for line in frame))

    def test_adaptive_terminal_medium_and_compact(self):
        for width, height in ((90, 27), (60, 22), (25, 10), (200, 52)):
            frame = a.render_frame(self.doc, 0, width=width, height=height)
            self.assertEqual(len(frame), height)
            self.assertTrue(all(len(line) == width for line in frame))

    def test_no_more_flat_custom_r58z_renderer(self):
        with patch.object(z, 'frame', side_effect=AssertionError('old renderer called')):
            self.assertIn('MONITOR R38', a.render_frame(self.doc, 0)[0])

    def test_source_is_verified_ssh_only(self):
        ssh = '\n'.join(a.stage_detail(self.doc, 0, 9))
        self.assertIn('OBS_SSH_', ssh)
        self.assertIn(y.r424.R422_PIN, ssh)
        self.assertIn(y.r424.R423_PIN, ssh)
        self.assertIn('NO PRUEBA AISLAMIENTO NI CONDICION A6', ssh)
        for i in (1, 2):
            no = '\n'.join(a.stage_detail(self.doc, i, 9))
            self.assertIn('NO EXISTEN OBSERVACIONES', no)
            self.assertNotIn('OBS_SSH_', no)

    def test_original_stage_keys_kept(self):
        state = r38.DashboardState(selected=9)
        group, state = a.handle_event(self.doc, 0, state, '1')
        self.assertEqual((group, state.selected), (0, 0))
        group, state = a.handle_event(self.doc, 0, state, '0')
        self.assertEqual((group, state.selected), (0, 9))

    def test_service_switch_uses_v_not_original_stage_keys(self):
        state = r38.DashboardState(selected=5)
        g, state = a.handle_event(self.doc, 0, state, 'v')
        self.assertEqual((g, state.selected), (1, 5))
        g, state = a.handle_event(self.doc, g, state, 'v')
        self.assertEqual(g, 2)
        g, state = a.handle_event(self.doc, g, state, 'v')
        self.assertEqual(g, 0)
        g, state = a.handle_event(self.doc, g, state, 'V')
        self.assertEqual(g, 2)

    def test_search_v_does_not_switch_service(self):
        state = replace(r38.DashboardState(), search_active=True)
        g, state = a.handle_event(self.doc, 0, state, 'v')
        self.assertEqual(g, 0)
        self.assertEqual(state.query, 'v')

    def test_selected_highlight_not_over_detail(self):
        state = r38.DashboardState(selected=5)
        frame = a.render_frame(self.doc, 0, state, 140, 35)
        line = next(line for line in frame if line.startswith('| > '))
        span = r38._selected_nav_span(line, state, 140)
        self.assertEqual(span, (1, 32))
        self.assertEqual(line[32], '|')

    def test_only_documentary_A10_and_no_Rf(self):
        for service in range(3):
            body = '\n'.join(a.render_frame(self.doc, service, width=140, height=40))
            self.assertIn('A6:ND', body)
            self.assertIn('RF:NO', body)
            self.assertIn('A9:NO', body)
            self.assertIn('NO-GO', body)
        self.assertEqual(a.project_report(self.doc, 0)['a10']['stages'][9]['status'],
                         'OBSERVACION_VERIFICADA')
        self.assertEqual(a.project_report(self.doc, 1)['a10']['stages'][9]['status'],
                         'SIN_OBSERVACION')

    def test_r38_renderer_called(self):
        original = r38.render_dashboard_frame
        with patch.object(r38, 'render_dashboard_frame', wraps=original) as mocked:
            a.render_frame(self.doc, 0, width=120, height=32)
            self.assertEqual(mocked.call_count, 1)

    def test_deterministic_and_no_mutation(self):
        saved = deepcopy(self.doc)
        x = a.render_frame(self.doc, 0, width=120, height=32)
        self.assertEqual(x, a.render_frame(self.doc, 0, width=120, height=32))
        self.assertEqual(self.doc, saved)

    def test_reject_tampered_document_before_display(self):
        bad = deepcopy(self.doc)
        bad['a7_confirmed_rf'] = '1/2'
        with self.assertRaises(z.WorkspaceError):
            a.render_frame(bad, 0)

    def test_tui_rejects_noninteractive(self):
        with patch.object(a.sys.stdin, 'isatty', return_value=False):
            with self.assertRaisesRegex(a.AdapterError, 'interactive_terminal'):
                a.run_tui(self.doc)

    def test_help_uses_r38_and_documents_service_key(self):
        state = r38.DashboardState(help_open=True)
        frame = a.render_frame(self.doc, 0, state)
        self.assertIn('AYUDA', '\n'.join(frame))
        self.assertIn('v/V', frame[-1])

    def test_three_service_audit_counts(self):
        for i, name in enumerate(z.SERVICES):
            rows = a.physical_audit(self.doc, i)
            self.assertIn('SERVICIO: ' + name, rows)
            self.assertIn('SSH/FTPS/SMB: 1/0/0', rows)


if __name__ == '__main__':
    unittest.main()
