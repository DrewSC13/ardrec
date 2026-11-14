"""P14-R38: pruebas de interfaz puras; sin terminal, red ni máquina virtual."""
from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.coordination.dashboard_tui import (
    DashboardError, DashboardState, detail_rows, handle_key,
    render_dashboard_frame, run_dashboard_tui, summary_rows,
    validate_dashboard_report, visible_indices, _key_name, _selected_nav_span,
)


def sample(*, imported: bool = False) -> dict:
    statuses = [
        'EXECUTED_IN_R26', 'EXECUTED_IN_R26', 'DIAGNOSED_NO_AUTHORITY',
        'SELECTION_WITHOUT_DISPATCH', 'NOT_EXECUTED',
        'ND_DOCUMENTARY_ACCEPTED' if imported else 'ND',
        'RF_NOT_ACREDITED', 'PAUSE_RECOMMENDED_NOT_APPLIED',
        'RECEIPT_VERIFIED_NO_GENERATION', 'READ_ONLY_REPORT',
    ]
    report = {
        'session_id': 'DEV_TUTOR_001',
        'sha256': 'a' * 64, 'session_sha256': 'b' * 64,
        'source_kind': 'SYNTHETIC_FIXTURE_ONLY',
        'p8_operational': 'NO-GO', 'operational_dispatch': False,
        'vm_checks_executed': False, 'final_risk': None,
        'r26_units': [
            {'protocol': p, 'service_id': f'{p}_DEV', 'a1': 'VERDADERO',
             'a2': 'PREPARADO', 'a3': 'VERDADERO', 'initial_risk': '1/4'}
            for p in ('FTP', 'SMB', 'SSH')
        ],
        'r27': {
            'selected_actual': None,
            'selected_hypothetical': {'service_id': 'SSH_DEV', 'case_id': 'CASE_REFERENCE'},
            'a5_state': None, 'a5_start_count': None,
            'a6_classification': 'ND',
        },
        'a7': {'hypothetical_rf': '5/12', 'confirmed_rf': None},
        'a8': {'recommendation': 'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA',
               'applied_transition': None},
        'a9': {'receipt_sha256': 'c' * 64, 'durable_local_receipt': False,
               'published_generation': None},
        'a10': {'stages': [
            {'algorithm': f'A{i+1}', 'status': status,
             'source': 'SYNTHETIC_FIXTURE', 'detail': 'Vista de desarrollo sin autoridad'}
            for i, status in enumerate(statuses)
        ]},
    }
    if imported:
        report['a6_import'] = {
            'admission': 'ACCEPTED_FOR_DOCUMENTARY_REVIEW',
            'classification': 'ND',
            'record_id': 'DEV-SSH-0001', 'service_id': 'SSH_DEV',
            'source_kind': 'SYNTHETIC_FIXTURE',
            'captured_at_utc': '2026-11-14T19:59:00Z',
            'review_as_of_utc': '2026-11-14T20:00:00Z',
            'observed_claim_unverified': 'INCONCLUSIVE',
            'support_sha256_verified': 'd' * 64,
        }
    return report


class DashboardModelTests(unittest.TestCase):
    def test_selection_highlight_stops_at_nav_border(self):
        report = sample(imported=True)
        state = DashboardState(selected=5)
        for width in (88, 132, 200):
            frame = render_dashboard_frame(report, state, width=width, height=25)
            row = next(line for line in frame if line.startswith('| > '))
            self.assertEqual(_selected_nav_span(row, state, width), (1, 32))
            self.assertEqual(row[32], '|')  # borde del panel izquierdo
            self.assertIn('A6 / DETALLE', '\n'.join(frame))

    def test_highlight_is_absent_outside_navigation(self):
        report = sample()
        normal = DashboardState(selected=0)
        frame = render_dashboard_frame(report, normal, width=120, height=22)
        other = next(line for line in frame if line.startswith('|   A2'))
        self.assertIsNone(_selected_nav_span(other, normal, 120))
        selected = next(line for line in frame if line.startswith('| > '))
        self.assertIsNone(_selected_nav_span(selected, DashboardState(compact=True), 120))
        self.assertIsNone(_selected_nav_span(selected, DashboardState(help_open=True), 120))
        self.assertIsNone(_selected_nav_span(selected, normal, 60))

    def test_ten_stages_and_read_only_contract(self):
        self.assertIsNone(validate_dashboard_report(sample()))
        self.assertEqual(tuple(range(10)), visible_indices(sample(), DashboardState()))

    def test_all_ten_direct_keys(self):
        report = sample()
        for i, key in enumerate('1234567890'):
            self.assertEqual(handle_key(report, DashboardState(), key).selected, i)

    def test_arrow_cycle_and_wrap(self):
        report = sample()
        self.assertEqual(handle_key(report, DashboardState(selected=9), 'RIGHT').selected, 0)
        self.assertEqual(handle_key(report, DashboardState(), 'LEFT').selected, 9)
        self.assertEqual(handle_key(report, DashboardState(), 'DOWN').selected, 1)
        self.assertEqual(handle_key(report, DashboardState(), 'UP').selected, 9)

    def test_filter_pending_and_clear(self):
        report = sample()
        filtered = handle_key(report, DashboardState(selected=0), 'F4')
        self.assertEqual(filtered.filter_mode, 'PENDING')
        self.assertEqual(filtered.selected, 2)
        self.assertEqual(visible_indices(report, filtered), (2, 4, 5, 6, 7, 8))
        self.assertEqual(handle_key(report, filtered, 'F4').filter_mode, 'ALL')

    def test_search_finds_a6_and_preserves_no_go(self):
        report = sample(imported=True)
        s = handle_key(report, DashboardState(), '/')
        for key in 'DOCUMENTARY':
            s = handle_key(report, s, key)
        s = handle_key(report, s, 'ENTER')
        self.assertEqual(visible_indices(report, s), (5,))
        self.assertEqual(s.selected, 5)
        frame = '\n'.join(render_dashboard_frame(report, s))
        self.assertIn('P8:NO-GO', frame)
        self.assertIn('RF:ND', frame)

    def test_search_esc_cancels(self):
        report = sample()
        s = handle_key(report, DashboardState(), 'F3')
        s = handle_key(report, s, 'x')
        s = handle_key(report, s, 'ESC')
        self.assertFalse(s.search_active)
        self.assertEqual(s.query, '')

    def test_focus_changes_navigation_semantics(self):
        report = sample()
        s = handle_key(report, DashboardState(), 'TAB')
        self.assertEqual(s.focus, 'DETAIL')
        s = handle_key(report, s, 'DOWN')
        self.assertEqual(s.selected, 0)
        self.assertEqual(s.scroll, 1)

    def test_compact_and_help(self):
        report = sample()
        s = handle_key(report, DashboardState(), 'F2')
        self.assertTrue(s.compact)
        s = handle_key(report, s, 'F1')
        self.assertIn('AYUDA', '\n'.join(render_dashboard_frame(report, s)))
        self.assertFalse(handle_key(report, s, 'ESC').help_open)

    def test_does_not_mutate_report(self):
        report = sample(imported=True)
        before = copy.deepcopy(report)
        s = DashboardState(selected=5)
        for key in ['F4', 'F3', 'd', 'F2', 'TAB', 'RIGHT', 'r', '?']:
            s = handle_key(report, s, key)
            render_dashboard_frame(report, s)
        self.assertEqual(report, before)

    def test_a6_import_detail_semantics(self):
        report = sample(imported=True)
        details = '\n'.join(detail_rows(report, 5))
        self.assertIn('ACCEPTED_FOR_DOCUMENTARY_REVIEW', details)
        self.assertIn('DEV-SSH-0001', details)
        self.assertIn('VERDAD TECNICA: NO ACREDITADA', details)
        self.assertIn('RIESGO FINAL: ND', details)

    def test_without_a6_import_does_not_invent_one(self):
        self.assertIn('IMPORTACION DEFENSIVA: NO', '\n'.join(detail_rows(sample(), 5)))
        self.assertIn('IMPORT A6: NO', '\n'.join(summary_rows(sample())))

    def test_render_wide_medium_small(self):
        report = sample(imported=True)
        for width, height in ((132, 35), (90, 24), (58, 18), (40, 10)):
            with self.subTest(width=width):
                output = render_dashboard_frame(report, DashboardState(selected=5), width, height)
                self.assertEqual(len(output), height)
                self.assertTrue(all(len(s) == width for s in output))
                self.assertIn('P8:NO-GO', '\n'.join(output))

    def test_safety_banner_visible_all_stages(self):
        report = sample(imported=True)
        for i in range(10):
            frame = '\n'.join(render_dashboard_frame(report, DashboardState(selected=i), 120, 30))
            self.assertIn('P8:NO-GO', frame)
            self.assertIn('DESPACHO:NO', frame)
            self.assertIn('RF:ND', frame)

    def test_reject_false_authority_rehashed_or_not(self):
        for field, value in (('p8_operational', 'GO'),
                             ('operational_dispatch', True),
                             ('vm_checks_executed', True),
                             ('final_risk', '5/12')):
            with self.subTest(field=field):
                report = sample()
                report[field] = value
                with self.assertRaises(DashboardError):
                    render_dashboard_frame(report, DashboardState())

    def test_reject_publication_claim(self):
        report = sample()
        report['a9']['published_generation'] = 5
        with self.assertRaises(DashboardError):
            validate_dashboard_report(report)

    def test_reject_partial_stage_list(self):
        report = sample()
        report['a10']['stages'].pop()
        with self.assertRaises(DashboardError):
            render_dashboard_frame(report, DashboardState())

    def test_reject_import_claim_without_nd(self):
        report = sample(imported=True)
        report['a6_import']['classification'] = 'VERDADERO'
        with self.assertRaises(DashboardError):
            validate_dashboard_report(report)

    def test_curses_real_function_keys(self):
        import curses
        for n in range(1, 6):
            self.assertEqual(_key_name(getattr(curses, f'KEY_F{n}'), curses), f'F{n}')

    def test_non_tty_rejected_without_curses(self):
        report = sample()
        with patch('ardrec.coordination.dashboard_tui.sys.stdin') as fake_in, \
             patch('ardrec.coordination.dashboard_tui.sys.stdout') as fake_out:
            fake_in.isatty.return_value = False
            fake_out.isatty.return_value = False
            with self.assertRaises(RuntimeError):
                run_dashboard_tui(report)


if __name__ == '__main__':
    unittest.main()
