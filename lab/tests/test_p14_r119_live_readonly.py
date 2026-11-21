"""R119: fixtures *syntéticos* para la ruta de lectura operativa, nunca VM física."""
from __future__ import annotations

import copy
from datetime import datetime, timezone, timedelta
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r119_live_inspection as r119
from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f5_lifecycle_readiness as f5
from ardrec.coordination import dashboard_tui as tui

REPO = Path(__file__).resolve().parents[2]
CATALOG = (REPO / 'lab/operational-catalog-v1/catalog.json').read_bytes()
CLOSURE = (REPO / 'lab/operational-controller/r117-f5b-physical-closure-v3.json').read_bytes()
NOW = datetime(2026, 11, 21, 18, 0, 0, tzinfo=timezone.utc)


def synthetic_capture():
    """No se conecta a ninguna VM; marca las lecturas como fallidas explícitas."""
    iso = '2026-11-21T18:00:00Z'
    probe = {'rc': 1, 'timeout': False, 'truncated': False,
             'start': iso, 'end': iso, 'stdout': '', 'stderr': ''}
    return {'schema': f5.SCHEMA, 'start': iso, 'end': iso,
            'probes': {name: dict(probe) for name in f5.READS},
            'source': 'LOCAL_ROOT_READONLY_NOT_AUTHORITY',
            'traffic_authorized': False}


def view(capture=None, *, mode='F5_LIVE_CAPTURE', now=NOW):
    return r119.build(capture or synthetic_capture(), closure_raw=CLOSURE,
                      catalog_raw=CATALOG, mode=mode, now=now)


class LiveViewTest(unittest.TestCase):
    def test_01_fixture_report_has_all_ten_phases(self):
        result = view()
        self.assertTrue(r119.verify_view(result))
        tui.validate_dashboard_report(result)
        self.assertEqual([s['algorithm'] for s in result['a10']['stages']],
                         [f'A{i}' for i in range(1, 11)])
        self.assertEqual(result['r119_live']['host']['lifecycle_stage'],
                         'INCOMPLETE_OR_TRANSITION_NO_GO')
        self.assertEqual(result['r119_live']['host']['states']['ssh'], 'ND')

    def test_02_no_operational_authority(self):
        x = view()
        self.assertFalse(x['operational_dispatch'])
        self.assertIsNone(x['final_risk'])
        self.assertIsNone(x['a9']['published_generation'])
        self.assertFalse(x['r119_live']['current_operational_authority_attested'])
        self.assertEqual(x['r119_live']['connections_by_r119'], 0)
        self.assertEqual(x['r119_live']['guest_starts_by_r119'], 0)
        self.assertEqual(x['r119_live']['firewall_changes_by_r119'], 0)

    def test_03_replay_is_not_recent(self):
        result = view(mode='F5_PRIVATE_RECEIPT_REPLAY')
        self.assertFalse(result['r119_live']['captured_fresh_for_display'])
        self.assertIn('CAPTURE_REPLAY_OR_NOT_FRESH', result['r119_live']['blockers'])
        self.assertEqual(result['a10']['stages'][9]['status'], 'READONLY_REPLAY')

    def test_04_old_live_capture_marked_stale(self):
        result = view(now=NOW + timedelta(minutes=3))
        self.assertFalse(result['r119_live']['captured_fresh_for_display'])

    def test_05_future_capture_marked_stale(self):
        result = view(now=NOW-timedelta(minutes=2))
        self.assertFalse(result['r119_live']['captured_fresh_for_display'])

    def test_06_invalid_clock_rejected(self):
        with self.assertRaisesRegex(r119.Stop, 'CLOCK_UNTRUSTED'):
            view(now=NOW.replace(tzinfo=None))

    def test_07_catalog_pinned(self):
        with self.assertRaisesRegex(r119.Stop, 'PINNED_P7_CATALOG'):
            r119.build(synthetic_capture(), closure_raw=CLOSURE,
                       catalog_raw=CATALOG+b' ', now=NOW, mode='F5_LIVE_CAPTURE')

    def test_08_closure_pinned(self):
        with self.assertRaisesRegex(r119.Stop, 'HISTORICAL_F5B_CLOSURE'):
            r119.build(synthetic_capture(), closure_raw=CLOSURE+b' ',
                       catalog_raw=CATALOG, now=NOW, mode='F5_LIVE_CAPTURE')

    def test_09_source_only_not_current_release(self):
        self.assertFalse(view()['r119_live']['source']['runtime_installation_attested_now'])

    def test_10_tamper_f5_capture_denied(self):
        bad = synthetic_capture()
        bad['traffic_authorized'] = True
        with self.assertRaisesRegex(r119.Stop, 'F5_CAPTURE_REJECTED'):
            view(bad)

    def test_11_missing_source_probe_denied(self):
        bad = synthetic_capture()
        bad['probes'].pop(next(iter(bad['probes'])))
        with self.assertRaisesRegex(r119.Stop, 'F5_CAPTURE_REJECTED'):
            view(bad)

    def test_12_garbled_f5_base64_denied(self):
        bad = synthetic_capture()
        bad['probes']['nft']['stdout'] = '%%%'
        with self.assertRaisesRegex(r119.Stop, 'F5_CAPTURE_REJECTED'):
            view(bad)

    def test_13_tamper_sha_denied(self):
        doc = view()
        doc['r119_live']['blockers'] = []
        with self.assertRaises(r119.Stop):
            r119.verify_view(doc)
        with self.assertRaises(tui.DashboardError):
            tui.validate_dashboard_report(doc)

    def test_14_forged_a6_status_denied_even_with_rehash(self):
        doc = view()
        doc['a10']['stages'][5]['status'] = 'ADMITTED'
        doc['sha256'] = f1.digest(f1.canonical({k:v for k,v in doc.items() if k!='sha256'}))
        with self.assertRaisesRegex(r119.Stop, 'VIEW_STAGE_INVALID'):
            r119.verify_view(doc)

    def test_15_forged_generation_denied(self):
        doc = view()
        doc['a9']['published_generation'] = 1
        doc['sha256'] = f1.digest(f1.canonical({k:v for k,v in doc.items() if k!='sha256'}))
        with self.assertRaises(r119.Stop):
            r119.verify_view(doc)

    def test_16_view_navigation_is_pure(self):
        report = view()
        first = tui.DashboardState()
        second = tui.handle_key(report, first, 'DOWN')
        self.assertEqual(second.selected, 1)
        self.assertEqual(tui.handle_key(report, second, 'r'), second)
        self.assertIn('HOST REAL / SOLO LECTURA',
                      tui.render_dashboard_frame(report, second, 125, 30)[0])

    def test_17_vm_stages_relate_to_actual_capture_fields(self):
        report = view()
        details = '\n'.join(tui.detail_rows(report, 2))
        self.assertIn('F11 HOOK:', details)
        self.assertIn('RUNNER:', details)
        self.assertIn('SMB:', details)
        summary = '\n'.join(tui.summary_rows(report))
        self.assertIn('VM SSH:', summary)

    def test_18_f13_candidate_reference_is_not_a6_admission(self):
        fake = {
            'source_case_key': 'a'*64, 'case_id': 'FTP-T01-S01-01',
            'family_id': 'FTP-T01', 'source_status': 'RESULT_CANDIDATE_ONLY',
            'candidate_outcome': 'REPLY_COMPLETE', 'candidate_complete_220': True,
            'source_reservation_sha256': 'b'*64, 'source_f10_sha256': 'c'*64,
            'a6':'ND', 'p8':'NO-GO', 'physical_origin_attested':False,
            'accepted_support_count':0, 'a9_published_generation':None}
        with patch.object(r119.f14, 'build', return_value=fake):
            result = view()
            linked = r119.build(synthetic_capture(), closure_raw=CLOSURE,
                                catalog_raw=CATALOG, now=NOW,
                                mode='F5_LIVE_CAPTURE',
                                a5_case_folder=Path('/tmp/synthetic-private'))
        self.assertIsNone(result['r119_live']['a5'])
        self.assertEqual(linked['a10']['stages'][4]['status'], 'RESULT_CANDIDATE_ONLY')
        self.assertEqual(linked['a10']['stages'][5]['status'], 'ND')
        self.assertIsNone(linked['a9']['published_generation'])

    def test_19_f13_promoted_response_rejected(self):
        with patch.object(r119.f14, 'build', return_value={
                'a6':'VERDADERO', 'p8':'NO-GO', 'physical_origin_attested':True}):
            with self.assertRaisesRegex(r119.Stop, 'F13_F14_A5_CANDIDATE_REJECTED'):
                r119.build(synthetic_capture(), closure_raw=CLOSURE,
                           catalog_raw=CATALOG, now=NOW, mode='F5_LIVE_CAPTURE',
                           a5_case_folder=Path('/tmp/synthetic-private'))

    def test_20_noncanonical_json_rejected(self):
        with self.assertRaisesRegex(r119.Stop, 'CAPTURE_INVALID_JSON'):
            r119._decode_large(b'{"x":1,"x":2}')

    def test_21_mode_required(self):
        with self.assertRaisesRegex(r119.Stop, 'MODE_INVALID'):
            view(mode='OPERATIONAL_GO')

    def test_22_original_entrypoint_untouched_on_standard_args(self):
        from ardrec import __main__
        with patch('ardrec.coordination.r119_live_inspection.main', return_value=17) as task:
            self.assertEqual(__main__.main(['live', '--texto']), 17)
            task.assert_called_once_with(['--texto'])

    def test_23_private_replay_integrity(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / 'f5'
            root.mkdir(mode=0o700)
            with patch.object(f5, 'ROOT', root):
                original = synthetic_capture()
                report = f5.report(original)
                folder = f5.save_private(original, report, root=root)
                loaded, same = r119.replay_capture(folder)
                self.assertEqual(loaded, original)
                self.assertEqual(same, report)
                (folder/'report.json').write_bytes(b'{}\n')
                with self.assertRaisesRegex(r119.Stop, 'RECEIPT_MANIFEST_NOT_AUTHENTICATED'):
                    r119.replay_capture(folder)

    def test_24_private_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / 'f5'
            root.mkdir(mode=0o700)
            with patch.object(f5, 'ROOT', root):
                original = synthetic_capture()
                folder = f5.save_private(original, f5.report(original), root=root)
                (folder/'manifest.json').unlink()
                (folder/'manifest.json').symlink_to('/etc/passwd')
                with self.assertRaisesRegex(r119.Stop, 'RECEIPT_FILE_UNTRUSTED'):
                    r119.replay_capture(folder)

    def test_25_private_unexpected_file_rejected(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / 'f5'
            root.mkdir(mode=0o700)
            with patch.object(f5, 'ROOT', root):
                original = synthetic_capture()
                folder = f5.save_private(original, f5.report(original), root=root)
                (folder/'extra.txt').write_text('extra')
                with self.assertRaisesRegex(r119.Stop, 'RECEIPT_ENTRY_SET'):
                    r119.replay_capture(folder)

    def test_26_replay_command_never_invokes_host(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / 'f5'
            root.mkdir(mode=0o700)
            with patch.object(f5, 'ROOT', root):
                original = synthetic_capture()
                folder = f5.save_private(original, f5.report(original), root=root)
                with patch.object(f5, 'capture', side_effect=AssertionError('HOST_CALL')):
                    with patch('builtins.print'):
                        self.assertEqual(r119.main(['--reproducir',str(folder),'--texto','--repo',str(REPO)]),0)

    def test_27_cli_source_invalid_stop(self):
        with patch('builtins.print'):
            self.assertEqual(r119.main(['--reproducir','/tmp/outside','--texto','--repo',str(REPO)]),2)

    def test_28_explicitly_no_root(self):
        with patch.object(os, 'geteuid', return_value=0):
            with patch('builtins.print'):
                self.assertEqual(r119.main(['--capturar','--texto','--repo',str(REPO)]),2)


if __name__ == '__main__':
    unittest.main()
