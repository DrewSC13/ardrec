"""R36.2: read-only real evidence attribution + htop-like curses presenter."""
from __future__ import annotations

from pathlib import Path
import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.coordination import r36_readonly_dashboard as d


def fake_report():
    return {
        'session_id': 'DEV_TUTOR_001', 'sha256': 'e' * 64,
        'source_kind': 'SYNTHETIC_FIXTURE_ONLY', 'vm_checks_executed': False,
        'operational_dispatch': False, 'final_risk': None,
        'p8_operational': 'NO-GO',
        'r26_units': [
            {'protocol': 'FTP', 'service_id': 'FTP_DEV', 'a1': 'ND',
             'a2': 'PREPARADO', 'a3': 'ND', 'initial_risk': '1/4'},
            {'protocol': 'SMB', 'service_id': 'SMB_DEV', 'a1': 'VERDADERO',
             'a2': 'PREPARADO', 'a3': 'VERDADERO', 'initial_risk': '1/4'},
            {'protocol': 'SSH', 'service_id': 'SSH_DEV', 'a1': 'VERDADERO',
             'a2': 'PREPARADO', 'a3': 'VERDADERO', 'initial_risk': '1/4'},
        ],
        'r27': {'selected_actual': None, 'selected_hypothetical': {'id': 'X'},
                'a5_state': None, 'a6_classification': 'ND'},
        'a7': {'hypothetical_rf': '5/12'},
        'a8': {'recommendation': 'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA'},
        'a9': {'receipt_sha256': 'a' * 64},
        'a10': {'stages': [{'algorithm': a, 'source': 'SYNTHETIC_FIXTURE',
                           'status': 'NOT_EXECUTED' if a in ('A5', 'A6') else 'DEV_PREVIEW',
                           'detail': f'Desarrollo {a}'} for a in d.STAGES]},
    }


def fake_snapshot():
    return {
        'schema': d.R36_SCHEMA, 'main': d.R35_MAIN,
        'networks_inactive': [f'ardrec-r33-dev-net-{r}' for r in d.NETWORK_ROLES],
        'domains_shut_off': [f'ardrec-r33-dev-{r}' for r in d.ROLES],
        'nft_verified': True, 'nwfilter_verified': True,
        'reserved_interfaces_absent': True,
        'physical_activation': False, 'p8_operational': 'NO-GO',
    }


def view():
    return d.make_view(snapshot=fake_snapshot(), report=fake_report(),
                       r35_sha='a'*64, r36_sha='b'*64, r361_sha='c'*64)


def sealed(directory, members):
    directory.chmod(0o700)
    for name, content in members.items():
        p=directory/name
        p.write_bytes(content)
        p.chmod(0o600)
    (directory/'SHA256SUMS').write_text('\n'.join(
        hashlib.sha256(content).hexdigest()+'  '+name
        for name, content in sorted(members.items()))+'\n')
    (directory/'SHA256SUMS').chmod(0o600)


class ProvenanceTests(unittest.TestCase):
    def test_exact_directory_authentication(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'source';p.mkdir()
            sealed(p, {'a.json': b'{}', 'b.txt': b'x'})
            found=d.verified_directory(p, frozenset({'a.json','b.txt'}))
            self.assertEqual(found['a.json'],b'{}')
    def test_changed_member_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'source';p.mkdir();sealed(p, {'a.json':b'{}'})
            (p/'a.json').write_text('changed')
            with self.assertRaisesRegex(d.DashboardError,'digest_mismatch'):
                d.verified_directory(p,frozenset({'a.json'}))
    def test_missing_member_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'source';p.mkdir();sealed(p, {'a.json':b'{}'})
            with self.assertRaisesRegex(d.DashboardError,'inventory_mismatch'):
                d.verified_directory(p,frozenset({'a.json','b.txt'}))
    def test_extra_member_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'source';p.mkdir();sealed(p, {'a.json':b'{}'})
            (p/'unknown.txt').write_bytes(b'x')
            with self.assertRaises(d.DashboardError):
                d.verified_directory(p,frozenset({'a.json'}))
    def test_directory_world_access_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'source';p.mkdir();sealed(p, {'a.json':b'{}'})
            p.chmod(0o755)
            with self.assertRaisesRegex(d.DashboardError,'not_private'):
                d.verified_directory(p,frozenset({'a.json'}))
    def test_symlink_directory_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'source';p.mkdir();sealed(p, {'a.json':b'{}'})
            link=Path(td)/'link';link.symlink_to(p,target_is_directory=True)
            with self.assertRaises(d.DashboardError):
                d.verified_directory(link,frozenset({'a.json'}))
    def test_symlink_member_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'source';p.mkdir();sealed(p, {'a.json':b'{}'})
            orig=p/'a.json';orig.unlink();orig.symlink_to('/etc/passwd')
            with self.assertRaises(d.DashboardError):
                d.verified_directory(p,frozenset({'a.json'}))
    def test_duplicate_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'source';p.mkdir();sealed(p, {'a.json':b'{}'})
            line=(p/'SHA256SUMS').read_text()
            (p/'SHA256SUMS').write_text(line+line)
            with self.assertRaises(d.DashboardError):
                d.verified_directory(p,frozenset({'a.json'}))
    def test_invalid_json_duplicate_key_rejected(self):
        with self.assertRaises(d.DashboardError):
            d._read_json(b'{"a":1,"a":2}')
    def test_nonfinite_json_rejected(self):
        with self.assertRaises(d.DashboardError):
            d._read_json(b'{"a":NaN}')
    def test_r36_inventory_is_complete(self):
        self.assertEqual(len(d.EXPECTED_R36_FILES),26)
        self.assertTrue({'r36_snapshot.json','nft_guard.json','nwfilter.xml'} <= d.EXPECTED_R36_FILES)


class ViewTests(unittest.TestCase):
    def test_real_host_and_synthetic_algorithm_sources_distinct(self):
        x=view()
        self.assertEqual(x['host_evidence']['kind'],'REAL_READONLY_SNAPSHOT')
        self.assertEqual(x['algorithm_evidence']['kind'],'SYNTHETIC_PREVIEW_ONLY')
        self.assertEqual(x['laboratory_pentesting'],'NOT_EXECUTED')
        self.assertIsNone(x['final_risk'])
        self.assertEqual(x['p8_operational'],'NO-GO')
    def test_all_ten_algorithms_visible(self):
        x=view()
        text=d.text_report(x)
        for i in range(1,11):
            self.assertIn(f'A{i}  ',text)
        self.assertIn('R36.0 SNAPSHOT',text)
        self.assertIn('Rf real: ND',text)
    def test_every_stage_has_input_output_and_guard(self):
        x=view()
        for i in range(10):
            lines=d.stage_detail(x,i)
            blob='\n'.join(lines)
            self.assertIn('QUE HACE:',blob)
            self.assertIn('SALIDA DE LA SESION:',blob)
            self.assertIn('BLOQUEO:',blob)
            self.assertIn('NO ES PENTESTING',blob)
    def test_stage_selection_rejects_out_of_range(self):
        x=view()
        for i in (-1,10,22):
            with self.assertRaises(d.DashboardError):
                d.stage_detail(x,i)
    def test_source_label_cannot_claim_real_algorithm(self):
        source=fake_report();source['source_kind']='REAL_PENTEST'
        with self.assertRaises(d.DashboardError):
            d.make_view(snapshot=fake_snapshot(),report=source,
                        r35_sha='a'*64,r36_sha='b'*64,r361_sha='c'*64)
    def test_host_activation_cannot_be_misreported(self):
        source=fake_snapshot();source['physical_activation']=True
        with self.assertRaises(d.DashboardError):
            d.make_view(snapshot=source,report=fake_report(),
                        r35_sha='a'*64,r36_sha='b'*64,r361_sha='c'*64)
    def test_network_inventory_drift_rejected(self):
        source=fake_snapshot();source['networks_inactive'].pop()
        with self.assertRaises(d.DashboardError):
            d.make_view(snapshot=source,report=fake_report(),
                        r35_sha='a'*64,r36_sha='b'*64,r361_sha='c'*64)
    def test_vm_inventory_drift_rejected(self):
        source=fake_snapshot();source['domains_shut_off'].pop()
        with self.assertRaises(d.DashboardError):
            d.make_view(snapshot=source,report=fake_report(),
                        r35_sha='a'*64,r36_sha='b'*64,r361_sha='c'*64)
    def test_operational_dispatch_claim_rejected(self):
        source=fake_report();source['operational_dispatch']=True
        with self.assertRaises(d.DashboardError):
            d.make_view(snapshot=fake_snapshot(),report=source,
                        r35_sha='a'*64,r36_sha='b'*64,r361_sha='c'*64)
    def test_exact_source_sha_required(self):
        with self.assertRaises(d.DashboardError):
            d.make_view(snapshot=fake_snapshot(),report=fake_report(),
                        r35_sha='wrong',r36_sha='b'*64,r361_sha='c'*64)
    def test_tui_renders_without_subprocess(self):
        class Terminal:
            def keypad(self,*a):pass
            def timeout(self,*a):pass
            def getmaxyx(self):return 39,120
            def erase(self):pass
            def addnstr(self,*a):pass
            def refresh(self):pass
            def getch(self):return ord('q')
        fake_curses = types.ModuleType('curses')
        fake_curses.error = type('CursesError',(Exception,),{})
        fake_curses.A_BOLD = 1
        fake_curses.KEY_RIGHT=261;fake_curses.KEY_LEFT=260
        fake_curses.KEY_DOWN=258;fake_curses.KEY_UP=259
        fake_curses.KEY_NPAGE=338;fake_curses.KEY_PPAGE=339
        fake_curses.noecho = lambda:None
        fake_curses.curs_set=lambda *a:None
        fake_curses.has_colors=lambda:False
        fake_curses.wrapper=lambda func:func(Terminal())
        with mock.patch.object(sys,'stdin',types.SimpleNamespace(isatty=lambda:True)), \
             mock.patch.object(sys,'stdout',types.SimpleNamespace(isatty=lambda:True)), \
             mock.patch.dict(sys.modules,{'curses':fake_curses}), \
             mock.patch('subprocess.run',side_effect=AssertionError('unexpected subprocess')):
            d.run_tui(view())
    def test_host_telemetry_safe(self):
        a=d.HostTelemetry.read()
        b=d.HostTelemetry.read(a)
        for n in (a.ram,b.ram,b.cpu):
            if n is not None:
                self.assertGreaterEqual(n,0)
                self.assertLessEqual(n,100)
    def test_text_renderer_has_no_host_process(self):
        with mock.patch('subprocess.run',side_effect=AssertionError('unexpected command')):
            txt=d.text_report(view())
        self.assertIn('SIN',txt.upper())

if __name__ == '__main__':
    unittest.main()
