"""Offline tests for scoped libvirt hook, dependency, and watchdog candidates."""
from __future__ import annotations

import importlib.machinery
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT/'lab/f11-runtime-v1/00-ardrec-r33-deny'
TOOL = ROOT/'scripts/ardrec_p14_r58b_runtime_design.py'


def module_from(path: Path, name: str):
    loader=importlib.machinery.SourceFileLoader(name,str(path))
    spec=importlib.util.spec_from_loader(name,loader)
    module=importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class TestHook(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hook=module_from(HOOK,'r58b_test_hook')

    def test_expected_guests(self):
        self.assertEqual(len(self.hook.SCOPED),4)
        self.assertEqual(self.hook.SCOPED,{
            'ardrec-r33-dev-runner','ardrec-r33-dev-ssh',
            'ardrec-r33-dev-ftp','ardrec-r33-dev-smb'})

    def test_prepare_blocks_all_scoped(self):
        for guest in self.hook.SCOPED:
            with self.subTest(guest=guest):
                self.assertNotEqual(self.hook.decision([guest,'prepare','begin','-'])[0],0)

    def test_start_blocks_all_scoped(self):
        for guest in self.hook.SCOPED:
            self.assertNotEqual(self.hook.decision([guest,'start','begin','-'])[0],0)

    def test_restore_blocks_all_scoped(self):
        for guest in self.hook.SCOPED:
            self.assertNotEqual(self.hook.decision([guest,'restore','begin','-'])[0],0)

    def test_migration_blocks_all_scoped(self):
        for guest in self.hook.SCOPED:
            self.assertNotEqual(self.hook.decision([guest,'migrate','begin','-'])[0],0)

    def test_attach_blocks_all_scoped(self):
        for guest in self.hook.SCOPED:
            self.assertNotEqual(self.hook.decision([guest,'attach','begin','-'])[0],0)

    def test_reconnect_blocks_scoped(self):
        for guest in self.hook.SCOPED:
            self.assertNotEqual(self.hook.decision([guest,'reconnect','begin','-'])[0],0)

    def test_started_blocks_scoped(self):
        for guest in self.hook.SCOPED:
            self.assertNotEqual(self.hook.decision([guest,'started','begin','-'])[0],0)

    def test_unknown_ardrec_guest_denied(self):
        self.assertNotEqual(self.hook.decision(['ardrec-r33-dev-unknown','prepare','begin','-'])[0],0)

    def test_name_variations_not_in_scope(self):
        for name in ('build-server','default','ardrec-smb-guest','ardrec-r34-dev-runner'):
            self.assertEqual(self.hook.decision([name,'prepare','begin','-'])[0],0)

    def test_unrelated_guest_shutdown_allowed(self):
        self.assertEqual(self.hook.decision(['unrelated','release','end','-'])[0],0)

    def test_scoped_shutdown_allowed(self):
        for event in ('stopped','release'):
            for name in self.hook.SCOPED:
                self.assertEqual(self.hook.decision([name,event,'end','-'])[0],0)

    def test_unknown_event_denied(self):
        self.assertNotEqual(self.hook.decision(['ardrec-r33-dev-ftp','unknown','begin','-'])[0],0)

    def test_malformed_arguments_denied(self):
        for arguments in ([],['ardrec-r33-dev-ftp'],['ardrec-r33-dev-ftp','prepare','begin'],
                          ['ardrec-r33-dev-ftp','prepare','begin','-','unexpected'],
                          ['', 'start','begin','-'],['ardrec-r33-dev-ftp','','','']):
            with self.subTest(arguments=arguments):
                self.assertNotEqual(self.hook.decision(arguments)[0],0)

    def test_hook_invocation_scope_and_no_stdout(self):
        for guest,exp in [('ardrec-r33-dev-ftp',79),('ordinary-vm',0)]:
            p=subprocess.run([sys.executable,'-I',str(HOOK),guest,'prepare','begin','-'],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                timeout=4,check=False)
            self.assertEqual(p.returncode,exp)
            self.assertEqual(p.stdout,b'')
            self.assertEqual(bool(p.stderr),exp!=0)

    def test_hook_contains_no_subprocess(self):
        raw=HOOK.read_text()
        self.assertNotIn('import subprocess',raw)
        self.assertNotIn('import socket',raw)
        self.assertNotIn('systemctl',raw)
        self.assertNotIn('virsh ',raw)


class TestOfflineCandidates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod=module_from(TOOL,'r58b_design_test')

    def test_source_audit(self):
        doc=self.mod.audit(ROOT)
        self.assertEqual(doc['status'],'F11_RUNTIME_CANDIDATES_VERIFIED_SOURCE_ONLY')
        self.assertEqual(len(doc['sources_sha256']),4)

    def test_flags_honest(self):
        doc=self.mod.audit(ROOT)
        for k in ('effective_hook_installed','libvirt_restarted','watchdog_installed',
                  'boot_attested','guest_traffic_generated'):
            self.assertIs(doc[k],False)
        self.assertEqual(doc['p8'],'NO-GO')
        self.assertEqual(doc['physical_mutations'],0)

    def test_reject_missing_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(self.mod.AuditError):self.mod.audit(Path(d))

    def test_requires_dependency(self):
        p=ROOT/'lab/f11-runtime-v1/libvirtd-f11-guard.conf'
        data=p.read_text()
        self.assertIn('Requires=ardrec-r34-boot-deny.service',data)
        self.assertIn('After=ardrec-r34-boot-deny.service',data)
        self.assertNotIn('BindsTo=',data)

    def test_watchdog_root_boundary(self):
        p=ROOT/'lab/f11-runtime-v1/ardrec-r34-deny-watchdog.service'
        data=p.read_text()
        self.assertEqual(data.count('ExecStart='),1)
        self.assertIn(self.mod.EXPECTED_UNIT,data)
        self.assertIn('ProtectSystem=strict',data)

    def test_timer_is_system_timer_candidate(self):
        p=ROOT/'lab/f11-runtime-v1/ardrec-r34-deny-watchdog.timer'
        data=p.read_text()
        self.assertIn('WantedBy=timers.target',data)
        self.assertIn('OnUnitInactiveSec=10s',data)
        self.assertNotIn('OnCalendar=',data)

    def test_no_service_install_actions(self):
        text=(ROOT/'scripts/ardrec_p14_r58b_runtime_design.py').read_text()
        self.assertNotIn('subprocess.run(',text)
        self.assertNotIn('os.system(',text)
        self.assertNotIn('virsh define',text)
        self.assertNotIn('systemctl enable',text)

    def test_check_stale_watcher(self):
        p=ROOT/'lab/f11-runtime-v1/ardrec-r34-deny-watchdog.timer'
        d=p.read_text()
        self.assertIn('OnBootSec=20s',d)
        self.assertNotIn('OnBootSec=0',d)

    def test_no_allow_path_in_scoped_hook(self):
        source=HOOK.read_text()
        self.assertNotIn('ALLOW_START',source)
        self.assertNotIn('AUTHORIZATION_TOKEN',source)
        self.assertNotIn('P8=GO',source)

    def test_sources_not_root_installed(self):
        self.assertTrue((ROOT/'lab/f11-runtime-v1').is_dir())
        self.assertEqual(len(list((ROOT/'lab/f11-runtime-v1').iterdir())),4)

    def test_reject_tampered_timer(self):
        with tempfile.TemporaryDirectory() as d:
            other=Path(d)/'lab/f11-runtime-v1';other.mkdir(parents=True)
            for f in self.mod.FILES:
                raw=(ROOT/'lab/f11-runtime-v1'/f).read_bytes()
                (other/f).write_bytes(raw)
            p=other/'ardrec-r34-deny-watchdog.timer'
            p.write_text(p.read_text().replace('OnUnitInactiveSec=10s','OnUnitInactiveSec=0s'))
            with self.assertRaises(self.mod.AuditError):self.mod.audit(Path(d))


if __name__ == '__main__':
    unittest.main()
