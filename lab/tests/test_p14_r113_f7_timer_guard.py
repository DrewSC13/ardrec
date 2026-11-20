"""Unit and adversarial tests. No libvirt, nftables, systemd or network access."""
from pathlib import Path
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
from ardrec.coordination import r113_f7_timer_guard as g

TOKEN='abcdef123456'
TIMER=(b'LoadState=loaded\nActiveState=active\n'
       b'Unit=ardrec-r113-f7-deny-abcdef123456.service\n'
       b'NextElapseUSecMonotonic=23456789\n')
SERVICE=(b'LoadState=loaded\nActiveState=inactive\nResult=success\n'
         b'ExecMainStatus=0\nExecMainStartTimestampMonotonic=34567890\n')
ROOT_CHECK=b'{"result":"ROOT_BUNDLE_VERIFIED","bindings":6,"p8":"NO-GO"}'
ATTEST=b'{"result":"SIX_BINDING_DENY_ATTESTED","bindings":6,"p8":"NO-GO"}'


def intent():
    return {'schema':g.SCHEMA,'token':TOKEN,'action':'DENY_ONLY_SMOKE',
            'schedule_seconds':g.INTERVAL,'allow_traffic':False,'p8':'NO-GO'}

def outputs():
    return {'root_check':ROOT_CHECK,'before_attest':ATTEST,'schedule':b'Created timer unit.\n',
            'timer_armed':TIMER,'service_done':SERVICE,'after_attest':ATTEST,
            'journal':b'systemd: Deny restored\n'}

def aux():
    return {key:b"" for key in g.AUX_NAMES}

class GuardTests(unittest.TestCase):
    def test_01_token_ok(self): self.assertEqual(g.units(TOKEN)[1],'ardrec-r113-f7-deny-abcdef123456.timer')
    def test_02_token_short(self):
        with self.assertRaises(g.GuardError): g.units('short')
    def test_03_token_path(self):
        with self.assertRaises(g.GuardError): g.units('../../etc/x')
    def test_04_token_unicode(self):
        with self.assertRaises(g.GuardError): g.units('é'*12)
    def test_05_schedule_pinned(self):
        c=g.schedule(TOKEN)
        self.assertEqual(c[-3:],['/usr/bin/python3',g.ROOT_HELPER,'--restore-deny'])
        self.assertIn('--on-active=20s',c)
        self.assertNotIn('allow',' '.join(c).lower())
    def test_06_check_pinned(self): self.assertEqual(g.check_command()[-1],'--check-root-bundle')
    def test_07_attest_pinned(self): self.assertEqual(g.attest_command()[-1],'--attest-deny')
    def test_08_show_timer_pinned(self): self.assertEqual(g.show_timer(TOKEN)[2],g.units(TOKEN)[1])
    def test_09_show_service_pinned(self): self.assertEqual(g.show_service(TOKEN)[2],g.units(TOKEN)[0])
    def test_10_props_valid(self): self.assertEqual(g.props(TIMER)['ActiveState'],'active')
    def test_11_props_duplicate_rejected(self):
        with self.assertRaises(g.GuardError): g.props(b'ActiveState=active\nActiveState=active\n')
    def test_12_props_malformed_rejected(self):
        with self.assertRaises(g.GuardError): g.props(b'badline\n')
    def test_13_timer_armed(self): self.assertTrue(g.armed(TIMER,TOKEN))
    def test_14_timer_wrong_service(self):
        with self.assertRaises(g.GuardError): g.armed(TIMER.replace(TOKEN.encode(),b'123456abcdef'),TOKEN)
    def test_15_timer_no_elapsed(self):
        with self.assertRaises(g.GuardError): g.armed(TIMER.replace(b'23456789',b'0'),TOKEN)
    def test_16_service_never_run_not_success(self):
        self.assertFalse(g.triggered_success(SERVICE.replace(b'34567890',b'0')))
    def test_17_service_run_ok(self): self.assertTrue(g.triggered_success(SERVICE))
    def test_18_service_failed(self):
        with self.assertRaises(g.GuardError): g.triggered_success(SERVICE.replace(b'Result=success',b'Result=exit-code'))
    def test_19_check_root(self): self.assertTrue(g.checked_root_result(ROOT_CHECK,g.F6_CHECK))
    def test_20_check_wrong_bindings(self):
        with self.assertRaises(g.GuardError): g.checked_root_result(ROOT_CHECK.replace(b'6',b'2'),g.F6_CHECK)
    def test_21_positive_receipt(self):
        d=g.receipt(intent(),outputs(),aux()); self.assertEqual(d['firewall_allow_rules'],0)
        self.assertTrue(d['physical_deny_restore_tested'])
    def test_22_receipt_lacks_capture(self):
        c=outputs();c.pop('journal')
        with self.assertRaises(g.GuardError): g.receipt(intent(),c,aux())
    def test_23_receipt_wrong_post_deny(self):
        c=outputs();c['after_attest']=ROOT_CHECK
        with self.assertRaises(g.GuardError): g.receipt(intent(),c,aux())
    def test_24_receipt_intent_allow(self):
        d=intent();d['allow_traffic']=True
        with self.assertRaises(g.GuardError): g.receipt(d,outputs(),aux())
    def test_25_receipt_journal_empty(self):
        c=outputs();c['journal']=b''
        self.assertEqual(g.receipt(intent(),c,aux())['p8'],'NO-GO')

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)/'receipts'
        self.root.mkdir(mode=0o700)
        self.folder=self.root/'smoke-test-abc'
        self.folder.mkdir(mode=0o700)
        spec=importlib.util.spec_from_file_location('ardrec_test_f7_script',str(Path(__file__).resolve().parents[2]/'scripts'/'ardrec_p14_r113_f7_timer.py'))
        self.s=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.s)
        self.original=self.s.EVIDENCE
        self.s.EVIDENCE=self.root
        self.create()
    def tearDown(self):
        self.s.EVIDENCE=self.original
        self.temp.cleanup()
    def create(self):
        i=intent();o=outputs()
        self.s.save(self.folder/'intent.json',g.canonical(i))
        self.s.save(self.folder/'armed.once',b'SYSTEMD_TIMER_ARM_ATTEMPTED\n')
        for name in (*self.s.LOGS,'timer_status_early','service_status_early'):
            self.s.save(self.folder/(name+'.stdout'),o.get(name,b''))
            self.s.save(self.folder/(name+'.stderr'),b'')
        self.s.save(self.folder/'manifest.json',g.canonical(g.receipt(i,o,aux())))
    def test_26_complete_replay(self): self.assertEqual(self.s.replay(self.folder)['p8'],'NO-GO')
    def test_27_tamper_intent(self):
        path=self.folder/'intent.json';path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaises(g.GuardError):self.s.replay(self.folder)
    def test_28_tamper_result(self):
        path=self.folder/'after_attest.stdout';path.write_bytes(ROOT_CHECK)
        with self.assertRaises(g.GuardError):self.s.replay(self.folder)
    def test_29_tamper_manifest(self):
        path=self.folder/'manifest.json';path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaises(g.GuardError):self.s.replay(self.folder)
    def test_30_missing_capture(self):
        (self.folder/'journal.stdout').unlink()
        with self.assertRaises((g.GuardError,FileNotFoundError)):self.s.replay(self.folder)
    def test_31_extra_capture(self):
        self.s.save(self.folder/'extra',b'x')
        with self.assertRaises(g.GuardError):self.s.replay(self.folder)
    def test_32_symlink_capture(self):
        p=self.folder/'journal.stdout';p.unlink();p.symlink_to(self.folder/'intent.json')
        with self.assertRaises(g.GuardError):self.s.replay(self.folder)
    def test_33_wrong_parent(self):
        with self.assertRaises(g.GuardError):self.s.replay(self.root)
    def test_34_marker_altered(self):
        (self.folder/'armed.once').write_bytes(b'ARMED\n')
        with self.assertRaises(g.GuardError):self.s.replay(self.folder)
    def test_35_permissions_altered(self):
        (self.folder/'manifest.json').chmod(0o644)
        with self.assertRaises(g.GuardError):self.s.replay(self.folder)

if __name__=='__main__':unittest.main()
