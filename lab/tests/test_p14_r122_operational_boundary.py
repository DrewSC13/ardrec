"""R122: host + F16 + FTP F13/R121 case; all receipts synthetic/local.

No VM, network, firewall or privileged command may be invoked by these tests.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f12_ftp_budget_preflight as f12
from ardrec.coordination import r115_f13_ftp_a5_journal as f13
from ardrec.coordination import r115_f5_lifecycle_readiness as f5
from ardrec.coordination import r119_live_inspection as r119
from ardrec.coordination import r122_operational_boundary as m
from ardrec.coordination import r115_f16_physical_pilot_controller as f16
from ardrec.coordination import r121_ftp_case_chain as r121
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import dashboard_tui as tui

REPO=Path(__file__).resolve().parents[2]
CAT=(REPO/'lab/operational-catalog-v1/catalog.json').read_bytes()
NOW=datetime(2026,11,21,18,0,0,tzinfo=timezone.utc)
HEAD='4ef82fd204b8a0ba6970da23ada53e3143b1ad2b'


def synthetic_capture():
    iso='2026-11-21T18:00:00Z'
    probe={'rc':1,'timeout':False,'truncated':False,
           'start':iso,'end':iso,'stdout':'','stderr':''}
    return {'schema':f5.SCHEMA,'start':iso,'end':iso,
            'probes':{name:dict(probe) for name in f5.READS},
            'source':'LOCAL_ROOT_READONLY_NOT_AUTHORITY',
            'traffic_authorized':False}


class Socket:
    import socket as _socket
    family=_socket.AF_INET
    type=_socket.SOCK_STREAM
    def __init__(self): self.data=b'220 Welcome\r\n'
    def getpeername(self): return ('10.203.31.2',21)
    def settimeout(self,x): pass
    def recv(self,n):
        b=self.data[:n];self.data=self.data[n:];return b


class Clock:
    def __init__(self):self.v=0.0
    def __call__(self):self.v+=0.001;return self.v


@unittest.skipIf(os.geteuid()==0,'needs nonroot private F5/F13 files')
class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)
        self.f5root=self.base/'captures'
        self.f5root.mkdir(mode=0o700)
        self.f5patch=patch.object(f5,'ROOT',self.f5root)
        self.f5patch.start()
        self.addCleanup(self.f5patch.stop)
        snap=synthetic_capture()
        self.receipt=f5.save_private(snap,f5.report(snap),root=self.f5root)
        self.journal=None
        self.unit=None
        self.audits=self.base/'audits'

    def case(self):
        intent=f13.make_intent(case_id='FTP-T01-S01-01',session_id='R122_CASE',
            assessment_index=0,attempt_id='ATT_R122_01',head=HEAD,
            contract_sha256='b'*64,scope_authorization_sha256='c'*64,
            p8_window_sha256='d'*64)
        self.journal=f13.reserve(intent,f12.DRAFT_BUDGET,root=self.base/'journal')
        self.unit={'service_id':'FTP_DEV','case_id':'FTP_T01_S01_01',
            'assessment_index':0,'initial_risk':'1/2',
            'normalized_criticality':'1/3','replacement_risk':'1/4',
            'evidence':[]}

    def build(self,**kw):
        opts=dict(capture_folder=self.receipt,catalog_raw=CAT,head=HEAD,
                  now=NOW,journal_folder=self.journal,unit=self.unit)
        opts.update(kw)
        return m.build(**opts)

    def test_01_schema(self):self.assertEqual(self.build()['schema'],m.SCHEMA)
    def test_02_no_go(self):self.assertEqual(self.build()['p8'],'NO-GO')
    def test_03_no_admission(self):self.assertEqual(self.build()['a6'],'ND')
    def test_04_no_publication(self):self.assertIsNone(self.build()['a9_generation'])
    def test_05_no_authoritative_transition(self):
        self.assertIsNone(self.build()['a8_authoritative_transition'])
    def test_06_no_risk(self):self.assertIsNone(self.build()['a7_confirmed_rf'])
    def test_07_source_only(self):
        self.assertFalse(self.build()['physical_origin_attested'])
    def test_08_no_dispatch(self):self.assertFalse(self.build()['dispatch_authorized'])
    def test_09_real_f5_source(self):
        self.assertEqual(len(self.build()['capture_sha256']),64)
    def test_10_missing_case_blocker(self):
        self.assertIn('F13_R121_CASE_NOT_SELECTED',self.build()['blockers'])
    def test_11_global_p7_blocker(self):
        self.assertIn('P7_DRAFT_NOT_FROZEN',self.build()['blockers'])
    def test_12_zero_actions(self):
        r=self.build()
        self.assertEqual((r['network_connections_by_r122'],r['guest_starts_by_r122'],r['firewall_changes_by_r122']),(0,0,0))
    def test_13_determinism(self):self.assertEqual(self.build(),self.build())
    def test_14_verify(self):self.assertTrue(m.verify(self.build(),CAT))
    def test_15_wrong_catalog(self):
        with self.assertRaisesRegex(m.Stop,'CATALOG_PIN_MISMATCH'):
            self.build(catalog_raw=CAT+b'x')
    def test_16_naive_time(self):
        with self.assertRaisesRegex(m.Stop,'CLOCK_UNTRUSTED'):
            self.build(now=NOW.replace(tzinfo=None))
    def test_17_subsecond_time(self):
        with self.assertRaisesRegex(m.Stop,'CLOCK_SUBSECOND'):
            self.build(now=NOW.replace(microsecond=1))
    def test_18_wrong_sha(self):
        with self.assertRaisesRegex(m.Stop,'GIT_HEAD'):
            self.build(head='INVALID')
    def test_19_partial_case(self):
        with self.assertRaisesRegex(m.Stop,'PARTIAL_CASE_INPUT'):
            self.build(unit={'x':1})
    def test_20_case_source(self):
        self.case();r=self.build()
        self.assertEqual(r['case_id'],'FTP-T01-S01-01')
        self.assertEqual(r['case_key'],r121.build(self.journal,CAT,self.unit)['case_key'])
    def test_21_risk_interval_not_confirmed(self):
        self.case();r=self.build()
        self.assertEqual(len(r['a7_interval']),2)
        self.assertIsNone(r['a7_confirmed_rf'])
    def test_22_case_mismatched_commit(self):
        self.case()
        with self.assertRaisesRegex(m.Stop,'CASE_HEAD_NOT_CURRENT'):
            self.build(head='a'*40)
    def test_23_case_drift_rational(self):
        self.case();self.unit['initial_risk']='0.5'
        with self.assertRaises(m.Stop):self.build()
    def test_24_case_tampered(self):
        self.case();p=self.journal/'reservation.json'
        d=f1.load(p.read_bytes());d['role']='FALSE';p.write_bytes(f1.canonical(d))
        with self.assertRaises(m.Stop):self.build()
    def test_25_capture_missing(self):
        with self.assertRaises(m.Stop):self.build(capture_folder=self.base/'missing')
    def test_26_receipt_tampered(self):
        p=self.receipt/'manifest.json';p.write_bytes(b'{}\n')
        with self.assertRaises(m.Stop):self.build()
    def test_27_extra_capture_file(self):
        (self.receipt/'extra').write_text('x')
        with self.assertRaises(m.Stop):self.build()
    def test_28_report_forged_p8(self):
        r=self.build();r['p8']='GO';r['sha256']=f1.digest(f1.canonical({k:v for k,v in r.items() if k!='sha256'}))
        with self.assertRaises(m.Stop):m.verify(r,CAT)
    def test_29_report_forged_a6(self):
        r=self.build();r['a6']='VERDADERO'
        with self.assertRaises(m.Stop):m.verify(r,CAT)
    def test_30_report_forged_a9(self):
        r=self.build();r['a9_generation']=1
        with self.assertRaises(m.Stop):m.verify(r,CAT)
    def test_31_no_network(self):
        import socket
        with patch.object(socket,'socket',side_effect=AssertionError('SOCKET_OPENED')):
            self.build()
    def test_32_no_process(self):
        import subprocess
        with patch.object(subprocess,'run',side_effect=AssertionError('SUBPROCESS')):
            self.build()
    def test_33_audit_persist_and_replay(self):
        r=self.build();folder=m.persist(r,CAT,root=self.audits)
        self.assertEqual(m.verify_persisted(folder,CAT),r)
    def test_34_audit_private_modes(self):
        folder=m.persist(self.build(),CAT,root=self.audits)
        self.assertEqual(folder.stat().st_mode&0o777,0o700)
        self.assertEqual((folder/'report.json').stat().st_mode&0o777,0o600)
    def test_35_audit_modified_manifest(self):
        folder=m.persist(self.build(),CAT,root=self.audits)
        p=folder/'manifest.json';d=f1.load(p.read_bytes());d['report_sha256']='0'*64
        p.write_bytes(f1.canonical(d))
        with self.assertRaises(m.Stop):m.verify_persisted(folder,CAT)
    def test_36_audit_extra_file(self):
        folder=m.persist(self.build(),CAT,root=self.audits)
        (folder/'extra').write_text('x')
        with self.assertRaises(m.Stop):m.verify_persisted(folder,CAT)
    def test_37_audit_modified_receipt_after_persist(self):
        folder=m.persist(self.build(),CAT,root=self.audits)
        p=self.receipt/'manifest.json';p.write_bytes(b'{}\n')
        with self.assertRaises(m.Stop):m.verify_persisted(folder,CAT)
    def test_38_audit_symlink_prohibited(self):
        folder=m.persist(self.build(),CAT,root=self.audits)
        p=folder/'report.json';p.unlink();p.symlink_to('/etc/passwd')
        with self.assertRaises(m.Stop):m.verify_persisted(folder,CAT)
    def test_39_root_not_allowed(self):
        with patch.object(m.os,'geteuid',return_value=0):
            with self.assertRaises(m.Stop):m.persist(self.build(),CAT,root=self.audits)
    def test_40_capabilities(self):
        self.assertFalse(m.capabilities()['independent_current_p8_permit_accepted'])
    def test_41_cli_capabilities(self):
        from scripts import ardrec_p14_r122_operational_boundary as cli
        with patch('builtins.print'):
            self.assertEqual(cli.main(['--capabilities']),0)
    def test_42_cli_inspect(self):
        from scripts import ardrec_p14_r122_operational_boundary as cli
        with patch('builtins.print'):
            self.assertEqual(cli.main(['--inspect','--head',HEAD,'--capture',str(self.receipt),'--repo',str(REPO)]),0)
    def test_43_cli_partial_case(self):
        from scripts import ardrec_p14_r122_operational_boundary as cli
        with patch('builtins.print'):
            self.assertEqual(cli.main(['--inspect','--head',HEAD,'--capture',str(self.receipt),'--unit-file',str(self.base/'missing'),'--repo',str(REPO)]),2)
    def test_44_cli_bad_source(self):
        from scripts import ardrec_p14_r122_operational_boundary as cli
        with patch('builtins.print'):
            self.assertEqual(cli.main(['--inspect','--head',HEAD,'--capture',str(self.base/'bad'),'--repo',str(REPO)]),2)
    def test_45_case_source_only(self):
        self.case();r=self.build()
        self.assertIn('F13_CANDIDATE_NOT_INDEPENDENT_PHYSICAL_WITNESS',r['blockers'])
    def test_46_ftp_offline_replay(self):
        r=self.build()
        self.assertEqual(r['host_states']['ftp'],'ND')
        self.assertIn('FTP_RUNNING_FIVE_DENY_ONE_OFF_NOT_ATTESTED',r['blockers'])
    def test_47_future_capture(self):
        with self.assertRaisesRegex(m.Stop,'CAPTURE_CLOCK_OUTSIDE_REPLAY_WINDOW'):
            self.build(now=NOW-timedelta(days=366))
    def test_48_invalid_mode_persist(self):
        with self.assertRaises(m.Stop):m.persist(self.build(),CAT,root=Path('relative'))
    def test_49_source_immutable_audit_hash(self):
        r=self.build();self.assertEqual(r['sha256'],f1.digest(f1.canonical({k:v for k,v in r.items() if k!='sha256'})))
    def test_50_pending_p7_always_no_go(self):
        self.case();self.assertEqual(self.build()['p7'],'DRAFT_NOT_EXECUTABLE')


if __name__ == '__main__':unittest.main()
