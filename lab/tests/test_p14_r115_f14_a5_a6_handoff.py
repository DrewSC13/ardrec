"""F14 isolated replay of F13, no networking or root actions."""
from __future__ import annotations
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f12_ftp_budget_preflight as f12
from ardrec.coordination import r115_f13_ftp_a5_journal as f13
from ardrec.coordination import r115_f14_a5_a6_handoff as m

REPO=Path(__file__).resolve().parents[2]
HEAD='3db3f079d2050d6c25a503df142eb212c40bf4d5'

class DummySocket:
    family=socket.AF_INET
    type=socket.SOCK_STREAM
    def __init__(self, data=b'220 Service ready\r\n'):
        self.data=data
        self.reads=0
        self.peer=('10.203.31.2',21)
    def getpeername(self):return self.peer
    def settimeout(self,t):self.timeout=t
    def recv(self,size):
        self.reads+=1
        result=self.data[:size]
        self.data=self.data[size:]
        return result

class Time:
    def __init__(self):self.value=0.0
    def __call__(self):self.value+=.0005;return self.value

@unittest.skipIf(os.geteuid()==0, 'private journal requires nonroot user')
class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.jroot=Path(self.temp.name)/'j'
        self.report_root=Path(self.temp.name)/'r'
        self.cat=(REPO/'lab/operational-catalog-v1/catalog.json').read_bytes()
        self.intent=f13.make_intent(
            case_id='FTP-T01-S01-01',session_id='F14_CASE',assessment_index=0,
            attempt_id='ATT_F14_01',head=HEAD,
            contract_sha256='a'*64,scope_authorization_sha256='b'*64,
            p8_window_sha256='c'*64)
    def reserve(self):
        return f13.reserve(self.intent, f12.DRAFT_BUDGET,root=self.jroot)
    def result(self, data=b'220 Service ready\r\n'):
        f=self.reserve()
        s=DummySocket(data)
        f13.consume_reserved(f,s,current_p8_guard=lambda:True,monotonic=Time())
        return f
    def build(self, folder):return m.build(folder,self.cat)
    def test_01_catalog_draft(self):
        self.assertEqual(m.catalog_check(self.cat)['status'],'PROFILE_PROPOSED_NOT_CALIBRATED')
    def test_02_capabilities_no_go(self):
        d=m.capabilities();self.assertEqual(d['p8'],'NO-GO');self.assertFalse(d['opens_sockets'])
    def test_03_reserved_is_not_evidence(self):
        d=self.build(self.reserve())
        self.assertEqual(d['source_status'],'RESERVED_NO_RETRY')
        self.assertEqual(d['accepted_support_count'],0)
    def test_04_result_220_only_candidate(self):
        d=self.build(self.result())
        self.assertEqual(d['candidate_outcome'],'REPLY_COMPLETE')
        self.assertTrue(d['candidate_complete_220'])
        self.assertEqual(d['a6'],'ND')
        self.assertIsNone(d['a7_confirmed_risk'])
    def test_05_result_negative_only_candidate(self):
        d=self.build(self.result(b'421 Service unavailable\r\n'))
        self.assertFalse(d['candidate_complete_220'])
        self.assertEqual(d['a6'],'ND')
    def test_06_no_physical_proof_promoted(self):
        d=self.build(self.result());self.assertFalse(d['physical_origin_attested'])
        self.assertEqual([x['support_accepted'] for x in d['supports'].values()], [False]*3)
    def test_07_no_transition_generation(self):
        d=self.build(self.result())
        self.assertIsNone(d['a8_transition_applied'])
        self.assertIsNone(d['a9_published_generation'])
        self.assertIsNone(d['a10_generation_confirmation'])
    def test_08_report_deterministic(self):
        f=self.result();self.assertEqual(self.build(f),self.build(f))
    def test_09_report_replay_valid(self):
        d=self.build(self.result());self.assertTrue(m.replay(d,self.cat))
    def test_10_report_replay_reject_promoted_a6(self):
        d=self.build(self.result());d['a6']='VERDADERO'
        with self.assertRaises(m.Stop):m.replay(d,self.cat)
    def test_11_report_replay_reject_risk(self):
        d=self.build(self.result());d['a7_confirmed_risk']='1'
        with self.assertRaises(m.Stop):m.replay(d,self.cat)
    def test_12_report_replay_reject_a9(self):
        d=self.build(self.result());d['a9_published_generation']='G1'
        with self.assertRaises(m.Stop):m.replay(d,self.cat)
    def test_13_report_replay_reject_source_hash(self):
        d=self.build(self.result());d['source_reservation_sha256']='0'*64
        with self.assertRaises(m.Stop):m.replay(d,self.cat)
    def test_14_catalog_bytes_changed(self):
        with self.assertRaises(m.Stop):m.catalog_check(self.cat+b' ')
    def test_15_catalog_flag_changed_and_rehashed(self):
        obj=f1.load(self.cat);obj['pilot_completed']=True
        with self.assertRaises(m.Stop):m.catalog_check(f1.canonical(obj))
    def test_16_spent_unresolved(self):
        f=self.reserve();r=f13._read_json(f,'reservation.json')
        s={'schema':f13.SCHEMA+'-spent',
           'reservation_sha256':f1.digest(f1.canonical(r)),
           'status':'ATTEMPT_CONSUMED_NO_RETRY','a6':'ND','p8':'NO-GO'}
        h=f13._save(f,'spent.json',s)
        f13._save(f,'spent.manifest.json',{
           'schema':f13.SCHEMA+'-manifest','file':'spent.json',
           'sha256':h,'case_key':r['case_key'],'p8':'NO-GO'})
        d=self.build(f)
        self.assertEqual(d['source_status'],'ATTEMPT_CONSUMED_UNRESOLVED')
    def test_17_failed_receipt_no_evidence(self):
        f=self.reserve();s=DummySocket();s.peer=('10.203.31.7',21)
        with self.assertRaises(f13.Stop):
            f13.consume_reserved(f,s,current_p8_guard=lambda:True,monotonic=Time())
        d=self.build(f);self.assertEqual(d['source_status'],'FAILED_NO_RETRY')
        self.assertEqual(d['accepted_support_count'],0)
    def test_18_reject_changed_terminal(self):
        f=self.result();p=f/'result.json';v=f1.load(p.read_bytes())
        v['f10']['raw_b64']='QQ=='
        p.write_bytes(f1.canonical(v))
        with self.assertRaises(m.Stop):self.build(f)
    def test_19_reject_extra_journal_entry(self):
        f=self.reserve();(f/'spurious').write_text('x')
        with self.assertRaises(m.Stop):self.build(f)
    def test_20_reject_symlink_journal(self):
        f=self.reserve();p=f/'reservation.json';q=f/'orig.json'
        p.rename(q);p.symlink_to(q)
        with self.assertRaises(m.Stop):self.build(f)
    def test_21_reject_relative_path(self):
        with self.assertRaises(m.Stop):self.build(Path('relative'))
    def test_22_reject_missing_path(self):
        with self.assertRaises(m.Stop):self.build(Path('/tmp/does-not-exist-ardrec-f14'))
    def test_23_persist_and_verify(self):
        d=self.build(self.result());folder=m.persist(d,root=self.report_root)
        self.assertEqual(m.verify_persisted(folder,self.cat),d)
        self.assertEqual(folder.stat().st_mode&0o777,0o700)
    def test_24_persist_reject_root_shell(self):
        d=self.build(self.result())
        with patch.object(m.os,'geteuid',return_value=0):
            with self.assertRaises(m.Stop):m.persist(d,root=self.report_root)
    def test_25_tamper_report(self):
        d=self.build(self.result());folder=m.persist(d,root=self.report_root)
        p=folder/'report.json';v=f1.load(p.read_bytes());v['a6']='VERDADERO'
        p.write_bytes(f1.canonical(v))
        with self.assertRaises(m.Stop):m.verify_persisted(folder,self.cat)
    def test_26_tamper_manifest(self):
        d=self.build(self.result());folder=m.persist(d,root=self.report_root)
        p=folder/'manifest.json';v=f1.load(p.read_bytes());v['report_sha256']='0'*64
        p.write_bytes(f1.canonical(v))
        with self.assertRaises(m.Stop):m.verify_persisted(folder,self.cat)
    def test_27_extra_report_file(self):
        d=self.build(self.result());folder=m.persist(d,root=self.report_root)
        (folder/'extra.txt').write_text('x')
        with self.assertRaises(m.Stop):m.verify_persisted(folder,self.cat)
    def test_28_untrusted_catalog_on_replay(self):
        d=self.build(self.result())
        with self.assertRaises(m.Stop):m.replay(d,self.cat+b' ')
    def test_29_script_capabilities_only(self):
        script=REPO/'scripts/ardrec_p14_r115_f14_a5_a6_handoff.py'
        proc=subprocess.run([sys.executable,str(script),'--capabilities'],
                            capture_output=True,text=True,env={**os.environ,'PYTHONPATH':'src:scripts'})
        self.assertEqual(proc.returncode,0,proc.stderr)
        self.assertFalse(json.loads(proc.stdout)['admits_a6'])
    def test_30_script_verify_report(self):
        folder=m.persist(self.build(self.result()),root=self.report_root)
        script=REPO/'scripts/ardrec_p14_r115_f14_a5_a6_handoff.py'
        proc=subprocess.run([sys.executable,str(script),'--verify-report',str(folder)],
                  cwd=REPO,capture_output=True,text=True,
                  env={**os.environ,'PYTHONPATH':'src:scripts'})
        self.assertEqual(proc.returncode,0,proc.stdout+proc.stderr)
        self.assertIn('R115_F14_REPLAY=PASS_SOURCE_AND_REPORT',proc.stdout)
    def test_31_no_calls_to_network(self):
        f=self.result()
        with patch('socket.socket',side_effect=AssertionError('network call')):
            self.build(f)
    def test_32_corrupt_reserved_manifest(self):
        f=self.reserve();p=f/'reservation.manifest.json';p.write_bytes(b'{}\n')
        with self.assertRaises(m.Stop):self.build(f)

if __name__=='__main__':unittest.main()
