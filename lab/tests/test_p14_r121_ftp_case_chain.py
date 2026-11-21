"""R121 F13->F14->R58-E->A8->A10 provenance-safe, source-only integration."""
from __future__ import annotations

from copy import deepcopy
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
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r121_ftp_case_chain as m

REPO=Path(__file__).resolve().parents[2]
CAT=(REPO/'lab/operational-catalog-v1/catalog.json').read_bytes()
SCRIPT=REPO/'scripts/ardrec_p14_r121_ftp_case_chain.py'

class Socket:
    family=socket.AF_INET
    type=socket.SOCK_STREAM
    def __init__(self, data=b'220 Welcome\r\n'):
        self.data=data
    def getpeername(self): return ('10.203.31.2', 21)
    def settimeout(self,t): self.timeout=t
    def recv(self,n):
        chunk=self.data[:n]
        self.data=self.data[n:]
        return chunk

class Clock:
    def __init__(self): self.value=0.0
    def __call__(self):
        self.value+=0.0005
        return self.value

@unittest.skipIf(os.geteuid()==0, 'requires non-root private journal')
class Integration(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'journal'
        self.audit=Path(self.temp.name)/'audits'
        self.intent=f13.make_intent(case_id='FTP-T01-S01-01',
            session_id='R121_CASE', assessment_index=3,
            attempt_id='ATT_R121_001', head='a'*40,
            contract_sha256='b'*64,scope_authorization_sha256='c'*64,
            p8_window_sha256='d'*64)
        self.unit={'service_id':'FTP_DEV', 'case_id':'FTP_T01_S01_01',
            'assessment_index':3,'initial_risk':'1/2',
            'normalized_criticality':'1/3','replacement_risk':'1/4',
            'evidence':[]}
        self.folder=f13.reserve(self.intent,f12.DRAFT_BUDGET,root=self.root)

    def result(self, data=b'220 Welcome\r\n'):
        f13.consume_reserved(self.folder,Socket(data),current_p8_guard=lambda:True,
                             monotonic=Clock())
        return self.folder

    def build(self): return m.build(self.folder,CAT,self.unit)

    def terminal_doc(self):
        self.result()
        return self.build()

    def test_01_schema(self): self.assertEqual(self.build()['schema'],m.SCHEMA)
    def test_02_reserved_is_not_a5_result(self):
        self.assertEqual(self.build()['f14_source_status'],'RESERVED_NO_RETRY')
    def test_03_no_approval(self):
        self.assertEqual(self.build()['p8'],'NO-GO')
    def test_04_no_a6(self):
        self.assertEqual(self.build()['a6_classification'],'ND')
    def test_05_no_true_220(self):
        self.assertFalse(self.build()['candidate_complete_220'])
    def test_06_negative_candidate(self):
        self.result(b'421 Busy\r\n')
        self.assertFalse(self.build()['candidate_complete_220'])
    def test_07_complete_candidate(self):
        self.assertTrue(self.terminal_doc()['candidate_complete_220'])
    def test_08_full_uncertainty(self):
        self.assertEqual(self.build()['a7_uncertainty'],'UNRESOLVED_0_TO_1')
    def test_09_exact_bounds(self):
        r=self.build()
        self.assertIn('/', r['a7_lower']+' '+r['a7_upper'])
    def test_10_no_rf_confirmed(self):
        self.assertIsNone(self.build()['a7_confirmed_rf'])
    def test_11_no_state_transition(self):
        self.assertIsNone(self.build()['a8_applied_transition'])
    def test_12_no_generation(self):
        self.assertIsNone(self.build()['a9_published_generation'])
    def test_13_a10_not_global_state(self):
        self.assertEqual(self.build()['a10_status'],
                         'REPLAYABLE_AUDIT_NO_OPERATIONAL_GENERATION')
    def test_14_no_physical_actions(self):
        self.assertEqual(self.build()['physical_actions_by_r121'],0)
    def test_15_stages_complete(self):
        self.assertEqual([x['algorithm'] for x in self.build()['stages']],list(m.COVERAGE))
    def test_16_stage_chain_linked(self):
        stages=self.build()['stages']
        self.assertIsNone(stages[0]['previous_sha256'])
        for i in range(1,10): self.assertEqual(stages[i]['previous_sha256'],stages[i-1]['sha256'])
    def test_17_deterministic(self): self.assertEqual(self.build(),self.build())
    def test_18_replay(self): self.assertTrue(m.verify(self.build(),CAT))
    def test_19_source_mutated_detected(self):
        doc=self.build(); p=self.folder/'reservation.json'
        data=f1.load(p.read_bytes()); data['role']='CHANGED'
        p.write_bytes(f1.canonical(data))
        with self.assertRaises((m.Stop,f14.Stop)): m.verify(doc,CAT)
    def test_20_forged_risk(self):
        doc=self.build(); doc['a7_confirmed_rf']='1/2'
        doc['sha256']=f1.digest(f1.canonical({k:v for k,v in doc.items() if k!='sha256'}))
        with self.assertRaises(m.Stop):m.verify(doc,CAT)
    def test_21_forged_a6(self):
        doc=self.build();doc['a6_classification']='VERDADERO'
        with self.assertRaises(m.Stop):m.verify(doc,CAT)
    def test_22_forged_a9(self):
        doc=self.build();doc['a9_published_generation']=1
        with self.assertRaises(m.Stop):m.verify(doc,CAT)
    def test_23_forged_stage(self):
        doc=self.build();doc['stages'][4]['status']='EXECUTED'
        with self.assertRaises(m.Stop):m.verify(doc,CAT)
    def test_24_unit_not_matching_case(self):
        self.unit['case_id']='FTP_T01_S01_02'
        with self.assertRaisesRegex(m.Stop,'UNIT_NOT_BOUND_TO_F13'):self.build()
    def test_25_index_mismatch(self):
        self.unit['assessment_index']=2
        with self.assertRaisesRegex(m.Stop,'UNIT_NOT_BOUND_TO_F13'):self.build()
    def test_26_evidence_injection(self):
        self.unit['evidence']=[{'evidence_id':'X','kind':'SYNTHETIC_FIXED',
                                'lower':'1','upper':'1'}]
        with self.assertRaises(m.Stop):self.build()
    def test_27_reject_float(self):
        self.unit['initial_risk']='0.5'
        with self.assertRaises(ValueError):self.build()
    def test_28_bad_replacement(self):
        self.unit['replacement_risk']='1'
        with self.assertRaises(ValueError):self.build()
    def test_29_wrong_catalog(self):
        with self.assertRaises(f14.Stop):m.build(self.folder,CAT+b' ',self.unit)
    def test_30_f13_missing(self):
        with self.assertRaises(f14.Stop):m.build(self.audit,CAT,self.unit)
    def test_31_private_persist(self):
        folder=m.persist(self.build(),CAT,root=self.audit)
        self.assertEqual(folder.stat().st_mode&0o777,0o700)
        self.assertEqual((folder/'report.json').stat().st_mode&0o777,0o600)
    def test_32_private_verify(self):
        folder=m.persist(self.terminal_doc(),CAT,root=self.audit)
        self.assertEqual(m.verify_persisted(folder,CAT)['sha256'],self.build()['sha256'])
    def test_33_replay_detects_modified_report(self):
        folder=m.persist(self.build(),CAT,root=self.audit)
        p=folder/'report.json'; data=f1.load(p.read_bytes());data['p8']='GO'
        p.write_bytes(f1.canonical(data))
        with self.assertRaises(m.Stop):m.verify_persisted(folder,CAT)
    def test_34_replay_detects_modified_manifest(self):
        folder=m.persist(self.build(),CAT,root=self.audit)
        p=folder/'manifest.json'; data=f1.load(p.read_bytes());data['report_sha256']='0'*64
        p.write_bytes(f1.canonical(data))
        with self.assertRaises(m.Stop):m.verify_persisted(folder,CAT)
    def test_35_replay_detects_extra_file(self):
        folder=m.persist(self.build(),CAT,root=self.audit)
        (folder/'extra').write_text('x')
        with self.assertRaises(m.Stop):m.verify_persisted(folder,CAT)
    def test_36_readonly_no_network(self):
        with patch('socket.socket',side_effect=AssertionError('network')):
            self.build()
    def test_37_persist_refuses_root(self):
        doc=self.build()
        with patch.object(m.os,'geteuid',return_value=0):
            with self.assertRaises(m.Stop):m.persist(doc,CAT,root=self.audit)
    def test_38_capabilities(self):
        c=m.capabilities();self.assertFalse(c['a9_global_generation_publication'])
    def test_39_cli_capabilities(self):
        run=subprocess.run([sys.executable,str(SCRIPT),'--capabilities'],
            cwd=REPO,env={**os.environ,'PYTHONPATH':'src:scripts'},
            capture_output=True,text=True)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertIn('"p8":"NO-GO"',run.stdout)
    def test_40_cli_build_persist_verify(self):
        self.result()
        unit_file=Path(self.temp.name)/'unit.json'
        unit_file.write_bytes(f1.canonical(self.unit))
        env={**os.environ,'PYTHONPATH':'src:scripts'}
        run=subprocess.run([sys.executable,str(SCRIPT),'--build',
            '--journal',str(self.folder),'--unit-file',str(unit_file),
            '--persist','--audit-root',str(self.audit)],cwd=REPO,
            env=env,capture_output=True,text=True)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertIn('R121_A10_REPLAY=PASS',run.stdout)
        folder=Path(next(v.split('=',1)[1] for v in run.stdout.splitlines()
                         if v.startswith('R121_A10_AUDIT_FOLDER=')))
        check=subprocess.run([sys.executable,str(SCRIPT),'--verify-report',str(folder)],
                             cwd=REPO,env=env,capture_output=True,text=True)
        self.assertEqual(check.returncode,0,check.stderr)
        self.assertIn('R121_REPLAY=PASS_SOURCE_AND_EXACT_A7_A8',check.stdout)
    def test_41_cli_refuse_partial_args(self):
        p=subprocess.run([sys.executable,str(SCRIPT),'--build'],cwd=REPO,
                         env={**os.environ,'PYTHONPATH':'src:scripts'},
                         capture_output=True,text=True)
        self.assertNotEqual(p.returncode,0)
    def test_42_cli_unit_not_canonical(self):
        unit_file=Path(self.temp.name)/'unit.json'
        unit_file.write_text('{"service_id":"FTP_DEV"}')
        p=subprocess.run([sys.executable,str(SCRIPT),'--build',
           '--journal',str(self.folder),'--unit-file',str(unit_file)],cwd=REPO,
           env={**os.environ,'PYTHONPATH':'src:scripts'},capture_output=True,text=True)
        self.assertNotEqual(p.returncode,0)
    def test_43_f14_report_binds_f13(self):
        d=self.build()
        report=f14.build(self.folder,CAT)
        self.assertEqual(d['f14_report_sha256'],f1.digest(f1.canonical(report)))
    def test_44_r58e_conservative_no_promotion(self):
        d=self.build()
        self.assertEqual(d['a6_supports_accepted'],0)
        self.assertTrue(d['a9_audit_only_not_global_store'])
    def test_45_reject_bool_index(self):
        self.unit['assessment_index']=True
        with self.assertRaises(m.Stop):self.build()
    def test_46_reject_synthetic_unit_extra(self):
        self.unit['a6']='MATCH'
        with self.assertRaises(m.Stop):self.build()

if __name__ == '__main__':unittest.main()
