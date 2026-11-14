"""R27 vertical: reuse del pipeline benigno, no red, sin acreditacion tecnica."""
from __future__ import annotations
import os
import subprocess
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.benign_review import (
    RID, ReviewError, analyze_selection, classify_local_attempt, execute_local_review)

SCENARIO=ROOT/'lab/p14-r26-session-v1/scenario.json'

class VerticalTests(unittest.TestCase):
    def setUp(self):
        self.scenario=read_fixed_scenario(SCENARIO)
    def test_original_prepared_state_remains_unselectable(self):
        a=analyze_selection(self.scenario)
        self.assertIsNone(a['a4_confirmed']['selected'])
        self.assertEqual(a['a4_hypothetical']['selected']['case_id'],'CASE_REFERENCE')
        self.assertEqual(a['a4_hypothetical']['eligible_count'],2)
    def test_durable_local_fixture_and_idempotent_replay(self):
        with TemporaryDirectory() as temp:
            p=Path(temp)/'journal'
            one=execute_local_review(self.scenario,p)
            two=execute_local_review(self.scenario,p)
            self.assertEqual(one,two)
            self.assertEqual(one['a5']['start_count_reserved'],1)
            self.assertEqual(one['a5']['state'],'RECORDED_LIMITED')
            self.assertEqual(one['a5']['outcome'],'BENIGN_EXIT_ZERO')
            self.assertEqual(one['a6']['classification'],'ND')
            self.assertFalse(one['a6']['technical_truth_accredited'])
            self.assertFalse(one['vm_checks_executed'])

    def test_crash_after_start_intent_recovers_without_second_start(self):
        from ardrec.benign_pipeline import BenignPipeline
        with TemporaryDirectory() as temp:
            root=Path(temp)/'journal'
            script=("from ardrec.benign_pipeline import BenignPipeline; "
                    "p=BenignPipeline("+repr(str(root))+"); "
                    "p.submit("+repr(RID)+", 'ok',deadline_ms=1000,output_cap=4096); "
                    "p.execute("+repr(RID)+")")
            env=dict(os.environ)
            env['ARDREC_DEV_FAILPOINT_AFTER_START_INTENT']='1'
            env['PYTHONPATH']=str(ROOT/'src')+os.pathsep+env.get('PYTHONPATH','')
            process=subprocess.run([sys.executable,'-B','-c',script],
                                   env=env,capture_output=True,timeout=10,check=False)
            self.assertEqual(process.returncode,77,process.stderr.decode(errors='replace'))
            p=BenignPipeline(root)
            self.assertIn(RID,p.recover())
            before=p.read(RID)
            self.assertEqual(before['state'],'RECOVERY_UNCERTAIN')
            self.assertEqual(before['start_count'],1)
            p.execute(RID)  # No second attempt permitted.
            after=p.read(RID)
            self.assertEqual(after['start_count'],1)
            self.assertEqual(after['state'],'RECOVERY_UNCERTAIN')
            self.assertFalse(p.verify(RID)['artifacts_verified'])

    def test_tampered_artifact_rejected(self):
        from ardrec.benign_pipeline import BenignPipeline, VerificationError
        with TemporaryDirectory() as temp:
            root=Path(temp)/'journal'
            p=BenignPipeline(root)
            p.submit(RID,'ok',deadline_ms=1000,output_cap=4096)
            p.execute(RID)
            self.assertTrue(p.verify(RID)['artifacts_verified'])
            artifact=p.read(RID)['result']['artifacts']['stdout']['name']
            (root/'artifacts'/artifact).write_bytes(b'TAMPER')
            with self.assertRaises(VerificationError): p.verify(RID)

    def test_support_wrong_binding_rejected(self):
        record={'id':RID,'state':'RECORDED_LIMITED',
                'p8_operational':'NO-GO','result':{'schema':'ardrec-p9-p12-benign-pipeline-v1',
                'outcome':'BENIGN_EXIT_ZERO'}}
        receipt={'request_id':RID,'p8_operational':'NO-GO',
                 'artifacts_verified':True,'event_head_sha256':'a'*64}
        with self.assertRaises(ReviewError):
            classify_local_attempt(rid=RID,record=record,verification=receipt,
                                   service_id='FTP_DEV',case_id='CASE_REFERENCE')
        receipt['request_id']='wrong'
        with self.assertRaises(ReviewError):
            classify_local_attempt(rid=RID,record=record,verification=receipt,
                                   service_id='SSH_DEV',case_id='CASE_REFERENCE')
    def test_support_integrity_not_authority(self):
        record={'id':RID,'state':'RECORDED_LIMITED','p8_operational':'NO-GO',
                'result':{'schema':'ardrec-p9-p12-benign-pipeline-v1','outcome':'BENIGN_EXIT_ZERO'}}
        receipt={'request_id':RID,'p8_operational':'NO-GO','artifacts_verified':True,
                 'event_head_sha256':'a'*64}
        v=classify_local_attempt(rid=RID,record=record,verification=receipt,
                                 service_id='SSH_DEV',case_id='CASE_REFERENCE')
        self.assertTrue(v['support_integrity_verified'])
        self.assertIsNone(v['technical_evidence'])
        self.assertEqual(v['classification'],'ND')
        receipt['artifacts_verified']=False
        with self.assertRaises(ReviewError):
            classify_local_attempt(rid=RID,record=record,verification=receipt,
                                   service_id='SSH_DEV',case_id='CASE_REFERENCE')
    def test_uncertain_state_is_not_started_twice(self):
        record={'id':RID,'state':'RECOVERY_UNCERTAIN','p8_operational':'NO-GO'}
        receipt={'request_id':RID,'p8_operational':'NO-GO','artifacts_verified':False,
                 'event_head_sha256':'a'*64}
        v=classify_local_attempt(rid=RID,record=record,verification=receipt,
                                 service_id='SSH_DEV',case_id='CASE_REFERENCE')
        self.assertEqual(v['classification'],'ND')
        self.assertEqual(v['reason'],'ATTEMPT_UNRESOLVED_NO_RETRY')

if __name__=='__main__': unittest.main()
