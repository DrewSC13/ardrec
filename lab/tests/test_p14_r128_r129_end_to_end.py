"""R128/R129 B7: genuine F13/F14/R58-E/A10 replay, no real network actions."""
from __future__ import annotations
import copy
from datetime import datetime,timezone
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_f5_lifecycle_readiness as f5
from ardrec.coordination import r115_f12_ftp_budget_preflight as f12
from ardrec.coordination import r115_f13_ftp_a5_journal as f13
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r121_ftp_case_chain as r121
from ardrec.coordination import r122_operational_boundary as r122
from ardrec.coordination import r123_guarded_window as r123
from ardrec.coordination import r124_root_deny_readback as r124
from ardrec.coordination import r125_integrated_acceptance as r125
from ardrec.coordination import r126_operational_controller as r126
from ardrec.coordination import r128_ftp_pilot as r128
from ardrec.coordination import r129_a6_a10_recovery as r129
from ardrec.coordination import r128_r129_end_to_end as b7
from test_p14_r122_operational_boundary import synthetic_capture
from test_p14_r124_root_deny_readback import Fake

ROOT=Path(__file__).resolve().parents[2]
CAT=(ROOT/'lab/operational-catalog-v1/catalog.json').read_bytes()
HEAD='7c1bf90c36b17ace9b670b360b6c183770297bec'
NOW=datetime(2026,11,21,22,0,0,tzinfo=timezone.utc)


class FakeSocket:
    family=socket.AF_INET
    type=socket.SOCK_STREAM
    def __init__(self,parts=(b'220 Ready for service\r\n',),*,error=None,peer=('10.203.31.2',21)):
        self.parts=list(parts)
        self.error=error
        self.peer=peer
        self.recv_count=0
        self.timeouts=[]
    def getpeername(self):return self.peer
    def settimeout(self,v):self.timeouts.append(v)
    def recv(self,size):
        self.recv_count+=1
        if self.error is not None:raise self.error
        if not self.parts:return b''
        value=self.parts.pop(0)
        if len(value)>size:self.parts.insert(0,value[size:])
        return value[:size]


class Clock:
    def __init__(self):self.t=0.0
    def __call__(self):self.t+=.001;return self.t


@unittest.skipIf(os.geteuid()==0,'F13 and A10 require non-root owner')
class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ardrec-b7-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        p=patch.object(f5,'ROOT',self.root/'captures')
        p.start();self.addCleanup(p.stop)
        f5.ROOT.mkdir(mode=0o700)
        capture=synthetic_capture()
        folder=f5.save_private(capture,f5.report(capture),root=f5.ROOT)
        boundary=r122.build(capture_folder=folder,catalog_raw=CAT,head=HEAD,now=NOW)
        plan=r123.plan(boundary=boundary,catalog_raw=CAT,now=NOW)
        readback=r124.inspect(head=HEAD,now=NOW,run=Fake())
        integrated=r125.build(head=HEAD,catalog_raw=CAT,now=NOW,boundary=boundary,
                              plan=plan,root_report=readback)
        handoff=r126.review(head=HEAD,now=NOW,root_report=readback,
                            integrated_report=integrated)
        self.intent=f13.make_intent(case_id='FTP-T01-S01-01',session_id='E2E_B7',
            assessment_index=1,attempt_id='ATT_E2E_B7',head=HEAD,
            contract_sha256='b'*64,scope_authorization_sha256='c'*64,
            p8_window_sha256='d'*64)
        self.profile=f12.DRAFT_BUDGET.copy()
        self.prep=r128.prepare(handoff=handoff,intent=self.intent,profile=self.profile)
        self.unit={'service_id':'FTP_DEV','case_id':'FTP_T01_S01_01',
             'assessment_index':1,'initial_risk':'1/2',
             'normalized_criticality':'1/3','replacement_risk':'1/4',
             'evidence':[]}
        self.journal=r128.reserve_prepared(preparation=self.prep,
            intent=self.intent,profile=self.profile,root=self.root/'journal')

    def run_reconcile(self):
        return b7.reconcile(preparation=self.prep,journal=self.journal,
                             declared_unit=self.unit,catalog_raw=CAT)

    def consume(self,sock=None,guard=None):
        sock=FakeSocket() if sock is None else sock
        if guard is None:guard=lambda:True
        return f13.consume_reserved(self.journal,sock,current_p8_guard=guard,
                                     monotonic=Clock())

    def test_01_capabilities_fail_closed(self):
        info=b7.capabilities()
        self.assertEqual(info['p8'],'NO-GO')
        self.assertFalse(info['physical_ftp_dispatch_implemented'])
        self.assertFalse(info['global_a9_publication_performed'])

    def test_02_reservation_can_be_replayed(self):
        result=self.run_reconcile()
        self.assertEqual(result['journal_status'],'RESERVED_NO_RETRY')
        self.assertFalse(result['a5_attempt_consumed'])

    def test_03_algorithm_chain_complete(self):
        result=self.run_reconcile()
        self.assertEqual([r['algorithm'] for r in result['stages']],list(b7.STAGES))
        self.assertEqual(result['chain_head_sha256'],result['stages'][-1]['sha256'])

    def test_04_reserved_no_false_a6(self):
        result=self.run_reconcile()
        self.assertEqual(result['a6'],'ND')
        self.assertEqual(result['a6_supports_accepted'],0)

    def test_05_math_exact_interval(self):
        result=self.run_reconcile()
        self.assertEqual(len(result['a7_exact_interval']),2)
        self.assertIsNone(result['a7_confirmed_rf'])

    def test_06_reserved_no_a9(self):
        self.assertIsNone(self.run_reconcile()['a9_global_generation'])

    def test_07_verify_report(self):
        r=self.run_reconcile()
        self.assertTrue(b7.verify(r,preparation=self.prep,journal=self.journal,
                                  declared_unit=self.unit,catalog_raw=CAT))

    def test_08_changed_report_fails(self):
        r=self.run_reconcile();r['a6']='VERDADERO'
        with self.assertRaises(b7.Stop):
            b7.verify(r,preparation=self.prep,journal=self.journal,
                      declared_unit=self.unit,catalog_raw=CAT)

    def test_09_successful_fake_ftp_greeting_is_candidate_only(self):
        sock=FakeSocket()
        self.consume(sock)
        self.assertEqual(sock.recv_count,1)
        r=self.run_reconcile()
        self.assertTrue(r['a5_attempt_consumed'])
        self.assertTrue(r['a5_result_candidate'])
        self.assertEqual(r['a6'],'ND')
        self.assertIsNone(r['a9_global_generation'])
        self.assertEqual(r['journal_status'],'RESULT_CANDIDATE_ONLY')

    def test_10_no_retry_after_result(self):
        self.consume()
        sock=FakeSocket()
        with self.assertRaises(f13.Stop):self.consume(sock)
        self.assertEqual(sock.recv_count,0)

    def test_11_421_is_not_technical_truth(self):
        self.consume(FakeSocket((b'421 Not available\r\n',)))
        r=self.run_reconcile()
        self.assertEqual(r['a6'],'ND')
        self.assertEqual(r['journal_status'],'RESULT_CANDIDATE_ONLY')

    def test_12_malformed_is_candidate(self):
        self.consume(FakeSocket((b'not FTP\r\n',)))
        self.assertEqual(self.run_reconcile()['a6'],'ND')

    def test_13_server_closes_without_220(self):
        self.consume(FakeSocket((b'',)))
        self.assertEqual(self.run_reconcile()['a6'],'ND')

    def test_14_guard_denial_is_irreversible(self):
        with self.assertRaises(f13.Stop):self.consume(guard=lambda:False)
        r=self.run_reconcile()
        self.assertEqual(r['journal_status'],'FAILED_NO_RETRY')
        self.assertFalse(r['a5_result_candidate'])
        with self.assertRaises(f13.Stop):self.consume()

    def test_15_socket_failure_is_irreversible(self):
        with self.assertRaises(f13.Stop):
            self.consume(FakeSocket(error=ConnectionResetError('offline-test')))
        self.assertEqual(self.run_reconcile()['journal_status'],'FAILED_NO_RETRY')

    def test_16_wrong_peer_consumes_attempt(self):
        with self.assertRaises(f13.Stop):
            self.consume(FakeSocket(peer=('10.203.31.99',21)))
        self.assertEqual(self.run_reconcile()['journal_status'],'FAILED_NO_RETRY')

    def test_17_simulated_sigkill_after_reservation(self):
        # No cleanup, no automatic retry, no assertion of a performed capture.
        self.assertEqual(self.run_reconcile()['journal_status'],'RESERVED_NO_RETRY')
        with self.assertRaises(r128.Stop):
            r128.reserve_prepared(preparation=self.prep,intent=self.intent,
                                  profile=self.profile,root=self.root/'journal')

    def test_18_simulated_sigkill_after_spent(self):
        from ardrec.coordination import r115_dev_admission_contract as f1
        from ardrec.coordination import r115_f2_a3_current_sources as f2
        state=f13.inspect(self.journal)
        spent={'schema':f13.SCHEMA+'-spent',
               'reservation_sha256':state['reservation_sha256'],
               'status':'ATTEMPT_CONSUMED_NO_RETRY','a6':'ND','p8':'NO-GO'}
        raw=f1.canonical(spent)
        f2.exclusive(self.journal/'spent.json',raw)
        f2.exclusive(self.journal/'spent.manifest.json',f1.canonical({
            'schema':f13.SCHEMA+'-manifest','file':'spent.json',
            'sha256':f1.digest(raw),'case_key':state['case_key'],'p8':'NO-GO'}))
        self.assertEqual(self.run_reconcile()['journal_status'],
                         'ATTEMPT_CONSUMED_UNRESOLVED')
        with self.assertRaises(f13.Stop):self.consume()

    def test_19_tamper_source_rejected(self):
        (self.journal/'reservation.json').write_text('{}\n')
        with self.assertRaises(b7.Stop):self.run_reconcile()

    def test_20_tamper_manifest_rejected(self):
        (self.journal/'reservation.manifest.json').write_text('{}\n')
        with self.assertRaises(b7.Stop):self.run_reconcile()

    def test_21_wrong_case_identity_rejected(self):
        unit=dict(self.unit);unit['case_id']='FTP_T01_S02_02'
        with self.assertRaises(b7.Stop):
            b7.reconcile(preparation=self.prep,journal=self.journal,
                         declared_unit=unit,catalog_raw=CAT)

    def test_22_wrong_risk_type_rejected(self):
        unit=dict(self.unit);unit['initial_risk']=0.5
        with self.assertRaises(b7.Stop):
            b7.reconcile(preparation=self.prep,journal=self.journal,
                         declared_unit=unit,catalog_raw=CAT)

    def test_23_forged_preparation_rejected(self):
        bad=dict(self.prep);bad['dispatch']=True
        with self.assertRaises(b7.Stop):
            b7.reconcile(preparation=bad,journal=self.journal,
                         declared_unit=self.unit,catalog_raw=CAT)

    def test_24_wrong_head_rejected(self):
        bad=dict(self.prep);bad['head']='0'*40
        with self.assertRaises(b7.Stop):
            b7.reconcile(preparation=bad,journal=self.journal,
                         declared_unit=self.unit,catalog_raw=CAT)

    def test_25_wrong_catalog_rejected(self):
        with self.assertRaises(b7.Stop):
            b7.reconcile(preparation=self.prep,journal=self.journal,
                         declared_unit=self.unit,catalog_raw=b'{}')

    def test_26_persist_and_recover_nd(self):
        result=b7.persist_a10(preparation=self.prep,journal=self.journal,
                 declared_unit=self.unit,catalog_raw=CAT,audit_root=self.root/'a10')
        self.assertEqual(result['a6'],'ND')
        self.assertIsNone(result['a9_generation'])
        self.assertFalse(result['global_durable_store_opened'])
        self.assertTrue(Path(result['a10_folder']).is_dir())

    def test_27_persist_after_fake_greeting(self):
        self.consume()
        r=b7.persist_a10(preparation=self.prep,journal=self.journal,
              declared_unit=self.unit,catalog_raw=CAT,audit_root=self.root/'a10')
        self.assertEqual(r['source_journal_status'],'RESULT_CANDIDATE_ONLY')
        self.assertTrue(r['a5_attempt_consumed'])

    def test_28_recover_rejects_corrupt_private_a10(self):
        r=b7.persist_a10(preparation=self.prep,journal=self.journal,
              declared_unit=self.unit,catalog_raw=CAT,audit_root=self.root/'a10')
        (Path(r['a10_folder'])/'manifest.json').write_text('{}\n')
        with self.assertRaises(r129.Stop):r129.verify_private(Path(r['a10_folder']),CAT)

    def test_29_recover_rejects_altered_original_journal(self):
        r=b7.persist_a10(preparation=self.prep,journal=self.journal,
              declared_unit=self.unit,catalog_raw=CAT,audit_root=self.root/'a10')
        (self.journal/'reservation.json').write_text('{}\n')
        with self.assertRaises((r129.Stop,r121.Stop)):
            r129.verify_private(Path(r['a10_folder']),CAT)

    def test_30_repeated_a10_does_not_change_a5_spend(self):
        self.consume()
        first=b7.persist_a10(preparation=self.prep,journal=self.journal,
            declared_unit=self.unit,catalog_raw=CAT,audit_root=self.root/'a10')
        second=b7.persist_a10(preparation=self.prep,journal=self.journal,
            declared_unit=self.unit,catalog_raw=CAT,audit_root=self.root/'a10')
        self.assertEqual(first['end_to_end_sha256'],second['end_to_end_sha256'])
        self.assertNotEqual(first['a10_folder'],second['a10_folder'])
        self.assertEqual(f13.inspect(self.journal)['status'],'RESULT_CANDIDATE_ONLY')

    def test_31_private_mode_rejected(self):
        a=self.root/'a10';a.mkdir(mode=0o755)
        a.chmod(0o755)
        self.assertEqual(a.stat().st_mode & 0o777, 0o755)
        with self.assertRaises((r129.Stop,b7.Stop,r121.Stop)):
            b7.persist_a10(preparation=self.prep,journal=self.journal,
                declared_unit=self.unit,catalog_raw=CAT,audit_root=a)

    def test_32_symlink_private_store_rejected(self):
        actual=self.root/'real';actual.mkdir(mode=0o700)
        alias=self.root/'a10';alias.symlink_to(actual)
        with self.assertRaises((r129.Stop,b7.Stop,r121.Stop)):
            b7.persist_a10(preparation=self.prep,journal=self.journal,
                declared_unit=self.unit,catalog_raw=CAT,audit_root=alias)

    def test_33_unprivileged_readback_is_source_only(self):
        report=self.run_reconcile()
        self.assertFalse(report['root_witness_accepted'])
        self.assertFalse(report['traffic_enabled_by_b7'])
        self.assertEqual(report['network_connections_by_b7'],0)

    def test_34_no_separate_A9_store_access(self):
        with patch('ardrec.persistence.DurableStore',side_effect=AssertionError('A9_OPENED'),create=True):
            self.assertEqual(self.run_reconcile()['a9_global_generation'],None)

    def test_35_f13_failure_still_has_replayable_a10(self):
        with self.assertRaises(f13.Stop):self.consume(guard=lambda:False)
        r=b7.persist_a10(preparation=self.prep,journal=self.journal,
            declared_unit=self.unit,catalog_raw=CAT,audit_root=self.root/'a10')
        self.assertEqual(r['a6'],'ND')
        self.assertEqual(r['source_journal_status'],'FAILED_NO_RETRY')

    def test_36_candidate_220_not_vulnerability(self):
        self.consume()
        report=self.run_reconcile()
        self.assertEqual(report['a6_supports_accepted'],0)
        self.assertIsNone(report['a7_confirmed_rf'])
        self.assertIsNone(report['a8_transition_applied'])

    def test_37_extra_f13_file_fails(self):
        (self.journal/'intrusion.json').write_text('{}')
        with self.assertRaises(b7.Stop):self.run_reconcile()

    def test_38_report_replay_after_result(self):
        self.consume()
        report=self.run_reconcile()
        self.assertTrue(b7.verify(report,preparation=self.prep,journal=self.journal,
                                  declared_unit=self.unit,catalog_raw=CAT))

    def test_39_wrong_unit_assessment_rejected(self):
        bad=dict(self.unit);bad['assessment_index']=2
        with self.assertRaises(b7.Stop):
            b7.reconcile(preparation=self.prep,journal=self.journal,
                         declared_unit=bad,catalog_raw=CAT)

    def test_40_no_authorized_session_assumed(self):
        report=self.run_reconcile()
        self.assertFalse(report['a5_result_candidate'])
        self.assertEqual(report['p8'],'NO-GO')

    def test_41_cli_capabilities(self):
        path=ROOT/'scripts/ardrec_p14_r128_r129_end_to_end.py'
        c=subprocess.run([sys.executable,'-B',str(path),'--capabilities'],
            cwd=ROOT,env={**os.environ,'PYTHONPATH':'src'},
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(c.returncode,0,c.stderr.decode())
        self.assertIn(b'NO-GO',c.stdout)

    def test_42_cli_missing_sources_fails(self):
        path=ROOT/'scripts/ardrec_p14_r128_r129_end_to_end.py'
        c=subprocess.run([sys.executable,'-B',str(path),'--replay'],
            cwd=ROOT,env={**os.environ,'PYTHONPATH':'src'},
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(c.returncode,2)
        self.assertIn(b'REPLAY_INPUTS_REQUIRED',c.stdout)

    def test_43_cli_rejects_private_json_world_readable(self):
        from importlib.util import spec_from_file_location,module_from_spec
        path=ROOT/'scripts/ardrec_p14_r128_r129_end_to_end.py'
        spec=spec_from_file_location('b7_cli',path)
        module=module_from_spec(spec);spec.loader.exec_module(module)
        p=self.root/'readable.json';p.write_bytes(b'{}\n');p.chmod(0o644)
        with self.assertRaises(module.Stop):module.read_private(p)

    def test_44_cli_accepts_canonical_private_json(self):
        from importlib.util import spec_from_file_location,module_from_spec
        path=ROOT/'scripts/ardrec_p14_r128_r129_end_to_end.py'
        spec=spec_from_file_location('b7_cli',path)
        module=module_from_spec(spec);spec.loader.exec_module(module)
        p=self.root/'data.json';p.write_bytes(b'{"case":"ok"}\n');p.chmod(0o600)
        self.assertEqual(module.read_private(p),{'case':'ok'})

    def test_45_cli_rejects_symlink_private_json(self):
        from importlib.util import spec_from_file_location,module_from_spec
        path=ROOT/'scripts/ardrec_p14_r128_r129_end_to_end.py'
        spec=spec_from_file_location('b7_cli',path)
        module=module_from_spec(spec);spec.loader.exec_module(module)
        p=self.root/'target.json';p.write_bytes(b'{}\n');p.chmod(0o600)
        link=self.root/'alias.json';link.symlink_to(p)
        with self.assertRaises(module.Stop):module.read_private(link)


if __name__=='__main__':unittest.main()
