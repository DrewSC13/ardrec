"""R43: pruebas reales del fixture local y contrato de NO-GO; ninguna VM/red."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import os
import tempfile
import unittest
from unittest import mock

from ardrec.coordination import r43_local_cycle as r43
from ardrec.coordination import r424_evidence_tui as r424
from ardrec.coordination import r425_classic_evidence_dashboard as r425
from ardrec.coordination import demo_session, development_cycle
from ardrec.persistence import development_receipt

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT/'lab/p14-r26-session-v1/scenario.json'


def physical():
    return dict(source_kind='REAL_READONLY_SSH_SNAPSHOT',
                r422_report_sha256=r424.R422_PIN,
                r423_report_sha256=r424.R423_PIN,
                route='DIRECT_ENS3_EXPECTED', arp='ABSENT',
                tx_snapshot=0, rx_snapshot=15,
                tap_frames_r422=0, bridge_frames_r422=0,
                guest_ping_reported_transmitted_r422=1,
                isolation_proven=False,p8_operational='NO-GO')


class RootGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)
        self.r422=self.base/'r422';self.r423=self.base/'r423'
        self.journal=self.base/'r43-local-cycle-20261115T013900Z-123'

    def check(self,path=None):
        return r43.private_journal_guard(self.r422,self.r423,path or self.journal)

    def test_valid_new_private_target(self): self.assertIsNone(self.check())
    def test_main_pin(self): self.assertEqual(r43.BASE_MAIN,'2169c2bd24f87efe03357d90a41843a2d900e619')
    def test_reject_relative(self):
        with self.assertRaises(r43.LocalCycleError):self.check(Path('r43-local-cycle-20261115T013900Z-123'))
    def test_reject_wrong_name(self):
        with self.assertRaises(r43.LocalCycleError):self.check(self.base/'attempts')
    def test_reject_write_in_git(self):
        with self.assertRaises(r43.LocalCycleError):self.check(Path('/home/cicada/Development/GitHub/ardrec/attempts'))
    def test_reject_other_parent(self):
        with self.assertRaises(r43.LocalCycleError):
            r43.private_journal_guard(self.r422,self.base/'other'/'r423',self.journal)
    def test_reject_symlink_root(self):
        target=self.base/'other';target.mkdir()
        self.journal.symlink_to(target,target_is_directory=True)
        with self.assertRaises(r43.LocalCycleError):self.check()
    def test_reject_public_parent(self):
        self.base.chmod(0o755)
        try:
            with self.assertRaises(r43.LocalCycleError):self.check()
        finally:self.base.chmod(0o700)
    def test_reject_existing_open_root(self):
        self.journal.mkdir();self.journal.chmod(0o755)
        try:
            with self.assertRaises(r43.LocalCycleError):self.check()
        finally:self.journal.chmod(0o700)
    def test_existing_safe_directory_allowed(self):
        self.journal.mkdir(mode=0o700)
        self.assertIsNone(self.check())
    def test_reject_incorrect_path_type(self):
        with self.assertRaises(r43.LocalCycleError):self.check(str(self.journal))


class LocalIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)
        self.r422=self.base/'r422';self.r423=self.base/'r423'
        self.journal=self.base/'r43-local-cycle-20261115T013900Z-567'
        self.patch=mock.patch.object(r424,'read_physical',return_value=physical())
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def run_cycle(self):
        return r43.execute_local_cycle(self.r422,self.r423,FIXTURE,self.journal)

    def test_a5_local_benign_and_a9_persisted(self):
        report,bundle=self.run_cycle()
        self.assertEqual(report['a10']['stages'][4]['status'],'RECORDED_LIMITED')
        self.assertEqual(report['r27']['a5_start_count'],1)
        self.assertTrue(report['a9']['durable_local_receipt'])
        self.assertTrue((self.journal/development_receipt.FILE_NAME).is_file())
        self.assertTrue(r424.verify_bundle(bundle))
        self.assertIsNone(r425.validate_binding(report,bundle))
        self.assertEqual(bundle['development']['source_kind'],
                         'SYNTHETIC_AND_LOCAL_BENIGN_A1_A10_DEVELOPMENT_ONLY')

    def test_no_fake_service_pentesting_or_risk(self):
        r,b=self.run_cycle()
        self.assertEqual(r['a10']['stages'][5]['status'],'ND')
        self.assertEqual(r['a10']['stages'][5]['source'],'LOCAL_BENIGN_FIXTURE')
        self.assertFalse(r['operational_dispatch'])
        self.assertIsNone(r['final_risk'])
        self.assertIsNone(r['a7']['confirmed_rf'])
        self.assertIsNone(r['a9']['published_generation'])
        self.assertFalse(b['real_pentesting_executed'])
        self.assertFalse(b['isolation_proven'])
        self.assertEqual(b['p8_operational'],'NO-GO')

    def test_same_root_idempotent_no_second_start(self):
        r1,b1=self.run_cycle()
        r2,b2=self.run_cycle()
        self.assertEqual(r1['sha256'],r2['sha256'])
        self.assertEqual(b1['sha256'],b2['sha256'])
        self.assertEqual(r43.verify_local_run(self.journal,r2)['start_count'],1)

    def test_journal_tamper_denied(self):
        r,b=self.run_cycle()
        f=self.journal/development_receipt.FILE_NAME
        f.write_text('{}',encoding='utf-8')
        with self.assertRaises((ValueError,RuntimeError)):
            r43.verify_local_run(self.journal,r)

    def test_journal_symlink_denied(self):
        r,b=self.run_cycle()
        f=self.journal/development_receipt.FILE_NAME
        target=self.journal/'copy.json';target.write_bytes(f.read_bytes())
        f.unlink();f.symlink_to(target)
        with self.assertRaises(r43.LocalCycleError):r43.verify_local_run(self.journal,r)

    def test_visual_r38_three_panels_no_change(self):
        r,b=self.run_cycle()
        frame='\n'.join(r425.render_frame(r,b,width=120,height=32))
        self.assertIn('ALGORITMOS',frame)
        self.assertIn('ESTADO / AUDITORIA SSH',frame)
        self.assertIn('RECORDED_LIMITED',frame)
        self.assertIn('P8:NO-GO',frame)
        self.assertIn('RF:ND',frame)

    def test_rehashed_local_claim_changed_rejected(self):
        r,b=self.run_cycle()
        bad=deepcopy(b)
        bad['development']['local_benign_attempt']['start_count']=2
        r424.seal(bad)
        with self.assertRaises(r424.EvidenceViewError):r424.verify_bundle(bad)

    def test_rehashed_fake_vm_source_rejected(self):
        r,b=self.run_cycle()
        bad=deepcopy(b)
        bad['development']['stages'][4]['source']='REAL_SSH_PENTEST'
        r424.seal(bad)
        with self.assertRaises(r424.EvidenceViewError):r424.verify_bundle(bad)

    def test_rehashed_p8_go_rejected(self):
        r,b=self.run_cycle()
        bad=deepcopy(b);bad['p8_operational']='GO';r424.seal(bad)
        with self.assertRaises(r424.EvidenceViewError):r424.verify_bundle(bad)


class PreviewCompatibilityTests(unittest.TestCase):
    def test_preview_not_marked_local(self):
        scenario=demo_session.read_fixed_scenario(FIXTURE)
        report=development_cycle.build_development_cycle(scenario)
        bundle=r424.make_bundle(physical(),report)
        self.assertTrue(r424.verify_bundle(bundle))
        self.assertEqual(bundle['development']['source_kind'],
                         'SYNTHETIC_A1_A10_DEVELOPMENT_ONLY')
        self.assertNotIn('local_benign_attempt',bundle['development'])

    def test_preview_cannot_rehash_local_marker(self):
        scenario=demo_session.read_fixed_scenario(FIXTURE)
        report=development_cycle.build_development_cycle(scenario)
        b=r424.make_bundle(physical(),report)
        b['development']['local_benign_attempt']={'state':'RECORDED_LIMITED'}
        r424.seal(b)
        with self.assertRaises(r424.EvidenceViewError):r424.verify_bundle(b)

    def test_unverified_development_source_denied(self):
        scenario=demo_session.read_fixed_scenario(FIXTURE)
        report=development_cycle.build_development_cycle(scenario)
        report['source_kind']='REAL_VM'
        from ardrec.analytics.exact_preview import digest
        report['sha256']=digest({k:v for k,v in report.items() if k!='sha256'})
        with self.assertRaises(r424.EvidenceViewError):r424.make_bundle(physical(),report)

    def test_preview_path_does_not_invoke_pipeline(self):
        scenario=demo_session.read_fixed_scenario(FIXTURE)
        with mock.patch.object(development_cycle,'execute_local_review') as spy:
            report=development_cycle.build_development_cycle(scenario)
            r424.make_bundle(physical(),report)
            spy.assert_not_called()


if __name__=='__main__': unittest.main()
