"""Offline R42.4 contract tests; no actual machine/network work."""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import unittest
from unittest import mock
from ardrec.coordination import r424_evidence_tui as r424
from ardrec.coordination import r423_guest_path_inventory as r423


def physical():
    return dict(source_kind='REAL_READONLY_SSH_SNAPSHOT',
        r422_report_sha256=r424.R422_PIN,r423_report_sha256=r424.R423_PIN,
        route='DIRECT_ENS3_EXPECTED',arp='ABSENT',tx_snapshot=0,rx_snapshot=15,
        tap_frames_r422=0,bridge_frames_r422=0,
        guest_ping_reported_transmitted_r422=1,
        isolation_proven=False,p8_operational='NO-GO')


def development():
    return {'p8_operational':'NO-GO','operational_dispatch':False,
            'vm_checks_executed':False,'final_risk':None,
            'a9':{'published_generation':None},
            'session_id':'DEV_TUTOR_001','sha256':'a'*64,
            'a10':{'stages':[{'algorithm':'A'+str(i),'status':'NOT_EXECUTED',
                             'source':'SYNTHETIC_FIXTURE','detail':'fixture '+str(i)}
                            for i in range(1,11)]}}


class R424Tests(unittest.TestCase):
    def bundle(self):
        with mock.patch.object(r424.dashboard_tui,'validate_dashboard_report'), \
             mock.patch.object(r424.development_cycle,'verify_development_cycle'):
            return r424.make_bundle(physical(),development())

    def test_main_pin(self):
        self.assertEqual(r424.MAIN_PIN,'b67550840b3b30f29361654bfed3d573a7167e59')

    def test_real_and_synthetic_separated(self):
        b=self.bundle()
        self.assertEqual(b['physical']['source_kind'],'REAL_READONLY_SSH_SNAPSHOT')
        self.assertEqual(b['development']['source_kind'],'SYNTHETIC_A1_A10_DEVELOPMENT_ONLY')
        self.assertTrue(r424.verify_bundle(b))

    def test_tui_has_10_stages(self):
        self.assertEqual(sum(line.lstrip(' >').startswith('A'+str(i)+' ') for line in
                             r424.lines(self.bundle()) for i in range(1,11)),10)

    def test_banner_and_nogo(self):
        s='\n'.join(r424.lines(self.bundle()))
        self.assertIn('P8 NO-GO',s)
        self.assertIn('DESARROLLO SINTETICO',s)
        self.assertIn('TX: 0',s)
        self.assertIn('ARP: ABSENT',s)

    def test_selected_detail(self):
        self.assertIn('DETALLE SELECCIONADO: A10','\n'.join(r424.lines(self.bundle(),9)))

    def test_tampered_packet_summary_rejected(self):
        bad=physical();bad['tap_frames_r422']=1
        with self.assertRaises(r424.EvidenceViewError):
            with mock.patch.object(r424.dashboard_tui,'validate_dashboard_report'), \
                 mock.patch.object(r424.development_cycle,'verify_development_cycle'):
                r424.make_bundle(bad,development())

    def test_tampered_snapshot_provenance_rejected(self):
        bad=physical();bad['r423_report_sha256']='b'*64
        with self.assertRaises(r424.EvidenceViewError):
            with mock.patch.object(r424.dashboard_tui,'validate_dashboard_report'), \
                 mock.patch.object(r424.development_cycle,'verify_development_cycle'):
                r424.make_bundle(bad,development())

    def test_fake_p8_go_rejected(self):
        bad=physical();bad['p8_operational']='GO'
        with self.assertRaises(r424.EvidenceViewError):
            with mock.patch.object(r424.dashboard_tui,'validate_dashboard_report'), \
                 mock.patch.object(r424.development_cycle,'verify_development_cycle'):
                r424.make_bundle(bad,development())

    def test_false_development_dispatch_rejected(self):
        r=development();r['operational_dispatch']=True
        with self.assertRaises(r424.EvidenceViewError):
            with mock.patch.object(r424.dashboard_tui,'validate_dashboard_report'), \
                 mock.patch.object(r424.development_cycle,'verify_development_cycle'):
                r424.make_bundle(physical(),r)

    def test_false_generation_rejected(self):
        r=development();r['a9']['published_generation']=99
        with self.assertRaises(r424.EvidenceViewError):
            with mock.patch.object(r424.dashboard_tui,'validate_dashboard_report'), \
                 mock.patch.object(r424.development_cycle,'verify_development_cycle'):
                r424.make_bundle(physical(),r)

    def test_unordered_stages_rejected(self):
        r=development();r['a10']['stages'].reverse()
        with self.assertRaises(r424.EvidenceViewError):
            with mock.patch.object(r424.dashboard_tui,'validate_dashboard_report'), \
                 mock.patch.object(r424.development_cycle,'verify_development_cycle'):
                r424.make_bundle(physical(),r)

    def test_digest_mutation_rejected(self):
        b=self.bundle();b['physical']['tx_snapshot']=1
        with self.assertRaises(r424.EvidenceViewError):r424.verify_bundle(b)

    def test_new_digest_false_go_rejected(self):
        b=self.bundle();b['p8_operational']='GO';r424.seal(b)
        with self.assertRaises(r424.EvidenceViewError):r424.verify_bundle(b)

    def test_new_digest_false_real_pentest_rejected(self):
        b=self.bundle();b['real_pentesting_executed']=True;r424.seal(b)
        with self.assertRaises(r424.EvidenceViewError):r424.verify_bundle(b)

    def test_new_digest_false_isolation_rejected(self):
        b=self.bundle();b['isolation_proven']=True;r424.seal(b)
        with self.assertRaises(r424.EvidenceViewError):r424.verify_bundle(b)

    def test_no_execution_in_views(self):
        b=self.bundle();s='\n'.join(r424.lines(b));self.assertIn('Pentesting real NO EJECUTADO',s)

    def test_selection_bounds(self):
        for selected in (-1,10,True):
            with self.assertRaises(r424.EvidenceViewError):r424.lines(self.bundle(),selected)

    def test_width_bounds(self):
        for width in (-1,39,301,True):
            with self.assertRaises(r424.EvidenceViewError):r424.lines(self.bundle(),width=width)

    def test_physical_report_binding(self):
        obs={'tap':{'observed':{'frames':0}},'bridge':{'observed':{'frames':0}}}
        wit={'sha256':r424.R422_PIN,'status':'NO_GUEST_EGRESS_WITNESSED_NO_GO',
             'p8_operational':'NO-GO','isolation_proven':False,
             'capture_files':obs,'guest_agent_evidence':{'exit':{'transmitted':1,'received':0}}}
        route={'sha256':r424.R423_PIN,'source_r422_report_sha256':r424.R422_PIN,
               'source_main':r423.MAIN_PIN,'status':r423.STATUS_DIRECT,
               'p8_operational':'NO-GO','isolation_proven':False,
               'guest_ping_executed':False,'test_packets_injected':False,
               'guest_route_state':'DIRECT_ENS3_EXPECTED','guest_arp_state':'ABSENT',
               'guest_tx_packets_snapshot':0,'guest_rx_packets_snapshot':15}
        intent={'schema':r423.INTENT_SCHEMA,'source_r422_report_sha256':r424.R422_PIN,
                'exact_paths':list(r423.READ_PATHS),'p8_operational':'NO-GO',
                'no_packet_generators':True}
        with mock.patch.object(r424.r422,'verify_private_receipt',return_value=wit), \
             mock.patch.object(r424,'verified_directory',return_value={
                 r423.RESULT:b'route',r423.INTENT:b'intent'}), \
             mock.patch.object(r424.r365,'read_json',side_effect=lambda v: route if v==b'route' else intent), \
             mock.patch.object(r424.r423,'verify_report',return_value=True):
            self.assertEqual(r424.read_physical(Path('/r422'),Path('/r423')),physical())

    def test_source_changed_refused(self):
        with mock.patch.object(r424.r422,'verify_private_receipt',return_value={'sha256':'bad'}), \
             mock.patch.object(r424,'verified_directory',return_value={
                 r423.RESULT:b'route',r423.INTENT:b'intent'}), \
             mock.patch.object(r424.r365,'read_json',return_value={}), \
             mock.patch.object(r424.r423,'verify_report',return_value=True):
            with self.assertRaises(r424.EvidenceViewError):
                r424.read_physical(Path('/r422'),Path('/r423'))

    def test_tui_closes_on_q(self):
        class FakeScreen:
            def keypad(self,x):pass
            def erase(self):pass
            def getmaxyx(self):return (24,110)
            def addnstr(self,*args):pass
            def refresh(self):pass
            def getch(self):return ord('q')
        with mock.patch.object(r424.curses,'wrapper',side_effect=lambda app: app(FakeScreen())) as w, \
             mock.patch.object(r424.curses,'curs_set'):
            r424.run_tui(self.bundle())
            self.assertEqual(w.call_count,1)

if __name__=='__main__':unittest.main()
