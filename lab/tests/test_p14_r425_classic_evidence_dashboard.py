"""R42.5 tests: R38 layout retained, physical provenance strictly separate."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import unittest
from unittest import mock

from ardrec.coordination import dashboard_tui as r38
from ardrec.coordination import r424_evidence_tui as r424
from ardrec.coordination import r425_classic_evidence_dashboard as r425


def report():
    statuses = ('EXECUTED_IN_R26','EXECUTED_IN_R26','DIAGNOSED_NO_AUTHORITY',
                'SELECTION_WITHOUT_DISPATCH','NOT_EXECUTED','ND',
                'RF_NOT_ACREDITED','PAUSE_RECOMMENDED_NOT_APPLIED',
                'RECEIPT_VERIFIED_NO_GENERATION','READ_ONLY_REPORT')
    return {
        'session_id':'DEV_TUTOR_001','sha256':'a'*64,'session_sha256':'b'*64,
        'source_kind':'SYNTHETIC_FIXTURE_ONLY',
        'p8_operational':'NO-GO','operational_dispatch':False,
        'vm_checks_executed':False,'final_risk':None,
        'r26_units':[{'protocol':p,'service_id':p+'_DEV','a1':'VERDADERO',
                      'a2':'PREPARADO','a3':'VERDADERO','initial_risk':'1/4'}
                     for p in ('FTP','SMB','SSH')],
        'r27':{'selected_actual':None,'selected_hypothetical':{'service_id':'SSH_DEV'},
               'a5_state':None,'a5_start_count':None,'a6_classification':'ND'},
        'a7':{'hypothetical_rf':'5/12','confirmed_rf':None},
        'a8':{'recommendation':'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA',
              'applied_transition':None},
        'a9':{'receipt_sha256':'c'*64,'durable_local_receipt':False,
              'published_generation':None},
        'a10':{'stages':[{'algorithm':'A'+str(i+1),'status':statuses[i],
                         'source':'SYNTHETIC_FIXTURE','detail':'Fixture A'+str(i+1)}
                        for i in range(10)]},
    }


def physical():
    return {'source_kind':'REAL_READONLY_SSH_SNAPSHOT',
            'r422_report_sha256':r424.R422_PIN,
            'r423_report_sha256':r424.R423_PIN,
            'route':'DIRECT_ENS3_EXPECTED','arp':'ABSENT',
            'tx_snapshot':0,'rx_snapshot':15,
            'tap_frames_r422':0,'bridge_frames_r422':0,
            'guest_ping_reported_transmitted_r422':1,
            'isolation_proven':False,'p8_operational':'NO-GO'}


def bundle(r):
    with mock.patch.object(r424.development_cycle,'verify_development_cycle'):
        return r424.make_bundle(physical(),r)


class R425Tests(unittest.TestCase):
    def setUp(self):
        self.dev = report()
        self.bundle = bundle(self.dev)

    def frame(self,state=None,width=120,height=32):
        return r425.render_frame(self.dev,self.bundle,state,width,height)

    def test_classic_three_panel_layout(self):
        s='\n'.join(self.frame())
        self.assertIn('ALGORITMOS',s)
        self.assertIn('A1 / DETALLE',s)
        self.assertIn('ESTADO / AUDITORIA SSH',s)
        self.assertIn('MONITOR R38',s)

    def test_original_dashboard_is_reused(self):
        with mock.patch.object(r38,'render_dashboard_frame',wraps=r38.render_dashboard_frame) as spy:
            self.frame()
            spy.assert_called_once()

    def test_physical_snapshot_in_audit(self):
        s='\n'.join(self.frame())
        for term in ('R42.2','R42.3','ARP: ABSENT','ENS3 TX: 0','ENS3 RX: 15',
                     'PCAP TAP: 0','PCAP BRIDGE: 0','NO PROBADO'):
            self.assertIn(term,s)

    def test_strict_no_go_unchanged(self):
        s='\n'.join(self.frame())
        self.assertIn('P8:NO-GO',s)
        self.assertIn('RF:ND',s)
        self.assertIn('DESPACHO:NO',s)
        self.assertIn('PENTEST: NO EJECUTADO',s)

    def test_selection_highlight_stays_in_nav(self):
        frame=self.frame(r38.DashboardState(selected=4))
        sel=next(line for line in frame if line.startswith('| > '))
        self.assertEqual(r38._selected_nav_span(sel,r38.DashboardState(selected=4),120),(1,32))
        self.assertEqual(sel[32],'|')
        self.assertIn('A5 / DETALLE','\n'.join(frame))

    def test_all_ten_direct_selection_keys(self):
        for n,key in enumerate('1234567890'):
            state=r38.handle_key(self.dev,r38.DashboardState(),key)
            self.assertEqual(state.selected,n)
            self.assertIn('VISTA:A'+str(n+1),'\n'.join(self.frame(state)))

    def test_navigation_follows_original(self):
        s=r38.DashboardState(selected=9)
        self.assertEqual(r38.handle_key(self.dev,s,'DOWN').selected,0)
        self.assertEqual(r38.handle_key(self.dev,s,'UP').selected,8)

    def test_search_original(self):
        s=r38.handle_key(self.dev,r38.DashboardState(),'/')
        for key in 'NOT_EXECUTED':s=r38.handle_key(self.dev,s,key)
        s=r38.handle_key(self.dev,s,'ENTER')
        self.assertEqual(r38.visible_indices(self.dev,s),(4,))
        self.assertIn('ESTADO / AUDITORIA SSH','\n'.join(self.frame(s)))

    def test_filter_original(self):
        s=r38.handle_key(self.dev,r38.DashboardState(),'F4')
        self.assertEqual(s.filter_mode,'PENDING')
        self.assertIn('SSH FISICO','\n'.join(self.frame(s)))

    def test_help_original(self):
        s=r38.handle_key(self.dev,r38.DashboardState(),'F1')
        self.assertIn('AYUDA','\n'.join(self.frame(s)))
        self.assertIn('P8:NO-GO','\n'.join(self.frame(s)))

    def test_medium_preserves_details_and_snapshot(self):
        s='\n'.join(self.frame(width=94,height=34))
        self.assertIn('ALGORITMOS',s)
        self.assertIn('ENS3 TX: 0',s)
        self.assertIn('Fixture A1',s)

    def test_compact_modes_work(self):
        for width,height in ((75,35),(58,28),(45,20)):
            with self.subTest(width=width):
                f=self.frame(r38.DashboardState(compact=True),width,height)
                self.assertEqual(len(f),height)
                self.assertTrue(all(len(row)==width for row in f))
                self.assertIn('P8:NO-GO','\n'.join(f))

    def test_tiny_mode_fail_closed_visible(self):
        self.assertIn('P8:NO-GO','\n'.join(self.frame(width=38,height=10)))

    def test_no_bundle_mutation(self):
        before=deepcopy((self.dev,self.bundle))
        self.frame();self.frame(r38.DashboardState(selected=5))
        self.assertEqual((self.dev,self.bundle),before)

    def test_tampered_signed_bundle_rejected(self):
        bad=deepcopy(self.bundle)
        bad['physical']['rx_snapshot']=999
        with self.assertRaises((r424.EvidenceViewError,r425.ClassicDashboardError)):
            r425.render_frame(self.dev,bad)

    def test_swapped_development_report_rejected(self):
        bad=deepcopy(self.dev);bad['sha256']='d'*64
        with self.assertRaises(r425.ClassicDashboardError):
            r425.render_frame(bad,self.bundle)

    def test_changed_stage_source_rejected(self):
        bad=deepcopy(self.dev)
        bad['a10']['stages'][4]['source']='REAL_PENTEST'
        with self.assertRaises(r425.ClassicDashboardError):
            r425.render_frame(bad,self.bundle)

    def test_false_go_rejected(self):
        bad=deepcopy(self.dev);bad['p8_operational']='GO'
        with self.assertRaises(r38.DashboardError):
            r425.render_frame(bad,self.bundle)

    def test_development_from_bundle_check(self):
        with mock.patch.object(r425.demo_session,'read_fixed_scenario',return_value={}), \
             mock.patch.object(r425.development_cycle,'build_development_cycle',return_value=self.dev), \
             mock.patch.object(r425.development_cycle,'verify_development_cycle') as verify:
            self.assertIs(r425.development_from_bundle(self.bundle,Path('/fixture')),self.dev)
            verify.assert_called_once_with(self.dev)

    def test_run_tui_rejects_notty(self):
        with mock.patch.object(r425.sys,'stdin') as i, mock.patch.object(r425.sys,'stdout') as o:
            i.isatty.return_value=False;o.isatty.return_value=False
            with self.assertRaises(r425.ClassicDashboardError):
                r425.run_tui(self.dev,self.bundle)

    def test_run_tui_q_and_original_keys(self):
        import curses
        class FakeScreen:
            def __init__(self): self.frames=[];self.keys=[ord('5'),ord('q')]
            def keypad(self,x):pass
            def erase(self):pass
            def getmaxyx(self):return (32,120)
            def addnstr(self,y,x,s,n,*attr):
                if y==0:self.frames.append(s)
            def refresh(self):pass
            def getch(self):return self.keys.pop(0)
        screen=FakeScreen()
        with mock.patch.object(r425.sys,'stdin') as i, mock.patch.object(r425.sys,'stdout') as o, \
             mock.patch.object(curses,'wrapper',side_effect=lambda cb:cb(screen)), \
             mock.patch.object(curses,'curs_set'),mock.patch.object(curses,'has_colors',return_value=False):
            i.isatty.return_value=True;o.isatty.return_value=True
            r425.run_tui(self.dev,self.bundle)
        self.assertEqual(len(screen.frames),2)

    def test_consistent_exact_width_and_height(self):
        for w,h in ((120,32),(145,37),(90,25),(60,20)):
            with self.subTest(width=w,height=h):
                lines=self.frame(width=w,height=h)
                self.assertEqual((len(lines),len(lines[0])),(h,w))
                self.assertTrue(all(len(s)==w for s in lines))

    def test_no_live_ssh_authority_via_a5(self):
        s='\n'.join(self.frame(r38.DashboardState(selected=4)))
        self.assertIn('NOT_EXECUTED',s)
        self.assertIn('PENTEST: NO EJECUTADO',s)

    def test_original_module_untouched(self):
        self.assertEqual(r38.DashboardState.__module__,'ardrec.coordination.dashboard_tui')

    def test_source_reports_not_network_calls(self):
        src=Path(r425.__file__).read_text(encoding='utf-8')
        for forbidden in ('subprocess.', 'socket.', 'virsh ', 'tcpdump ', 'sudo '):
            self.assertNotIn(forbidden,src)

if __name__=='__main__':unittest.main()
