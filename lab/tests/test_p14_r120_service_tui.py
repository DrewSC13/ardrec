"""R120: navegación SSH/FTP/SMB y catálogo P7 real, sin ejecución."""
from __future__ import annotations
import copy
from dataclasses import replace
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from ardrec.coordination import dashboard_tui as tui
from ardrec.coordination import r119_live_inspection as live
from ardrec.coordination import r115_dev_admission_contract as f1
from test_p14_r119_live_readonly import view

class ServiceDashboardTests(unittest.TestCase):
    def setUp(self):
        self.report=view(mode='F5_PRIVATE_RECEIPT_REPLAY')
        self.original=tui.DashboardState()
        self.services=tui.handle_key(self.report, self.original, 'v')

    def test_01_default_algorithms(self):
        self.assertEqual(self.original.view_mode, 'ALGORITHMS')

    def test_02_services_enabled(self):
        self.assertEqual(self.services.view_mode, 'SERVICES')

    def test_03_f6_toggle(self):
        s=tui.handle_key(self.report,self.services,'F6')
        self.assertEqual(s.view_mode,'ALGORITHMS')
        self.assertEqual(tui.handle_key(self.report,s,'F6').view_mode,'SERVICES')

    def test_04_a_returns_to_algorithms(self):
        self.assertEqual(tui.handle_key(self.report,self.services,'a').view_mode,'ALGORITHMS')

    def test_05_down_selects_ftp(self):
        self.assertEqual(tui.handle_key(self.report,self.services,'DOWN').service_selected,1)

    def test_06_down_selects_smb(self):
        s=tui.handle_key(self.report,self.services,'DOWN')
        self.assertEqual(tui.handle_key(self.report,s,'DOWN').service_selected,2)

    def test_07_up_wraps(self):
        self.assertEqual(tui.handle_key(self.report,self.services,'UP').service_selected,2)

    def test_08_numeric_keys_select_services(self):
        self.assertEqual([tui.handle_key(self.report,self.services,str(i)).service_selected for i in (1,2,3)],[0,1,2])

    def test_09_right_moves_family(self):
        self.assertEqual(tui.handle_key(self.report,self.services,'RIGHT').family_selected,1)

    def test_10_left_wraps_ssh(self):
        self.assertEqual(tui.handle_key(self.report,self.services,'LEFT').family_selected,7)

    def test_11_left_wraps_smb(self):
        smb=tui.handle_key(self.report,self.services,'3')
        self.assertEqual(tui.handle_key(self.report,smb,'[').family_selected,8)

    def test_12_change_service_resets_family(self):
        s=tui.handle_key(self.report,self.services,'LEFT')
        self.assertEqual(tui.handle_key(self.report,s,'2').family_selected,0)

    def test_13_catalog_counts(self):
        self.assertEqual(self.report['r119_live']['catalog']['counts'],{'ssh':8,'ftp':8,'smb':9})

    def test_14_all_25_family_ids(self):
        c=self.report['r119_live']['catalog']
        ids=[f['id'] for proto in ('ssh','ftp','smb') for f in c['families'][proto]]
        self.assertEqual(len(ids),25)
        self.assertEqual((ids[0],ids[-1]),('SSH-T01','SMB-T09'))

    def test_15_catalog_draft_not_executable(self):
        c=self.report['r119_live']['catalog']
        self.assertFalse(c['execution_enabled'])
        self.assertFalse(c['catalog_frozen'])
        self.assertIn('DRAFT',c['status'])

    def test_16_live_verify_and_dashboard_verify(self):
        self.assertTrue(live.verify_view(self.report))
        tui.validate_dashboard_report(self.report)

    def test_17_catalog_sha_pinned(self):
        from ardrec.coordination import r115_f14_a5_a6_handoff as f14
        self.assertEqual(self.report['r119_live']['catalog']['sha256'],f14.CATALOG_SHA256)

    def _tamper(self, field, val):
        bad=copy.deepcopy(self.report)
        bad['r119_live']['catalog'][field]=val
        bad['sha256']=f1.digest(f1.canonical({k:v for k,v in bad.items() if k!='sha256'}))
        return bad

    def test_18_fake_execution_rejected_even_rehashed(self):
        with self.assertRaisesRegex(live.Stop,'VIEW_CATALOG_UNTRUSTED'):
            live.verify_view(self._tamper('execution_enabled',True))

    def test_19_fake_frozen_rejected(self):
        with self.assertRaises(live.Stop):
            live.verify_view(self._tamper('catalog_frozen',True))

    def test_20_missing_family_rejected(self):
        family_copy=copy.deepcopy(self.report['r119_live']['catalog']['families'])
        family_copy['ssh'].pop()
        with self.assertRaisesRegex(live.Stop,'VIEW_CATALOG_FAMILY_SET'):
            live.verify_view(self._tamper('families',family_copy))

    def test_21_display_ssh(self):
        frame='\n'.join(tui.render_dashboard_frame(self.report,self.services,128,40))
        self.assertIn('SERVICIO: SSH',frame)
        self.assertIn('SSH-T01',frame)
        self.assertIn('SERVICIOS / FAMILIAS',frame)

    def test_22_display_ftp(self):
        s=tui.handle_key(self.report,self.services,'2')
        self.assertIn('FTP-T01','\n'.join(tui.render_dashboard_frame(self.report,s,128,40)))

    def test_23_display_smb(self):
        s=tui.handle_key(self.report,self.services,'3')
        self.assertIn('SMB-T01','\n'.join(tui.render_dashboard_frame(self.report,s,128,40)))

    def test_24_navigation_does_not_change_operational_flags(self):
        s=self.services
        for k in ('DOWN','RIGHT','3','LEFT','v','v'):
            s=tui.handle_key(self.report,s,k)
        self.assertIsNone(self.report['final_risk'])
        self.assertIsNone(self.report['a9']['published_generation'])
        self.assertIs(self.report['operational_dispatch'],False)
        self.assertEqual(self.report['p8_operational'],'NO-GO')

    def test_25_navigation_has_no_host_reads(self):
        with patch.object(live.f5,'capture',side_effect=AssertionError('HOST')):
            s=self.services
            for k in ('2','RIGHT','3','LEFT','1','a','v'):
                s=tui.handle_key(self.report,s,k)
                tui.render_dashboard_frame(self.report,s,128,27)

    def test_26_compact_render(self):
        frame=tui.render_dashboard_frame(self.report,self.services,65,18)
        self.assertTrue(any('SERVICIO SSH' in row for row in frame))
        self.assertEqual(len(frame),18)

    def test_27_replay_not_live(self):
        self.assertIn('REPLAY HISTORICO',tui.render_dashboard_frame(self.report,self.services,128,30)[1])

    def test_28_summary_no_a9(self):
        summary=tui._service_page(self.report,tui.handle_key(self.report,self.services,'2'))[2]
        self.assertIn('A9: SIN GENERACION',summary)
        self.assertIn('P8: NO-GO',summary)

    def test_29_original_algorithm_navigation(self):
        self.assertEqual(tui.handle_key(self.report,self.original,'DOWN').selected,1)
        self.assertEqual(tui.handle_key(self.report,self.original,'2').selected,1)
        self.assertEqual(tui.handle_key(self.report,self.original,'F4').filter_mode,'PENDING')

    def test_30_f6_key_recognized(self):
        class FakeCurses:
            KEY_UP,KEY_DOWN,KEY_LEFT,KEY_RIGHT,KEY_ENTER=101,102,103,104,105
            KEY_BACKSPACE,KEY_F0=106,200
            KEY_F1,KEY_F2,KEY_F3,KEY_F4,KEY_F5,KEY_F6=201,202,203,204,205,206
        self.assertEqual(tui._key_name(206,FakeCurses),'F6')

    def test_31_detail_scroll_not_change_service(self):
        s=replace(self.services,focus='DETAIL',scroll=4)
        after=tui.handle_key(self.report,s,'UP')
        self.assertEqual((after.scroll,after.service_selected),(3,s.service_selected))

    def test_32_no_a6_admission_for_ssh(self):
        detail='\n'.join(tui._service_page(self.report,self.services)[1])
        self.assertIn('A6: ND',detail)
        self.assertIn('A4: SIN ELECCION',detail)

    def test_33_catalog_family_conditions_exact(self):
        src=json.loads((Path(__file__).resolve().parents[2] / 'lab/operational-catalog-v1/catalog.json').read_text())
        expected={f['id']:f['condition_es'] for f in src['families']}
        actual={f['id']:f['condition_es'] for fam in self.report['r119_live']['catalog']['families'].values() for f in fam}
        self.assertEqual(actual,expected)

    def test_34_no_credential_fields(self):
        cat=self.report['r119_live']['catalog']
        self.assertEqual(set(cat),{'sha256','status','execution_enabled','catalog_frozen','counts','families'})
        for families in cat['families'].values():
            for f in families:
                self.assertEqual(set(f),{'id','source_table','condition_es','minimum_action_es',
                                         'interpretation_boundary_es','preconditions','required_supports'})

    def test_35_non_live_disallows_service_mode(self):
        other=copy.deepcopy(self.report)
        del other['r119_live']
        self.assertFalse(tui._services_enabled(other))

    def test_36_family_select_has_thesis_table(self):
        state=tui.handle_key(self.report,self.services,'RIGHT')
        rows='\n'.join(tui._service_page(self.report,state)[1])
        self.assertIn('SSH-T02',rows)
        self.assertIn('TABLA TESIS:',rows)

if __name__=='__main__': unittest.main()
