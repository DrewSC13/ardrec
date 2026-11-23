"""R115-F16: real F5 structural replay and authority separation, never dispatch."""
from __future__ import annotations
import copy
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_f16_physical_pilot_controller as m
from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f7_controlled_boot as f7
from test_p14_r115_f5_lifecycle_readiness import fixture

NOW=datetime(2026,11,20,14,30,6,tzinfo=timezone.utc)
HEAD='9a1d95a7df5da3a400489f815161b4dc00faa689'
CATALOG=(Path(__file__).resolve().parents[2]/m.CATALOG).read_bytes()
STATES={'ssh':'RUNNING','runner':'RUNNING','ftp':'RUNNING','smb':'OFF'}
BINDINGS=['runner_ssh','ssh','runner_ftp','runner_smb','ftp']

def live():
    return fixture(states=STATES,active=BINDINGS)

def replay_proof(plan, boot):
    return {'role':'ftp','state':'FTP_RUNNING_DENY_ATTESTED','vm_starts':1,
            'traffic_authorized':False,'p8':'NO-GO','a6':'ND'}

def document(*args,**kwargs):
    return {'document_status':'DOCUMENT_SIGNED',
            'authorized_to_connect_by_module':False,
            'physical_pilot_session_attested':False,'p8':'NO-GO',
            'pilot_sha256':'1'*64}

def kw(capture=None, **updates):
    doc={'head':HEAD,'catalog_raw':CATALOG,'capture':live() if capture is None else capture,
         'now':NOW}
    doc.update(updates)
    return doc

class Lifecycle(unittest.TestCase):
    def test_true_five_deny_one_absent(self):
        r=m.physical_deny_stage(live(),now=NOW)
        self.assertEqual(r['active_deny_bindings'],5)
        self.assertEqual(r['offline_absent_bindings'],1)
        self.assertFalse(r['traffic_authorized'])
    def test_all_offline_not_ready(self):
        with self.assertRaises(m.Stop):m.physical_deny_stage(fixture(),now=NOW)
    def test_smb_active_not_accepted(self):
        doc=fixture(states={**STATES,'smb':'RUNNING'},active=BINDINGS+['smb'])
        with self.assertRaises(m.Stop):m.physical_deny_stage(doc,now=NOW)
    def test_ftp_not_running(self):
        doc=fixture(states={**STATES,'ftp':'OFF'},active=['runner_ssh','ssh','runner_ftp','runner_smb'])
        with self.assertRaises(m.Stop):m.physical_deny_stage(doc,now=NOW)
    def test_missing_ftp_deny(self):
        doc=fixture(states=STATES,active=['runner_ssh','ssh','runner_ftp','runner_smb'])
        with self.assertRaises(m.Stop):m.physical_deny_stage(doc,now=NOW)
    def test_unexpected_binding_while_smb_off(self):
        doc=fixture(states=STATES,active=BINDINGS+['smb'])
        with self.assertRaises(m.Stop):m.physical_deny_stage(doc,now=NOW)
    def test_nft_drift(self):
        doc=live();doc['probes']['nft']['rc']=1
        with self.assertRaises(m.Stop):m.physical_deny_stage(doc,now=NOW)
    def test_f11_hook_drift(self):
        doc=live();doc['probes']['hook_sha']['stdout']='Y2hhbmdlZA=='
        with self.assertRaises(m.Stop):m.physical_deny_stage(doc,now=NOW)
    def test_invalid_vm_definition(self):
        doc=live();doc['probes']['xml_ftp']['rc']=1
        with self.assertRaises(m.Stop):m.physical_deny_stage(doc,now=NOW)
    def test_old_capture_rejected(self):
        with self.assertRaisesRegex(m.Stop,'NOT_FRESH'):
            m.physical_deny_stage(live(),now=NOW+timedelta(seconds=100))
    def test_future_capture_rejected(self):
        with self.assertRaisesRegex(m.Stop,'NOT_FRESH'):
            m.physical_deny_stage(live(),now=NOW-timedelta(minutes=2))
    def test_naive_clock_rejected(self):
        with self.assertRaisesRegex(m.Stop,'UTC_AWARE'):
            m.physical_deny_stage(live(),now=datetime(2026,11,20,14,30,0))

class Boot(unittest.TestCase):
    def test_replay_good(self):
        r=m.boot_chain(m.f8.ROOT/'plan-fixture',m.f8.ROOT/'boot-fixture',replay=replay_proof)
        self.assertEqual(r['traffic_authorized'],False)
    def test_bad_source_path(self):
        with self.assertRaisesRegex(m.Stop,'OUT_OF_SCOPE'):
            m.boot_chain(Path('/tmp/plan-x'),Path('/tmp/boot-y'))
    def test_relative_path(self):
        with self.assertRaisesRegex(m.Stop,'PATH_REQUIRED'):
            m.boot_chain(Path('plan-x'),Path('boot-y'))
    def test_signed_but_not_physical(self):
        def bad(plan,boot):
            return {'role':'ftp','state':'FTP_RUNNING_DENY_ATTESTED',
                    'vm_starts':1,'traffic_authorized':True,'p8':'NO-GO','a6':'ND'}
        with self.assertRaisesRegex(m.Stop,'NOT_ATTESTED'):
            m.boot_chain(m.f8.ROOT/'plan-fixture',m.f8.ROOT/'boot-fixture',replay=bad)
    def test_wrong_guest_role(self):
        def bad(plan,boot):
            doc=replay_proof(plan,boot);doc['role']='runner';return doc
        with self.assertRaisesRegex(m.Stop,'NOT_ATTESTED'):
            m.boot_chain(m.f8.ROOT/'plan-fixture',m.f8.ROOT/'boot-fixture',replay=bad)

class Assessment(unittest.TestCase):
    def test_offline_no_documents_no_go(self):
        r=m.assess(**kw(capture=fixture()))
        self.assertFalse(r['pilot_release']);self.assertEqual(r['ordinary_p8'],'NO-GO')
        self.assertIn('FTP_RUNNING_FIVE_DENY_ONE_OFF_NOT_ATTESTED',r['blockers'])
    def test_live_no_documents_still_no_go(self):
        r=m.assess(**kw())
        self.assertIsNotNone(r['physical_deny'])
        self.assertIn('INDEPENDENT_SCOPE_PILOT_AND_REVOCATION_MISSING',r['blockers'])
        self.assertFalse(r['pilot_release'])
    def test_complete_mocked_documents_still_no_go(self):
        r=m.assess(**kw(contract_raw=b'contract',authorization_raw=b'scope',
                       pilot_raw=b'pilot',ftp_plan_dir=m.f8.ROOT/'plan-fixture',
                       ftp_boot_dir=m.f8.ROOT/'boot-fixture',
                       pilot_review=document,boot_replay=replay_proof))
        self.assertEqual(r['independent_pilot_document']['status'],'DOCUMENT_SIGNED')
        self.assertIsNotNone(r['boot_chain'])
        self.assertEqual(r['blockers'],sorted(r['blockers']))
        self.assertIn('ROOT_60S_LIFECYCLE_COMPATIBLE_WINDOW_NOT_IMPLEMENTED',r['blockers'])
        self.assertFalse(r['pilot_release'])
        self.assertEqual(r['network_connections_by_module'],0)
    def test_revoked_document_never_go(self):
        def revoked(*args,**kwargs):
            return {'document_status':'REVOKED','authorized_to_connect_by_module':False,
                    'physical_pilot_session_attested':False,'p8':'NO-GO'}
        r=m.assess(**kw(contract_raw=b'contract',authorization_raw=b'scope',
                        pilot_raw=b'pilot',pilot_review=revoked))
        self.assertEqual(r['independent_pilot_document']['status'],'ND')
    def test_incomplete_document_set_refused(self):
        with self.assertRaisesRegex(m.Stop,'PARTIAL_SIGNED'):
            m.assess(**kw(contract_raw=b'c'))
    def test_one_boot_path_refused(self):
        with self.assertRaisesRegex(m.Stop,'PARTIAL_BOOT'):
            m.assess(**kw(ftp_plan_dir=m.f8.ROOT/'plan-a'))
    def test_wrong_catalog_sha(self):
        with self.assertRaisesRegex(m.Stop,'CATALOG_SHA'):
            m.assess(**kw(catalog_raw=CATALOG+b' '))
    def test_bool_or_wrong_head_refused(self):
        with self.assertRaisesRegex(m.Stop,'GIT_HEAD'):
            m.assess(**kw(head='incorrect'))
    def test_invalid_snapshot_is_not_ignored(self):
        with self.assertRaises(Exception):m.assess(**kw(capture={'schema':'fake'}))
    def test_mocked_pilot_claiming_traffic_approval_rejected(self):
        def invalid(*args,**kwargs):
            a=document();a['authorized_to_connect_by_module']=True;return a
        r=m.assess(**kw(contract_raw=b'c',authorization_raw=b'a',pilot_raw=b'p',
                        pilot_review=invalid))
        self.assertEqual(r['independent_pilot_document']['status'],'ND')
    def test_legacy_r113_attest_not_reused(self):
        s=m.physical_deny_stage(live(),now=NOW)
        self.assertEqual(s['active_deny_bindings'],5)
        self.assertNotEqual(s['active_deny_bindings'],6)

class Packaging(unittest.TestCase):
    def test_nonroot_capabilities(self):
        c=m.capabilities()
        self.assertTrue(c['live_five_deny_one_off_lifecycle_check'])
        self.assertFalse(c['opens_sockets'])
        self.assertFalse(c['changes_firewall'])
        self.assertEqual(c['p8'],'NO-GO')
    def test_cli_capabilities(self):
        import importlib.util
        path=Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r115_f16_physical_pilot_controller.py'
        spec=importlib.util.spec_from_file_location('f16cli',path)
        mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        with patch('builtins.print') as out:
            self.assertEqual(mod.main(['--capabilities']),0)
        self.assertTrue(any('NO-GO' in str(x) for x in out.call_args_list))
    def test_cli_inspection_no_network(self):
        import importlib.util
        path=Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r115_f16_physical_pilot_controller.py'
        spec=importlib.util.spec_from_file_location('f16cli2',path)
        mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        with patch.object(mod.f7,'git_guard',return_value=HEAD), \
             patch.object(mod.f5,'capture',return_value=live()), \
             patch.object(mod.f16,'persist',return_value=Path('/tmp/receipt')), \
             patch.object(mod,'datetime') as dt, patch('builtins.print') as printed:
            dt.now.return_value=NOW
            self.assertEqual(mod.main(['--inspect-current']),0)
            self.assertIn('R115_F16_PHYSICAL_DENY=MATCH_5_ACTIVE_1_OFFLINE',
                          [x.args[0] for x in printed.call_args_list])
    def test_signed_reports_are_not_permits(self):
        out=m.assess(**kw())
        self.assertIsNone(out['a9'])
        self.assertIsNone(out['a10'])
        self.assertFalse(out['root_window_open'])
