"""R125: full cross-gate source acceptance, no physical action or GO."""
from __future__ import annotations
import copy
from datetime import datetime,timezone,timedelta
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_f5_lifecycle_readiness as f5
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r122_operational_boundary as r122
from ardrec.coordination import r123_guarded_window as r123
from ardrec.coordination import r124_root_deny_readback as r124
from ardrec.coordination import r125_integrated_acceptance as m
from test_p14_r122_operational_boundary import synthetic_capture
from test_p14_r124_root_deny_readback import Fake

HERE=Path(__file__).resolve().parents[2]
CAT=(HERE/'lab/operational-catalog-v1/catalog.json').read_bytes()
HEAD='2db609afcd6fcdd0148179713aad9d5baa14516c'
NOW=datetime(2026,11,21,21,30,0,tzinfo=timezone.utc)


def trace(plan):
    start=300_000_000_000
    return [
       {'stage': stage, 'at_monotonic_ns':start+sec*1_000_000_000,
        'plan_sha256':plan['sha256'], 'firewall_allow':False,
        'network_connections':0,'vm_starts':0}
       for stage,sec in zip(r123.STAGES,(0,1,40,44))
    ]


class Capacity(unittest.TestCase):
    def test_01_catalog_pin(self):self.assertEqual(len(m.coverage(CAT)['catalog_sha256']),64)
    def test_02_54_slots(self):self.assertEqual(len(m.coverage(CAT)['slots']),54)
    def test_03_18_each(self):self.assertEqual(m.coverage(CAT)['expected_by_protocol'],m.CAPACITY)
    def test_04_families(self):self.assertEqual(m.coverage(CAT)['family_counts_by_protocol'],{'SSH':8,'FTP':8,'SMB':9})
    def test_05_25_ids(self):self.assertEqual(len(m.coverage(CAT)['family_ids']),25)
    def test_06_no_scenario(self):self.assertTrue(all(x['scenario_id'] is None for x in m.coverage(CAT)['slots']))
    def test_07_no_case(self):self.assertTrue(all(x['case_id'] is None for x in m.coverage(CAT)['slots']))
    def test_08_no_assigned_family(self):self.assertTrue(all(x['family_id'] is None for x in m.coverage(CAT)['slots']))
    def test_09_no_physical_attempt(self):self.assertTrue(all(x['physical_attempt_id'] is None for x in m.coverage(CAT)['slots']))
    def test_10_no_evidence(self):self.assertTrue(all(x['evidence_sha256'] is None for x in m.coverage(CAT)['slots']))
    def test_11_no_risk(self):self.assertTrue(all(x['confirmed_risk'] is None for x in m.coverage(CAT)['slots']))
    def test_12_no_a9(self):self.assertTrue(all(x['a9_generation'] is None for x in m.coverage(CAT)['slots']))
    def test_13_no_executed(self):self.assertEqual(m.coverage(CAT)['executed_real_unit_count'],0)
    def test_14_no_admitted(self):self.assertEqual(m.coverage(CAT)['accepted_real_unit_count'],0)
    def test_15_first_ssh(self):self.assertEqual(m.coverage(CAT)['slots'][0]['protocol'],'SSH')
    def test_16_first_ftp(self):self.assertEqual(m.coverage(CAT)['slots'][18]['protocol'],'FTP')
    def test_17_first_smb(self):self.assertEqual(m.coverage(CAT)['slots'][36]['protocol'],'SMB')
    def test_18_last_smb(self):self.assertEqual(m.coverage(CAT)['slots'][-1]['planning_position'],18)
    def test_19_unique_slots(self):
        v=m.coverage(CAT)['slots'];self.assertEqual(len({(x['protocol'],x['planning_position']) for x in v}),54)
    def test_20_no_go(self):self.assertEqual(m.coverage(CAT)['p8'],'NO-GO')
    def test_21_wrong_catalog(self):
        with self.assertRaises(m.Stop):m.coverage(CAT+b'\n')
    def test_22_repeatability(self):self.assertEqual(m.coverage(CAT),m.coverage(CAT))
    def test_23_bad_type(self):
        with self.assertRaises(m.Stop):m.coverage('not-bytes')
    def test_24_matrix_sha(self):
        d=m.coverage(CAT);self.assertEqual(d['sha256'],m._sha({k:v for k,v in d.items() if k!='sha256'}))
    def test_25_no_counterfeit_54_claim(self):
        self.assertEqual(m.coverage(CAT)['assigned_real_unit_count'],0)


@unittest.skipIf(os.geteuid()==0,'needs unprivileged test user for F5 receipts')
class Integrated(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        f5root=self.root/'captures';f5root.mkdir(mode=0o700)
        self.replace=patch.object(f5,'ROOT',f5root)
        self.replace.start();self.addCleanup(self.replace.stop)
        doc=synthetic_capture()
        self.capture=f5.save_private(doc,f5.report(doc),root=f5root)
        self.boundary=r122.build(capture_folder=self.capture,catalog_raw=CAT,
                                 head=HEAD,now=NOW)
        self.plan=r123.plan(boundary=self.boundary,catalog_raw=CAT,now=NOW)
        self.readback=r124.inspect(head=HEAD,now=NOW,run=Fake())
        self.audit_root=self.root/'audit'

    def build(self,**kw):
        args={'head':HEAD,'catalog_raw':CAT,'now':NOW,
              'boundary':self.boundary,'plan':self.plan,
              'root_report':self.readback}
        args.update(kw)
        return m.build(**args)

    def test_26_build(self):self.assertEqual(self.build()['schema'],m.SCHEMA)
    def test_27_verify(self):
        self.assertTrue(m.verify(self.build(),catalog_raw=CAT,boundary=self.boundary,
                                 plan=self.plan,root_report=self.readback))
    def test_28_baseline(self):self.assertEqual(self.build()['root_status']['status'],'OFFLINE_DENY_MATCH')
    def test_29_p8(self):self.assertEqual(self.build()['p8'],'NO-GO')
    def test_30_p7(self):self.assertEqual(self.build()['p7'],'DRAFT')
    def test_31_a5(self):self.assertEqual(self.build()['a5'],'NOT_AUTHORIZED_FOR_NEW_DISPATCH')
    def test_32_a6(self):self.assertEqual(self.build()['a6'],'ND')
    def test_33_risk(self):self.assertIsNone(self.build()['a7_confirmed_rf'])
    def test_34_transition(self):self.assertIsNone(self.build()['a8_applied_transition'])
    def test_35_a9(self):self.assertIsNone(self.build()['a9_global_generation'])
    def test_36_a10(self):self.assertEqual(self.build()['a10'],'SOURCE_BOUND_READONLY_AUDIT')
    def test_37_54_slots(self):self.assertEqual(self.build()['planned_units'],54)
    def test_38_zero_real(self):self.assertEqual(self.build()['assigned_real_units'],0)
    def test_39_no_60s(self):self.assertFalse(self.build()['physical_60s_closure_attested'])
    def test_40_no_root_permit(self):self.assertFalse(self.build()['root_operational_permit_attested'])
    def test_41_no_consumption(self):self.assertFalse(self.build()['one_shot_attempt_consumed_by_r125'])
    def test_42_no_network(self):self.assertEqual(self.build()['network_connections'],0)
    def test_43_no_boot(self):self.assertEqual(self.build()['vm_starts'],0)
    def test_44_no_nft(self):self.assertEqual(self.build()['firewall_changes'],0)
    def test_45_gate_count(self):self.assertEqual(len(self.build()['gates']),11)
    def test_46_gate_link(self):self.assertEqual(self.build()['gate_chain_sha256'],self.build()['gates'][-1]['sha256'])
    def test_47_gate_predecessor(self):self.assertEqual(self.build()['gates'][1]['previous_sha256'],self.build()['gates'][0]['sha256'])
    def test_48_case_missing(self):self.assertIn('F13_NO_SOURCE_CASE_SELECTED',self.build()['blockers'])
    def test_49_timer_missing(self):self.assertIn('SESSION_TIMER_NOT_CURRENTLY_ACTIVE',self.build()['blockers'])
    def test_50_five_one_missing(self):self.assertIn('FTP_FIVE_ONE_NOT_OBSERVED',self.build()['blockers'])
    def test_51_deterministic(self):self.assertEqual(self.build(),self.build())
    def test_52_timing_candidate(self):
        x=self.build(timing_events=trace(self.plan))
        self.assertEqual(x['closure_timing_candidate']['interpretation'],'MODEL_ONLY_NOT_ROOT_WITNESS')
        self.assertFalse(x['closure_timing_candidate']['physical_60s_closure_verified'])
    def test_53_refuse_allow_in_trace(self):
        v=trace(self.plan);v[2]['firewall_allow']=True
        with self.assertRaises(m.Stop):self.build(timing_events=v)
    def test_54_refuse_duration(self):
        v=trace(self.plan);v[-1]['at_monotonic_ns']+=60*1_000_000_000
        with self.assertRaises(m.Stop):self.build(timing_events=v)
    def test_55_refuse_order(self):
        v=trace(self.plan);v[0],v[1]=v[1],v[0]
        with self.assertRaises(m.Stop):self.build(timing_events=v)
    def test_56_refuse_plan_hash_in_trace(self):
        v=trace(self.plan);v[1]['plan_sha256']='0'*64
        with self.assertRaises(m.Stop):self.build(timing_events=v)
    def test_57_refuse_wrong_head(self):
        with self.assertRaises(m.Stop):self.build(head='0'*40)
    def test_58_refuse_wrong_catalog(self):
        with self.assertRaises(m.Stop):self.build(catalog_raw=CAT+b'x')
    def test_59_refuse_naive_clock(self):
        with self.assertRaises(m.Stop):self.build(now=NOW.replace(tzinfo=None))
    def test_60_refuse_subsecond_clock(self):
        with self.assertRaises(m.Stop):self.build(now=NOW.replace(microsecond=1))
    def test_61_refuse_stale_host(self):
        with self.assertRaises(m.Stop):self.build(now=NOW+timedelta(minutes=2))
    def test_62_refuse_host_future(self):
        with self.assertRaises(m.Stop):self.build(now=NOW-timedelta(minutes=2))
    def test_63_refuse_forged_guard_pin(self):
        r=copy.deepcopy(self.readback);r['root_guard_sha256']='0'*64
        with self.assertRaises(m.Stop):self.build(root_report=r)
    def test_64_refuse_forged_guard_sha(self):
        r=copy.deepcopy(self.readback);r['sha256']='0'*64
        with self.assertRaises(m.Stop):self.build(root_report=r)
    def test_65_refuse_forged_p8(self):
        r=copy.deepcopy(self.readback);r['p8']='GO'
        with self.assertRaises(m.Stop):self.build(root_report=r)
    def test_66_refuse_forged_a6(self):
        r=copy.deepcopy(self.readback);r['a6']='VERDADERO'
        with self.assertRaises(m.Stop):self.build(root_report=r)
    def test_67_refuse_forged_a9(self):
        r=copy.deepcopy(self.readback);r['a9']=1
        with self.assertRaises(m.Stop):self.build(root_report=r)
    def test_68_refuse_fake_deadline(self):
        r=copy.deepcopy(self.readback);r['root_60s_deadline_verified']=True
        with self.assertRaises(m.Stop):self.build(root_report=r)
    def test_69_refuse_host_network(self):
        r=copy.deepcopy(self.readback);r['network_connections_by_r124']=1
        with self.assertRaises(m.Stop):self.build(root_report=r)
    def test_70_refuse_host_boot(self):
        r=copy.deepcopy(self.readback);r['guest_starts_by_r124']=1
        with self.assertRaises(m.Stop):self.build(root_report=r)
    def test_71_refuse_host_firewall(self):
        r=copy.deepcopy(self.readback);r['nft_writes_by_r124']=1
        with self.assertRaises(m.Stop):self.build(root_report=r)
    def test_72_refuse_forged_boundary(self):
        r=copy.deepcopy(self.boundary);r['a6']='VERDADERO'
        with self.assertRaises(m.Stop):self.build(boundary=r)
    def test_73_refuse_forged_plan(self):
        r=copy.deepcopy(self.plan);r['p8']='GO'
        with self.assertRaises(m.Stop):self.build(plan=r)
    def test_74_report_drift(self):
        r=self.build();r['p8']='GO'
        with self.assertRaises(m.Stop):m.verify(r,catalog_raw=CAT,boundary=self.boundary,
            plan=self.plan,root_report=self.readback)
    def test_75_source_manifest_modified(self):
        (self.capture/'manifest.json').write_bytes(b'{}\n')
        with self.assertRaises(m.Stop):self.build()
    def test_76_persist(self):
        folder=m.persist(self.build(),catalog_raw=CAT,boundary=self.boundary,
                         plan=self.plan,root_report=self.readback,root=self.audit_root)
        self.assertEqual(m.verify_persisted(folder,CAT),self.build())
    def test_77_file_modes(self):
        folder=m.persist(self.build(),catalog_raw=CAT,boundary=self.boundary,
                         plan=self.plan,root_report=self.readback,root=self.audit_root)
        self.assertEqual(folder.stat().st_mode & 0o777,0o700)
        self.assertTrue(all(x.stat().st_mode & 0o777==0o600 for x in folder.iterdir()))
    def test_78_manifest_mutated(self):
        folder=m.persist(self.build(),catalog_raw=CAT,boundary=self.boundary,
                         plan=self.plan,root_report=self.readback,root=self.audit_root)
        (folder/'manifest.json').write_bytes(b'{}\n')
        with self.assertRaises(m.Stop):m.verify_persisted(folder,CAT)
    def test_79_report_mutated(self):
        folder=m.persist(self.build(),catalog_raw=CAT,boundary=self.boundary,
                         plan=self.plan,root_report=self.readback,root=self.audit_root)
        (folder/'report.json').write_bytes(b'{}\n')
        with self.assertRaises(m.Stop):m.verify_persisted(folder,CAT)
    def test_80_symlink_rejected(self):
        folder=m.persist(self.build(),catalog_raw=CAT,boundary=self.boundary,
                         plan=self.plan,root_report=self.readback,root=self.audit_root)
        (folder/'report.json').unlink();(folder/'report.json').symlink_to('/etc/passwd')
        with self.assertRaises(m.Stop):m.verify_persisted(folder,CAT)
    def test_81_extra_file_rejected(self):
        folder=m.persist(self.build(),catalog_raw=CAT,boundary=self.boundary,
                         plan=self.plan,root_report=self.readback,root=self.audit_root)
        (folder/'extra').write_text('x')
        with self.assertRaises(m.Stop):m.verify_persisted(folder,CAT)
    def test_82_tamper_original_source(self):
        folder=m.persist(self.build(),catalog_raw=CAT,boundary=self.boundary,
                         plan=self.plan,root_report=self.readback,root=self.audit_root)
        (self.capture/'manifest.json').write_bytes(b'{}\n')
        with self.assertRaises(m.Stop):m.verify_persisted(folder,CAT)
    def test_83_root_process_rejected(self):
        with patch.object(m.os,'geteuid',return_value=0):
            with self.assertRaises(m.Stop):
                m.persist(self.build(),catalog_raw=CAT,boundary=self.boundary,
                          plan=self.plan,root_report=self.readback,root=self.audit_root)
    def test_84_capabilities(self):self.assertFalse(m.capabilities()['independent_p8_operational_permit'])
    def test_85_cli_capabilities(self):
        from scripts import ardrec_p14_r125_integrated_acceptance as cli
        with patch('builtins.print'):
            self.assertEqual(cli.main(['--capabilities']),0)
    def test_86_no_socket(self):
        import socket
        with patch.object(socket,'socket',side_effect=AssertionError('SOCKET_OPENED')):
            self.build()
    def test_87_no_process(self):
        import subprocess
        with patch.object(subprocess,'run',side_effect=AssertionError('PROCESS_SPAWNED')):
            self.build()
    def test_88_no_root_permit_through_readback(self):
        root=copy.deepcopy(self.readback)
        self.assertFalse(m.root_check(root,head=HEAD)['independent_60s_closure_attested'])
    def test_89_invalid_monotonic(self):
        v=trace(self.plan);v[1]['at_monotonic_ns']=-1
        with self.assertRaises(m.Stop):self.build(timing_events=v)
    def test_90_source_sha_matches(self):
        self.assertEqual(self.build()['boundary_sha256'],self.boundary['sha256'])
