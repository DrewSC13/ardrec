"""R123 regression: one-shot monotonic contract and R122 provenance, offline."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f5_lifecycle_readiness as f5
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r122_operational_boundary as r122
from ardrec.coordination import r123_guarded_window as m
from test_p14_r122_operational_boundary import synthetic_capture

REPO=Path(__file__).resolve().parents[2]
CAT=(REPO/'lab/operational-catalog-v1/catalog.json').read_bytes()
HEAD='5ca73c52898cfc2bf58e64d998579eefb06e17c5'
NOW=datetime(2026,11,21,19,45,0,tzinfo=timezone.utc)
SIG='a'*64
PLAN='f'*64


def sequence(*, base=10_000_000_000, increments=(0,1,40,44)):
    return [{'stage':stage,'at_monotonic_ns':base+value*1_000_000_000,
             'plan_sha256':PLAN,'firewall_allow':False,
             'network_connections':0,'vm_starts':0}
            for stage,value in zip(m.STAGES,increments)]


@unittest.skipIf(os.geteuid()==0,'needs nonroot R122 synthetic receipt')
class ContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        f5root=self.root/'capture-root'
        f5root.mkdir(mode=0o700)
        self.mock_root=patch.object(f5,'ROOT',f5root)
        self.mock_root.start()
        self.addCleanup(self.mock_root.stop)
        # The snapshot is synthetic and is explicitly never treated as physical admission.
        snapshot=synthetic_capture()
        self.capture=f5.save_private(snapshot,f5.report(snapshot),root=f5root)
        self.boundary=r122.build(capture_folder=self.capture,head=HEAD,
                                 catalog_raw=CAT,now=NOW)

    def build(self,**overrides):
        args={'boundary':self.boundary,'catalog_raw':CAT,'now':NOW}
        args.update(overrides)
        return m.plan(**args)

    def test_01_schema(self): self.assertEqual(self.build()['schema'],m.SCHEMA)
    def test_02_current_source(self): self.assertEqual(self.build()['head'],HEAD)
    def test_03_source_bound(self): self.assertEqual(self.build()['boundary_sha256'],self.boundary['sha256'])
    def test_04_current_capture(self): self.assertEqual(self.build()['capture_sha256'],self.boundary['capture_sha256'])
    def test_05_60_second_ceiling(self): self.assertEqual(self.build()['max_window_seconds'],60)
    def test_06_default_target_45(self): self.assertEqual(self.build()['deny_restore_target_seconds'],45)
    def test_07_shorter_target(self): self.assertEqual(self.build(duration_seconds=10)['deny_restore_target_seconds'],10)
    def test_08_zero_target_refused(self):
        with self.assertRaises(m.Stop):self.build(duration_seconds=0)
    def test_09_46_target_refused(self):
        with self.assertRaises(m.Stop):self.build(duration_seconds=46)
    def test_10_bool_duration_refused(self):
        with self.assertRaises(m.Stop):self.build(duration_seconds=True)
    def test_11_float_duration_refused(self):
        with self.assertRaises(m.Stop):self.build(duration_seconds=45.0)
    def test_12_naive_clock_refused(self):
        with self.assertRaises(m.Stop):self.build(now=NOW.replace(tzinfo=None))
    def test_13_subsecond_clock_refused(self):
        with self.assertRaises(m.Stop):self.build(now=NOW.replace(microsecond=100))
    def test_14_confirmed_risk_not_present(self):self.assertIsNone(self.build()['a7_confirmed_rf'])
    def test_15_a6_nd(self): self.assertEqual(self.build()['a6'],'ND')
    def test_16_a9_null(self): self.assertIsNone(self.build()['a9_generation'])
    def test_17_a8_no_transition(self): self.assertIsNone(self.build()['a8_authoritative_transition'])
    def test_18_p8_nogo(self): self.assertEqual(self.build()['p8'],'NO-GO')
    def test_19_root_not_installed(self):self.assertFalse(self.build()['guard_installed'])
    def test_20_root_not_armed(self):self.assertFalse(self.build()['guard_armed'])
    def test_21_zero_physical_actions(self):
        r=self.build();self.assertEqual((r['guest_starts'],r['network_connections'],r['firewall_changes']),(0,0,0))
    def test_22_not_consumed(self): self.assertFalse(self.build()['one_shot_attempt_consumed'])
    def test_23_no_operational_permit(self):self.assertFalse(self.build()['root_permit_authenticated'])
    def test_24_blockers(self):
        self.assertIn('ROOT_AUTONOMOUS_60S_DENY_GUARD_NOT_PROVISIONED',self.build()['blockers'])
    def test_25_identical_plan_same_inputs(self):self.assertEqual(self.build(),self.build())
    def test_26_plan_verify_with_sources(self):self.assertTrue(m.verify_plan(self.build(),boundary=self.boundary,catalog_raw=CAT))
    def test_27_forged_a9_refused(self):
        r=self.build();r['a9_generation']=1
        with self.assertRaises(m.Stop):m.verify_plan(r,boundary=self.boundary,catalog_raw=CAT)
    def test_28_forged_p8_refused(self):
        r=self.build();r['p8']='GO'
        with self.assertRaises(m.Stop):m.verify_plan(r,boundary=self.boundary,catalog_raw=CAT)
    def test_29_changed_utc_refused(self):
        r=self.build();r['checked_at_utc']='2026-11-21T19:46:00Z'
        with self.assertRaises(m.Stop):m.verify_plan(r,boundary=self.boundary,catalog_raw=CAT)
    def test_30_wrong_catalog_refused(self):
        with self.assertRaises(m.Stop):self.build(catalog_raw=CAT+b'x')
    def test_31_corrupted_receipt_refused(self):
        (self.capture/'manifest.json').write_text('{}\n')
        with self.assertRaises(m.Stop):self.build()
    def test_32_wrong_head_refused(self):
        fake=dict(self.boundary);fake['head']='1'*40
        with self.assertRaises(m.Stop):self.build(boundary=fake)
    def test_33_r122_report_forged_refused(self):
        fake=dict(self.boundary);fake['dispatch_authorized']=True
        with self.assertRaises(m.Stop):self.build(boundary=fake)
    def test_34_no_network(self):
        with patch.object(socket,'socket',side_effect=AssertionError('SOCKET')):self.build()
    def test_35_no_subprocess(self):
        with patch.object(subprocess,'run',side_effect=AssertionError('SUBPROCESS')):self.build()
    def test_36_partial_pilot_tuple_refused(self):
        with self.assertRaises(m.Stop):self.build(pilot_bundle=(b'A',))
    def test_37_untrusted_pilot_refused(self):
        with self.assertRaises(m.Stop):self.build(pilot_bundle=(b'A',b'B',b'C'),
                                                  pilot_reviewer=lambda *a,**kw: {})
    def test_38_pilot_rejection_failclosed(self):
        def fail(*a,**kw):raise ValueError('REVOKED')
        with self.assertRaises(m.Stop):self.build(pilot_bundle=(b'A',b'B',b'C'),pilot_reviewer=fail)
    def test_39_documentary_status_not_permission(self):
        def signed(*a,**kw):
            return {'document_status':'DOCUMENT_SIGNED','head':HEAD,'family_id':'FTP-T01',
                    'pilot_sha256':SIG,'p8':'NO-GO','authorized_to_connect_by_module':False,
                    'physical_pilot_session_attested':False}
        r=self.build(pilot_bundle=(b'A',b'B',b'C'),pilot_reviewer=signed)
        self.assertEqual(r['pilot_document_status'],'DOCUMENT_SIGNED')
        self.assertEqual(r['p8'],'NO-GO')
        self.assertFalse(r['guard_installed'])
    def test_40_false_signed_grant_refused(self):
        def fake(*a,**kw):
            return {'document_status':'DOCUMENT_SIGNED','head':HEAD,'family_id':'FTP-T01',
                    'pilot_sha256':SIG,'p8':'GO','authorized_to_connect_by_module':True,
                    'physical_pilot_session_attested':True}
        with self.assertRaises(m.Stop):self.build(pilot_bundle=(b'A',b'B',b'C'),pilot_reviewer=fake)
    def test_41_capabilities_nogo(self):self.assertEqual(m.capabilities()['p8'],'NO-GO')
    def test_42_root_watchdog_not_installed(self):self.assertFalse(m.capabilities()['physical_root_watchdog_installed'])
    def test_63_old_boundary_is_blocked(self):
        r=self.build(now=NOW+timedelta(seconds=61))
        self.assertIn('R122_BOUNDARY_EVALUATION_NOT_FRESH',r['blockers'])
    def test_64_future_boundary_is_blocked(self):
        r=self.build(now=NOW-timedelta(seconds=3))
        self.assertIn('R122_BOUNDARY_EVALUATION_NOT_FRESH',r['blockers'])
    def test_65_fresh_boundary_not_stale(self):
        self.assertNotIn('R122_BOUNDARY_EVALUATION_NOT_FRESH',self.build()['blockers'])


class TraceTests(unittest.TestCase):
    def test_43_complete_synthetic_not_root(self):
        x=m.guard_model(plan_sha256=PLAN,events=sequence())
        self.assertTrue(x['monotonic_protocol_complete'])
        self.assertFalse(x['physical_deny_reapplied'])
        self.assertEqual(x['p8'],'NO-GO')
    def test_44_partial_prepared(self): self.assertFalse(m.guard_model(plan_sha256=PLAN,events=sequence()[:1])['monotonic_protocol_complete'])
    def test_45_one_short(self): self.assertFalse(m.guard_model(plan_sha256=PLAN,events=sequence()[:3])['monotonic_protocol_complete'])
    def test_46_empty_trace(self):
        with self.assertRaises(m.Stop):m.guard_model(plan_sha256=PLAN,events=[])
    def test_47_too_many_events(self):
        with self.assertRaises(m.Stop):m.guard_model(plan_sha256=PLAN,events=sequence()+sequence()[:1])
    def test_48_wrong_order(self):
        q=sequence();q[1]['stage']='SESSION_CLOSED'
        with self.assertRaises(m.Stop):m.guard_model(plan_sha256=PLAN,events=q)
    def test_49_tampered_binding(self):
        q=sequence();q[2]['plan_sha256']='0'*64
        with self.assertRaises(m.Stop):m.guard_model(plan_sha256=PLAN,events=q)
    def test_50_wrong_sha(self):
        with self.assertRaises(m.Stop):m.guard_model(plan_sha256='nothex',events=sequence())
    def test_51_clock_regression(self):
        with self.assertRaises(m.Stop):m.guard_model(plan_sha256=PLAN,events=sequence(increments=(0,1,0,44)))
    def test_52_hard_60_seconds(self):
        with self.assertRaises(m.Stop):m.guard_model(plan_sha256=PLAN,events=sequence(increments=(0,1,40,61)))
    def test_53_arm_after_45_seconds(self):
        with self.assertRaises(m.Stop):m.guard_model(plan_sha256=PLAN,events=sequence(increments=(0,46,47,48)))
    def test_54_integer_monotonic_only(self):
        q=sequence();q[1]['at_monotonic_ns']=True
        with self.assertRaises(m.Stop):m.guard_model(plan_sha256=PLAN,events=q)
    def test_55_nft_allow_forbidden(self):
        q=sequence();q[1]['firewall_allow']=True
        with self.assertRaises(m.Stop):m.guard_model(plan_sha256=PLAN,events=q)
    def test_56_one_connection_forbidden(self):
        q=sequence();q[2]['network_connections']=1
        with self.assertRaises(m.Stop):m.guard_model(plan_sha256=PLAN,events=q)
    def test_57_vm_start_forbidden(self):
        q=sequence();q[0]['vm_starts']=1
        with self.assertRaises(m.Stop):m.guard_model(plan_sha256=PLAN,events=q)
    def test_58_root_claim_forbidden(self):
        with self.assertRaises(m.Stop):m.guard_model(plan_sha256=PLAN,events=sequence(),root_supervisor_proof=True)
    def test_59_duplicate_field_forbidden(self):
        q=sequence();q[0]['p8']='GO'
        with self.assertRaises(m.Stop):m.guard_model(plan_sha256=PLAN,events=q)
    def test_60_noninteger_attempts_forbidden(self):
        q=sequence();q[0]['network_connections']=False
        with self.assertRaises(m.Stop):m.guard_model(plan_sha256=PLAN,events=q)
    def test_61_exact_at_60_possible_model_only(self):
        x=m.guard_model(plan_sha256=PLAN,events=sequence(increments=(0,1,40,60)))
        self.assertTrue(x['monotonic_protocol_complete'])
        self.assertFalse(x['root_supervisor_independently_attested'])
    def test_62_same_ns_allowed_but_no_root(self):
        x=m.guard_model(plan_sha256=PLAN,events=sequence(increments=(0,0,0,0)))
        self.assertEqual(x['a6'],'ND')


if __name__=='__main__':unittest.main()
