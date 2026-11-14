"""R41.1 bounded observation tests; no real VM starts or packet traffic."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path
import copy
import json
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'src'))
from ardrec.coordination import r411_external_ssh_observation as ob
from ardrec.coordination import r41_ssh_resume as r41
from ardrec.coordination import r365_first_boot as r365
from ardrec.coordination import r35_inactive_deployment as r35

H = 'a' * 64


def live():
    return {'phase':'SSH_RUNNING', 'active_networks':[r365.SSH_NETWORK],
            'active_domains':[r365.SSH_DOMAIN],
            'reserved_links':sorted([r365.t33.NET_BRIDGE['ssh'],'a33d30t']),
            'bridge_macs':copy.deepcopy(r35.R354_EXISTING_BRIDGE_MACS),
            'deny_first_still_verified':True}


def source():
    return {'source_r41_preflight_sha256':H,
            'source_r41_preflight_file_sha256':'b'*64,
            'source_r41_preflight_captured_at_utc':
                (datetime.now(timezone.utc)-timedelta(minutes=6)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'source_r40_report_sha256':r41.R40_PIN,
            'source_r39_report_sha256':'c'*64,
            'source_r365_first_boot_report_sha256':'d'*64,
            'source_archive_sha256':r35.ARCHIVE_SHA256}


def report():
    return ob.make_report(source(),live(),live(),
                          captured_at_utc=r41.now_utc(),operator_acknowledged=True)


def rehash(d):
    d['sha256']=r41.sha(r41.canon({k:v for k,v in d.items() if k!='sha256'}))
    return d


class R411Tests(unittest.TestCase):
    def test_valid_report_keeps_no_go(self):
        x=report()
        self.assertTrue(ob.verify_report(x))
        self.assertEqual(x['status'],ob.STATUS)
        self.assertEqual(x['p8_operational'],'NO-GO')
        self.assertFalse(x['guest_isolation_tested'])
        self.assertFalse(x['start_command_attributed_to_r41_executor'])
    def test_no_acknowledgment_denied(self):
        with self.assertRaisesRegex(ob.R411Error,'acknowledgment'):
            ob.make_report(source(),live(),live(),captured_at_utc=r41.now_utc(),operator_acknowledged=False)
    def test_source_pin_rejected(self):
        x=source();x['source_r40_report_sha256']='0'*64
        with self.assertRaises(ob.R411Error):
            ob.make_report(x,live(),live(),captured_at_utc=r41.now_utc(),operator_acknowledged=True)
    def test_host_drift_rejected(self):
        y=live();y['active_domains']=[]
        with self.assertRaisesRegex(ob.R411Error,'ssh_running_host_scope_invalid'):
            ob.make_report(source(),live(),y,captured_at_utc=r41.now_utc(),operator_acknowledged=True)
    def test_extra_guest_rejected(self):
        x=live();x['active_domains'].append('ardrec-r33-dev-ftp')
        with self.assertRaises(ob.R411Error):ob._validate_running(x)
    def test_extra_network_rejected(self):
        x=live();x['active_networks'].append('ardrec-r33-dev-net-smb')
        with self.assertRaises(ob.R411Error):ob._validate_running(x)
    def test_wrong_tap_rejected(self):
        x=live();x['reserved_links']=['br33d30']
        with self.assertRaises(ob.R411Error):ob._validate_running(x)
    def test_wrong_mac_rejected(self):
        x=live();x['bridge_macs']['ssh']='00:00:00:00:00:00'
        with self.assertRaises(ob.R411Error):ob._validate_running(x)
    def test_no_deny_policy_rejected(self):
        x=live();x['deny_first_still_verified']=False
        with self.assertRaises(ob.R411Error):ob._validate_running(x)
    def test_false_independent_origin_rejected_even_if_rehashed(self):
        x=report();x['start_origin_independently_attested']=True;rehash(x)
        with self.assertRaisesRegex(ob.R411Error,'false_authority'):
            ob.verify_report(x)
    def test_false_r41_executor_attribution_rejected(self):
        x=report();x['start_command_attributed_to_r41_executor']=True;rehash(x)
        with self.assertRaises(ob.R411Error):ob.verify_report(x)
    def test_false_isolation_rejected(self):
        x=report();x['guest_isolation_tested']=True;rehash(x)
        with self.assertRaises(ob.R411Error):ob.verify_report(x)
    def test_false_storage_live_claim_rejected(self):
        x=report();x['storage_integrity_attested_while_running']=True;rehash(x)
        with self.assertRaises(ob.R411Error):ob.verify_report(x)
    def test_final_risk_rejected(self):
        x=report();x['final_risk']=17;rehash(x)
        with self.assertRaises(ob.R411Error):ob.verify_report(x)
    def test_tampered_digest_rejected(self):
        x=report();x['status']='PASS'
        with self.assertRaisesRegex(ob.R411Error,'digest'):
            ob.verify_report(x)
    def test_future_preflight_rejected(self):
        x=source();x['source_r41_preflight_captured_at_utc']='2099-01-01T00:00:00Z'
        with self.assertRaises(ob.R411Error):
            ob.make_report(x,live(),live(),captured_at_utc=r41.now_utc(),operator_acknowledged=True)
    def test_readback_only_calls_current(self):
        with mock.patch.object(ob.r365,'current',return_value=live()) as curr:
            self.assertEqual(ob.readback(object()),live())
        curr.assert_called_once()
        self.assertEqual(curr.call_args.kwargs,{'phase':'SSH_RUNNING'})
    def test_observe_persists_private_receipts(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);root.chmod(0o700)
            dest=root/'new'
            with mock.patch.object(ob,'load_history',return_value=source()),\
                 mock.patch.object(ob,'readback',return_value=live()) as cap:
                x=ob.observe(r41_preflight_dir=Path('/fake'),r40_dir=Path('/fake'),
                             r39_dir=Path('/fake'),r365_preflight_dir=Path('/fake'),
                             r365_boot_dir=Path('/fake'),receipt_dir=dest,
                             operator_acknowledged=True,host=object())
            self.assertEqual(cap.call_count,2)
            self.assertTrue(ob.verify_report(x))
            self.assertEqual({p.name for p in dest.iterdir()},
                             {'r411_external_start.json','SHA256SUMS'})
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE((dest/'r411_external_start.json').stat().st_mode),0o600)
            self.assertEqual(stat.S_IMODE((dest/'SHA256SUMS').stat().st_mode),0o600)
            self.assertEqual(json.loads((dest/'r411_external_start.json').read_bytes())['sha256'],x['sha256'])
    def test_no_new_receipt_when_host_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);root.chmod(0o700)
            dest=root/'new'
            with mock.patch.object(ob,'load_history',return_value=source()),\
                 mock.patch.object(ob,'readback',side_effect=[live(),{'phase':'BEFORE'}]):
                with self.assertRaises(ob.R411Error):
                    ob.observe(r41_preflight_dir=Path('/fake'),r40_dir=Path('/fake'),
                               r39_dir=Path('/fake'),r365_preflight_dir=Path('/fake'),
                               r365_boot_dir=Path('/fake'),receipt_dir=dest,
                               operator_acknowledged=True,host=object())
            self.assertFalse(dest.exists())
    def test_no_permission_blocks_before_sources(self):
        with mock.patch.object(ob,'load_history') as source_read:
            with self.assertRaises(ob.R411Error):
                ob.observe(r41_preflight_dir=Path('/fake'),r40_dir=Path('/fake'),
                           r39_dir=Path('/fake'),r365_preflight_dir=Path('/fake'),
                           r365_boot_dir=Path('/fake'),receipt_dir=Path('/fake'),
                           operator_acknowledged=False)
            source_read.assert_not_called()
    def test_readonly_host_denies_activation(self):
        h=object.__new__(r41.ReadOnlyHost)
        with self.assertRaises(r41.R41Error):h.activate_ssh_domain()
        with self.assertRaises(r41.R41Error):h.activate_ssh_network()
        with self.assertRaises(r41.R41Error):h.virsh_write(['start'])
    def test_historical_expired_preflight_can_be_observed_without_grant(self):
        x=source();x['source_r41_preflight_captured_at_utc']='2026-01-01T00:00:00Z'
        y=ob.make_report(x,live(),live(),captured_at_utc=r41.now_utc(),operator_acknowledged=True)
        self.assertFalse(y['r41_preflight_grants_new_permission'])


if __name__=='__main__': unittest.main()
