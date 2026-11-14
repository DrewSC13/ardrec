"""R41 synthetic bounded tests: no real VM starts or traffic from unittest."""
from __future__ import annotations
import copy
from datetime import datetime,timezone,timedelta
import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r41_ssh_resume as r41
from ardrec.coordination import r40_ssh_resume_preflight as r40
from ardrec.coordination import r365_first_boot as r365
from ardrec.coordination import r35_inactive_deployment as r35

H='a'*64
N='0123456789abcdef'*2
T='2026-11-14T22:40:00Z'

def live():
    return {'phase':'NETWORK_ONLY','active_networks':[r365.SSH_NETWORK],
            'active_domains':[],'reserved_links':[r365.t33.NET_BRIDGE['ssh']],
            'bridge_macs':copy.deepcopy(r35.R354_EXISTING_BRIDGE_MACS),
            'deny_first_still_verified':True}

def running():
    x=live();x['phase']='SSH_RUNNING';x['active_domains']=[r365.SSH_DOMAIN]
    x['reserved_links']=sorted([r365.t33.NET_BRIDGE['ssh'],'a33d30t'])
    return x

def storage():
    assets=[]
    for role in r35.t33.ROLES:
        assets.append({'role':role,'runtime_sha256_observed':H,
                       'runtime_preboot_sha256':('b'*64 if role=='ssh' else H),
                       'runtime_sha256_policy':('POSTBOOT_OBSERVATION_NOT_PREBOOT_ORACLE'
                               if role=='ssh' else 'UNMODIFIED_PREBOOT_EXPECTED'),
                       'immutable_layers_verified':True,'qcow2_structure_verified':True,
                       'runtime_observation_stable':True})
    return {'verified_roles':4,'assets':assets,'source_images_mutated_by_r40':False,
            'ssh_runtime_preboot_hash_enforced':False,
            'non_ssh_runtime_preboot_hash_enforced':True}

def source():
    return {'r40_report_sha256':r41.R40_PIN,'r40_file_sha256':'b'*64,
            'r39_report_sha256':'c'*64,'r365_first_boot_report_sha256':'d'*64,
            'r40_host_readback':live(),'r40_storage':storage()}

def pre():
    return r41._common_report('PREFLIGHT_ONLY',r41.PREFLIGHT_STATUS,source(),live(),storage(),
                              datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),N)

def digest_doc(doc):
    doc['sha256']=r41.sha(r41.canon({k:v for k,v in doc.items() if k!='sha256'}))
    return doc

class Host:
    def __init__(self,fail=False):self.calls=0;self.fail=fail
    def activate_ssh_domain(self):
        self.calls+=1
        if self.fail: raise r41.R41Error('fake_virsh_failed')

class R41Tests(unittest.TestCase):
    def _tmp(self):
        parent=tempfile.TemporaryDirectory();self.addCleanup(parent.cleanup)
        p=Path(parent.name);p.chmod(0o700)
        return p
    def _patch_sources(self):
        return mock.patch.multiple(r41, _verify_r40_source=mock.Mock(return_value=source()),
              verify_storage_and_live=mock.Mock(return_value=(live(),storage())),
              _validate_fresh_memory=mock.Mock(return_value=8000))
    def _resume(self, host, *, prior=None):
        with self._patch_sources(),mock.patch.object(r41,'_verify_prior_preflight',return_value=prior or pre()),\
             mock.patch.object(r41.r39,'capture_current',return_value=live()),\
             mock.patch.object(r41.r365,'current',return_value=running()):
            return r41.resume(source_archive=Path('/unused'),r39_dir=Path('/unused'),
               r40_dir=Path('/unused'),r365_preflight_dir=Path('/unused'),
               r365_boot_dir=Path('/unused'),prior_r41_dir=Path('/unused'),
               receipt_dir=self._tmp()/'r41-final',authorized=True,host=host)
    def test_status_schema_contract(self):
        x=pre();self.assertTrue(r41.verify_report(x))
        self.assertEqual(x['p8_operational'],'NO-GO')
        self.assertFalse(x['permission_from_prior_receipt'])
    def test_preflight_no_activation(self):
        h=Host();dest=self._tmp()/'receipt'
        with self._patch_sources():
            x=r41.preflight(source_archive=Path('/unused'),r39_dir=Path('/unused'),
                r40_dir=Path('/unused'),r365_preflight_dir=Path('/unused'),
                r365_boot_dir=Path('/unused'),receipt_dir=dest,host=h)
        self.assertEqual(h.calls,0)
        self.assertEqual(x['status'],r41.PREFLIGHT_STATUS)
        self.assertEqual({p.name for p in dest.iterdir()}, {'r41_preflight.json','SHA256SUMS'})
        self.assertEqual(stat.S_IMODE((dest/'r41_preflight.json').stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE(dest.stat().st_mode),0o700)
    def test_preflight_rejects_source_drift(self):
        h=Host()
        with mock.patch.object(r41,'_verify_r40_source',side_effect=r41.R41Error('drift')):
            with self.assertRaises(r41.R41Error):
                r41.preflight(source_archive=Path('/unused'),r39_dir=Path('/unused'),
                    r40_dir=Path('/unused'),r365_preflight_dir=Path('/unused'),
                    r365_boot_dir=Path('/unused'),receipt_dir=self._tmp()/'notwritten',host=h)
        self.assertEqual(h.calls,0)
    def test_preflight_rejects_memory_shortage(self):
        with self._patch_sources(),mock.patch.object(r41,'_validate_fresh_memory',side_effect=r41.R41Error('memory')):
            with self.assertRaises(r41.R41Error):
                r41.preflight(source_archive=Path('/unused'),r39_dir=Path('/unused'),
                    r40_dir=Path('/unused'),r365_preflight_dir=Path('/unused'),
                    r365_boot_dir=Path('/unused'),receipt_dir=self._tmp()/'no',host=Host())
    def test_no_authorization_means_no_mutation(self):
        with self.assertRaisesRegex(r41.R41Error,'explicit_authorization_missing'):
            r41.resume(source_archive=Path('/unused'),r39_dir=Path('/unused'),
                r40_dir=Path('/unused'),r365_preflight_dir=Path('/unused'),
                r365_boot_dir=Path('/unused'),prior_r41_dir=Path('/unused'),
                receipt_dir=self._tmp()/'never',authorized=False,host=Host())
    def test_host_activation_scope(self):
        self.assertIn("SSH_START",r41.AuthorizedSSHHost.activate_ssh_domain.__code__.co_names)
        self.assertEqual(r41.SSH_START,['/usr/bin/virsh','-c','qemu:///system','start',r365.SSH_DOMAIN])
        self.assertNotIn('net-start',r41.SSH_START)
        self.assertNotIn('destroy',r41.SSH_START)
    def test_report_rehashed_false_authority_rejected(self):
        x=pre();x['operational_dispatch']=True;digest_doc(x)
        with self.assertRaisesRegex(r41.R41Error,'r41_false_authority_claim'):r41.verify_report(x)
    def test_report_rehashed_false_isolation_rejected(self):
        x=pre();x['isolation_tested']=True;digest_doc(x)
        with self.assertRaises(r41.R41Error):r41.verify_report(x)
    def test_report_rehashed_ssh_running_in_preflight_rejected(self):
        x=pre();x['vm_started_by_r41']=True;digest_doc(x)
        with self.assertRaises(r41.R41Error):r41.verify_report(x)
    def test_report_rehashed_false_final_risk_rejected(self):
        x=pre();x['final_risk']=5;digest_doc(x)
        with self.assertRaises(r41.R41Error):r41.verify_report(x)
    def test_report_noncanonical_json_hash_rejected(self):
        x=pre();x['attempt_id']='!'*32
        with self.assertRaises(r41.R41Error):r41.verify_report(x)
    def test_no_world_readable_receipt(self):
        root=self._tmp();root.chmod(0o755)
        with self.assertRaisesRegex(r41.R41Error,'receipt_parent_not_private'):
            r41._make_dir(root/'x')
    def test_no_symlink_parent(self):
        root=self._tmp();sub=root/'actual';sub.mkdir(mode=0o700)
        (root/'link').symlink_to(sub,target_is_directory=True)
        with self.assertRaisesRegex(r41.R41Error,'receipt_path_invalid'):
            r41._make_dir(root/'link'/'receipt')
    def test_never_overwrite_existing_receipt(self):
        root=self._tmp();(root/'existing').mkdir()
        with self.assertRaisesRegex(r41.R41Error,'receipt_path_invalid'):
            r41._make_dir(root/'existing')
    def test_readonly_host_denies_write_methods(self):
        x=object.__new__(r41.ReadOnlyHost)
        with self.assertRaises(r41.R41Error):x.activate_ssh_network()
        with self.assertRaises(r41.R41Error):x.activate_ssh_domain()
        with self.assertRaises(r41.R41Error):x.virsh_write(['start'])
    def test_intent_written_before_start(self):
        h=Host();parent=self._tmp();dest=parent/'final'
        def check():
            self.assertTrue((dest/'r41_intent.json').exists())
            self.assertFalse((dest/'r41_result.json').exists())
        h.activate_ssh_domain=mock.Mock(side_effect=check)
        with self._patch_sources(),mock.patch.object(r41,'_verify_prior_preflight',return_value=pre()),\
             mock.patch.object(r41.r39,'capture_current',return_value=live()),\
             mock.patch.object(r41.r365,'current',return_value=running()):
            x=r41.resume(source_archive=Path('/unused'),r39_dir=Path('/unused'),
                r40_dir=Path('/unused'),r365_preflight_dir=Path('/unused'),
                r365_boot_dir=Path('/unused'),prior_r41_dir=Path('/unused'),
                receipt_dir=dest,authorized=True,host=h)
        self.assertEqual(x['status'],r41.STARTED_STATUS)
        self.assertEqual(h.activate_ssh_domain.call_count,1)
        self.assertEqual({p.name for p in dest.iterdir()},
             {'r41_intent.json','r41_result.json','SHA256SUMS'})
        self.assertTrue(r41.verify_report(x))
        self.assertTrue(x['vm_started_by_r41'])
        self.assertFalse(x['isolation_tested'])
    def test_failed_start_generates_partial_receipt(self):
        h=Host(fail=True)
        result=self._resume(h)
        self.assertEqual(result['status'],r41.PARTIAL_STATUS)
        self.assertEqual(h.calls,1)
        self.assertTrue(result['outcome_uncertain'])
        self.assertFalse(result['vm_started_by_r41'])
        self.assertTrue(r41.verify_report(result))
    def test_failed_readback_does_not_retry_start(self):
        h=Host();dest=self._tmp()/'partial'
        with self._patch_sources(),mock.patch.object(r41,'_verify_prior_preflight',return_value=pre()),\
             mock.patch.object(r41.r39,'capture_current',return_value=live()),\
             mock.patch.object(r41.r365,'current',side_effect=r41.R41Error('unexpected_vm_state')):
            out=r41.resume(source_archive=Path('/unused'),r39_dir=Path('/unused'),
                r40_dir=Path('/unused'),r365_preflight_dir=Path('/unused'),
                r365_boot_dir=Path('/unused'),prior_r41_dir=Path('/unused'),
                receipt_dir=dest,authorized=True,host=h)
        self.assertEqual(h.calls,1)
        self.assertEqual(out['status'],r41.PARTIAL_STATUS)
        self.assertTrue((dest/'r41_intent.json').exists())
        self.assertTrue((dest/'r41_result.json').exists())
    def test_last_readback_drift_blocks_start(self):
        h=Host()
        with self._patch_sources(),mock.patch.object(r41,'_verify_prior_preflight',return_value=pre()),\
             mock.patch.object(r41.r39,'capture_current',return_value=running()):
            with self.assertRaisesRegex(r41.R41Error,'last_instant_host_drift'):
                r41.resume(source_archive=Path('/unused'),r39_dir=Path('/unused'),
                    r40_dir=Path('/unused'),r365_preflight_dir=Path('/unused'),
                    r365_boot_dir=Path('/unused'),prior_r41_dir=Path('/unused'),
                    receipt_dir=self._tmp()/'no-start',authorized=True,host=h)
        self.assertEqual(h.calls,0)
    def test_expired_preflight_rejected(self):
        x=pre();x['captured_at_utc']='2026-01-01T00:00:00Z';digest_doc(x)
        raw=r41.canon(x)+b'\n'
        with mock.patch.object(r41,'verified_directory',return_value={'r41_preflight.json':raw}):
            with self.assertRaisesRegex(r41.R41Error,'r41_preflight_expired_or_future'):
                r41._verify_prior_preflight(Path('/fake'),source())
    def test_foreign_r40_source_rejected(self):
        x=pre();x['source_r40_report_sha256']='0'*64;digest_doc(x)
        with self.assertRaisesRegex(r41.R41Error,'r41_false_authority_claim'):
            r41.verify_report(x)
    def test_storage_drift_rejected(self):
        with self._patch_sources(),mock.patch.object(r41,'verify_storage_and_live',
                 side_effect=r41.R41Error('storage_drift_since_r40')):
            with self.assertRaisesRegex(r41.R41Error,'storage_drift_since_r40'):
                r41.preflight(source_archive=Path('/unused'),r39_dir=Path('/unused'),
                    r40_dir=Path('/unused'),r365_preflight_dir=Path('/unused'),
                    r365_boot_dir=Path('/unused'),receipt_dir=self._tmp()/'no',host=Host())

if __name__=='__main__':unittest.main()
