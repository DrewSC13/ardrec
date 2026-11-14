"""R30-H1: regression for actual R29 CLI linked JSON consumption."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import restoration_inventory as r30
from ardrec.coordination import vm_host_preflight as r29


class R29LinkedContractTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.profile=ROOT/'lab/p14-r30-restoration-inventory-v1/expected.json'
        self.r29_file=self.root/'libvirt.json'
        self.r29_source=ROOT/'lab/p14-r29-vm-preflight-v1/expected.json'
        self.evidence=ROOT/'lab/services-v1/evidence.json'
        self.commands=[]

        def no_domains(argv, **kwargs):
            self.commands.append(tuple(argv))
            self.assertEqual(argv[:4],['virsh','--readonly','--connect','qemu:///system'])
            self.assertIn(argv[4:],(["list","--all","--name"],
                                    ["net-list","--all","--name"]))
            return subprocess.CompletedProcess(argv,0,b'',b'')

        self.bare=r29.collect(self.r29_source,self.evidence,observe=True,
                              runner=no_domains)
        self.assertEqual(len(self.commands),2)
        self.assertTrue(r29.verify_report(self.bare))
        self.linked={
            'schema':'ardrec-p14-r29-linked-lab-view-v1',
            'previous_cycle_sha256':'a'*64,
            'vm_host_preflight':self.bare,
            'p8_operational':'NO-GO',
            'guest_checks_executed':False
        }
        self.reseal()

    def reseal(self):
        self.linked['sha256']=hashlib.sha256(r29.canonical({
            k:v for k,v in self.linked.items() if k!='sha256'})).hexdigest()
        self.r29_file.write_bytes(r29.canonical(self.linked)+b'\n')
        self.expected_sha=hashlib.sha256(self.r29_file.read_bytes()).hexdigest()

    def consume(self,scan=False):
        def no_qemu(*args, **kwargs):
            raise AssertionError('No qemu-img when images do not exist in fixture')
        return r30.collect(self.profile,self.r29_file,self.expected_sha,
                           scan=scan,root=self.root,runner=no_qemu)

    def test_original_linked_cli_contract_unwrapped(self):
        nested, digest=r30.read_r29(self.r29_file,self.expected_sha)
        self.assertEqual(nested,self.bare)
        self.assertEqual(digest,self.expected_sha)

    def test_historical_linked_cli_no_execution(self):
        report=self.consume()
        self.assertTrue(r30.verify_report(report))
        self.assertEqual(report['mode'],'HISTORICAL_PATHS_ONLY')
        self.assertFalse(report['operational_dispatch'])
        self.assertFalse(report['can_restore'])
        self.assertEqual(report['source_r29_report_sha256'],self.bare['sha256'])
        self.assertEqual(report['source_r29_file_sha256'],self.expected_sha)

    def test_scan_absent_images_with_linked_cli_no_qemu(self):
        report=self.consume(scan=True)
        self.assertEqual(report['metadata_matching_roles'],0)
        self.assertFalse(report['vm_started'])
        self.assertFalse(report['can_restore'])
        self.assertTrue(all(r['base']['state']=='ABSENT' for r in report['roles']))

    def test_bare_existing_format_still_accepted(self):
        self.r29_file.write_bytes(r29.canonical(self.bare)+b'\n')
        sha=hashlib.sha256(self.r29_file.read_bytes()).hexdigest()
        actual, received_sha=r30.read_r29(self.r29_file,sha)
        self.assertEqual(actual,self.bare)
        self.assertEqual(sha,received_sha)

    def test_reject_tampered_outer_hash_even_if_file_sha_recomputed(self):
        self.linked['previous_cycle_sha256']='b'*64
        self.r29_file.write_bytes(r29.canonical(self.linked)+b'\n')
        digest=hashlib.sha256(self.r29_file.read_bytes()).hexdigest()
        with self.assertRaises(r30.RestoreInventoryError):
            r30.read_r29(self.r29_file,digest)

    def test_reject_non_digest_cycle_reference(self):
        self.linked['previous_cycle_sha256']='not-a-hash'
        self.reseal()
        with self.assertRaises(r30.RestoreInventoryError):self.consume()

    def test_reject_outer_operational_claim(self):
        self.linked['p8_operational']='GO'
        self.reseal()
        with self.assertRaises(r30.RestoreInventoryError):self.consume()

    def test_reject_outer_guest_check_claim(self):
        self.linked['guest_checks_executed']=True
        self.reseal()
        with self.assertRaises(r30.RestoreInventoryError):self.consume()

    def test_reject_extra_outer_key(self):
        self.linked['dispatch_allowed']=True
        self.reseal()
        with self.assertRaises(r30.RestoreInventoryError):self.consume()

    def test_reject_missing_outer_key(self):
        del self.linked['previous_cycle_sha256']
        self.reseal()
        with self.assertRaises(r30.RestoreInventoryError):self.consume()

    def test_reject_nested_tamper_even_when_outer_is_resealed(self):
        self.linked['vm_host_preflight']=copy.deepcopy(self.bare)
        self.linked['vm_host_preflight']['identity_accredited']=True
        # Re-signing only the outer envelope is insufficient.
        self.reseal()
        with self.assertRaises(r29.VMPreflightError):self.consume()

    def test_reject_rehashed_nested_false_authority(self):
        self.linked['vm_host_preflight']=copy.deepcopy(self.bare)
        nested=self.linked['vm_host_preflight']
        nested['technical_truth_accredited']=True
        nested['sha256']=hashlib.sha256(r29.canonical({k:v for k,v in nested.items()
                                                       if k!='sha256'})).hexdigest()
        self.reseal()
        with self.assertRaises(r29.VMPreflightError):self.consume()

    def test_reject_linked_historical_unobserved_r29(self):
        self.linked['vm_host_preflight']=copy.deepcopy(self.bare)
        nested=self.linked['vm_host_preflight']
        nested['mode']='HISTORICAL_ONLY'
        nested['host_metadata_observed']=False
        nested['sha256']=hashlib.sha256(r29.canonical({k:v for k,v in nested.items()
                                                       if k!='sha256'})).hexdigest()
        self.reseal()
        with self.assertRaises(r30.RestoreInventoryError):self.consume()

    def test_reject_nested_residual_even_if_rehashed(self):
        self.linked['vm_host_preflight']=copy.deepcopy(self.bare)
        nested=self.linked['vm_host_preflight']
        nested['ardrec_networks_listed']=['ardrec-dev-ssh']
        nested['sha256']=hashlib.sha256(r29.canonical({k:v for k,v in nested.items()
                                                       if k!='sha256'})).hexdigest()
        self.reseal()
        with self.assertRaises(r30.RestoreInventoryError):self.consume()


if __name__=='__main__':unittest.main()
