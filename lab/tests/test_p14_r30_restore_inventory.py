"""R30: verified read-only QCOW2 asset inventory, without image restoration."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import restoration_inventory as inv
from ardrec.coordination.vm_host_preflight import SCHEMA as R29_SCHEMA,canonical as r29_canonical


def good_r29():
    r={
        'schema':R29_SCHEMA,'host':'Prometheus','mode':'READONLY_LIBVIRT',
        'host_metadata_observed':True,
        'summary':'NO_NAMED_ARDREC_DOMAINS_OR_NETWORKS_IN_LIBVIRT_LIST',
        'roles':[{'role':name,'state':'ABSENT_FROM_LIBVIRT_LIST'} for name in inv.ROLES],
        'unrecognized_ardrec_domains':[],'ardrec_networks_listed':[],
        'p8_operational':'NO-GO','operational_dispatch':False,
        'guest_checks_executed':False,'vm_network_probes':False,
        'identity_accredited':False,'technical_truth_accredited':False,
        'external_freshness_custody_verified':False,'published_generation':None,
        'final_risk':None,
    }
    r['sha256']=hashlib.sha256(r29_canonical(r)).hexdigest()
    return r


class R30InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.profile_path=ROOT/'lab/p14-r30-restoration-inventory-v1/expected.json'
        self.profile,self.profile_sha=inv.read_profile(self.profile_path)
        self.r29path=self.root/'libvirt.json'
        self.r29path.write_bytes(r29_canonical(good_r29())+b'\n')
        self.r29sha=hashlib.sha256(self.r29path.read_bytes()).hexdigest()

    def collect(self,scan=False,runner=subprocess.run):
        return inv.collect(self.profile_path,self.r29path,self.r29sha,
                           scan=scan,root=self.root,runner=runner)

    def seed(self):
        for role in self.profile['roles']:
            b=inv.mapped(self.root,role['base_path'])
            t=inv.mapped(self.root,role['runtime_path'])
            b.parent.mkdir(parents=True,exist_ok=True)
            t.parent.mkdir(parents=True,exist_ok=True)
            b.write_bytes(b'fake-qcow2-base')
            t.write_bytes(b'fake-qcow2-runtime')
            b.chmod(0o444)
            t.chmod(0o600)

    @staticmethod
    def owned_stat(path):
        original=R30InventoryTests._original_lstat(path)
        class StatProxy:
            st_uid=0
            st_mode=original.st_mode
            st_nlink=original.st_nlink
            st_size=original.st_size
        return StatProxy()

    def run_qemu(self,argv,**kwargs):
        self.assertEqual(argv[:5],['/usr/bin/qemu-img','info','--output=json','-f','qcow2'])
        self.assertIs(kwargs['stdin'],subprocess.DEVNULL)
        self.assertFalse(kwargs['check'])
        self.assertEqual(kwargs['timeout'],20)
        fname=Path(argv[-1]).name
        role=fname.split('-',1)[0]
        gib=inv.HISTORIC_BASES[role][1]
        meta={'format':'qcow2','virtual-size':gib*1024**3}
        if fname.endswith('runtime.qcow2'):
            meta['backing-filename']=inv.BASE_ROOT+'/'+role+'-base.qcow2'
        return subprocess.CompletedProcess(argv,0,json.dumps(meta).encode(),b'')

    def test_historical_only_no_external_process(self):
        def forbidden(*a,**k): raise AssertionError('subprocess not allowed')
        doc=self.collect(runner=forbidden)
        self.assertTrue(inv.verify_report(doc))
        self.assertEqual(doc['mode'],'HISTORICAL_PATHS_ONLY')
        self.assertEqual(doc['metadata_matching_roles'],0)
        self.assertTrue(all(r['base']['state']=='NOT_SCANNED' for r in doc['roles']))

    def test_metadata_absent_no_process(self):
        def forbidden(*a,**k): raise AssertionError('no qemu-img for missing images')
        doc=self.collect(scan=True,runner=forbidden)
        self.assertEqual(doc['metadata_matching_roles'],0)
        self.assertEqual({r['base']['state'] for r in doc['roles']},{'ABSENT'})
        self.assertFalse(doc['can_restore'])

    def test_known_profile_pins_are_exact(self):
        self.assertEqual([r['role'] for r in self.profile['roles']],list(inv.ROLES))
        self.assertEqual(self.profile['historical_base_root'],inv.BASE_ROOT)
        self.assertFalse(self.profile['authorization_to_restore'])

    def test_manifest_cannot_enable_dispatch(self):
        doc=json.loads(self.profile_path.read_text())
        doc['authorization_to_restore']=True
        replacement=self.root/'bad.json'
        replacement.write_text(json.dumps(doc))
        with self.assertRaises(inv.RestoreInventoryError):inv.read_profile(replacement)

    def test_manifest_cannot_redirect_path(self):
        doc=json.loads(self.profile_path.read_text())
        doc['roles'][0]['base_path']='/etc/shadow'
        replacement=self.root/'bad.json'
        replacement.write_text(json.dumps(doc))
        with self.assertRaises(inv.RestoreInventoryError):inv.read_profile(replacement)

    def test_duplicate_json_key_rejected(self):
        replacement=self.root/'bad.json'
        replacement.write_bytes(b'{"a":1,"a":2}')
        with self.assertRaises(inv.RestoreInventoryError):inv.read_profile(replacement)

    def test_r29_digest_mismatch_rejected(self):
        with self.assertRaises(inv.RestoreInventoryError):
            inv.collect(self.profile_path,self.r29path,'a'*64,scan=False)

    def test_r29_host_residuals_rejected(self):
        report=good_r29()
        report['ardrec_networks_listed']=['ardrec-dev-ssh']
        report['summary']='ARDREC_DOMAINS_OR_NETWORKS_PRESENT_REVIEW_REQUIRED'
        report['sha256']=hashlib.sha256(r29_canonical({k:v for k,v in report.items() if k!='sha256'})).hexdigest()
        self.r29path.write_bytes(r29_canonical(report))
        with self.assertRaises(inv.RestoreInventoryError):
            self.collect(scan=False,runner=lambda *a,**kw:None)

    def test_symlinked_base_rejected(self):
        self.seed()
        b=inv.mapped(self.root,self.profile['roles'][0]['base_path'])
        b.unlink();b.symlink_to(self.root/'fake')
        self.assertEqual(inv.path_metadata(self.root,self.profile['roles'][0]['base_path'],base=True)['state'],'SYMLINK_REJECTED')

    def test_symlinked_parent_rejected(self):
        self.seed()
        first=self.root/'var/lib/libvirt/images/ardrec-dev-point4-v4'
        first.rename(first.with_name('stored-v4'))
        first.symlink_to(first.with_name('stored-v4'),target_is_directory=True)
        self.assertEqual(inv.path_metadata(self.root,self.profile['roles'][0]['base_path'],base=True)['state'],'SYMLINK_REJECTED')

    def test_writable_base_rejected(self):
        self.seed()
        b=inv.mapped(self.root,self.profile['roles'][0]['base_path']);b.chmod(0o644)
        self.assertEqual(inv.path_metadata(self.root,self.profile['roles'][0]['base_path'],base=True)['state'],'UNEXPECTED_LEAF_IDENTITY' if b.stat().st_uid not in (0,64055) else 'BASE_NOT_READONLY')

    def test_qemu_info_cmd_is_readonly(self):
        info=inv.qemu_info(Path('/tmp/ssh-base.qcow2'),runner=self.run_qemu)
        self.assertEqual(info['format'],'qcow2')
        self.assertEqual(info['state'],'QEMU_INFO_READONLY')

    def test_qemu_info_nonzero_fails_closed(self):
        def fail(argv,**kw):return subprocess.CompletedProcess(argv,1,b'',b'error')
        self.assertEqual(inv.qemu_info(Path('/tmp/not-real.qcow2'),runner=fail)['state'],'QEMU_INFO_FAILED')

    def test_qemu_info_invalid_json_fails_closed(self):
        def bad(argv,**kw):return subprocess.CompletedProcess(argv,0,b'not-json',b'')
        self.assertEqual(inv.qemu_info(Path('/tmp/not-real.qcow2'),runner=bad)['state'],'QEMU_INFO_INVALID')

    def test_scan_matching_four_metadata_not_authority(self):
        self.seed()
        # Only the test replaces uid in lstat; production uses actual filesystem identity.
        from pathlib import Path as P
        original=P.lstat
        def owned(path):
            st=original(path)
            class Proxy:
                st_mode=st.st_mode;st_uid=0;st_nlink=st.st_nlink;st_size=st.st_size
            return Proxy()
        with patch.object(P,'lstat',owned):
            doc=self.collect(scan=True,runner=self.run_qemu)
        self.assertEqual(doc['metadata_matching_roles'],4)
        self.assertTrue(inv.verify_report(doc))
        self.assertFalse(doc['can_restore'])
        self.assertFalse(doc['actual_image_content_hashes_verified'])
        self.assertFalse(doc['vm_started'])

    def test_wrong_backing_chain_reported_not_authorized(self):
        self.seed()
        from pathlib import Path as P
        original=P.lstat
        def owned(path):
            st=original(path)
            class Proxy:
                st_mode=st.st_mode;st_uid=0;st_nlink=st.st_nlink;st_size=st.st_size
            return Proxy()
        def wrong(argv,**kwargs):
            p=self.run_qemu(argv,**kwargs)
            meta=json.loads(p.stdout)
            if argv[-1].endswith('ftp-runtime.qcow2'):
                meta['backing-filename']='/tmp/wrong.qcow2'
            return subprocess.CompletedProcess(argv,0,json.dumps(meta).encode(),b'')
        with patch.object(P,'lstat',owned):
            doc=self.collect(scan=True,runner=wrong)
        self.assertEqual(doc['metadata_matching_roles'],3)
        self.assertFalse(doc['can_restore'])

    def test_digest_tampering_detected(self):
        doc=self.collect()
        doc['can_restore']=True
        with self.assertRaises(inv.RestoreInventoryError):inv.verify_report(doc)

    def test_semantic_authority_guard_after_rehash(self):
        doc=self.collect()
        doc['can_restore']=True
        doc['sha256']=hashlib.sha256(inv.canonical({k:v for k,v in doc.items() if k!='sha256'})).hexdigest()
        with self.assertRaises(inv.RestoreInventoryError):inv.verify_report(doc)

    def test_same_input_same_bytes(self):
        a=self.collect();b=self.collect()
        self.assertEqual(inv.canonical(a),inv.canonical(b))


if __name__=='__main__':unittest.main()
