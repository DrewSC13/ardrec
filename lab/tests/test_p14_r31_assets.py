"""R31: real R30 contract, strict fixed-path audit, and no authority escalation."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))

from test_p14_r30_restore_inventory import good_r29
from ardrec.coordination import restoration_inventory as r30
from ardrec.coordination import qcow2_readonly_attestation as a31
from ardrec.coordination.vm_host_preflight import canonical as canonical_r29


class ReadOnlyAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        r29_file=self.root/'libvirt.json'
        r29_file.write_bytes(canonical_r29(good_r29())+b'\n')
        r29_sha=hashlib.sha256(r29_file.read_bytes()).hexdigest()
        self.r30=r30.collect(ROOT/'lab/p14-r30-restoration-inventory-v1/expected.json',
                             r29_file,r29_sha,scan=True,root=self.root)
        self.r30_file=self.root/'host_assets.json'
        self.r30_file.write_bytes(r30.canonical(self.r30)+b'\n')
        self.r30_sha=hashlib.sha256(self.r30_file.read_bytes()).hexdigest()
        self.commands=[]
        self.bad_backing=False
        self.bad_base_sha=False
        self.bad_parent=False
        self.stat_changed=False
        self.sudo_denied=False

    def runner(self,argv,**kwargs):
        self.commands.append(list(argv))
        self.assertEqual(argv[:3], ['/usr/bin/sudo','-n','--'])
        self.assertEqual(kwargs['env'],a31.ENV)
        self.assertIs(kwargs['stdin'],subprocess.DEVNULL)
        self.assertIs(kwargs['stdout'],subprocess.PIPE)
        self.assertIs(kwargs['stderr'],subprocess.PIPE)
        self.assertFalse(kwargs['check'])
        self.assertTrue(kwargs['close_fds'])
        self.assertNotIn('shell',kwargs)
        if self.sudo_denied:
            return subprocess.CompletedProcess(argv,1,b'',b'password required')
        path=argv[-1]
        leaf=path.endswith('.qcow2')
        if argv[3]=='/usr/bin/stat':
            if self.bad_parent and path=='/var/lib/libvirt/images':
                return subprocess.CompletedProcess(argv,0,b'symbolic link|0|0|1|777|1|10|1|1',b'')
            if leaf:
                isbase=path.endswith('-base.qcow2')
                out=('regular file|0|0|1|444|123|10|1|1' if isbase else
                     'regular file|64055|64055|1|600|123|10|1|1')
                if self.stat_changed and self.commands.count(list(argv))==2:
                    out=out.replace('|123|10|','|124|10|')
            else:
                out='directory|0|0|2|750|4096|5|1|1'
            return subprocess.CompletedProcess(argv,0,out.encode('ascii'),b'')
        if argv[3]=='/usr/bin/sha256sum':
            role=Path(path).name.split('-',1)[0]
            val=(r30.HISTORIC_BASES[role][0] if path.endswith('-base.qcow2') else 'e'*64)
            if self.bad_base_sha and path.endswith('-base.qcow2'):
                val='f'*64
            return subprocess.CompletedProcess(argv,0,(val+' *'+path+'\n').encode(),b'')
        if argv[3]=='/usr/bin/qemu-img':
            role=Path(path).name.split('-',1)[0]
            d={'format':'qcow2','virtual-size':r30.HISTORIC_BASES[role][1]*1024**3}
            if path.endswith('-runtime.qcow2'):
                d['backing-filename']=a31.file_path(role,'base')
                if self.bad_backing:
                    d['backing-filename']='/tmp/unknown'
            return subprocess.CompletedProcess(argv,0,json.dumps(d).encode(),b'')
        self.fail('Unknown root command')

    def test_read_actual_r30_contract(self):
        d, sha=a31.load_r30(self.r30_file,self.r30_sha)
        self.assertEqual(d,self.r30)
        self.assertEqual(sha,self.r30_sha)

    def test_reject_changed_r30_source(self):
        self.r30_file.write_bytes(b'{}')
        with self.assertRaises((a31.AssetAuditError,r30.RestoreInventoryError)):
            a31.load_r30(self.r30_file,self.r30_sha)

    def test_reject_rehashed_r30_redirected_path(self):
        d=deepcopy(self.r30)
        d['roles'][0]['historical_base_path']='/etc/shadow'
        d['sha256']=r30.hashlib.sha256(r30.canonical({k:v for k,v in d.items() if k!='sha256'})).hexdigest()
        self.r30_file.write_bytes(r30.canonical(d)+b'\n')
        with self.assertRaises(a31.AssetAuditError):
            a31.load_r30(self.r30_file,hashlib.sha256(self.r30_file.read_bytes()).hexdigest())

    def test_plan_no_external_calls(self):
        def forbidden(*x,**y):raise AssertionError('No calls in plan')
        d=a31.build_report(self.r30,self.r30_sha,mode='PLAN_ONLY',runner=forbidden)
        self.assertTrue(a31.verify_report(d))
        self.assertEqual(d['base_hashes_matching_count'],0)
        self.assertTrue(all(x['base']['status']=='NOT_RUN' for x in d['roles']))

    def test_plan_reproducible(self):
        a=a31.build_report(self.r30,self.r30_sha,mode='PLAN_ONLY')
        b=a31.build_report(self.r30,self.r30_sha,mode='PLAN_ONLY')
        self.assertEqual(a31.canonical(a),a31.canonical(b))

    def test_all_known_pins_match_but_no_restore(self):
        d=a31.build_report(self.r30,self.r30_sha,mode='EXPLICIT_SUDO_READONLY',runner=self.runner)
        self.assertEqual(d['base_hashes_matching_count'],4)
        self.assertEqual(d['overlay_metadata_matching_count'],4)
        self.assertTrue(a31.verify_report(d))
        self.assertFalse(d['can_restore'])
        self.assertFalse(d['backing_chain_custody_accredited'])
        self.assertFalse(d['operational_dispatch'])
        self.assertEqual(d['p8_operational'],'NO-GO')
        self.assertEqual({c[3] for c in self.commands},
                         {'/usr/bin/stat','/usr/bin/sha256sum','/usr/bin/qemu-img'})

    def test_base_hash_mismatch_remains_blocked(self):
        self.bad_base_sha=True
        d=a31.build_report(self.r30,self.r30_sha,mode='EXPLICIT_SUDO_READONLY',runner=self.runner)
        self.assertEqual(d['base_hashes_matching_count'],0)
        self.assertEqual(d['overlay_metadata_matching_count'],4)
        self.assertFalse(d['can_restore'])

    def test_wrong_backing_rejected(self):
        self.bad_backing=True
        d=a31.build_report(self.r30,self.r30_sha,mode='EXPLICIT_SUDO_READONLY',runner=self.runner)
        self.assertEqual(d['overlay_metadata_matching_count'],0)
        self.assertTrue(all(x['overlay']['status']=='HASH_OR_QCOW2_METADATA_MISMATCH' for x in d['roles']))

    def test_untrusted_parent_blocks_before_hash(self):
        self.bad_parent=True
        d=a31.build_report(self.r30,self.r30_sha,mode='EXPLICIT_SUDO_READONLY',runner=self.runner)
        self.assertEqual(d['base_hashes_matching_count'],0)
        self.assertFalse(any(c[3]=='/usr/bin/sha256sum' for c in self.commands))

    def test_sudo_denied_fail_closed(self):
        self.sudo_denied=True
        d=a31.build_report(self.r30,self.r30_sha,mode='EXPLICIT_SUDO_READONLY',runner=self.runner)
        self.assertEqual(d['base_hashes_matching_count'],0)
        self.assertTrue(all(x['base']['status']=='ACCESS_OR_PATH_GUARD_FAILED' for x in d['roles']))

    def test_changed_stat_rejects_unstable_file(self):
        self.stat_changed=True
        d=a31.build_report(self.r30,self.r30_sha,mode='EXPLICIT_SUDO_READONLY',runner=self.runner)
        self.assertEqual(d['base_hashes_matching_count'],0)
        self.assertEqual(d['overlay_metadata_matching_count'],0)
        self.assertTrue(all(x['base']['status']=='UNSTABLE_OR_READ_FAILED' for x in d['roles']))

    def test_bad_filename_rejected(self):
        with self.assertRaises(a31.AssetAuditError):a31.file_path('unknown','base')
        with self.assertRaises(a31.AssetAuditError):a31.file_path('ssh','runtime')

    def test_cannot_dispatch_after_report_rehash(self):
        d=a31.build_report(self.r30,self.r30_sha,mode='PLAN_ONLY')
        d['operational_dispatch']=True
        d['sha256']=a31.sha256(a31.canonical({k:v for k,v in d.items() if k!='sha256'}))
        with self.assertRaises(a31.AssetAuditError):a31.verify_report(d)

    def test_cannot_claim_restore_after_rehash(self):
        d=a31.build_report(self.r30,self.r30_sha,mode='PLAN_ONLY')
        d['can_restore']=True
        d['sha256']=a31.sha256(a31.canonical({k:v for k,v in d.items() if k!='sha256'}))
        with self.assertRaises(a31.AssetAuditError):a31.verify_report(d)

    def test_cannot_forge_plan_execution(self):
        d=a31.build_report(self.r30,self.r30_sha,mode='PLAN_ONLY')
        d['roles'][0]['base']['status']='READONLY_VERIFIED'
        d['roles'][0]['base']['metadata_match']=True
        d['roles'][0]['base']['historical_base_hash_match']=True
        d['roles'][0]['base']['sha256_current']=r30.HISTORIC_BASES['ssh'][0]
        d['base_hashes_matching_count']=1
        d['sha256']=a31.sha256(a31.canonical({k:v for k,v in d.items() if k!='sha256'}))
        with self.assertRaises(a31.AssetAuditError):a31.verify_report(d)

    def test_invalid_sudo_command_forbidden(self):
        with self.assertRaises(a31.AssetAuditError):
            a31.run_readonly(['/usr/bin/sudo','-n','--','/bin/sh','-c','id'],
                             runner=self.runner,timeout=1)

    def test_no_network_or_vm_commands(self):
        self.assertNotIn('virsh',a31.__doc__ or '')
        d=a31.build_report(self.r30,self.r30_sha,mode='PLAN_ONLY')
        self.assertFalse(d['vm_started'])
        self.assertFalse(d['network_probe_performed'])
        self.assertIsNone(d['final_risk'])


if __name__=='__main__':unittest.main()
