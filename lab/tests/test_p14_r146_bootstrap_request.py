"""R146 public review archive is deterministic and contains NO authority."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

REPO=Path(__file__).resolve().parents[2]
SOURCE=REPO/'scripts/ardrec_p14_r146_bootstrap_request.py'
SPEC=importlib.util.spec_from_file_location('r146_request',SOURCE)
assert SPEC is not None and SPEC.loader is not None
m=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

class BootstrapRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contents={key:(REPO/value).read_bytes() for key,value in m.SOURCES.items()}
        cls.head='a'*40
        cls.tree='b'*40

    def test_01_review_manifest_schema(self):
        manifest,request=m.evaluate_sources(head=self.head,tree=self.tree,contents=self.contents)
        self.assertEqual(manifest['schema'],m.SCHEMA)
        self.assertFalse(request['installation_authorized'])
        self.assertEqual(request['p8'],'NO-GO')

    def test_02_installer_source_bound(self):
        manifest,_=m.evaluate_sources(head=self.head,tree=self.tree,contents=self.contents)
        self.assertEqual(manifest['files']['installer.py'],m.sha(self.contents['installer.py']))

    def test_03_all_runtime_sources_bound(self):
        manifest,_=m.evaluate_sources(head=self.head,tree=self.tree,contents=self.contents)
        self.assertEqual(set(manifest['files']),set(m.SOURCES))

    def test_04_drop_includes_no_private_keys(self):
        manifest,request=m.evaluate_sources(head=self.head,tree=self.tree,contents=self.contents)
        self.assertEqual(request['signers_additional_to_operational'],2)
        self.assertFalse(request['permit_present'])
        self.assertFalse(request['root_trust_installed'])

    def test_05_no_reused_production_key(self):
        for source in self.contents.values():
            self.assertNotIn(b'-----BEGIN PRIVATE KEY-----',source)

    def test_06_reject_missing_runtime_module(self):
        bad=dict(self.contents)
        bad.pop('runtime/r139_independent_release_review.py')
        with self.assertRaises(m.Stop):m.evaluate_sources(head=self.head,tree=self.tree,contents=bad)

    def test_07_reject_extra_file(self):
        bad=dict(self.contents)
        bad['etc/root-trust.json']=b'{}'
        with self.assertRaises(m.Stop):m.evaluate_sources(head=self.head,tree=self.tree,contents=bad)

    def test_08_reject_short_head(self):
        with self.assertRaises(m.Stop):m.evaluate_sources(head='a'*32,tree=self.tree,contents=self.contents)

    def test_09_reject_bytes_forgery(self):
        bad=dict(self.contents)
        bad['installer.py']='malformed'
        with self.assertRaises(m.Stop):m.evaluate_sources(head=self.head,tree=self.tree,contents=bad)

    def test_10_bundle_manifest_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            folder.chmod(0o700)
            file,digest,_=m.public_bundle(folder,self.head,self.tree,self.contents)
            self.assertEqual(digest,m.sha(file.read_bytes()))
            self.assertEqual(file.stat().st_mode&0o777,0o600)
            with zipfile.ZipFile(file) as z:
                self.assertIsNone(z.testzip())
                self.assertEqual(set(z.namelist()),set(m.SOURCES)|{'manifest.json','REQUEST.json','MANIFEST.json'})
                request=json.loads(z.read('REQUEST.json'))
                self.assertFalse(request['installed'])
                self.assertFalse(request['installation_authorized'])

    def test_11_bundle_deterministic_bytes(self):
        with tempfile.TemporaryDirectory() as a,tempfile.TemporaryDirectory() as b:
            pa,pb=Path(a),Path(b)
            pa.chmod(0o700);pb.chmod(0o700)
            fa,sha1,_=m.public_bundle(pa,self.head,self.tree,self.contents)
            fb,sha2,_=m.public_bundle(pb,self.head,self.tree,self.contents)
            self.assertEqual(sha1,sha2)
            self.assertEqual(fa.read_bytes(),fb.read_bytes())

    def test_12_bundle_requires_private_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            folder.chmod(0o755)
            with self.assertRaises(m.Stop):m.public_bundle(folder,self.head,self.tree,self.contents)

    def test_13_reject_bundle_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            folder.chmod(0o700)
            m.public_bundle(folder,self.head,self.tree,self.contents)
            with self.assertRaises(m.Stop):m.public_bundle(folder,self.head,self.tree,self.contents)

    def test_14_denies_sudo_and_vm(self):
        script=self.contents['installer.py']
        self.assertNotIn(b'virsh start',script)
        self.assertNotIn(b'sudo',script)
        self.assertNotIn(b'nft -f',script)

    def test_15_source_capabilities(self):
        p=subprocess.run(['python3','-B',str(REPO/'scripts/ardrec_p14_r146_root_installer.py'),
                           '--capabilities'],capture_output=True,text=True,check=False)
        self.assertEqual(p.returncode,0)
        self.assertIn('R146_RUNNING_ROOT_INSTALL=NO',p.stdout)

    def test_16_checkout_cannot_execute_root_install(self):
        p=subprocess.run(['python3','-B',str(REPO/'scripts/ardrec_p14_r146_root_installer.py'),
                           '--install'],capture_output=True,text=True,check=False)
        self.assertEqual(p.returncode,23)
        self.assertIn('R146_STOP=',p.stdout)

    def test_17_source_has_expected_root_paths(self):
        s=self.contents['installer.py'].decode('utf-8')
        self.assertIn('/opt/ardrec/r146-installer-v1',s)
        self.assertIn('/var/lib/ardrec/r146-source-drop-v1',s)
        self.assertIn('/etc/ardrec/r146-install-revocation-v1.json',s)

if __name__=='__main__':unittest.main()
