"""R143: rejection-first tests; no root operations and no network requests."""
from __future__ import annotations
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

from ardrec.coordination import r143_root_release_handoff as m

HERE = Path(__file__).resolve().parents[2]
B4 = HERE / 'scripts/ardrec_p14_r130_b4_root_guard_v2.py'
B9 = HERE / 'scripts/ardrec_p14_r130_b9_ftp_executor_v2.py'


class ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = {name: ('review:' + name).encode()
                      for name in m.SOURCE}
        cls.sample['operational/B4/root-controller.py'] = B4.read_bytes()
        cls.sample['operational/B9/root-executor.py'] = B9.read_bytes()
        cls.head = 'a' * 40
        cls.tree = 'b' * 40

    def setUp(self):
        self.sources = dict(self.sample)
        self.doc = m.plan(head=self.head, tree=self.tree, sources=self.sources)

    def denied(self, expected, document=None, sources=None):
        with self.assertRaises(m.Refusal) as ctx:
            m.validate_plan(self.doc if document is None else document,
                            self.sources if sources is None else sources)
        self.assertIn(expected, str(ctx.exception))

    def test_01_valid_request(self):
        self.assertEqual(m.validate_plan(self.doc, self.sources), self.doc)
    def test_02_is_canonical(self):
        self.assertEqual(m.canonical(json.loads(m.canonical(self.doc))), m.canonical(self.doc))
    def test_03_is_reproducible(self):
        self.assertEqual(self.doc, m.plan(head=self.head, tree=self.tree, sources=dict(reversed(list(self.sources.items())))))
    def test_04_missing_file_rejected(self):
        self.sources.pop('review/r141_root_material_reader.py'); self.denied('INVENTORY_SCOPE')
    def test_05_extra_file_rejected(self):
        self.sources['review/rogue.py'] = b'anything'; self.denied('INVENTORY_SCOPE')
    def test_06_wrong_bytes_type_rejected(self):
        self.sources['review/r135_root_transaction.py'] = 'not bytes'
        with self.assertRaises(m.Refusal): m.plan(head=self.head, tree=self.tree, sources=self.sources)
    def test_07_b4_modified_rejected(self):
        self.sources['operational/B4/root-controller.py'] += b'X'; self.denied('INVENTORY_ENTRY_MISMATCH')
    def test_08_b9_modified_rejected(self):
        self.sources['operational/B9/root-executor.py'] += b'X'; self.denied('INVENTORY_ENTRY_MISMATCH')
    def test_09_invalid_head_rejected(self):
        with self.assertRaisesRegex(m.Refusal,'HEAD_INVALID'): m.plan(head='G'*40, tree=self.tree, sources=self.sources)
    def test_10_invalid_tree_rejected(self):
        with self.assertRaisesRegex(m.Refusal,'TREE_INVALID'): m.plan(head=self.head, tree='*'*40, sources=self.sources)
    def test_11_target_change_rejected(self):
        doc = copy.deepcopy(self.doc); doc['destinations']['B4']='/tmp'; self.denied('DESTINATION',doc)
    def test_12_signer_roles_change_rejected(self):
        doc = copy.deepcopy(self.doc); doc['required_independent_signer_roles'].pop(); self.denied('INDEPENDENT_AUTHORITIES',doc)
    def test_13_external_material_change_rejected(self):
        doc = copy.deepcopy(self.doc); doc['external_evidence_to_obtain'] = []; self.denied('INDEPENDENT_AUTHORITIES',doc)
    def test_14_root_authority_raised_rejected(self):
        doc = copy.deepcopy(self.doc); doc['root_install_authorized']=True; self.denied('UNAUTHORIZED_AUTHORITY',doc)
    def test_15_network_authority_raised_rejected(self):
        doc = copy.deepcopy(self.doc); doc['network_traffic_authorized']=True; self.denied('UNAUTHORIZED_AUTHORITY',doc)
    def test_16_a6_raised_rejected(self):
        doc = copy.deepcopy(self.doc); doc['a6']='CONFIRMADO'; self.denied('UNAUTHORIZED_AUTHORITY',doc)
    def test_17_a9_raised_rejected(self):
        doc = copy.deepcopy(self.doc); doc['a9']='PUBLISHED'; self.denied('UNAUTHORIZED_AUTHORITY',doc)
    def test_18_p8_raised_rejected(self):
        doc = copy.deepcopy(self.doc); doc['p8']='GO'; self.denied('UNAUTHORIZED_AUTHORITY',doc)
    def test_19_unexpected_field_rejected(self):
        doc = copy.deepcopy(self.doc); doc['magic']=True; self.denied('UNEXPECTED_PLAN',doc)
    def test_20_sha_change_rejected(self):
        doc = copy.deepcopy(self.doc); doc['source_inventory']['review/r142_material_transaction_bridge.py']['sha256']='0'*64; self.denied('INVENTORY_ENTRY',doc)
    def test_21_byte_length_change_rejected(self):
        doc = copy.deepcopy(self.doc); doc['source_inventory']['review/r136_operational_semantics.py']['bytes']=2; self.denied('INVENTORY_ENTRY',doc)
    def test_22_mode_change_rejected(self):
        doc = copy.deepcopy(self.doc); doc['source_inventory']['operational/B4/root-controller.py']['mode']='root approved'; self.denied('INVENTORY_ENTRY',doc)
    def test_23_git_path_change_rejected(self):
        doc = copy.deepcopy(self.doc); doc['source_inventory']['review/r139_independent_release_review.py']['git_path']='../../secret'; self.denied('INVENTORY_ENTRY',doc)
    def test_24_review_only_source_mode(self):
        self.assertTrue(all(x['mode']=='review-only-NOT-root-runtime' for k,x in self.doc['source_inventory'].items() if k.startswith('review/')))
    def test_25_capabilities_no_authority(self):
        cap=m.capabilities(); self.assertFalse(cap['root_install_authorized']); self.assertFalse(cap['independent_root_installer']); self.assertEqual(cap['p8'],'NO-GO')
    def test_26_zip_reproducible_and_verified(self):
        with tempfile.TemporaryDirectory() as folder:
            a=Path(folder)/'a.zip';b=Path(folder)/'b.zip'
            first=m.create_public_bundle(request=self.doc,sources=self.sources,destination=a)
            second=m.create_public_bundle(request=self.doc,sources=self.sources,destination=b)
            self.assertEqual(first, second)
            with zipfile.ZipFile(a) as z:
                self.assertIsNone(z.testzip()); self.assertEqual(set(z.namelist()),set(self.sources)|{'REQUEST.json','MANIFEST.json'})
                self.assertEqual(json.loads(z.read('REQUEST.json')),self.doc)
                self.assertFalse(json.loads(z.read('MANIFEST.json'))['install_authorized'])
    def test_27_existing_target_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/'exists.zip'; target.write_bytes(b'old')
            with self.assertRaisesRegex(m.Refusal,'DESTINATION_INVALID'):
                m.create_public_bundle(request=self.doc,sources=self.sources,destination=target)
    def test_28_nonprivate_parent_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder).chmod(0o755)
            with self.assertRaisesRegex(m.Refusal,'PRIVATE_PARENT_REQUIRED'):
                m.create_public_bundle(request=self.doc,sources=self.sources,destination=Path(folder)/'x.zip')
    def test_29_symlink_target_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            dest=Path(folder)/'link.zip';dest.symlink_to(Path(folder)/'missing')
            with self.assertRaisesRegex(m.Refusal,'DESTINATION_INVALID'):
                m.create_public_bundle(request=self.doc,sources=self.sources,destination=dest)
    def test_30_root_execution_forbidden(self):
        with mock.patch.object(m.os,'geteuid',return_value=0):
            with tempfile.TemporaryDirectory() as folder:
                with self.assertRaisesRegex(m.Refusal,'ROOT_BUNDLE_FORBIDDEN'):
                    m.create_public_bundle(request=self.doc,sources=self.sources,destination=Path(folder)/'x.zip')
    def test_31_unsigned_checkout_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(m,'_git',return_value=''):
                with self.assertRaises(m.Refusal): m.signed_checkout(Path(folder))
    def test_32_checkout_branch_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            def fake(repo,*args):
                return str(repo) if args==('rev-parse','--show-toplevel') else 'other-branch'
            with mock.patch.object(m,'_git',side_effect=fake):
                with self.assertRaisesRegex(m.Refusal,'GIT_BRANCH_INVALID'): m.signed_checkout(Path(folder))
    def test_33_source_missing_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            def fake(repo,*args):
                return {('rev-parse','--show-toplevel'):str(repo),('branch','--show-current'):m.BRANCH,
                        ('remote','get-url','origin'):'https://github.com/DrewSC13/ardrec.git',
                        ('status','--porcelain=v1','--untracked-files=all'):'',
                        ('rev-parse','HEAD'):self.head,('rev-parse','HEAD^{tree}'):self.tree,
                        ('merge-base','--is-ancestor',m.ANCHOR,self.head):'',
                        ('log','-1','--format=%G?'):'G',('verify-commit',self.head):''}[args]
            with mock.patch.object(m,'_git',side_effect=fake):
                with self.assertRaisesRegex(m.Refusal,'SOURCE_FILE_UNSAFE'):
                    m.signed_checkout(root)
    def test_34_source_inconsistent_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name, path in m.SOURCE.items():
                p=root/path; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(self.sources[name])
            def fake(repo,*args):
                return {('rev-parse','--show-toplevel'):str(repo),('branch','--show-current'):m.BRANCH,
                        ('remote','get-url','origin'):'https://github.com/DrewSC13/ardrec.git',
                        ('status','--porcelain=v1','--untracked-files=all'):'',
                        ('rev-parse','HEAD'):self.head,('rev-parse','HEAD^{tree}'):self.tree,
                        ('merge-base','--is-ancestor',m.ANCHOR,self.head):'',
                        ('log','-1','--format=%G?'):'G',('verify-commit',self.head):''}[args]
            with mock.patch.object(m,'_git',side_effect=fake):
                with self.assertRaisesRegex(m.Refusal,'WORKTREE_SOURCE_DIFFERS'):
                    m.signed_checkout(root)
    def test_35_signed_checkout_mocked_git(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name,path in m.SOURCE.items():
                p=root/path; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(self.sources[name])
            def fake(repo,*args):
                return {('rev-parse','--show-toplevel'):str(repo),('branch','--show-current'):m.BRANCH,
                        ('remote','get-url','origin'):'https://github.com/DrewSC13/ardrec.git',
                        ('status','--porcelain=v1','--untracked-files=all'):'',
                        ('rev-parse','HEAD'):self.head,('rev-parse','HEAD^{tree}'):self.tree,
                        ('merge-base','--is-ancestor',m.ANCHOR,self.head):'',
                        ('log','-1','--format=%G?'):'G',('verify-commit',self.head):''}[args]
            def proc(cmd,**kwargs):
                prefix='HEAD:'
                key=cmd[-1].removeprefix(prefix)
                p=root/key
                return mock.Mock(returncode=0,stdout=p.read_bytes())
            with mock.patch.object(m,'_git',side_effect=fake), mock.patch.object(m.subprocess,'run',side_effect=proc):
                req,source=m.signed_checkout(root)
            self.assertEqual(req['source_commit'],self.head)
            self.assertEqual(source,self.sources)
    def test_36_no_secret_or_runtime_approval_in_request(self):
        raw=m.canonical(self.doc)
        self.assertNotIn(b'PRIVATE KEY',raw)
        self.assertNotIn(b'BEGIN OPENSSH',raw)
        self.assertNotIn(b'authorization_signature_b64',raw)
        self.assertFalse(self.doc['root_install_authorized'])
        self.assertFalse(self.doc['trust_anchor_provenance_verified'])

if __name__=='__main__':unittest.main()
