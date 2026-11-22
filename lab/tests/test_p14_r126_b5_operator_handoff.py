"""R126 B5: operator handoff is a reproducible, non-deployable document."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH=Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r126_b5_operator_handoff.py'
SOURCE=Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r126_root_session_guard.py'
spec=importlib.util.spec_from_file_location('ardrec_b5_operator_handoff',PATH)
b5=importlib.util.module_from_spec(spec)
spec.loader.exec_module(b5)

class TestB5(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='ardrec-b5-')
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'ardrec'
        self.root.mkdir()
        self.patches=Path(self.tmp.name)/'patches'
        self.patches.mkdir()
        self.src=self.root/b5.SOURCE
        self.src.parent.mkdir(parents=True)
        self.src.write_bytes(SOURCE.read_bytes())
        self.src.chmod(0o644)
        self.files={name:(b' M' if name=='.github/workflows/ci.yml' else b'??')
                    for name in b5.EXPECTED}
        self.addCleanup(patch.stopall)
        patch.object(b5,'REPO',self.root).start()
        patch.object(b5,'PATCHES',self.patches).start()
        patch.object(b5,'git',side_effect=self.git).start()
        patch.object(b5,'metadata',return_value='ABSENT').start()
        patch.object(b5.os,'geteuid',return_value=self.patches.stat().st_uid).start()
        patch.object(b5.Path,'cwd',return_value=self.root).start()

    def git(self,*a):
        if a==('rev-parse','--show-toplevel'): return (str(self.root)+'\n').encode()
        if a==('branch','--show-current'): return (b5.BRANCH+'\n').encode()
        if a==('rev-parse','HEAD'): return (b5.BASE+'\n').encode()
        if a[:1]==('status',):
            return b''.join(status+b' '+name.encode()+b'\0'
                           for name,status in sorted(self.files.items()))
        raise AssertionError(a)

    def test_source_pin(self):
        self.assertEqual(b5.digest(b5.secure_source(self.src)),b5.PIN)
    def test_source_edit_denied(self):
        self.src.write_bytes(self.src.read_bytes()+b'# drift\n')
        with self.assertRaisesRegex(b5.Stop,'PIN_MISMATCH'):b5.secure_source(self.src)
    def test_empty_source_denied(self):
        self.src.write_bytes(b'')
        with self.assertRaisesRegex(b5.Stop,'SOURCE_MODE_OR_SIZE'):b5.secure_source(self.src)
    def test_symlink_denied(self):
        self.src.unlink(); self.src.symlink_to(SOURCE)
        with self.assertRaisesRegex(b5.Stop,'SOURCE_SYMLINK'):b5.secure_source(self.src)
    def test_file_world_writable_denied(self):
        self.src.chmod(0o666)
        with self.assertRaisesRegex(b5.Stop,'SOURCE_MODE_OR_SIZE'):b5.secure_source(self.src)
    def test_uncommitted_review(self):
        report=b5.review()
        self.assertEqual(report['approved_head'],None)
        self.assertEqual(report['root_script_sha256'],b5.PIN)
        self.assertEqual(report['source_file_count'],16)
        self.assertEqual(report['p8'],'NO-GO')
    def test_json_canonical(self):
        raw=b5.canon(b5.review())
        self.assertEqual(raw,b5.canon(json.loads(raw)))
    def test_draft_cannot_be_staged_root(self):
        report=b5.review()
        m=json.loads(b5.drafts(report,self.src.read_bytes())['manifest.json.draft'])
        self.assertFalse(m['root_install_independent'])
        self.assertIsNone(m['approved_head'])
    def test_false_review_refused(self):
        report=b5.review(); report['status']='READY_FOR_EXECUTION'
        with self.assertRaisesRegex(b5.Stop,'REVIEW_NOT_REPRODUCIBLE'):
            b5.drafts(report,self.src.read_bytes())
    def test_wrong_branch_denied(self):
        original=self.git
        def fake(*a):
            if a==('branch','--show-current'):return b'main\n'
            return original(*a)
        with patch.object(b5,'git',side_effect=fake):
            with self.assertRaisesRegex(b5.Stop,'WRONG_BRANCH'):b5.review()
    def test_staged_denied(self):
        self.files['.github/workflows/ci.yml']=b'M '
        with self.assertRaisesRegex(b5.Stop,'UNEXPECTED_GIT_STATUS'):b5.review()
    def test_missing_file_denied(self):
        self.files.pop('src/ardrec/coordination/r129_a6_a10_recovery.py')
        with self.assertRaisesRegex(b5.Stop,'SIXTEEN_FILES'):b5.review()
    def test_extra_file_denied(self):
        self.files['extra.py']=b'??'
        with self.assertRaisesRegex(b5.Stop,'SIXTEEN_FILES'):b5.review()
    def test_prepare_permissions_and_idempotence(self):
        bundle=b5.prepare(parent=self.patches)
        self.assertEqual(bundle.parent,self.patches)
        self.assertEqual(bundle.stat().st_mode & 0o777,0o700)
        self.assertEqual({x.name for x in bundle.iterdir()},set(b5.FILES))
        self.assertTrue(all((x.stat().st_mode & 0o777)==0o600 for x in bundle.iterdir()))
        self.assertEqual(b5.prepare(parent=self.patches),bundle)
    def test_prepare_no_authorization(self):
        bundle=b5.prepare(parent=self.patches)
        manifest=json.loads((bundle/'manifest.json.draft').read_bytes())
        self.assertEqual(manifest['schema'],b5.ROOT_SCHEMA)
        self.assertIsNone(manifest['approved_head'])
        self.assertFalse(manifest['root_install_independent'])
    def test_tamper_rejected(self):
        bundle=b5.prepare(parent=self.patches)
        (bundle/'review.json').write_text('broken\n')
        with self.assertRaisesRegex(b5.Stop,'FILE_TAMPERED'):b5.prepare(parent=self.patches)
    def test_extra_entry_rejected(self):
        bundle=b5.prepare(parent=self.patches)
        (bundle/'unexpected').write_text('bad')
        with self.assertRaisesRegex(b5.Stop,'ENTRY_DRIFT'):b5.prepare(parent=self.patches)
    def test_unsafe_folder_rejected(self):
        bundle=b5.prepare(parent=self.patches)
        bundle.chmod(0o755)
        with self.assertRaisesRegex(b5.Stop,'FOLDER_UNSAFE'):b5.prepare(parent=self.patches)
    def test_wrong_output_parent_rejected(self):
        with self.assertRaisesRegex(b5.Stop,'OUTPUT_PARENT_UNTRUSTED'):
            b5.prepare(parent=self.root)
    def test_metadata_file_absent(self):
        with patch.object(b5,'metadata',wraps=b5.metadata):
            self.assertEqual(b5.metadata(self.root/'missing'),'ABSENT')
    def test_capabilities_no_root(self):
        doc=b5.capabilities()
        self.assertFalse(doc['stages_root'])
        self.assertFalse(doc['opens_traffic'])
        self.assertEqual(doc['p8'],'NO-GO')
    def test_prepare_does_not_touch_root_path(self):
        before=set(self.patches.iterdir())
        b5.prepare(parent=self.patches)
        after=set(self.patches.iterdir())
        self.assertEqual(len(after-before),1)
        self.assertFalse(any(str(x).startswith('/var/lib') for x in after-before))

if __name__=='__main__':unittest.main()
