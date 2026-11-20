"""R116-F8: real import regressions, no root access, VM, nft or network.

Builds a disposable analogue of the immutable R113/R114/F1 bundle; a loader
creating __pycache__ fails the exact file scope assertion in each scenario.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[2]
F1_FILE=REPO/'scripts/ardrec_p14_r116_f1_root_deny_guard.py'
F3_FILE=REPO/'scripts/ardrec_p14_r116_f3_root_pilot.py'
F1_LOCK=REPO/'lab/operational-controller/r116-f1-root-bundle.json'
F3_LOCK=REPO/'lab/operational-controller/r116-f3-root-source-lock-v1.json'

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

F1=load(F1_FILE,'ardrec_f8_test_guard')
F3=load(F3_FILE,'ardrec_f8_test_pilot')

R113_STUB='''import os
from pathlib import Path
def root_bundle():
    here=Path(__file__).parent
    if set(p.name for p in here.iterdir())!={'root-recover.py'}:
        raise ValueError('root_bundle_file_scope')
    return {'r34-deny-restore.nft':b'DENY'}
def expected_nft():return b'DENY'
'''
R114_STUB='''from pathlib import Path
def auth_bundle():
    here=Path(__file__).parent
    if set(p.name for p in here.iterdir())!={'root-window.py'}:
        raise ValueError('ROOT_BUNDLE_FILE_SCOPE_CHANGED')
    return {'r34-ftp-only.nft':b'FTP_ONLY'}
'''
F1_STUB='''from pathlib import Path
def protect_root():
    here=Path(__file__).parent
    if set(p.name for p in here.iterdir())!={'root-guard.py','manifest.json'}:
        raise ValueError('ROOT_FILE_SET_CHANGED')
'''

class PinConsistency(unittest.TestCase):
    def test_f1_manifest_source_digest(self):
        doc=json.loads(F1_LOCK.read_bytes())
        self.assertEqual(doc['guard_sha256'],hashlib.sha256(F1_FILE.read_bytes()).hexdigest())
    def test_f3_source_lock_digest(self):
        doc=json.loads(F3_LOCK.read_bytes())
        self.assertEqual(doc['files']['root-pilot.py'],hashlib.sha256(F3_FILE.read_bytes()).hexdigest())
    def test_f1_read_only_capabilities(self):
        self.assertEqual(F1.main(['--capabilities']),0)
    def test_f3_read_only_capabilities(self):
        self.assertEqual(F3.main(['--capabilities']),0)
    def test_legacy_120_second_runner_not_invoked(self):
        import inspect
        source=inspect.getsource(F3.old_ftp_material)
        self.assertNotIn('module.window(',source)
        self.assertNotIn('module.main(',source)
    def test_source_has_no_python_importlib_loader_for_root(self):
        self.assertNotIn('spec_from_file_location',F1_FILE.read_text())
        self.assertNotIn('spec_from_file_location',F3_FILE.read_text())

class ImportSafety(unittest.TestCase):
    def test_r113_helper_no_pycache_and_bundle_scope(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'root-recover.py';p.write_text(R113_STUB)
            raw=p.read_bytes()
            with patch.object(F1,'HELPER',p),patch.object(F1,'HELPER_SHA',hashlib.sha256(raw).hexdigest()),patch.object(F1,'safe_file',return_value=raw):
                helper,bundle=F1.historical()
            self.assertEqual(bundle['r34-deny-restore.nft'],b'DENY')
            self.assertEqual(helper.__file__,str(p))
            self.assertFalse((p.parent/'__pycache__').exists())
    def test_r113_refuses_unsigned_source(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'root-recover.py';p.write_text(R113_STUB)
            with patch.object(F1,'HELPER',p),patch.object(F1,'HELPER_SHA','0'*64),patch.object(F1,'safe_file',return_value=p.read_bytes()):
                with self.assertRaises(F1.Stop):F1.historical()
            self.assertFalse((p.parent/'__pycache__').exists())
    def test_r113_refuses_mismatched_nft_payload(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'root-recover.py';raw=R113_STUB.replace("b'DENY'","b'WRONG'",1).encode();p.write_bytes(raw)
            with patch.object(F1,'HELPER',p),patch.object(F1,'HELPER_SHA',hashlib.sha256(raw).hexdigest()),patch.object(F1,'safe_file',return_value=raw):
                with self.assertRaises(F1.Stop):F1.historical()
    def test_r114_material_no_pycache_and_bundle_scope(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'root-window.py';p.write_text(R114_STUB);raw=p.read_bytes()
            class Policy:
                def __init__(self):self.candidate=None
                def candidate_rules(self,value):self.candidate=value
            policy=Policy()
            with patch.object(F3,'F114',p),patch.object(F3,'R114_ROOT_SHA256',hashlib.sha256(raw).hexdigest()),patch.object(F3,'valid_dir'),patch.object(F3,'safe',return_value=raw):
                mod,bundle=F3.old_ftp_material(policy)
            self.assertEqual(policy.candidate,b'FTP_ONLY')
            self.assertEqual(mod.__file__,str(p))
            self.assertFalse((p.parent/'__pycache__').exists())
    def test_r114_unsigned_source_blocked_before_exec(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'root-window.py';p.write_text(R114_STUB)
            with patch.object(F3,'F114',p),patch.object(F3,'R114_ROOT_SHA256','0'*64),patch.object(F3,'valid_dir'),patch.object(F3,'safe',return_value=p.read_bytes()):
                with self.assertRaises(F3.Stop):F3.old_ftp_material(object())
            self.assertFalse((p.parent/'__pycache__').exists())
    def test_f1_library_no_pycache_and_source_pin(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'root-guard.py';p.write_text(F1_STUB)
            (p.parent/'manifest.json').write_text(json.dumps({'guard_sha256':hashlib.sha256(p.read_bytes()).hexdigest()}))
            with patch.object(F3,'F1',p),patch.object(F3,'safe',side_effect=lambda path,**_:path.read_bytes()):
                mod=F3.root_guard_library()
            self.assertEqual(mod.__file__,str(p))
            self.assertFalse((p.parent/'__pycache__').exists())
    def test_f1_library_mismatched_source_pin(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'root-guard.py';p.write_text(F1_STUB)
            (p.parent/'manifest.json').write_text(json.dumps({'guard_sha256':'0'*64}))
            with patch.object(F3,'F1',p),patch.object(F3,'safe',side_effect=lambda path,**_:path.read_bytes()):
                with self.assertRaises(F3.Stop):F3.root_guard_library()
            self.assertFalse((p.parent/'__pycache__').exists())
    def test_corrupt_r113_module_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'root-recover.py';p.write_text('def root_bundle():\n  return not_an_existing_name\n');raw=p.read_bytes()
            with patch.object(F1,'HELPER',p),patch.object(F1,'HELPER_SHA',hashlib.sha256(raw).hexdigest()),patch.object(F1,'safe_file',return_value=raw):
                with self.assertRaises(NameError):F1.historical()
            self.assertFalse((p.parent/'__pycache__').exists())
    def test_code_uses_nonmutating_in_memory_exec(self):
        for p in (F1_FILE,F3_FILE):
            text=p.read_text()
            self.assertIn('exec(compile(',text)
            self.assertNotIn('spec.loader.exec_module',text)
    def test_root_staging_remains_explicit(self):
        for p in (F1_FILE,F3_FILE):
            text=p.read_text()
            self.assertNotIn('os.system(',text)
            self.assertIn('NO-GO',text)

if __name__=='__main__':unittest.main()
