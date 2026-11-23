"""R166-F8: contractual signed source staging tests, without sudo or root writes."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[2]
HEAD='8c180def6629f34cc29994e3c3c7861fdf1e5f7c'

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,REPO/path)
    assert spec and spec.loader
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

f1=load('scripts/ardrec_p14_r116_f1_root_stage.py','r166_f8_f1_stage')
f3=load('scripts/ardrec_p14_r116_f3_root_stage.py','r166_f8_f3_stage')

class FakeGit:
    def __init__(self,module,*,branch=None,dirty=False,old_valid=True,
                 new_valid=True,signed=True,verify=True,drift=None):
        self.module=module
        self.branch=branch or module.ACTIVE_BRANCH
        self.dirty=dirty
        self.old_valid=old_valid
        self.new_valid=new_valid
        self.signed=signed
        self.verify=verify
        self.drift=drift
        self.queried=[]
    def __call__(self,*args):
        self.queried.append(args)
        if args==('branch','--show-current'):return self.branch.encode()
        if args==('status','--porcelain=v1','--untracked-files=all'):
            return b' M injected.py\n' if self.dirty else b''
        if args[:2]==('merge-base','--is-ancestor'):
            commit=args[2]
            if commit==self.module.BASE and not self.old_valid:
                raise self.module.Stop('MOCK_OLD_ANCESTOR_FAIL')
            if commit==self.module.ACTIVE_BASE and not self.new_valid:
                raise self.module.Stop('MOCK_ACTIVE_ANCESTOR_FAIL')
            return b''
        if args==('log','-1','--format=%G?'):return b'G' if self.signed else b'N'
        if args==('verify-commit','HEAD'):
            if not self.verify:raise self.module.Stop('MOCK_GIT_SIGNATURE_FAILURE')
            return b''
        if args==('rev-parse','HEAD'):return HEAD.encode()
        if len(args)==2 and args[0]=='show' and args[1].startswith('HEAD:'):
            name=args[1].removeprefix('HEAD:')
            raw=(REPO/name).read_bytes()
            return raw+b'TAMPER' if name==self.drift else raw
        raise AssertionError('unexpected git call '+repr(args))

class ContinuityTests(unittest.TestCase):
    def _check(self,module,**kw):
        fake=FakeGit(module,**kw)
        with patch.object(module,'git',side_effect=fake),\
             patch.object(module.os,'geteuid',return_value=0),\
             patch.object(module,'REPO',REPO):
            result=(module.checked_source() if module is f1 else module.checked())
        return fake,result
    def _reject(self,module,**kw):
        with self.assertRaises(module.Stop):self._check(module,**kw)
    def test_two_distinct_stage_helpers_remain(self):
        self.assertNotEqual(f1.BASE,f3.BASE)
        self.assertEqual(f1.ACTIVE_BASE,f3.ACTIVE_BASE)
        self.assertEqual(f1.ACTIVE_BRANCH,f3.ACTIVE_BRANCH)
    def test_both_signed_active(self):
        for m in (f1,f3):
            with self.subTest(name=m.__name__):
                fake,data=self._check(m)
                self.assertTrue(data)
                self.assertIn(('merge-base','--is-ancestor',m.BASE,'HEAD'),fake.queried)
                self.assertIn(('merge-base','--is-ancestor',m.ACTIVE_BASE,'HEAD'),fake.queried)
                self.assertIn(('verify-commit','HEAD'),fake.queried)
    def test_both_signed_historic(self):
        for m in (f1,f3):
            with self.subTest(name=m.__name__):
                fake,_=self._check(m,branch=m.BRANCH)
                self.assertIn(('merge-base','--is-ancestor',m.BASE,'HEAD'),fake.queried)
                self.assertNotIn(('merge-base','--is-ancestor',m.ACTIVE_BASE,'HEAD'),fake.queried)
    def test_arbitrary_branch_rejected(self):
        for m in (f1,f3):
            with self.subTest(name=m.__name__):self._reject(m,branch='work/unsafe')
    def test_active_branch_second_ancestor_missing_rejected(self):
        for m in (f1,f3):
            with self.subTest(name=m.__name__):self._reject(m,new_valid=False)
    def test_historical_ancestor_missing_rejected(self):
        for m in (f1,f3):
            with self.subTest(name=m.__name__):self._reject(m,old_valid=False)
    def test_dirty_repo_rejected(self):
        for m in (f1,f3):
            with self.subTest(name=m.__name__):self._reject(m,dirty=True)
    def test_unsigned_repo_rejected(self):
        for m in (f1,f3):
            with self.subTest(name=m.__name__):self._reject(m,signed=False)
    def test_bad_git_verify_rejected(self):
        for m in (f1,f3):
            with self.subTest(name=m.__name__):self._reject(m,verify=False)
    def test_committed_source_drift_rejected(self):
        self._reject(f1,drift=f1.SOURCE['root-guard.py'])
        self._reject(f3,drift=str(f3.LOCK))
    def test_root_mandatory(self):
        for m in (f1,f3):
            fake=FakeGit(m)
            with patch.object(m,'git',side_effect=fake),\
                 patch.object(m.os,'geteuid',return_value=1000):
                with self.assertRaises(m.Stop):
                    m.checked_source() if m is f1 else m.checked()
    def test_stage_never_implicitly_invoked(self):
        import inspect
        self.assertIn('stage()',inspect.getsource(f1.main))
        self.assertIn('stage()',inspect.getsource(f3.main))
        self.assertIn('--review-source',inspect.getsource(f1.main))
        self.assertIn('--review-source',inspect.getsource(f3.main))
    def test_window_is_not_auto_authorized(self):
        # Native F3 pilot remains a separately staged, explicitly authorized root source.
        raw=(REPO/'scripts/ardrec_p14_r116_f3_root_pilot.py').read_text()
        self.assertIn('ONE-SHOT durability precedes all mutations',raw)
        self.assertIn("selection.add_argument('--execute-pilot'",raw)
        self.assertIn("selection.add_argument('--inspect-root'",raw)
        self.assertIn("'p8':'NO-GO'",raw)
    def test_lock_pins_reconciled_exactly_with_sources(self):
        import json,hashlib
        lock=json.loads((REPO/'lab/operational-controller/r116-f3-root-source-lock-v1.json').read_bytes())
        self.assertGreaterEqual(len(lock['files']),30)
        for dest,sha_expected in lock['files'].items():
            original=('scripts/ardrec_p14_r116_f3_root_pilot.py' if dest=='root-pilot.py'
                      else 'src/'+dest.removeprefix('runtime/'))
            with self.subTest(dest=dest):
                self.assertEqual(hashlib.sha256((REPO/original).read_bytes()).hexdigest(),sha_expected)
    def test_no_active_permissions_in_stage_helpers(self):
        for m in (f1,f3):
            raw=(REPO/'scripts'/('ardrec_p14_r116_f1_root_stage.py' if m is f1 else 'ardrec_p14_r116_f3_root_stage.py')).read_text()
            self.assertIn('ACTIVE_BASE',raw)
            self.assertIn("git('verify-commit','HEAD')",raw)
            self.assertNotIn('sudo -S',raw)

if __name__=='__main__':unittest.main()
