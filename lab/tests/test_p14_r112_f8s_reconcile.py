"""Tests are synthetic contract tests only, not physical acceptance."""
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch

S=(Path(__file__).resolve().parents[2] / 'scripts' / 'ardrec_p14_r112_f8s_reconcile.py') if 'lab/tests' in str(Path(__file__).resolve()) else Path(__file__).with_name('ardrec_p14_r112_f8s_reconcile.py')
spec=importlib.util.spec_from_file_location('f8s_qa',S)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Contract(TestCase):
    def test_expected_inventory_thirteen_files(self):
        self.assertEqual(len(m.EXPECTED),13)
        self.assertEqual(len(set(m.EXPECTED.values())),12) # grant-dir + grant-file same bytes

    def test_sha256_identity(self):
        self.assertEqual(len(m.digest(b'abc')),64)
        self.assertNotEqual(m.digest(b'abc'),m.digest(b'abd'))

    def test_invalid_plan_absent_rejected(self):
        with TemporaryDirectory() as td:
            with patch.object(m,'PLAN',Path(td)/'missing'):
                with patch.object(m,'BOOT',Path(td)/'boot'):
                    with self.assertRaisesRegex(m.Stop,'PLAN_DIRECTORY_INVALID'):
                        m.read_original()

    def test_extra_file_denied(self):
        with TemporaryDirectory() as td:
            root=Path(td)
            plan=root/'plan';boot=root/'boot';plan.mkdir();boot.mkdir()
            (plan/'EXTRA').write_text('x')
            with patch.object(m,'PLAN',plan),patch.object(m,'BOOT',boot):
                with self.assertRaisesRegex(m.Stop,'PLAN_FILE_SET_DRIFT'):
                    m.read_original()

    def test_symlink_plan_denied(self):
        with TemporaryDirectory() as td:
            root=Path(td);p=root/'plan';p.mkdir();link=root/'link';link.symlink_to(p)
            with patch.object(m,'PLAN',link),patch.object(m,'BOOT',root/'boot'):
                with self.assertRaisesRegex(m.Stop,'PLAN_DIRECTORY_INVALID'):
                    m.read_original()

    def test_invalid_original_hash_denied(self):
        with TemporaryDirectory() as td:
            root=Path(td); plan=root/'plan';boot=root/'boot'
            plan.mkdir();boot.mkdir()
            for key in m.EXPECTED:
                typ,name=key.split('/')
                ((plan if typ=='plan' else boot)/name).write_text('invalid')
            with patch.object(m,'PLAN',plan),patch.object(m,'BOOT',boot):
                with self.assertRaisesRegex(m.Stop,'ORIGINAL_HASH_DRIFT'):
                    m.read_original()

    def test_invalid_scope_current_denied(self):
        after={'snapshot':{'probes':{'f11-hook-stat':{'stdout':'x'}}},'other_domains':{}}
        current={'snapshot':{'probes':{'f11-hook-stat':{'stdout':'x'}}},'other_domains':{}}
        fakecore=SimpleNamespace(ROLES=(),NETWORKS=(),audited=lambda *a,**k:None,
                                 sha=lambda x:'a'*64)
        fakef6=SimpleNamespace(capture=lambda: current)
        fakelegacy=SimpleNamespace()
        # Missing other required static keys is an explicit failure.
        with self.assertRaises(KeyError):
            m.validate_current(fakecore,fakelegacy,None,fakef6,after)

    def test_receipt_only_in_new_dir(self):
        with TemporaryDirectory() as td:
            root=Path(td)
            with patch.object(m,'OUTPUT',root/'receipts'):
                path,checksum=m.create_private_receipt({'p8_operational':'NO-GO'})
                f=Path(path)
                self.assertTrue(f.is_file())
                self.assertEqual(m.digest(f.read_bytes()),checksum)
                self.assertEqual(f.stat().st_mode & 0o777,0o600)
                self.assertEqual(f.parent.stat().st_mode & 0o777,0o700)
                self.assertEqual(json.loads(f.read_text())['p8_operational'],'NO-GO')

    def test_reject_insecure_private_dir(self):
        with TemporaryDirectory() as td:
            output=Path(td)/'bad';output.mkdir(mode=0o755);output.chmod(0o755)
            with patch.object(m,'OUTPUT',output):
                with self.assertRaisesRegex(m.Stop,'RECEIPT_PARENT_PERMISSIONS'):
                    m.create_private_receipt({})

    def test_no_virsh_start_in_source(self):
        source=S.read_text()
        self.assertNotIn("'virsh','-c','qemu:///system','start'",source)
        self.assertNotIn('subprocess.Popen(',source)
        self.assertNotIn('os.system(',source)

if __name__=='__main__': main()
