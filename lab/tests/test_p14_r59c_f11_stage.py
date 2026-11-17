"""R59-C: transacción F11 en caja temporal privada; nunca modifica /etc."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r59c_f11_stage as m


def demo():
    return {n: ('ARDRC-test-' + n).encode('ascii') for n in m.ORDER}


class R59CStageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='r59c-tests-')
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        os.chmod(self.root,0o700)
        self.blobs=demo()

    def test_complete_four_sources(self):
        self.assertEqual(len(m.FILES),4)
        self.assertEqual(set(demo()),set(m.FILES))

    def test_source_pins_are_valid_sha256(self):
        for digest,relative,mode in m.FILES.values():
            self.assertRegex(digest,r'^[a-f0-9]{64}$')
            self.assertTrue(relative.startswith('etc/'))
            self.assertIn(mode,(0o755,0o644))

    def test_initial_transaction_and_readback(self):
        result=m.simulate(self.root,self.blobs)
        self.assertEqual(result['status'],'STAGED_ONLY_IN_PRIVATE_SANDBOX')
        stage=self.root/m.STAGE
        for n in m.ORDER:
            p=stage/m.FILES[n][1]
            self.assertEqual(p.read_bytes(),self.blobs[n])
            self.assertEqual(stat.S_IMODE(p.stat().st_mode),m.FILES[n][2])

    def test_replay_identical(self):
        a=m.simulate(self.root,self.blobs)
        b=m.simulate(self.root,self.blobs)
        self.assertEqual(b['status'],'REPLAY_IDENTICAL')
        self.assertEqual(a['receipt_sha256'],b['receipt_sha256'])

    def test_explicit_verify(self):
        m.simulate(self.root,self.blobs)
        self.assertEqual(m.verify_simulation(self.root,self.blobs)['status'],'REPLAY_IDENTICAL')

    def test_input_extra_key_denied(self):
        bad=dict(self.blobs,extraneous=b'x')
        with self.assertRaises(m.StageError):m.simulate(self.root,bad)
        self.assertFalse((self.root/m.STAGE).exists())

    def test_input_missing_key_denied(self):
        bad=dict(self.blobs)
        bad.pop(m.ORDER[0])
        with self.assertRaises(m.StageError):m.simulate(self.root,bad)

    def test_input_nonbytes_denied(self):
        bad=dict(self.blobs)
        bad[m.ORDER[0]]='data'
        with self.assertRaises(m.StageError):m.simulate(self.root,bad)

    def test_private_root_mode_denied(self):
        os.chmod(self.root,0o755)
        with self.assertRaises(m.StageError):m.simulate(self.root,self.blobs)

    def test_simulation_root_under_etc_denied(self):
        with self.assertRaises(m.StageError):m._private_root(Path('/etc'))

    def test_symlink_root_denied(self):
        link=self.root.parent/('r59c-symlink-'+str(os.getpid()))
        link.symlink_to(self.root,target_is_directory=True)
        self.addCleanup(lambda:link.unlink(missing_ok=True))
        with self.assertRaises(m.StageError):m.simulate(link,self.blobs)

    def test_forged_receipt_denied(self):
        m.simulate(self.root,self.blobs)
        receipt=self.root/m.STAGE/m.RECEIPT
        receipt.write_bytes(b'forged')
        with self.assertRaises(m.StageError):m.simulate(self.root,self.blobs)

    def test_same_name_modified_bytes_denied(self):
        m.simulate(self.root,self.blobs)
        bad=dict(self.blobs)
        bad[m.ORDER[0]]=b'changed'
        with self.assertRaises(m.StageError):m.simulate(self.root,bad)

    def test_tampered_destination_denied(self):
        m.simulate(self.root,self.blobs)
        p=self.root/m.STAGE/m.FILES[m.ORDER[0]][1]
        p.write_bytes(b'injected')
        with self.assertRaises(m.StageError):m.verify_simulation(self.root,self.blobs)

    def test_unexpected_file_denied(self):
        m.simulate(self.root,self.blobs)
        (self.root/m.STAGE/'unexpected').write_text('x')
        with self.assertRaises(m.StageError):m.simulate(self.root,self.blobs)

    def test_unexpected_symlink_denied(self):
        m.simulate(self.root,self.blobs)
        (self.root/m.STAGE/'badlink').symlink_to('/etc')
        with self.assertRaises(m.StageError):m.simulate(self.root,self.blobs)

    def test_world_readable_receipt_denied(self):
        m.simulate(self.root,self.blobs)
        os.chmod(self.root/m.STAGE/m.RECEIPT,0o644)
        with self.assertRaises(m.StageError):m.simulate(self.root,self.blobs)

    def test_directory_mode_drift_denied(self):
        m.simulate(self.root,self.blobs)
        os.chmod(self.root/m.STAGE/'etc',0o755)
        with self.assertRaises(m.StageError):m.simulate(self.root,self.blobs)

    def test_conflicting_preexisting_stage_denied(self):
        (self.root/m.STAGE).mkdir()
        with self.assertRaises(m.StageError):m.simulate(self.root,self.blobs)

    def test_fault_injection_rollback_all_steps(self):
        for n in range(1,5):
            with self.subTest(n=n):
                with self.assertRaises(m.StageError):m.simulate(self.root,self.blobs,fail_after=n)
                self.assertEqual(list(self.root.iterdir()),[])

    def test_invalid_fault_injection_denied(self):
        with self.assertRaises(m.StageError):m.simulate(self.root,self.blobs,fail_after=5)
        self.assertFalse((self.root/m.STAGE).exists())

    def test_not_allowed_to_use_host_commands(self):
        src=Path(m.__file__).read_text()
        for forbidden in ('import subprocess', 'from subprocess', 'os.system(', 'Popen(', 'systemctl restart', 'virsh start', 'nft -f'):
            self.assertNotIn(forbidden,src)

    def test_no_host_privileged_apply_path(self):
        self.assertNotIn('apply_to_host',vars(m))
        self.assertNotIn('install_to_etc',vars(m))
        self.assertFalse(m.plan.__defaults__)

    def test_source_file_sha_rejects_drift(self):
        p=self.root/'sample'
        p.write_bytes(b'hello')
        os.chmod(p,0o600)  # El fixture debe ser seguro bajo cualquier umask.
        self.assertEqual(m._source_file(p,m.sha(b'hello')),b'hello')
        with self.assertRaises(m.StageError):m._source_file(p,m.sha(b'wrong'))

    def test_source_file_symlink_denied(self):
        real=self.root/'source'
        real.write_bytes(b'hello')
        link=self.root/'link'
        link.symlink_to(real)
        with self.assertRaises(m.StageError):m._source_file(link,m.sha(b'hello'))

    def test_source_file_empty_denied(self):
        p=self.root/'empty'
        p.touch()
        with self.assertRaises(m.StageError):m._source_file(p,m.sha(b''))

    def test_canonical_deterministic(self):
        receipt=m._receipt(self.blobs)
        self.assertEqual(receipt['sha256'],m.sha(m.canonical({k:v for k,v in receipt.items() if k!='sha256'})))
        self.assertEqual(m._receipt(copy.deepcopy(self.blobs)),receipt)

    def test_only_four_planned_paths(self):
        planned={v[1] for v in m.FILES.values()}
        self.assertEqual(len(planned),4)
        self.assertTrue(all(p.startswith('etc/') for p in planned))

    def test_no_unrelated_files_modified(self):
        sentinel=self.root/'private-user-file'
        sentinel.write_bytes(b'KEEP')
        m.simulate(self.root,self.blobs)
        self.assertEqual(sentinel.read_bytes(),b'KEEP')


if __name__=='__main__': unittest.main()
