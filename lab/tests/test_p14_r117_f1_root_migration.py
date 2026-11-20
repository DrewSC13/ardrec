"""R117-F1 unprivileged tests; NO host commands or privilege changes."""
import importlib.util
import json
from pathlib import Path
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

SCRIPT=Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r117_f1_redeploy_root.py'
spec=importlib.util.spec_from_file_location('r117_root_migration',SCRIPT)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class R117MigrationTests(unittest.TestCase):
    def test_source_hashes_pin_r116_f12(self):
        root=SCRIPT.parents[1]
        self.assertEqual(m.digest((root/m.F1_CODE).read_bytes()),m.PIN_NEW_F1)
        self.assertEqual(m.digest((root/m.F3_CODE).read_bytes()),m.PIN_NEW_F3)
    def test_manifest_f1_matches_guard(self):
        root=SCRIPT.parents[1]
        lock=json.loads((root/m.F1_LOCK).read_text())
        self.assertEqual(lock['guard_sha256'],m.PIN_NEW_F1)
        self.assertEqual(lock['window_seconds'],60)
        self.assertEqual(lock['p8'],'NO-GO')
        self.assertIs(lock['opens_ports'],False)
    def test_manifest_f3_33_sha(self):
        root=SCRIPT.parents[1]
        lock=json.loads((root/m.F3_LOCK).read_text())
        self.assertEqual(len(lock['files']),33)
        for name,sha in lock['files'].items():
            local=root/(m.F3_CODE if name=='root-pilot.py' else 'src/'+name.removeprefix('runtime/'))
            self.assertEqual(m.digest(local.read_bytes()),sha,name)
    def test_catalog_pinned(self):
        root=SCRIPT.parents[1]
        self.assertEqual(m.digest((root/m.CATALOG).read_bytes()),m.PIN_CATALOG)
    def test_branch_and_base_are_pinned(self):
        self.assertEqual(m.BASE,'fdb6efa0c297ce18b28cddb9494514f51d88bdb4')
        self.assertTrue(m.BRANCH.startswith('feat/p14-r117-'))
    def test_root_writes_require_explicit_apply(self):
        with patch.object(m,'preflight',return_value='source'),patch.object(m,'check_old'),patch.object(m,'historical'),patch.object(m,'offline'),patch.object(m,'apply') as applied:
            self.assertEqual(m.main(['--inspect']),0)
            applied.assert_not_called()
    def test_no_mode_is_denied(self):
        with self.assertRaises(m.Halt):m.main([])
    def test_ambiguous_mode_is_denied(self):
        with self.assertRaises(m.Halt):m.main(['--inspect','--apply'])
    def test_explicit_apply_path(self):
        with patch.object(m,'preflight',return_value='source'),patch.object(m,'check_old'),patch.object(m,'historical'),patch.object(m,'offline'),patch.object(m,'apply') as applied:
            self.assertEqual(m.main(['--apply']),0)
            applied.assert_called_once_with('source')
    def test_atomic_new_tree_preserves_bytes_and_modes(self):
        with tempfile.TemporaryDirectory() as t:
            d=Path(t); dest=d/'bundle'
            with patch.object(m,'ROOT',d):
                m.new_tree(dest,{'root-guard.py':b'guard','manifest.json':b'{}'})
            self.assertEqual((dest/'root-guard.py').read_bytes(),b'guard')
            self.assertEqual(stat.S_IMODE((dest/'root-guard.py').stat().st_mode),0o600)
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode),0o700)
    def test_new_tree_rejects_existing_destination(self):
        with tempfile.TemporaryDirectory() as t:
            d=Path(t); dest=d/'existing'; dest.mkdir()
            with patch.object(m,'ROOT',d):
                with self.assertRaises(Exception):m.new_tree(dest,{'manifest.json':b'ok'})
            self.assertTrue(dest.is_dir())
    def test_new_tree_rejects_empty_payload(self):
        with tempfile.TemporaryDirectory() as t:
            d=Path(t)
            with patch.object(m,'ROOT',d):
                with self.assertRaises(m.Halt):m.new_tree(d/'new',{'x':b''})
    def test_restore_prior_bundles_after_f3_failure(self):
        with tempfile.TemporaryDirectory() as t:
            d=Path(t); dossier=d/'evidence'; dossier.mkdir()
            f1=d/'f1';f3=d/'f3'; old1=dossier/'old1';old3=dossier/'old3'
            old1.mkdir();old3.mkdir();(old1/'prior').write_text('safe1');(old3/'prior').write_text('safe3')
            f1.mkdir();(f1/'new').write_text('new1')
            with patch.object(m,'F1',f1),patch.object(m,'F3',f3),patch.object(m,'ROOT',d):
                m.restore(old1,old3,dossier,['f1','f3'])
            self.assertEqual((f1/'prior').read_text(),'safe1')
            self.assertEqual((f3/'prior').read_text(),'safe3')
            self.assertTrue((dossier/'partial-new-f1'/'new').exists())
    def test_restore_does_not_rename_absent_old_when_unmoved(self):
        with tempfile.TemporaryDirectory() as t:
            d=Path(t); dossier=d/'evidence'; dossier.mkdir()
            f1=d/'f1';f1.mkdir();(f1/'a').write_text('original')
            with patch.object(m,'F1',f1),patch.object(m,'ROOT',d):m.restore(dossier/'none',dossier/'none3',dossier,[])
            self.assertTrue((f1/'a').exists())
    def test_canonicity_is_stable(self):
        self.assertEqual(m.canon({'z':1,'a':2}),b'{"a":2,"z":1}\n')
    def test_digest_is_sha256(self):
        self.assertEqual(m.digest(b''),'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    def test_unknown_source_paths_denied(self):
        with self.assertRaises(m.Halt):m.signed('../etc/shadow')
    def test_missing_root_privilege_denied(self):
        with patch.object(m.os,'geteuid',return_value=1000):
            with self.assertRaises(m.Halt):m.preflight()
    def test_no_execute_pilot_mode(self):
        with self.assertRaises(SystemExit):m.main(['--execute-pilot'])
    def test_historical_marker_sha_pinned(self):
        self.assertEqual(len(m.PIN_R114_MARKER),64)
        self.assertEqual(len(m.PIN_R114_RECEIPT),64)
    def test_root_redeployment_does_not_change_p8(self):
        self.assertIn(b'NO-GO',m.canon({'p8':'NO-GO'}))
    def test_apply_never_calls_nft_write_directly(self):
        import inspect
        source=inspect.getsource(m.apply)
        self.assertNotIn("'/usr/sbin/nft'",source)
        self.assertNotIn("'/usr/bin/virsh'",source)
        self.assertNotIn('--arm-deny',source)
        self.assertNotIn('--execute-pilot',source)

if __name__=='__main__':unittest.main()
