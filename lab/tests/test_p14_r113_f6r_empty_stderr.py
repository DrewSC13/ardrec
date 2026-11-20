"""R113-F6R: authenticated zero-byte stderr, never relax other evidence."""
from __future__ import annotations
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
SCRIPT = ROOT / 'scripts/ardrec_p14_r113_f6_bundle.py'
spec = importlib.util.spec_from_file_location('ardrec_f6r_bundle_under_test', SCRIPT)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
g = b.g


def create(path: Path, data: bytes):
    path.write_bytes(data)
    path.chmod(0o600)
    return path


class EmptyStderr(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.f5 = self.root / 'f5'
        self.f5.mkdir(mode=0o700)
        self.candidate = self.root / 'bundles'
        self.candidate.mkdir(mode=0o700)

    def test_empty_f5_stderr_accepted(self):
        path = create(self.f5 / 'binding_a33d30r.stderr', b'')
        with patch.object(g, 'F5', self.f5):
            self.assertEqual(b.private_file(path), b'')

    def test_nonempty_f5_stderr_accepted(self):
        path = create(self.f5 / 'nft_r34.stderr', b'warning\n')
        with patch.object(g, 'F5', self.f5):
            self.assertEqual(b.private_file(path), b'warning\n')

    def test_empty_f5_stdout_rejected(self):
        path = create(self.f5 / 'binding_a33d30r.stdout', b'')
        with patch.object(g, 'F5', self.f5):
            with self.assertRaises(g.GuardError):
                b.private_file(path)

    def test_empty_f5_manifest_rejected(self):
        path = create(self.f5 / 'manifest.json', b'')
        with patch.object(g, 'F5', self.f5):
            with self.assertRaises(g.GuardError):
                b.private_file(path)

    def test_empty_bundle_stderr_rejected(self):
        path = create(self.candidate / 'fake.stderr', b'')
        with patch.object(g, 'F5', self.f5):
            with self.assertRaises(g.GuardError):
                b.private_file(path)

    def test_nonempty_f5_stdout_accepted(self):
        path = create(self.f5 / 'binding_a33d30r.stdout', b'<filterbinding/>\n')
        with patch.object(g, 'F5', self.f5):
            self.assertEqual(b.private_file(path), b'<filterbinding/>\n')

    def test_wrong_mode_rejected(self):
        path = create(self.f5 / 'binding_a33d30r.stderr', b'')
        path.chmod(0o644)
        with patch.object(g, 'F5', self.f5):
            with self.assertRaises(g.GuardError):
                b.private_file(path)

    def test_symlink_rejected(self):
        original = create(self.f5 / 'original.bin', b'')
        link = self.f5 / 'binding_a33d30r.stderr'
        link.symlink_to(original)
        with patch.object(g, 'F5', self.f5):
            with self.assertRaises(g.GuardError):
                b.private_file(link)

    def test_hardlink_rejected(self):
        original = create(self.f5 / 'original.bin', b'')
        link = self.f5 / 'binding_a33d30r.stderr'
        os.link(original, link)
        with patch.object(g, 'F5', self.f5):
            with self.assertRaises(g.GuardError):
                b.private_file(link)

    def test_oversized_f5_stderr_rejected(self):
        path = create(self.f5 / 'binding_a33d30r.stderr', b'X' * 524288)
        with patch.object(g, 'F5', self.f5):
            with self.assertRaises(g.GuardError):
                b.private_file(path)

    def test_empty_authenticated_f5_integrated_build_and_replay(self):
        # Existing F6 realistic synthetic topology fixture; adds the missing
        # zero-byte stderr from the genuine F5 capture contract.
        import test_p14_r113_f6_six_binding_guard as previous
        data = previous.f5()
        data['binding_a33d30r.stderr'] = b''
        document = json.loads(data['manifest.json'])
        document['files_sha256']['binding_a33d30r.stderr'] = g.sha(b'')
        data['manifest.json'] = g.canonical(document)
        for name, raw in data.items():
            create(self.f5 / name, raw)
        with (patch.object(g, 'F5', self.f5),
              patch.object(g, 'F5_DIGEST', g.sha(data['manifest.json'])),
              patch.object(b, 'ROOT', self.candidate),
              patch.object(b, 'RECOVER', ROOT / 'scripts/ardrec_p14_r113_f6_root_recover.py')):
            generated = b.build()
            files = b.inspect_dir(generated)
            self.assertEqual(set(files), set(x.name for x in generated.iterdir()))
            self.assertEqual(len(files), 16)
            self.assertEqual(files['source-f5-manifest.json'], data['manifest.json'])
            self.assertTrue(files['r34-deny-restore.nft'].startswith(b'flush table bridge'))

    def test_manifest_authenticates_empty_stderr(self):
        import test_p14_r113_f6_six_binding_guard as previous
        data = previous.f5()
        data['binding_a33d30r.stderr'] = b''
        manifest = json.loads(data['manifest.json'])
        manifest['files_sha256']['binding_a33d30r.stderr'] = g.sha(b'')
        data['manifest.json'] = g.canonical(manifest)
        with patch.object(g, 'F5_DIGEST', g.sha(data['manifest.json'])):
            self.assertTrue(g.check_f5(data))
            data['binding_a33d30r.stderr'] = b'undocumented warning'
            with self.assertRaises(g.GuardError):
                g.check_f5(data)

if __name__ == '__main__':
    unittest.main()
