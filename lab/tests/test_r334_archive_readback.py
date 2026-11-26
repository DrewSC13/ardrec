"""R334: exact snapshot readback on real local files; no operational dispatch."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ardrec.persistence.analytical_archive import AnalyticalArchive
from ardrec.persistence.codec import StorageError
from test_analytical_archive import candidate, expected_snapshot, store


class ArchiveReadbackTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / 'archive'
        self.data = candidate()
        self.pin = expected_snapshot(self.data)

    def create(self):
        with AnalyticalArchive(self.path, create=True) as archive:
            self.assertEqual(store(archive, self.data), self.pin)
        return self.path / self.pin

    def test_new_snapshot_readback(self):
        with AnalyticalArchive(self.path, create=True) as archive:
            with patch.object(archive, '_load', wraps=archive._load) as readback:
                self.assertEqual(store(archive, self.data), self.pin)
                readback.assert_called_once_with(self.pin)

    def test_extra_file_rejected(self):
        folder = self.create()
        (folder / 'unbound.json').touch(mode=0o600)
        with AnalyticalArchive(self.path) as archive:
            with self.assertRaisesRegex(StorageError, 'snapshot_entries_mismatch'):
                archive.load(self.pin)
        self.assertTrue((folder / 'unbound.json').exists())

    def test_extra_directory_rejected_on_idempotent_store(self):
        folder = self.create()
        (folder / 'unbound').mkdir(mode=0o700)
        with AnalyticalArchive(self.path) as archive:
            with self.assertRaisesRegex(StorageError, 'snapshot_entries_mismatch'):
                store(archive, self.data)
            with self.assertRaisesRegex(StorageError, 'session_unavailable'):
                archive.load(self.pin)
        self.assertTrue((folder / 'unbound').is_dir())

    def test_corruption_after_install_rejected_before_return(self):
        def fault(point):
            if point == 'root_synced':
                target = self.path / self.pin / (self.pin + '.json')
                target.chmod(0o600)
                target.write_bytes(b'{}')
        with AnalyticalArchive(self.path, create=True, fault=fault) as archive:
            with self.assertRaisesRegex(StorageError, 'object_hash_mismatch'):
                store(archive, self.data)
            with self.assertRaisesRegex(StorageError, 'session_unavailable'):
                archive.load(self.pin)
        self.assertEqual((self.path / self.pin / (self.pin + '.json')).read_bytes(), b'{}')

    def test_earlier_object_changed_during_later_read(self):
        folder = self.create()
        target = folder / (self.pin + '.json')
        original = AnalyticalArchive._read
        changed = False
        def read(fd, reference):
            nonlocal changed
            raw = original(fd, reference)
            if reference != self.pin and not changed:
                changed = True
                target.chmod(0o600)
                target.write_bytes(b'{}')
            return raw
        with AnalyticalArchive(self.path) as archive, patch.object(AnalyticalArchive, '_read', side_effect=read):
            with self.assertRaisesRegex(StorageError, 'archive_entry_changed'):
                archive.load(self.pin)
        self.assertTrue(changed)

    def test_extra_symlink_is_not_followed(self):
        folder = self.create()
        outside = self.path.parent / 'outside'
        outside.write_bytes(b'preserve')
        (folder / 'foreign').symlink_to(outside)
        with AnalyticalArchive(self.path) as archive:
            with self.assertRaisesRegex(StorageError, 'snapshot_entries_mismatch'):
                archive.load(self.pin)
        self.assertEqual(outside.read_bytes(), b'preserve')

    def test_clean_reopen_and_repeat_preserve_bytes(self):
        folder = self.create()
        before = {p.name: (p.stat().st_ino, p.read_bytes()) for p in folder.iterdir()}
        with AnalyticalArchive(self.path) as archive:
            self.assertEqual(archive.load(self.pin).projections, self.data[0])
            self.assertEqual(store(archive, self.data), self.pin)
        self.assertEqual(before, {p.name: (p.stat().st_ino, p.read_bytes()) for p in folder.iterdir()})

if __name__ == '__main__':
    unittest.main(verbosity=2)
