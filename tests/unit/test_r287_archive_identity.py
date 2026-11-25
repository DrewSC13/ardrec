"""R287: deterministic local archival identity checks; no network or live operations."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ardrec.persistence.analytical_archive import AnalyticalArchive
from ardrec.persistence.codec import StorageError
from test_analytical_archive import candidate, store


class ArchiveIdentityTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / 'archive'
        with AnalyticalArchive(self.path, create=True) as archive:
            self.pin = store(archive, candidate())
        self.folder = self.path / self.pin
        self.target = self.folder / (self.pin + '.json')

    def test_unchanged(self):
        with AnalyticalArchive(self.path) as archive:
            self.assertEqual(archive.load(self.pin).snapshot_sha256, self.pin)

    def test_entry_replaced_by_identical_bytes(self):
        # A controlled filesystem mutation on a temporary synthetic fixture.
        original = os.fsync
        target = self.target.stat()
        called = False
        def sync(fd):
            nonlocal called
            original(fd)
            info = os.fstat(fd)
            if not called and (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino):
                called = True
                raw = self.target.read_bytes()
                self.target.rename(self.folder / 'retained-original')
                self.target.write_bytes(raw)
                self.target.chmod(0o400)
        with AnalyticalArchive(self.path) as archive, patch('os.fsync', side_effect=sync):
            with self.assertRaises(StorageError): archive.load(self.pin)
            with self.assertRaisesRegex(StorageError, 'session_unavailable'): archive.load(self.pin)
        self.assertTrue(called)

    def test_permission_changed_after_sync(self):
        original = os.fsync
        target = self.target.stat()
        called = False
        def sync(fd):
            nonlocal called
            original(fd)
            info = os.fstat(fd)
            if not called and (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino):
                called = True
                self.target.chmod(0o644)
        with AnalyticalArchive(self.path) as archive, patch('os.fsync', side_effect=sync):
            with self.assertRaisesRegex(StorageError, 'file_invalid'): archive.load(self.pin)
        self.assertTrue(called)

    def test_snapshot_directory_replaced(self):
        original = AnalyticalArchive._read
        called = False
        def read(fd, reference):
            nonlocal called
            result = original(fd, reference)
            if not called:
                called = True
                self.folder.rename(self.path / 'retained-snapshot')
                self.folder.mkdir(mode=0o700)
            return result
        with AnalyticalArchive(self.path) as archive, patch.object(AnalyticalArchive, '_read', side_effect=read):
            with self.assertRaises(StorageError): archive.load(self.pin)
        self.assertTrue(called)

    def test_directory_changed_during_read(self):
        original = AnalyticalArchive._read
        called = False
        def read(fd, reference):
            nonlocal called
            result = original(fd, reference)
            if not called:
                called = True
                (self.folder / 'unexpected').touch(mode=0o600)
            return result
        with AnalyticalArchive(self.path) as archive, patch.object(AnalyticalArchive, '_read', side_effect=read):
            with self.assertRaisesRegex(StorageError, 'snapshot_directory_changed'): archive.load(self.pin)
        self.assertTrue(called)

if __name__ == '__main__': unittest.main(verbosity=2)
