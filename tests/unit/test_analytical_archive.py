"""Pruebas de almacenamiento real en disco; no ejecutan herramientas del laboratorio."""
from dataclasses import replace, FrozenInstanceError
import errno
import multiprocessing
import os
from pathlib import Path
import signal
import tempfile
import threading
import unittest
from unittest.mock import patch

from ardrec.analytical import encode_projection
from ardrec.analytical_references import canonical, ReferenceError
from ardrec.persistence.analytical_archive import AnalyticalArchive, FORMAT, digest
from ardrec.persistence.codec import StorageError
from test_analytical_references import fixture


def candidate(generation=18):
    p, manifest, objects = fixture()
    p = replace(p, generation_index=generation)
    manifest['context']['generation_index'] = generation
    raw = canonical(manifest)
    return (p,), raw, objects


def expected_snapshot(data):
    projections, manifest, _ = data
    return digest(canonical({'format': FORMAT, 'manifest_sha256': digest(manifest),
                             'projection_sha256': [digest(encode_projection(p)) for p in projections]}))


def store(archive, data):
    projections, raw, objects = data
    return archive.store(projections, raw, expected_manifest_sha256=digest(raw), load_object=objects.__getitem__)


def killed_writer(path, data, point):
    def fault(actual):
        if actual == point:
            os.kill(os.getpid(), signal.SIGKILL)
    with AnalyticalArchive(path, fault=fault) as archive:
        store(archive, data)


class AnalyticalArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'archive'
        self.data = candidate()

    def initialized(self):
        with AnalyticalArchive(self.path, create=True) as archive:
            return store(archive, self.data)

    def test_roundtrip_reopen_and_exact_bytes(self):
        reference = self.initialized()
        self.assertEqual(reference, expected_snapshot(self.data))
        with AnalyticalArchive(self.path) as archive:
            result = archive.load(reference)
        self.assertEqual(result.projections, self.data[0])
        self.assertEqual(result.references.manifest_bytes, self.data[1])
        self.assertEqual(set(result.references.object_bytes), set(self.data[2].values()))

    def test_idempotent_store_never_rewrites(self):
        reference = self.initialized()
        before = {p.name: (p.stat().st_ino, p.stat().st_mtime_ns) for p in (self.path / reference).iterdir()}
        with AnalyticalArchive(self.path) as archive:
            self.assertEqual(store(archive, self.data), reference)
        self.assertEqual(before, {p.name: (p.stat().st_ino, p.stat().st_mtime_ns) for p in (self.path / reference).iterdir()})

    def test_generation_selection_is_explicit(self):
        previous = self.initialized()
        with AnalyticalArchive(self.path) as archive:
            newer = store(archive, candidate(19))
            self.assertEqual(archive.load(previous).projections[0].generation_index, 18)
            self.assertEqual(archive.load(newer).projections[0].generation_index, 19)
        self.assertFalse((self.path / 'HEAD').exists())

    def test_result_has_no_authority_and_is_immutable(self):
        reference = self.initialized()
        with AnalyticalArchive(self.path) as archive:
            result = archive.load(reference)
        self.assertFalse(hasattr(result, 'authority'))
        with self.assertRaises(FrozenInstanceError):
            result.snapshot_sha256 = '0' * 64

    def test_invalid_candidate_writes_nothing(self):
        with AnalyticalArchive(self.path, create=True) as archive:
            p, raw, objects = self.data
            with self.assertRaises(ReferenceError):
                archive.store(p, raw, expected_manifest_sha256='0' * 64, load_object=objects.__getitem__)
            self.assertEqual({p.name for p in self.path.iterdir()}, {'LOCK'})
            store(archive, self.data)

    def test_missing_provider_object_writes_nothing(self):
        p, raw, _ = self.data
        def missing(_):
            raise FileNotFoundError()
        with AnalyticalArchive(self.path, create=True) as archive:
            with self.assertRaises(ReferenceError):
                archive.store(p, raw, expected_manifest_sha256=digest(raw), load_object=missing)
            self.assertEqual({p.name for p in self.path.iterdir()}, {'LOCK'})

    def test_modified_object_rejected_and_session_poisoned(self):
        reference = self.initialized()
        target = self.path / reference / (next(iter(self.data[2])) + '.json')
        target.chmod(0o600)
        target.write_bytes(b'{}')
        with AnalyticalArchive(self.path) as archive:
            with self.assertRaises(StorageError): archive.load(reference)
            with self.assertRaisesRegex(StorageError, 'session_unavailable'): store(archive, self.data)

    def test_missing_object_rejected_without_repair(self):
        reference = self.initialized()
        target = self.path / reference / (next(iter(self.data[2])) + '.json')
        target.unlink()
        with AnalyticalArchive(self.path) as archive:
            with self.assertRaises(ReferenceError): archive.load(reference)
        self.assertFalse(target.exists())

    def test_modified_metadata_rejected(self):
        reference = self.initialized()
        target = self.path / reference / (reference + '.json')
        target.chmod(0o600); target.write_bytes(b'{}')
        with AnalyticalArchive(self.path) as archive:
            with self.assertRaises(StorageError): archive.load(reference)

    def test_corrupt_existing_snapshot_not_overwritten(self):
        reference = self.initialized()
        target = self.path / reference / (reference + '.json')
        target.chmod(0o600); target.write_bytes(b'corrupt')
        with AnalyticalArchive(self.path) as archive:
            with self.assertRaises(StorageError): store(archive, self.data)
        self.assertEqual(target.read_bytes(), b'corrupt')

    def test_missing_snapshot_never_promotes_orphans(self):
        reference = self.initialized()
        orphan = self.path / '.pending-retained'
        (self.path / reference).rename(orphan)
        with AnalyticalArchive(self.path) as archive:
            with self.assertRaises(FileNotFoundError): archive.load(reference)
        self.assertTrue(orphan.exists()); self.assertFalse((self.path / reference).exists())

    def test_path_traversal_rejected(self):
        self.initialized()
        for bad in ('../escape', '', 'A' * 64, True):
            with self.subTest(bad=bad), AnalyticalArchive(self.path) as archive:
                with self.assertRaises(ReferenceError): archive.load(bad)

    def test_symlink_directory_and_parent_rejected(self):
        self.initialized()
        link = self.path.parent / 'link'; link.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(OSError): AnalyticalArchive(link)
        with self.assertRaises(OSError): AnalyticalArchive(link / 'nested', create=True)

    def test_snapshot_symlink_rejected(self):
        reference = self.initialized()
        real = self.path / 'retained'; (self.path / reference).rename(real)
        (self.path / reference).symlink_to(real, target_is_directory=True)
        with AnalyticalArchive(self.path) as archive:
            with self.assertRaises(OSError): archive.load(reference)

    def test_object_symlink_hardlink_and_fifo_rejected(self):
        reference = self.initialized()
        target = self.path / reference / (next(iter(self.data[2])) + '.json')
        raw = target.read_bytes(); target.unlink()
        external = self.path.parent / 'external'; external.write_bytes(raw); external.chmod(0o400)
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind):
                if kind == 'symlink': target.symlink_to(external)
                elif kind == 'hardlink': os.link(external, target)
                else: os.mkfifo(target, 0o600)
                with AnalyticalArchive(self.path) as archive:
                    with self.assertRaises((StorageError, OSError)): archive.load(reference)
                target.unlink()

    def test_private_permissions_enforced(self):
        reference = self.initialized()
        self.path.chmod(0o755)
        with self.assertRaises(StorageError): AnalyticalArchive(self.path)
        self.path.chmod(0o700)
        target = self.path / reference / (reference + '.json'); target.chmod(0o644)
        with AnalyticalArchive(self.path) as archive:
            with self.assertRaises(StorageError): archive.load(reference)

    def test_concurrent_writer_rejected(self):
        with AnalyticalArchive(self.path, create=True):
            with self.assertRaisesRegex(StorageError, 'writer_busy'): AnalyticalArchive(self.path)
        with AnalyticalArchive(self.path): pass

    def test_replaced_lock_poison_session(self):
        with AnalyticalArchive(self.path, create=True) as archive:
            (self.path / 'LOCK').rename(self.path / 'old-lock')
            (self.path / 'LOCK').write_bytes(b''); (self.path / 'LOCK').chmod(0o600)
            with self.assertRaisesRegex(StorageError, 'session_replaced'): store(archive, self.data)
            with self.assertRaisesRegex(StorageError, 'session_unavailable'): store(archive, self.data)

    def test_replaced_directory_rejected(self):
        with AnalyticalArchive(self.path, create=True) as archive:
            self.path.rename(self.path.parent / 'old'); self.path.mkdir(mode=0o700)
            with self.assertRaises(StorageError): store(archive, self.data)

    def test_wrong_thread_and_closed_session_rejected(self):
        errors = []
        with AnalyticalArchive(self.path, create=True) as archive:
            def worker():
                try: store(archive, self.data)
                except StorageError as error: errors.append(error.code)
            t = threading.Thread(target=worker); t.start(); t.join(5)
            self.assertFalse(t.is_alive()); self.assertEqual(errors, ['session_owner'])
        with self.assertRaises(StorageError): store(archive, self.data)

    def test_short_writes_completed(self):
        original = os.write
        with AnalyticalArchive(self.path, create=True) as archive:
            with patch('ardrec.persistence.analytical_archive.os.write', side_effect=lambda fd, data: original(fd, data[:7])):
                reference = store(archive, self.data)
            self.assertEqual(archive.load(reference).projections, self.data[0])

    def test_zero_write_and_disk_full_do_not_confirm(self):
        for mode in ('zero', 'full'):
            path = self.path.parent / mode
            with AnalyticalArchive(path, create=True) as archive:
                kw = {'return_value': 0} if mode == 'zero' else {'side_effect': OSError(errno.ENOSPC, 'full')}
                with patch('ardrec.persistence.analytical_archive.os.write', **kw):
                    with self.assertRaises((StorageError, OSError)): store(archive, self.data)
                with self.assertRaises(StorageError): store(archive, self.data)
            self.assertFalse((path / expected_snapshot(self.data)).exists())

    def test_sync_failure_does_not_confirm(self):
        with AnalyticalArchive(self.path, create=True) as archive:
            with patch('ardrec.persistence.analytical_archive.os.fsync', side_effect=OSError('sync failed')):
                with self.assertRaises(OSError): store(archive, self.data)
            with self.assertRaises(StorageError): store(archive, self.data)
        self.assertFalse((self.path / expected_snapshot(self.data)).exists())

    def test_root_sync_failure_requires_recovery(self):
        with AnalyticalArchive(self.path, create=True) as archive:
            original = os.fsync
            def sync(fd):
                if fd == archive._root: raise OSError('root sync failed')
                original(fd)
            with patch('ardrec.persistence.analytical_archive.os.fsync', side_effect=sync):
                with self.assertRaises(OSError): store(archive, self.data)
        with AnalyticalArchive(self.path) as recovered:
            self.assertEqual(recovered.load(expected_snapshot(self.data)).projections, self.data[0])

    def test_snapshot_and_object_size_bounds(self):
        reference = self.initialized()
        with AnalyticalArchive(self.path) as archive:
            with patch('ardrec.persistence.analytical_archive.MAX_ARCHIVE_BYTES', 1):
                with self.assertRaises(StorageError): archive.load(reference)
        target = self.path / reference / (reference + '.json')
        target.chmod(0o600); target.write_bytes(b'x' * 262145)
        with AnalyticalArchive(self.path) as archive:
            with self.assertRaisesRegex(StorageError, 'object_too_large'): archive.load(reference)

    def test_fault_boundaries_preserve_previous_snapshot(self):
        previous = self.initialized()
        for index, point in enumerate(('directory_created', 'object_write', 'object_synced', 'snapshot_synced', 'before_install', 'after_install', 'root_synced')):
            newer = candidate(19 + index)
            def fail(actual):
                if actual == point: raise OSError(point)
            with AnalyticalArchive(self.path, fault=fail) as archive:
                with self.assertRaises(OSError): store(archive, newer)
                with self.assertRaises(StorageError): archive.load(previous)
            with AnalyticalArchive(self.path) as recovered:
                self.assertEqual(recovered.load(previous).projections, self.data[0])
                if point in ('after_install', 'root_synced'):
                    self.assertEqual(recovered.load(expected_snapshot(newer)).projections, newer[0])
                else:
                    with self.assertRaises(FileNotFoundError): recovered.load(expected_snapshot(newer))

    def test_sigkill_never_returns_partial_snapshot(self):
        previous = self.initialized()
        for index, point in enumerate(('object_write', 'object_synced', 'before_install', 'after_install', 'root_synced')):
            newer = candidate(40 + index)
            process = multiprocessing.get_context('fork').Process(target=killed_writer, args=(self.path, newer, point))
            process.start(); process.join(10)
            if process.is_alive(): process.kill(); process.join(5)
            self.assertEqual(process.exitcode, -signal.SIGKILL)
            process.close()
            with AnalyticalArchive(self.path) as recovered:
                self.assertEqual(recovered.load(previous).projections, self.data[0])
                if point in ('after_install', 'root_synced'):
                    self.assertEqual(recovered.load(expected_snapshot(newer)).projections, newer[0])
                else:
                    with self.assertRaises(FileNotFoundError): recovered.load(expected_snapshot(newer))


if __name__ == '__main__':
    unittest.main(verbosity=2)
