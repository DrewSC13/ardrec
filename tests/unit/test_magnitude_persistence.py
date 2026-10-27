"""Comprobar valores exactos y publicaciones completas ante fallos."""

from fractions import Fraction
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

from ardrec.contracts import ND
from ardrec.persistence.codec import StorageError, pack
from ardrec.persistence.magnitudes import (
    FORMAT, MAX_RECORD_BYTES, MagnitudeArchive, decode_record, encode_record,
)

POINTS = ('after_temp_create', 'after_write', 'after_file_sync',
          'before_replace', 'after_replace', 'after_directory_sync')


def crash_writer(path, point):
    def fault(current):
        if current == point:
            os.kill(os.getpid(), signal.SIGKILL)
    with MagnitudeArchive(path, fault=fault) as archive:
        archive.write(Fraction(2**255 + 1, 2**256 - 1))


def competing_writer(path, queue):
    try:
        with MagnitudeArchive(path):
            queue.put('unexpected')
    except StorageError as error:
        queue.put(error.code)


class MagnitudePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ardrec-magnitudes-test-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'magnitudes'

    def create(self, **kwargs):
        archive = MagnitudeArchive(self.path, create=True, **kwargs)
        self.addCleanup(archive.close)
        return archive

    def test_exact_record_round_trips(self):
        for value in (Fraction(0), Fraction(-1), Fraction(1, 2**100 + 1),
                      Fraction(2**256 - 1), Fraction(-(2**256 - 1)),
                      ND('NO_EVIDENCE'), ND('A' * 64)):
            with self.subTest(value=value):
                self.assertEqual(decode_record(encode_record(value)), value)
        self.assertEqual(encode_record(Fraction(1, 2)),
                         b'{"format":"ardrec-magnitude-1","magnitude":{"status":"DETERMINADO","value":{"denominator":2,"numerator":1}}}')

    def test_invalid_values_are_not_normalized(self):
        magnitude = {'status': 'DETERMINADO', 'value': {'numerator': 1, 'denominator': 2}}
        for n, d in ((True, 2), (1, False), (2, 4), (0, 2), (1, 0), (1, -1),
                     (2**256, 1), (1, 2**256), (1.0, 2), ('1', 2)):
            magnitude['value'] = {'numerator': n, 'denominator': d}
            with self.subTest(n=n, d=d), self.assertRaises(StorageError):
                decode_record(json.dumps({'format': FORMAT, 'magnitude': magnitude}).encode())
        for value in (True, 1, 0.5, Fraction(2**256), object()):
            with self.subTest(value=type(value).__name__), self.assertRaises(StorageError):
                encode_record(value)

    def test_fields_versions_duplicates_and_utf8(self):
        good = encode_record(ND('NO_EVIDENCE'))
        bad = (b'', b'null', b'[]', b'{}', b'\xff', b'\xef\xbb\xbf' + good,
               good + b'{}', good.replace(b'magnitude-1', b'magnitude-2'),
               good.replace(b'"format":', b'"extra":1,"format":'),
               good.replace(b'"format":', b'"format":"old","format":'),
               good.replace(b'"reason_code":', b'"reason_code":"X","reason_code":'),
               good.replace(b'"ND"', b'null'),
               good.replace(b'"NO_EVIDENCE"', b'NaN'))
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(StorageError):
                decode_record(raw)

    def test_payload_boundaries(self):
        raw = encode_record(Fraction(1, 3))
        self.assertEqual(decode_record(raw + b' ' * (MAX_RECORD_BYTES - len(raw))), Fraction(1, 3))
        with self.assertRaises(StorageError):
            decode_record(raw + b' ' * (MAX_RECORD_BYTES + 1 - len(raw)))
        with self.assertRaises(StorageError):
            decode_record(raw.decode())

    def test_archive_reopen_and_immutable_reuse(self):
        archive = self.create()
        value = Fraction(1, 2**100 + 1)
        reference = archive.write(value)
        target = self.path / (reference + '.json')
        before = target.stat().st_ino
        self.assertEqual(reference, hashlib.sha256(encode_record(value)).hexdigest())
        self.assertEqual(archive.write(value), reference)
        self.assertEqual(target.stat().st_ino, before)
        archive.close()
        with MagnitudeArchive(self.path) as reopened:
            self.assertEqual(reopened.read(reference), value)
            self.assertEqual(reopened.read(reopened.write(ND('UNKNOWN'))), ND('UNKNOWN'))

    def test_operational_codec_is_unchanged(self):
        self.assertEqual(pack(2**63 - 1), 2**63 - 1)
        self.assertEqual(pack(-(2**63)), -(2**63))
        for value in (2**63, Fraction(1, 2), ND('UNKNOWN')):
            with self.assertRaises(StorageError):
                pack(value)

    def test_corruption_blocks_session(self):
        archive = self.create()
        reference = archive.write(Fraction(1, 7))
        (self.path / (reference + '.json')).write_bytes(encode_record(Fraction(2, 7)))
        with self.assertRaisesRegex(StorageError, 'object_hash_mismatch'):
            archive.read(reference)
        with self.assertRaisesRegex(StorageError, 'session_unavailable'):
            archive.write(Fraction(3, 7))

    def test_noncanonical_object_is_not_authoritative(self):
        archive = self.create()
        raw = encode_record(Fraction(1, 7)) + b' '
        reference = hashlib.sha256(raw).hexdigest()
        target = self.path / (reference + '.json')
        target.write_bytes(raw)
        target.chmod(0o600)
        with self.assertRaisesRegex(StorageError, 'noncanonical_object'):
            archive.read(reference)

    def test_reference_path_rejected(self):
        for reference in ('../LOCK', 'A' * 64, '0' * 63, 0, None):
            with self.subTest(reference=reference):
                path = Path(self.temp.name) / str(len(list(Path(self.temp.name).iterdir())))
                with MagnitudeArchive(path, create=True) as archive:
                    with self.assertRaisesRegex(StorageError, 'hash_invalid'):
                        archive.read(reference)

    def test_concurrent_writer_is_blocked(self):
        archive = self.create()
        context = multiprocessing.get_context('spawn')
        queue = context.Queue()
        process = context.Process(target=competing_writer, args=(str(self.path), queue))
        process.start()
        process.join(10)
        if process.is_alive():
            process.kill()
            process.join()
            self.fail('El competidor no terminó')
        self.assertEqual(process.exitcode, 0)
        self.assertEqual(queue.get(timeout=2), 'writer_busy')
        queue.close()
        archive.close()
        with MagnitudeArchive(self.path):
            pass

    def test_symlink_and_hardlink_are_rejected(self):
        archive = self.create()
        reference = archive.write(Fraction(1, 7))
        target = self.path / (reference + '.json')
        os.link(target, Path(self.temp.name) / 'extra-link')
        with self.assertRaisesRegex(StorageError, 'file_invalid'):
            archive.read(reference)
        archive.close()
        link = Path(self.temp.name) / 'alias'
        link.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(OSError):
            MagnitudeArchive(link)

    def test_existing_object_is_not_overwritten(self):
        archive = self.create()
        raw = encode_record(Fraction(1, 9))
        target = self.path / (hashlib.sha256(raw).hexdigest() + '.json')
        target.write_bytes(b'corrupt')
        target.chmod(0o600)
        with self.assertRaises(StorageError):
            archive.write(Fraction(1, 9))
        self.assertEqual(target.read_bytes(), b'corrupt')

    def test_short_writes_are_completed(self):
        archive = self.create()
        original = os.write
        with patch('ardrec.persistence.magnitudes.os.write', side_effect=lambda fd, raw: original(fd, raw[:3])):
            reference = archive.write(Fraction(1, 11))
        self.assertEqual(archive.read(reference), Fraction(1, 11))

    def test_zero_write_and_sync_failure_do_not_confirm(self):
        for operation, options in (('write', {'return_value': 0}), ('fsync', {'side_effect': OSError('EIO')})):
            with self.subTest(operation=operation):
                path = Path(self.temp.name) / operation
                with MagnitudeArchive(path, create=True) as archive:
                    with patch('ardrec.persistence.magnitudes.os.' + operation, **options):
                        with self.assertRaises((StorageError, OSError)):
                            archive.write(Fraction(1, 13))
                    self.assertEqual(list(path.glob('*.json')), [])
                    with self.assertRaisesRegex(StorageError, 'session_unavailable'):
                        archive.write(Fraction(1, 13))

    def test_exception_after_publication_requires_reopen(self):
        def fault(point):
            if point == 'after_replace':
                raise OSError('Interrupción simulada')
        archive = self.create(fault=fault)
        with self.assertRaises(OSError):
            archive.write(ND('UNKNOWN'))
        with self.assertRaises(StorageError):
            archive.write(ND('UNKNOWN'))
        archive.close()
        with MagnitudeArchive(self.path) as reopened:
            reference = reopened.write(ND('UNKNOWN'))
            self.assertEqual(reopened.read(reference), ND('UNKNOWN'))
            self.assertEqual(len(list(self.path.glob('*.json'))), 1)

    def test_sigkill_preserves_previous_and_no_partial_confirmation(self):
        context = multiprocessing.get_context('spawn')
        for point in POINTS:
            with self.subTest(point=point):
                path = Path(self.temp.name) / point
                with MagnitudeArchive(path, create=True) as archive:
                    previous = archive.write(Fraction(1, 17))
                process = context.Process(target=crash_writer, args=(str(path), point))
                process.start()
                process.join(10)
                if process.is_alive():
                    process.kill()
                    process.join()
                    self.fail('El escritor no alcanzó el punto de fallo')
                self.assertEqual(process.exitcode, -signal.SIGKILL)
                value = Fraction(2**255 + 1, 2**256 - 1)
                reference = hashlib.sha256(encode_record(value)).hexdigest()
                published = path / (reference + '.json')
                self.assertEqual(published.exists(), point in ('after_replace', 'after_directory_sync'))
                with MagnitudeArchive(path) as recovered:
                    self.assertEqual(recovered.read(previous), Fraction(1, 17))
                    if published.exists():
                        self.assertEqual(recovered.read(reference), value)
                    self.assertEqual(recovered.write(value), reference)
                    self.assertEqual(recovered.read(reference), value)
                self.assertEqual(len(list(path.glob('*.json'))), 2)

    def test_replaced_lock_and_directory_block_use(self):
        archive = self.create()
        os.rename(self.path / 'LOCK', self.path / 'OLD_LOCK')
        (self.path / 'LOCK').write_bytes(b'')
        (self.path / 'LOCK').chmod(0o600)
        with self.assertRaisesRegex(StorageError, 'session_replaced'):
            archive.write(Fraction(1))
        archive.close()
        with MagnitudeArchive(self.path) as reopened:
            os.rename(self.path, self.path.with_name('moved'))
            self.path.mkdir(mode=0o700)
            with self.assertRaisesRegex(StorageError, 'session_replaced'):
                reopened.write(Fraction(1))

    def test_directory_sync_failure_requires_recovery(self):
        archive = self.create()
        original = os.fsync
        def fail_directory(fd):
            if fd == archive._root:
                raise OSError('Sin confirmación del directorio')
            return original(fd)
        with patch('ardrec.persistence.magnitudes.os.fsync', side_effect=fail_directory):
            with self.assertRaises(OSError):
                archive.write(Fraction(1, 19))
        archive.close()
        with MagnitudeArchive(self.path) as reopened:
            reference = reopened.write(Fraction(1, 19))
            self.assertEqual(reopened.read(reference), Fraction(1, 19))

    def test_read_sync_failure_does_not_confirm_recovery(self):
        archive = self.create()
        reference = archive.write(Fraction(1, 23))
        with patch('ardrec.persistence.magnitudes.os.fsync', side_effect=OSError('EIO')):
            with self.assertRaises(OSError):
                archive.read(reference)
        with self.assertRaisesRegex(StorageError, 'session_unavailable'):
            archive.read(reference)

    def test_changed_permissions_block_publication(self):
        archive = self.create()
        self.path.chmod(0o755)
        with self.assertRaisesRegex(StorageError, 'directory_not_private'):
            archive.write(Fraction(1))
        self.assertEqual(list(self.path.glob('*.json')), [])

    def test_object_symlink_is_rejected(self):
        archive = self.create()
        reference = archive.write(Fraction(1, 29))
        target = self.path / (reference + '.json')
        moved = Path(self.temp.name) / 'outside'
        target.rename(moved)
        target.symlink_to(moved)
        with self.assertRaises(OSError):
            archive.read(reference)

    def test_directory_privacy_and_existing_creation(self):
        self.path.mkdir(mode=0o755)
        with self.assertRaisesRegex(StorageError, 'directory_not_private'):
            MagnitudeArchive(self.path)
        with self.assertRaises(FileExistsError):
            MagnitudeArchive(self.path, create=True)


if __name__ == '__main__':
    unittest.main()
