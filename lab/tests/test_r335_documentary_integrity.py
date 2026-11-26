"""Synthetic regressions; no operational evidence or authority."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ardrec.experiments import baseline_preparation as i2, reference_supports as i4
import test_r228_baseline_preparation as t228
import test_r243_paired_reconciliation as t243


class DocumentaryIntegrityTests(unittest.TestCase):
    def baseline(self):
        t = t228.BaselineTests(); t.setUp(); return t

    def test_i2_service_pilot(self):
        t = self.baseline()
        t.row['service_instance_id'] = 'pilot-SSH-01'; t.rebind()
        with self.assertRaisesRegex(ValueError, 'PILOT_IDENTITY_REUSE_FORBIDDEN'):
            t.calculate()

    def test_i2_direct_candidate_pilot(self):
        for field in ('case_id', 'scenario_id', 'service_instance_id'):
            with self.subTest(field=field):
                t = self.baseline(); t.row[field] = 'PILOT-SSH-01'
                with self.assertRaisesRegex(ValueError, 'PILOT_IDENTITY_REUSE_FORBIDDEN'):
                    i2.candidate(t.row, t.entry, t.supports)

    def test_i8_service_pilot(self):
        for excluded in (False, True):
            with self.subTest(excluded=excluded):
                t = t243.ReconciliationTests(); t.setUp()
                t.record(0, ('0.8', '0.4', '0.2'), excluded=excluded)
                t.rows[0]['service_instance_id'] = 'pilot-SSH-01'
                with self.assertRaisesRegex(ValueError, 'PILOT_REUSE_FORBIDDEN'):
                    t.report()

    def test_i2_fifo_nonblocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fifo'; os.mkfifo(path, 0o600)
            real = os.open
            def guarded(name, flags, *args, **kwargs):
                if name == path:
                    self.assertTrue(flags & os.O_NONBLOCK)
                return real(name, flags, *args, **kwargs)
            with patch.object(os, 'open', guarded):
                with self.assertRaisesRegex(ValueError, 'I2_PRIVATE_FILE_INVALID'):
                    i2.read_private(path, 64)

    def check_replaced(self, reader, reason):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'object'; other = Path(tmp) / 'other'
            for p in (path, other):
                p.write_bytes(b'original'); p.chmod(0o600)
            real = os.fstat; count = 0
            def replace(fd):
                nonlocal count
                result = real(fd); count += 1
                if count == 2:
                    os.replace(other, path)
                return result
            with patch.object(os, 'fstat', replace):
                with self.assertRaisesRegex(ValueError, reason):
                    reader(path, 64)

    def test_i2_path_replacement(self):
        self.check_replaced(i2.read_private, 'I2_SOURCE_CHANGED_DURING_READ')

    def test_i4_path_replacement(self):
        self.check_replaced(i4.read_file, 'FILE_CHANGED_DURING_READ')

    def test_stable_private_supports(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'object'; p.write_bytes(b'authentic fixture'); p.chmod(0o600)
            self.assertEqual(i2.read_private(p, 64), b'authentic fixture')
            self.assertEqual(i4.read_file(p, 64), b'authentic fixture')
