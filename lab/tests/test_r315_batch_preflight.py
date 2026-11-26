"""R315: offline documentary batch preflight; no technical dispatch."""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

import test_r307_dev_batch as fixture
from ardrec.coordination import r166_case_archive_cli as cli


@unittest.skipIf(os.geteuid() == 0, "non-root contract")
class BatchPreflightTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.DevBatchTests()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()

    def entry(self, index):
        row = dict(self.f.rows[index], archive=self.f.archive)
        row.update(origin=Path(row['origin']), inputs=Path(row['inputs']))
        return row

    def orphan(self, index):
        entry = self.entry(index)
        cli.development_assessment(**entry)
        record, _ = cli.development_snapshot(**entry)
        (self.f.archive / (entry['case_id'] + '.snapshot.json')).unlink()
        return entry, record

    def test_preview_without_writes_and_exact_prediction(self):
        before = self.f.files()
        preview = self.f.call(preview=True)
        self.assertEqual(before, self.f.files())
        self.assertEqual(preview, self.f.call(preview=True))
        self.assertFalse(preview['persistence_requested'])
        self.assertEqual(set(preview['snapshot_statuses'].values()), {'DEV_SNAPSHOT_PREVIEW_NEW'})
        actual = self.f.call()
        self.assertEqual(actual['cases'], preview['cases'])
        self.assertEqual(actual['interval_batch_sha256'], preview['interval_batch_sha256'])
        self.assertEqual(actual, self.f.call(reopen=True))
        self.assertEqual(actual['experimental_observations'], 0)

    def test_existing_and_orphan_preflight_mixed(self):
        first = self.entry(0)
        cli.development_assessment(**first)
        cli.development_snapshot(**first)
        last, record = self.orphan(2)
        before = self.f.files()
        preview = self.f.call(preview=True)
        self.assertEqual(before, self.f.files())
        self.assertEqual(preview['snapshot_statuses'][first['case_id']], 'DEV_SNAPSHOT_REOPENED')
        self.assertEqual(preview['snapshot_statuses'][last['case_id']], 'DEV_SNAPSHOT_RECOVERABLE')
        self.assertEqual(preview['cases'][-1]['snapshot_sha256'], record['snapshot_sha256'])
        actual = self.f.call()
        self.assertEqual(actual['cases'], preview['cases'])

    def test_corrupt_orphan_last_rejected_before_first_write(self):
        entry, record = self.orphan(2)
        blob = self.f.archive / (entry['case_id'] + '.analytical') / record['snapshot_sha256'] / (record['manifest_sha256'] + '.json')
        blob.chmod(0o600)
        blob.write_bytes(b'{}')
        before = self.f.files()
        for preview in (True, False):
            with self.assertRaises(ValueError):
                self.f.call(preview=preview)
            self.assertEqual(before, self.f.files())

    def test_invalid_native_directory_last_rejects_entire_batch(self):
        native = self.f.archive / (self.f.rows[-1]['case_id'] + '.analytical')
        native.mkdir(mode=0o700)
        before = self.f.files()
        with self.assertRaises(OSError):
            self.f.call()
        self.assertEqual(before, self.f.files())
        self.assertFalse(list(self.f.archive.glob('*.assessment.json')))

    def test_expected_assessment_mismatch_before_persist(self):
        before = self.f.files()
        with self.assertRaisesRegex(ValueError, 'DEV_BATCH_ASSESSMENT_DRIFT'):
            cli.development_assessment(**self.entry(0), expected_sha256='0' * 64)
        self.assertEqual(before, self.f.files())

    def test_invalid_index_does_not_write(self):
        entry = self.entry(2)
        cli.development_assessment(**entry)
        cli.development_snapshot(**entry)
        fixture.put(self.f.archive / (entry['case_id'] + '.snapshot.json'), b'{}\n')
        before = self.f.files()
        with self.assertRaises(ValueError):
            self.f.call()
        self.assertEqual(before, self.f.files())

    def test_cli_preview(self):
        before = self.f.files()
        args = [sys.executable, '-m', 'ardrec', 'caso', 'prevalidar-lote-dev', '--manifiesto', str(self.f.manifest), '--sha256', self.f.pin, '--archivo', str(self.f.archive)]
        result = subprocess.run([*args, '--json'], check=True, capture_output=True)
        self.assertEqual(json.loads(result.stdout), self.f.call(preview=True))
        result = subprocess.run([*args, '--texto'], check=True, capture_output=True)
        self.assertIn(b'PREVIEW_ONLY', result.stdout)
        self.assertEqual(before, self.f.files())

    def test_preview_reopen_modes_conflict(self):
        with self.assertRaisesRegex(ValueError, 'DEV_BATCH_MODE_CONFLICT'):
            self.f.call(preview=True, reopen=True)


if __name__ == '__main__':
    unittest.main()
