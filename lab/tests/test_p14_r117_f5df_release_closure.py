"""F5D-F regression: source-only boundary and strict parser tests.

These tests are NOT real deployment or operational attestations.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from unittest.mock import patch
import unittest

from ardrec.coordination import r117_f4_root_release as f4

REPO=Path(__file__).resolve().parents[2]

class ReleaseClosureSourceTests(unittest.TestCase):
    def test_01_pin_matches_source(self):
        pin=json.loads((REPO/'lab/operational-controller/r117-f4-dispatch-sources-v1.json').read_bytes())
        src=(REPO/'src/ardrec/coordination/r117_f4_root_release.py').read_bytes()
        self.assertEqual(pin['source_sha256']['src/ardrec/coordination/r117_f4_root_release.py'],hashlib.sha256(src).hexdigest())
    def test_02_marker_set_f5b_exact(self):
        self.assertEqual(set(f4.MARKERS),{'prepared.once','pilot-visible.once','release-visible.once'})
        self.assertEqual(len(f4.JOURNAL_FILES),5)
    def test_03_valid_strict_document(self):
        self.assertEqual(f4._strict_document(b'{"a":1}\n'),{'a':1})
    def test_04_duplicate_json_rejected(self):
        with self.assertRaises(f4.Stop):f4._strict_document(b'{"a":1,"a":2}\n')
    def test_05_noncanonical_json_rejected(self):
        with self.assertRaises(f4.Stop):f4._strict_document(b'{"b":2,"a":1}\n')
    def test_06_nonfinite_json_rejected(self):
        with self.assertRaises(f4.Stop):f4._strict_document(b'{"a":NaN}\n')
    def test_07_trailing_data_rejected(self):
        with self.assertRaises(f4.Stop):f4._strict_document(b'{"a":1}\n{}')
    def test_08_malformed_transaction_id(self):
        self.assertIsNone(f4.TXN_NAME.fullmatch('.r117-f5b-transaction-'+('g'*24)))
    def test_09_signed_domain_preserved(self):
        self.assertEqual(f4.PREFIX,b'ARDREC-R117-F5B-ROOT-RELEASE-APPROVAL-v1\x00')
    def test_10_short_signature_rejected(self):
        with self.assertRaises(f4.Stop):f4._ed25519_verify(b'BEGIN PUBLIC KEY',b'x',b'stmt')
    def test_11_wrong_head_denied_before_disk(self):
        with self.assertRaisesRegex(f4.Stop,'RELEASE_HEAD_INVALID'):
            f4.require_attested_release('z'*40)
    def test_12_no_root_release_without_completion(self):
        with patch.object(f4,'_closed_transaction',side_effect=f4.Stop('NO_COMPLETE')) as guard:
            # Reader returns a correctly shaped release/manifest, no host writes.
            receipt={'schema':f4.RELEASE_SCHEMA,'head':'a'*40,
              'source_sha256':{s:hashlib.sha256((REPO/s).read_bytes()).hexdigest() for s in f4.SRC},
              'pilot_manifest_sha256':hashlib.sha256(b'{}').hexdigest(),
              'pilot_schema':f4.PILOT_SCHEMA,'p8':'NO-GO','authorized_to_boot':False}
            def reader(path):return (json.dumps(receipt).encode() if path==f4.RECEIPT else b'{}')
            # The pilot manifest must fail before release could be accepted.
            with self.assertRaises((f4.Stop,KeyError,ValueError)):
                f4.require_attested_release('a'*40,repo=REPO,reader=reader)
            guard.assert_not_called()
    def test_13_f5b_install_guard_unchanged(self):
        content=(REPO/'scripts/ardrec_p14_r117_f5b_root_stage.py').read_text()
        self.assertIn("need(False, 'F5B_APPLY_BLOCKED_PENDING_ATOMIC_RELEASE_AND_BOOT_GATE')",content)

if __name__=='__main__':unittest.main()
