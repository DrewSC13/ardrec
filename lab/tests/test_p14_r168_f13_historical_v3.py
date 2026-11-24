"""R168-F13: historical V3 identity and current-source separation."""
import hashlib
import json
from io import BytesIO
from pathlib import Path
import unittest
import zipfile

import ardrec_r117_release_core_v1 as core
import ardrec_p14_r117_f5_root_candidate as builder
from r117_v3_candidate_fixture import candidate_bytes, HEAD, SHA, ROOT

CLOSURE = ROOT / "lab/operational-controller/r117-f5b-physical-closure-v3.json"

class HistoricalV3Identity(unittest.TestCase):

    def test_01_signed_archive_identity(self):
        raw = candidate_bytes()
        result = core.verify_candidate(
            raw, head=HEAD, expected_sha=SHA
        )
        self.assertEqual(result["file_count"], 39)
        self.assertEqual(result["source_count"], 36)
        self.assertEqual(result["p8"], "NO-GO")

    def test_02_historical_closure_unchanged(self):
        raw = CLOSURE.read_bytes()
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "63629945aa1164973b0687318997be464c1c35be0f39c903a7dcf4a7c6381b74",
        )
        closure = json.loads(raw)
        self.assertEqual(closure["candidate_sha256"], SHA)
        self.assertEqual(closure["candidate_head"], HEAD)
        self.assertFalse(closure["network_authorized"])

    def test_03_current_candidate_is_distinct(self):
        old = candidate_bytes()
        new = builder.candidate(HEAD, repo=ROOT)

        builder.audit(new, repo=ROOT, expected_head=HEAD)
        self.assertNotEqual(
            hashlib.sha256(new).hexdigest(), SHA
        )

        with zipfile.ZipFile(BytesIO(old)) as archive:
            a = {name: archive.read(name) for name in archive.namelist()}

        with zipfile.ZipFile(BytesIO(new)) as archive:
            b = {name: archive.read(name) for name in archive.namelist()}

        self.assertEqual(set(a), set(b))
        self.assertEqual(
            {name for name in a if a[name] != b[name]},
            {
                "manifest.json",
                "runtime/ardrec/coordination/r115_f7_controlled_boot.py",
                "runtime/ardrec/coordination/r115_f16_physical_pilot_controller.py",
            },
        )

    def test_04_modified_archive_rejected(self):
        raw = bytearray(candidate_bytes())
        raw[-1] ^= 1
        with self.assertRaises(core.Stop):
            core.verify_candidate(
                bytes(raw), head=HEAD, expected_sha=SHA
            )

    def test_05_historical_fixture_is_not_permission(self):
        report = core.verify_candidate(
            candidate_bytes(), head=HEAD, expected_sha=SHA
        )
        self.assertEqual(report["a6"], "ND")
        self.assertEqual(report["p8"], "NO-GO")

if __name__ == "__main__":
    unittest.main()
