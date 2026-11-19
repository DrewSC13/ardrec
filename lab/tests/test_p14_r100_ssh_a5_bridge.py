"""R100 bridge tests: exact links, replay and fail-closed A6."""
import json
from pathlib import Path
import os
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ardrec.coordination import r100_ssh_a5_bridge as b


def fixture():
    return {
        "schema": b.R99_SCHEMA,
        "transport": "REAL_TCP_IPV4_LOOPBACK_ONLY",
        "identification": "SSH-2.0-ARDREC_R99_LOCAL",
        "banner_sha256": b.sha(b.BANNER),
        "bytes_received": len(b.BANNER),
        "elapsed_ms": 7,
        "tcp_connections": 1,
        "ssh_authentication": False,
        "remote_commands": 0,
        "a5_operational_attempts": 0,
        "a6_classification": "ND",
        "rf_confirmed": None,
        "evidence_accredited": False,
        "dispatch_allowed": False,
        "p8_operational": "NO-GO",
    }


class R100Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "case-1"
        self.root.mkdir(mode=0o700)
        self.session = "R100_012345ABCDEF"

    def test_valid_observation(self):
        self.assertTrue(b.observation_valid(fixture()))

    def test_false_authority_rejected(self):
        for key, value in (
            ("dispatch_allowed", True),
            ("evidence_accredited", True),
            ("p8_operational", "GO"),
            ("a6_classification", "POSITIVO"),
            ("a5_operational_attempts", 1),
        ):
            with self.subTest(field=key):
                modified = dict(fixture())
                modified[key] = value
                with self.assertRaises(b.BridgeError):
                    b.observation_valid(modified)

    def test_wrong_banner_digest_rejected(self):
        modified = dict(fixture())
        modified["banner_sha256"] = "0" * 64
        with self.assertRaises(b.BridgeError):
            b.observation_valid(modified)

    def test_wrong_target_or_scope_rejected(self):
        for key, value in (
            ("transport", "EXTERNAL_TCP"),
            ("tcp_connections", 2),
            ("ssh_authentication", True),
        ):
            modified = dict(fixture())
            modified[key] = value
            with self.assertRaises(b.BridgeError):
                b.observation_valid(modified)

    def test_a5_no_start_and_a6_nd(self):
        result = b.create(
            self.root, fixture(), "a" * 64, self.session
        )
        self.assertFalse(result["method_executed"])
        self.assertFalse(result["a5_physical_start_accredited"])
        self.assertEqual(result["a6_classification"], "ND")
        self.assertIsNone(result["a7_confirmed_rf"])
        self.assertEqual(result["p8_operational"], "NO-GO")

    def test_exact_replay_without_execution(self):
        created = b.create(
            self.root, fixture(), "a" * 64, self.session
        )
        self.assertEqual(created, b.verify(self.root))
        self.assertEqual(
            len(list(self.root.iterdir())), 3
        )

    def test_observation_tamper_rejected(self):
        b.create(self.root, fixture(), "a" * 64, self.session)
        path = self.root / "tcp-observation.json"
        path.write_bytes(path.read_bytes().replace(
            b"ARDREC_R99_LOCAL", b"ARDREC_R99_OTHER"
        ))
        with self.assertRaises((b.BridgeError, ValueError)):
            b.verify(self.root)

    def test_a5_report_tamper_rejected(self):
        result = b.create(
            self.root, fixture(), "a" * 64, self.session
        )
        report = self.root / (
            "r59d-a5-" + result["a5_report_sha256"] + ".json"
        )
        report.write_bytes(report.read_bytes() + b" ")
        with self.assertRaises(ValueError):
            b.verify(self.root)

    def test_extra_file_rejected(self):
        b.create(self.root, fixture(), "a" * 64, self.session)
        (self.root / "unexpected").write_bytes(b"x")
        with self.assertRaises(b.BridgeError):
            b.verify(self.root)


if __name__ == "__main__":
    unittest.main()
