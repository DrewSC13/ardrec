"""R130-B17-R6B2: pruebas de compatibilidad root sin privilegios."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

from ardrec.coordination import (
    r130_b17_r6_install_contract as intake,
)

REPO = Path(__file__).resolve().parents[2]

LOCK = REPO / (
    "lab/operational-controller/"
    "r130-b17-r6b2-compat-lock.json"
)

OLD_GATE = b"type(path) is Path and path.is_absolute()"
NEW_GATE = b"isinstance(path, Path) and path.is_absolute()"

def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class RootCompatibilityV2(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.lock_raw = LOCK.read_bytes()
        cls.lock = json.loads(cls.lock_raw)

        cls.old_b4 = (
            REPO / cls.lock["historical_b4_path"]
        ).read_bytes()

        cls.old_b9 = (
            REPO / cls.lock["historical_b9_path"]
        ).read_bytes()

        cls.b4 = (
            REPO / cls.lock["candidate_b4_path"]
        ).read_bytes()

        cls.b9 = (
            REPO / cls.lock["candidate_b9_path"]
        ).read_bytes()

    def test_01_lock_schema(self):
        self.assertEqual(
            self.lock["schema"],
            "ARDREC-R130-B17-R6B2-ROOT-COMPAT-CANDIDATE-v1",
        )

    def test_02_historical_b4_unchanged(self):
        self.assertEqual(
            sha(self.old_b4),
            self.lock["historical_b4_sha256"],
        )
        self.assertEqual(
            sha(self.old_b4),
            intake.B4_SHA,
        )

    def test_03_historical_b9_unchanged(self):
        self.assertEqual(
            sha(self.old_b9),
            self.lock["historical_b9_sha256"],
        )
        self.assertEqual(
            sha(self.old_b9),
            intake.B9_SHA,
        )

    def test_04_b4_exact_single_change(self):
        self.assertEqual(
            self.old_b4.count(OLD_GATE),
            1,
        )
        self.assertEqual(
            self.b4,
            self.old_b4.replace(OLD_GATE, NEW_GATE, 1),
        )

    def test_05_b9_exact_two_changes(self):
        old_pin = (
            "B4_PIN = '"
            + self.lock["historical_b4_sha256"]
            + "'"
        ).encode("ascii")

        new_pin = (
            "B4_PIN = '"
            + self.lock["candidate_b4_sha256"]
            + "'"
        ).encode("ascii")

        self.assertEqual(self.old_b9.count(OLD_GATE), 1)
        self.assertEqual(self.old_b9.count(old_pin), 1)

        expected = self.old_b9.replace(
            OLD_GATE,
            NEW_GATE,
            1,
        ).replace(
            old_pin,
            new_pin,
            1,
        )

        self.assertEqual(self.b9, expected)

    def test_06_b4_new_digest(self):
        self.assertEqual(
            sha(self.b4),
            self.lock["candidate_b4_sha256"],
        )

    def test_07_b9_new_digest(self):
        self.assertEqual(
            sha(self.b9),
            self.lock["candidate_b9_sha256"],
        )

    def test_08_b4_path_guard(self):
        self.assertNotIn(OLD_GATE, self.b4)
        self.assertIn(NEW_GATE, self.b4)

    def test_09_b9_path_guard(self):
        self.assertNotIn(OLD_GATE, self.b9)
        self.assertIn(NEW_GATE, self.b9)

    def test_10_python_syntax(self):
        ast.parse(self.b4)
        ast.parse(self.b9)

    def test_11_root_identity_preserved(self):
        marker = b"Path(__file__).resolve()==SCRIPT"
        self.assertIn(marker, self.b4)
        self.assertIn(marker, self.b9)

    def test_12_legacy_guard_pins_preserved(self):
        guard = self.lock[
            "installed_r116_guard_expected_sha256"
        ].encode("ascii")

        f3 = self.lock[
            "installed_r116_f3_expected_sha256"
        ].encode("ascii")

        self.assertIn(guard, self.b4)
        self.assertIn(guard, self.b9)
        self.assertIn(f3, self.b9)

    def test_13_b4_capabilities_only(self):
        process = subprocess.run(
            [
                sys.executable,
                "-B",
                str(REPO / self.lock["candidate_b4_path"]),
                "--capabilities",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        self.assertEqual(
            process.returncode,
            0,
            process.stderr,
        )

        report = json.loads(process.stdout)

        self.assertEqual(report["p8"], "NO-GO")
        self.assertFalse(report["opens_traffic"])
        self.assertFalse(report["starts_vm"])

    def test_14_b9_capabilities_only(self):
        process = subprocess.run(
            [
                sys.executable,
                "-B",
                str(REPO / self.lock["candidate_b9_path"]),
                "--capabilities",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        self.assertEqual(
            process.returncode,
            0,
            process.stderr,
        )

        report = json.loads(process.stdout)

        self.assertEqual(report["p8"], "NO-GO")
        self.assertFalse(report["starts_vms"])
        self.assertFalse(
            report["installed_from_this_package"]
        )

    def test_15_no_approval_in_candidate(self):
        self.assertFalse(
            self.lock["candidate_git_commit_signed"]
        )
        self.assertFalse(
            self.lock["independent_release_issued"]
        )
        self.assertFalse(
            self.lock["root_install_authorized"]
        )
        self.assertFalse(
            self.lock["root_install_performed"]
        )

    def test_16_no_physical_claim(self):
        self.assertFalse(
            self.lock["physical_execution_performed"]
        )
        self.assertEqual(self.lock["a6"], "ND")
        self.assertIsNone(self.lock["a9"])
        self.assertEqual(self.lock["p8"], "NO-GO")

    def test_17_original_r5b_remains_distinct(self):
        self.assertNotEqual(
            sha(self.b4),
            intake.B4_SHA,
        )
        self.assertNotEqual(
            sha(self.b9),
            intake.B9_SHA,
        )

    def test_18_lock_is_canonical(self):
        expected = (
            json.dumps(
                self.lock,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ) + "\n"
        ).encode("ascii")

        self.assertEqual(self.lock_raw, expected)

    def test_19_root_destinations_not_in_candidate(self):
        self.assertEqual(
            self.lock["change_class"],
            "LINUX_PATH_TYPE_COMPATIBILITY",
        )
        self.assertTrue(
            self.lock["candidate_b4_path"].startswith(
                "scripts/"
            )
        )
        self.assertTrue(
            self.lock["candidate_b9_path"].startswith(
                "scripts/"
            )
        )

    def test_20_historical_source_preserved(self):
        self.assertEqual(
            self.lock["historical_source_commit"],
            intake.HEAD,
        )


if __name__ == "__main__":
    unittest.main()
