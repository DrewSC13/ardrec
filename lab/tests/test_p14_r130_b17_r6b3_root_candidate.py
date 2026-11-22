"""R130-B17-R6B3: regresiones de fuente y transacción privada."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import (
    r130_b17_r6b3_root_candidate as m,
)

REPO = Path(__file__).resolve().parents[2]

class RootCandidateTransaction(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.lock, cls.b4, cls.b9 = m.from_repository(REPO)

    def review(self):
        return m.review_pair(self.lock, self.b4, self.b9)

    def denied(self, code, lock=None, b4=None, b9=None):
        with self.assertRaisesRegex(m.Stop, code):
            m.review_pair(
                self.lock if lock is None else lock,
                self.b4 if b4 is None else b4,
                self.b9 if b9 is None else b9,
            )

    def test_01_pinned_pair(self):
        plan, files = self.review()
        self.assertEqual(plan["b4_sha256"], m.B4_SHA)
        self.assertEqual(plan["b9_sha256"], m.B9_SHA)
        self.assertEqual(len(files), 5)

    def test_02_b4_tamper(self):
        self.denied("B4_V2_PIN_MISMATCH", b4=self.b4 + b"x")

    def test_03_b9_tamper(self):
        self.denied("B9_V2_PIN_MISMATCH", b9=self.b9 + b"x")

    def test_04_wrong_lock_sha(self):
        d = m.parse(self.lock)
        d["candidate_b4_sha256"] = "0" * 64
        self.denied("CANDIDATE_LOCK_INVALID", lock=m.canon(d))

    def test_05_wrong_lock_schema(self):
        d = m.parse(self.lock)
        d["schema"] = "UNTRUSTED"
        self.denied("CANDIDATE_LOCK_INVALID", lock=m.canon(d))

    def test_06_noncanonical_lock(self):
        with self.assertRaisesRegex(
            ValueError, "DOCUMENT_NONCANONICAL"
        ):
            m.review_pair(
                b'{"schema":"untrusted"}',
                self.b4,
                self.b9,
            )

    def test_07_root_targets_are_fixed(self):
        p, _ = self.review()
        self.assertEqual(
            p["root_destinations"], [m.TARGET_B4, m.TARGET_B9]
        )

    def test_08_b4_draft_not_authorized(self):
        _, files = self.review()
        doc = m.parse(files["manifest-b4.draft.json"])
        self.assertIsNone(doc["approved_head"])
        self.assertFalse(doc["root_install_independent"])

    def test_09_b9_draft_not_authorized(self):
        _, files = self.review()
        doc = m.parse(files["manifest-b9.draft.json"])
        self.assertIsNone(doc["approved_head"])
        self.assertFalse(doc["root_staged_independently"])

    def test_10_private_atomic_stage(self):
        with tempfile.TemporaryDirectory() as folder:
            result = m.stage(
                self.lock, self.b4, self.b9,
                parent=Path(folder),
            )
            location = Path(result["path"])
            self.assertTrue(location.is_dir())
            self.assertEqual(
                {p.name for p in location.iterdir()},
                {
                    "source-b4.py", "source-b9.py",
                    "manifest-b4.draft.json",
                    "manifest-b9.draft.json",
                    "candidate-plan.json", "receipt.json",
                },
            )
            for item in location.iterdir():
                self.assertEqual(
                    stat.S_IMODE(item.stat().st_mode), 0o600
                )
            self.assertFalse(result["root_install"])
            self.assertEqual(result["p8"], "NO-GO")

    def test_11_replay_denied(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            m.stage(self.lock, self.b4, self.b9, parent=parent)
            with self.assertRaisesRegex(
                m.Stop, "CANDIDATE_ALREADY_PUBLISHED"
            ):
                m.stage(self.lock, self.b4, self.b9, parent=parent)

    def test_12_crash_after_b4(self):
        self.check_fault("after_b4", "INJECTED_STOP_AFTER_B4")

    def test_13_crash_after_b9(self):
        self.check_fault("after_b9", "INJECTED_STOP_AFTER_B9")

    def test_14_crash_before_publication(self):
        self.check_fault(
            "before_publish", "INJECTED_STOP_BEFORE_PUBLICATION"
        )

    def check_fault(self, point, code):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            with self.assertRaisesRegex(m.Stop, code):
                m.stage(
                    self.lock, self.b4, self.b9,
                    parent=parent, fault=point,
                )
            pending = [
                p for p in parent.iterdir()
                if p.name.startswith(".r130-b3-incomplete-")
            ]
            published = [
                p for p in parent.iterdir()
                if p.name.startswith("r130-b3-review-")
            ]
            self.assertEqual(len(pending), 1)
            self.assertEqual(published, [])

    def test_15_insecure_parent_denied(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            parent.chmod(0o755)
            with self.assertRaisesRegex(
                m.Stop, "PRIVATE_PARENT_REQUIRED"
            ):
                m.stage(self.lock, self.b4, self.b9, parent=parent)

    def test_16_symlink_parent_denied(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            real = root / "real"
            real.mkdir(mode=0o700)
            link = root / "alias"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(
                m.Stop, "PRIVATE_PATH_INVALID"
            ):
                m.stage(self.lock, self.b4, self.b9, parent=link)

    def test_17_root_execution_denied(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(m.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(
                    m.Stop, "ROOT_EXECUTION_FORBIDDEN"
                ):
                    m.stage(
                        self.lock, self.b4, self.b9,
                        parent=Path(folder),
                    )

    def test_18_capabilities_no_activation(self):
        c = m.capabilities()
        self.assertFalse(c["can_install_root"])
        self.assertFalse(c["can_open_network"])
        self.assertFalse(c["can_issue_authority"])
        self.assertEqual(c["p8"], "NO-GO")

    def test_19_b4_posixpath_runtime(self):
        self.check_posixpath(
            "scripts/ardrec_p14_r130_b4_root_guard_v2.py",
            "safe_read", "ROOT_FILE_METADATA_UNSAFE",
        )

    def test_20_b9_posixpath_runtime(self):
        self.check_posixpath(
            "scripts/ardrec_p14_r130_b9_ftp_executor_v2.py",
            "read_root", "ROOT_INPUT_MODE_OR_SIZE",
        )

    def check_posixpath(self, script, method, reason):
        target = REPO / script
        spec = importlib.util.spec_from_file_location(
            "ardrec_r130_dynamic_" + method, target
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "user-owned-test-file"
            path.write_bytes(b"TEST-ONLY\n")
            path.chmod(0o600)
            with self.assertRaisesRegex(module.Stop, reason):
                getattr(module, method)(path)

if __name__ == "__main__":
    unittest.main()
