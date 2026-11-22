"""Pruebas de conciliación parcial R132."""
from __future__ import annotations

import fcntl
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r132_install_recovery as m

REPO = Path(__file__).resolve().parents[2]


class RecoveryTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)

    def run_case(self, fault=None):
        return m.apply(REPO, self.parent, fault=fault)

    def test_01_complete(self):
        result = self.run_case()
        self.assertEqual(result["status"], "PRIVATE_PAIR_CONCILED")
        self.assertFalse(result["root_installed"])

    def test_02_idempotent(self):
        first = self.run_case()
        second = self.run_case()
        self.assertEqual(first, second)

    def check_recovery(self, fault, expected):
        with self.assertRaisesRegex(m.Stop, expected):
            self.run_case(fault)
        result = self.run_case()
        self.assertEqual(result["status"], "PRIVATE_PAIR_CONCILED")

    def test_03_before_b4(self):
        self.check_recovery("before_b4", "INJECTED_BEFORE_B4")

    def test_04_after_b4(self):
        self.check_recovery("after_b4", "INJECTED_AFTER_B4")

    def test_05_after_b9(self):
        self.check_recovery("after_b9", "INJECTED_AFTER_B9")

    def test_06_before_receipt(self):
        self.check_recovery("before_receipt", "INJECTED_BEFORE_RECEIPT")

    def test_07_unknown_fault(self):
        with self.assertRaisesRegex(m.Stop, "UNKNOWN_FAULT"):
            self.run_case("unexpected")

    def test_08_preexisting_b4(self):
        (self.parent / "installed-b4").mkdir()
        with self.assertRaisesRegex(
            m.Stop, "PREEXISTING_DESTINATION_WITHOUT_JOURNAL"
        ):
            self.run_case()

    def test_09_preexisting_b9(self):
        (self.parent / "installed-b9").mkdir()
        with self.assertRaisesRegex(
            m.Stop, "PREEXISTING_DESTINATION_WITHOUT_JOURNAL"
        ):
            self.run_case()

    def test_10_tampered_b4(self):
        self.run_case()
        p = self.parent / "installed-b4" / "root-controller.py"
        p.write_bytes(b"tampered")
        with self.assertRaises(m.Stop):
            self.run_case()

    def test_11_tampered_b9(self):
        self.run_case()
        p = self.parent / "installed-b9" / "root-executor.py"
        p.write_bytes(b"tampered")
        with self.assertRaises(m.Stop):
            self.run_case()

    def test_12_journal_corrupted(self):
        self.run_case()
        p = self.parent / "transaction.json"
        p.write_bytes(b"invalid")
        with self.assertRaises(m.Stop):
            self.run_case()

    def test_13_receipt_corrupted(self):
        self.run_case()
        p = self.parent / "receipt.json"
        p.write_bytes(b"invalid")
        with self.assertRaises(m.Stop):
            self.run_case()

    def test_14_insecure_parent(self):
        self.parent.chmod(0o755)
        with self.assertRaisesRegex(
            m.Stop, "PRIVATE_DIRECTORY_REQUIRED"
        ):
            self.run_case()

    def test_15_parent_symlink(self):
        link = self.parent / "alias"
        link.symlink_to(self.parent, target_is_directory=True)
        with self.assertRaisesRegex(m.Stop, "DIRECTORY_PATH_INVALID"):
            m.apply(REPO, link)

    def test_16_root_execution_rejected(self):
        with patch.object(m.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(m.Stop, "ROOT_FORBIDDEN"):
                self.run_case()

    def test_17_no_traffic(self):
        result = self.run_case()
        self.assertFalse(result["traffic_enabled"])
        self.assertEqual(result["p8"], "NO-GO")

    def test_18_capabilities(self):
        caps = m.capabilities()
        self.assertFalse(caps["root_installer"])
        self.assertFalse(caps["can_open_network"])

    def test_19_partial_staging_corruption(self):
        with self.assertRaisesRegex(m.Stop, "INJECTED_BEFORE_B4"):
            self.run_case("before_b4")
        p = self.parent / ".pending-b4" / "root-controller.py"
        p.write_bytes(b"broken")
        with self.assertRaises(m.Stop):
            self.run_case()

    def test_20_lock_busy(self):
        lock = self.parent / ".r132-install.lock"
        lock.touch(mode=0o600)
        lock.chmod(0o600)
        with lock.open("rb+") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            with self.assertRaisesRegex(
                m.Stop, "INSTALL_TRANSACTION_BUSY"
            ):
                self.run_case()


if __name__ == "__main__":
    unittest.main()
