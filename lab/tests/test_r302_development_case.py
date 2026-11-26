"""R302: source-bound prospective DEV preparation, no transport."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from ardrec.coordination.r166_case_archive_cli import development_case
from ardrec.experiments import initial_assessment as a2


@unittest.skipIf(os.geteuid() == 0, "non-root contract")
class DevelopmentCaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.archive = self.root / "cases"
        self.archive.mkdir(mode=0o700)
        self.case = "DEV-" + "a" * 32

    def source(self, protocol):
        folder = self.root / protocol
        a2.materialize_case(folder, protocol, "b" * 40, {"fixture": "TEST_ONLY"})
        return folder, hashlib.sha256((folder / "scenario.json").read_bytes()).hexdigest()

    def call(self, folder, pin, **kwargs):
        return development_case(origin=folder, archive=self.archive,
                                case_id=self.case, scenario_pin=pin, **kwargs)

    def test_three_protocols_open_replay_and_no_promotion(self):
        for i, protocol in enumerate(a2.PROTOCOLS):
            self.case = "DEV-" + str(i) * 32
            folder, pin = self.source(protocol)
            record, status = self.call(folder, pin)
            self.assertEqual(status, "DEV_CASE_OPENED")
            self.assertEqual(record["protocol"], protocol)
            self.assertEqual(record["state"], "PREPARADO")
            self.assertFalse(record["execution_authorized"])
            self.assertFalse(record["experimental_admission"])
            self.assertEqual(record["attempts"], 0)
            self.assertIsNone(record["confirmed_rf"])
            self.assertEqual(record["p8"], "NO-GO")
            self.assertEqual(self.call(folder, pin), (record, "DEV_CASE_REOPENED"))
            self.assertEqual(self.call(folder, pin, reopen=True), (record, "DEV_CASE_REOPENED"))

    def test_cross_source_refused(self):
        first, pin = self.source("SSH")
        other, other_pin = self.source("SMB")
        self.call(first, pin)
        with self.assertRaises(ValueError):
            self.call(other, other_pin)
        with self.assertRaises(ValueError):
            self.call(other, pin, reopen=True)
        self.assertEqual(self.call(first, pin, reopen=True)[1], "DEV_CASE_REOPENED")

    def test_changed_config_and_permissions_refused(self):
        folder, pin = self.source("FTP")
        config = folder / a2.CONFIG_NAMES["FTP"]
        config.chmod(0o644)
        with self.assertRaises(ValueError):
            self.call(folder, pin)
        config.chmod(0o600)
        self.call(folder, pin)
        config.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.call(folder, pin, reopen=True)

    def test_absent_source_and_changed_record_refused(self):
        folder, pin = self.source("SMB")
        with self.assertRaises(OSError):
            self.call(folder, pin, reopen=True)
        self.call(folder, pin)
        record = self.archive / (self.case + ".json")
        record.write_bytes(b"{}\n")
        with self.assertRaises(ValueError):
            self.call(folder, pin, reopen=True)
        (folder / "inventory.json").unlink()
        with self.assertRaises(OSError):
            self.call(folder, pin)

    def test_symbolic_source_refused(self):
        folder, pin = self.source("SSH")
        alias = self.root / "alias"
        alias.symlink_to(folder, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.call(alias, pin)

    def test_cli_normal(self):
        import subprocess
        import sys
        import json
        folder, pin = self.source("FTP")
        args = ["--origen", str(folder), "--archivo", str(self.archive),
                "--id", self.case, "--sha256", pin, "--json"]
        for action in ("abrir-dev", "reabrir-dev"):
            result = subprocess.run([sys.executable, "-m", "ardrec", "caso", action, *args],
                                    capture_output=True, check=True)
            self.assertEqual(json.loads(result.stdout)["case_id"], self.case)
