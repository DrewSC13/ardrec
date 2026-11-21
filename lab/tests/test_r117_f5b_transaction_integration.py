"""Actual F5B publication exercised only on unprivileged temporary trees.

The physical host, independently provisioned trust, root provenance,
guest execution and traffic are deliberately not simulated as PASS.
"""
from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from io import BytesIO
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
HEAD = "a" * 40

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

f5b = load(
    ROOT / "scripts/ardrec_p14_r117_f5b_root_stage.py",
    "r117_f5b_transaction_test",
)
core = load(
    ROOT / "scripts/ardrec_r117_release_core_v1.py",
    "r117_transaction_crypto_test",
)
builder = load(
    ROOT / "scripts/ardrec_p14_r117_f5_root_candidate.py",
    "r117_transaction_builder_test",
)

class SimulatedInterruption(RuntimeError):
    pass

def local_directory(path, exact_mode=None):
    info = Path(path).lstat()
    if not (
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid()
        and not Path(path).is_symlink()
        and not (info.st_mode & 0o022)
    ):
        raise f5b.Stop("LOCAL_DIRECTORY_UNTRUSTED")
    if exact_mode is not None:
        if stat.S_IMODE(info.st_mode) != exact_mode:
            raise f5b.Stop("LOCAL_DIRECTORY_MODE")

def local_file(path, limit=200000):
    item = Path(path)
    info = item.lstat()
    if not (
        stat.S_ISREG(info.st_mode)
        and not item.is_symlink()
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
        and 0 < info.st_size <= limit
    ):
        raise f5b.Stop("LOCAL_FILE_UNTRUSTED")
    raw = item.read_bytes()
    if len(raw) != info.st_size:
        raise f5b.Stop("LOCAL_FILE_CHANGED")
    return raw


class TransactionIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.candidate = builder.candidate(HEAD, repo=ROOT)
        cls.sha = core.sha(cls.candidate)
        cls.manifest = builder.audit(
            cls.candidate, repo=ROOT, expected_head=HEAD
        )
        cls.keys = tempfile.TemporaryDirectory()

        directory = Path(cls.keys.name)
        private = directory / "private.pem"
        public = directory / "public.pem"

        subprocess.run(
            [
                "/usr/bin/openssl", "genpkey",
                "-algorithm", "ED25519",
                "-out", str(private),
            ],
            check=True, capture_output=True,
        )
        subprocess.run(
            [
                "/usr/bin/openssl", "pkey",
                "-in", str(private),
                "-pubout", "-out", str(public),
            ],
            check=True, capture_output=True,
        )

        cls.private = private
        cls.public = public.read_bytes()

        now = datetime.now(timezone.utc)
        cls.approval = core.canonical({
            "schema": core.APPROVAL_SCHEMA,
            "head": HEAD,
            "candidate_sha256": cls.sha,
            "valid_from": (
                now - timedelta(minutes=1)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "valid_until": (
                now + timedelta(minutes=5)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "purpose": "INSTALL_SOURCE_ONLY",
            "authority": "CI_TEMPORARY_NOT_REAL_AUTHORITY",
            "p8": "NO-GO",
        })

        statement = directory / "statement.bin"
        signature = directory / "signature.bin"
        statement.write_bytes(core.PREFIX + cls.approval)

        subprocess.run(
            [
                "/usr/bin/openssl", "pkeyutl",
                "-sign", "-rawin",
                "-inkey", str(private),
                "-in", str(statement),
                "-out", str(signature),
            ],
            check=True, capture_output=True,
        )
        cls.signature = signature.read_bytes()

        core.verify_signed_candidate(
            cls.candidate, cls.approval,
            cls.signature, cls.public,
            head=HEAD,
            candidate_sha=cls.sha,
            public_sha=core.sha(cls.public),
            now=now,
        )

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "r117-test-root"
        self.root.mkdir(mode=0o700)
        self.addCleanup(self.temp.cleanup)

    def run_transaction(self, interrupt=None):
        def signed_approval(head, candidate_sha, fresh=True):
            self.assertEqual(head, HEAD)
            self.assertEqual(candidate_sha, self.sha)
            return (
                self.approval,
                self.signature,
                core.document(self.approval),
            )

        def checkpoint(point):
            if point == interrupt:
                raise SimulatedInterruption(point)

        with ExitStack() as stack:
            stack.enter_context(patch.object(f5b, "ROOT", self.root))
            stack.enter_context(patch.object(
                f5b, "PILOT",
                self.root / "r117-f4-ftp-pilot-root-v1"
            ))
            stack.enter_context(patch.object(
                f5b, "RELEASE",
                self.root / "r117-f4-boot-release-v1"
            ))
            stack.enter_context(patch.object(
                f5b, "ACTIVATION",
                self.root / "r117-f5b-activation-v1.json"
            ))
            stack.enter_context(patch.object(
                f5b, "root_head", lambda: HEAD
            ))
            stack.enter_context(patch.object(
                f5b, "load_builder", lambda _: builder
            ))
            stack.enter_context(patch.object(
                f5b, "archive_bytes",
                lambda archive, head: self.candidate
            ))
            stack.enter_context(patch.object(
                f5b, "signed_approval", signed_approval
            ))
            stack.enter_context(patch.object(
                f5b, "physical_offline", lambda: None
            ))
            stack.enter_context(patch.object(
                f5b, "root_directory", local_directory
            ))
            stack.enter_context(patch.object(
                f5b, "root_file", local_file
            ))
            stack.enter_context(patch.object(
                f5b, "REPO", ROOT
            ))

            return f5b._install_authorized(
                Path("/not-a-real-deployment.zip"),
                checkpoint=checkpoint,
            )

    def state(self):
        return {
            "pilot": (
                self.root / "r117-f4-ftp-pilot-root-v1"
            ).exists(),
            "release": (
                self.root / "r117-f4-boot-release-v1"
            ).exists(),
            "activation": (
                self.root / "r117-f5b-activation-v1.json"
            ).exists(),
            "transactions": len(list(
                self.root.glob(".r117-f5b-transaction-*")
            )),
        }

    def test_01_positive_real_f5b_publication_in_temp(self):
        self.run_transaction()
        state = self.state()

        self.assertTrue(state["pilot"])
        self.assertTrue(state["release"])
        self.assertTrue(state["activation"])
        self.assertEqual(state["transactions"], 1)

        pilot = self.root / "r117-f4-ftp-pilot-root-v1"

        with zipfile.ZipFile(BytesIO(self.candidate)) as bundle:
            for name in bundle.namelist():
                self.assertEqual(
                    (pilot / name).read_bytes(),
                    bundle.read(name),
                )

        activation = core.document(
            (self.root / "r117-f5b-activation-v1.json").read_bytes()
        )
        self.assertEqual(activation["head"], HEAD)
        self.assertEqual(
            activation["candidate_sha256"], self.sha
        )
        self.assertIs(activation["boot_authorized"], False)
        self.assertIs(activation["network_authorized"], False)
        self.assertEqual(activation["p8"], "NO-GO")

        txn = next(self.root.glob(".r117-f5b-transaction-*"))
        self.assertEqual(
            {item.name for item in txn.iterdir()},
            {
                "intent.json", "complete.json",
                "prepared.once", "pilot-visible.once",
                "release-visible.once",
            },
        )

    def test_02_interruption_after_prepare(self):
        with self.assertRaises(SimulatedInterruption):
            self.run_transaction("PREPARED")
        self.assertFalse(self.state()["activation"])
        self.assertEqual(self.state()["transactions"], 1)

    def test_03_interruption_after_pilot(self):
        with self.assertRaises(SimulatedInterruption):
            self.run_transaction("PILOT_PUBLISHED")
        self.assertTrue(self.state()["pilot"])
        self.assertFalse(self.state()["release"])
        self.assertFalse(self.state()["activation"])

    def test_04_interruption_after_release(self):
        with self.assertRaises(SimulatedInterruption):
            self.run_transaction("RELEASE_PUBLISHED")
        self.assertTrue(self.state()["pilot"])
        self.assertTrue(self.state()["release"])
        self.assertFalse(self.state()["activation"])

    def test_05_interruption_after_completion(self):
        with self.assertRaises(SimulatedInterruption):
            self.run_transaction("COMPLETION_DURABLE")

        txn = next(self.root.glob(".r117-f5b-transaction-*"))
        self.assertTrue((txn / "complete.json").exists())
        self.assertFalse(self.state()["activation"])

    def test_06_interruption_after_activation(self):
        with self.assertRaises(SimulatedInterruption):
            self.run_transaction("ACTIVATION_PUBLISHED")
        self.assertTrue(self.state()["activation"])

    def test_07_partial_transaction_blocks_reinstallation(self):
        with self.assertRaises(SimulatedInterruption):
            self.run_transaction("PREPARED")

        with patch.object(f5b, "ROOT", self.root):
            with patch.object(
                f5b, "ACTIVATION",
                self.root / "r117-f5b-activation-v1.json"
            ):
                with patch.object(
                    f5b, "PILOT",
                    self.root / "r117-f4-ftp-pilot-root-v1"
                ):
                    with patch.object(
                        f5b, "RELEASE",
                        self.root / "r117-f4-boot-release-v1"
                    ):
                        with self.assertRaises(f5b.Stop):
                            f5b.stage_state()

    def test_08_public_apply_stays_blocked(self):
        with self.assertRaises(f5b.Stop) as caught:
            f5b.apply(Path("/nonexistent.zip"))
        self.assertEqual(
            str(caught.exception),
            "F5B_APPLY_BLOCKED_PENDING_ATOMIC_RELEASE_AND_BOOT_GATE",
        )


if __name__ == "__main__":
    unittest.main()
