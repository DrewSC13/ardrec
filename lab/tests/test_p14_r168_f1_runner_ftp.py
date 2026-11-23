"""R168-F1: independent Runner bridge and fail-closed tests."""
import hashlib
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from ardrec.coordination import (
    r168_f1_runner_ftp_boot as core,
    r167_f7d_controlled_boot as ssh,
)

REPO = Path(__file__).resolve().parents[2]
MANIFEST = (
    REPO / "lab/operational-controller/"
    "r168-f1-runner-source-v1.json"
)


class R168RunnerTests(unittest.TestCase):

    def test_historical_source_not_modified(self):
        doc = json.loads(MANIFEST.read_bytes())
        source = (
            REPO / "src/ardrec/coordination/"
            "r117_f4_runner_ftp_boot.py"
        )
        self.assertEqual(
            hashlib.sha256(source.read_bytes()).hexdigest(),
            doc["historical_r117_source_sha256"],
        )

    def test_source_manifest(self):
        doc = json.loads(MANIFEST.read_bytes())
        self.assertEqual(doc["p8"], "NO-GO")
        self.assertEqual(doc["boot_release"], "NOT_ATTESTED")
        self.assertTrue(doc["physical_boot_blocked"])
        self.assertEqual(len(doc["files_sha256"]), 3)
        for name, digest in doc["files_sha256"].items():
            self.assertEqual(
                hashlib.sha256((REPO / name).read_bytes()).hexdigest(),
                digest,
            )

    def test_uses_r167_ssh_predecessor(self):
        self.assertIs(core.f7, ssh)
        self.assertEqual(
            core.SCHEMA,
            "ARDREC-R168-F1-RUNNER-FTP-DENY-v1",
        )
        self.assertEqual(
            core.ROOT.name,
            "r168-f1-runner-ftp-deny-v1",
        )

    def test_runner_boot_denied_before_operations(self):
        with patch.object(
            core,
            "_check_sources",
            side_effect=AssertionError("UNEXPECTED_HOST_ACTION"),
        ):
            with self.assertRaisesRegex(
                core.Stop,
                "R168_RUNNER_RELEASE_NOT_ATTESTED",
            ):
                core.boot(None, None, None, None)

    def test_ssh_receipt_can_be_predecessor(self):
        receipt = {
            "role": "ssh",
            "state": "SSH_RUNNING_DENY_ATTESTED",
            "traffic_authorized": False,
            "p8": "NO-GO",
        }
        plan = ssh.ROOT / "plan-fixture"
        boot = ssh.ROOT / "boot-fixture"

        with patch.object(
            core,
            "_receipt_dir",
            side_effect=lambda path, root, prefix: path,
        ):
            with patch.object(
                core.f7, "_replay_ssh",
                return_value=receipt,
            ):
                got = core.predecessor("runner", plan, boot)

        self.assertEqual(got["role"], "ssh")
        self.assertEqual(got["plan_dir"], str(plan))
        self.assertEqual(got["boot_dir"], str(boot))
        self.assertEqual(
            got["receipt_sha256"],
            ssh.digest(receipt),
        )

    def test_untrusted_predecessor_rejected(self):
        receipt = {
            "role": "ssh",
            "state": "SSH_RUNNING_DENY_ATTESTED",
            "traffic_authorized": True,
            "p8": "NO-GO",
        }
        with patch.object(
            core,
            "_receipt_dir",
            side_effect=lambda path, root, prefix: path,
        ):
            with patch.object(
                core.f7, "_replay_ssh",
                return_value=receipt,
            ):
                with self.assertRaisesRegex(
                    core.Stop,
                    "SSH_PREDECESSOR_NOT_ATTESTED",
                ):
                    core.predecessor(
                        "runner",
                        ssh.ROOT / "plan-fixture",
                        ssh.ROOT / "boot-fixture",
                    )

    def test_runner_plan_preserves_predecessor(self):
        prior = {
            "role": "ssh",
            "plan_dir": "/test/plan-1",
            "boot_dir": "/test/boot-1",
            "receipt_sha256": "a" * 64,
        }

        with patch.object(
            core.f7,
            "state_gate",
            return_value={"role": "runner", "all_deny": "MATCH"},
        ):
            spec = core.plan_spec(
                "runner",
                "b" * 40,
                b"contract",
                b"authorization",
                {},
                {},
                prior,
                datetime.now(timezone.utc),
            )

        self.assertEqual(spec["predecessor"], prior)
        self.assertEqual(spec["role"], "runner")
        self.assertEqual(spec["head"], "b" * 40)
        self.assertFalse(spec["traffic_authorized"])
        self.assertEqual(spec["p8"], "NO-GO")
