"""R163-F4 durable staging and recovery tests; no root or traffic."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

import test_p14_r163_single_operator_install_policy as fixture

from ardrec.coordination import (
    r163_single_operator_stage as m,
    r163_install_phase_gate as phase,
)

REPO = Path(__file__).resolve().parents[2]


class R163F4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.R163PolicyTests.setUpClass()
        cls.b4 = (
            REPO / "scripts/ardrec_p14_r130_b4_root_guard_v2.py"
        ).read_bytes()
        cls.b9 = (
            REPO / "scripts/ardrec_p14_r130_b9_ftp_executor_v2.py"
        ).read_bytes()
        assert m.engine.sha(cls.b4) == m.engine.B4_SHA
        assert m.engine.sha(cls.b9) == m.engine.B9_SHA

    @classmethod
    def tearDownClass(cls):
        fixture.R163PolicyTests.tearDownClass()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.root = base / "root"
        self.state = base / "state"
        self.root.mkdir(mode=0o700)
        self.state.mkdir(mode=0o700)
        self.root.chmod(0o700)
        self.state.chmod(0o700)
        self.fx = fixture.R163PolicyTests(
            "test_01_valid_signed_policy"
        )
        self.fx.setUp()
        self.counter = 0
        self.read_override = None

    def plan(self):
        c = self.fx.claim
        return {
            "schema": phase.PLAN_SCHEMA,
            "session": c["session"],
            "head": c["head"],
            "tree": c["tree"],
            "boot_id": c["boot_id"],
            "operator_uid": c["operator_uid"],
            "operator_id": c["operator_id"],
            "inventory_sha256": c["inventory_sha256"],
            "agent_bundle_sha256": c["agent_bundle_sha256"],
            "source_b4_sha256": c["source_b4_sha256"],
            "source_b9_sha256": c["source_b9_sha256"],
            "destinations": c["destinations"],
            "custody_mode": "SINGLE_HUMAN_OPERATOR",
            "independent_authority": False,
            "root_install_authorized": False,
            "network_traffic_authorized": False,
            "vm_start_authorized": False,
            "action": "INSTALL_B4_B9_ONLY",
            "p8": "NO-GO",
        }

    def reader(self, name):
        self.counter += 1
        if self.read_override is not None:
            return self.read_override(name)
        return self.fx.rev_raw

    def gate(self, plan=None):
        return phase.PhaseGate(
            plan=self.plan() if plan is None else plan,
            trust_raw=m.engine.canonical(self.fx.trust),
            authorization_raw=self.fx.auth_raw,
            read_live_revocation=self.reader,
            now_provider=lambda: fixture.NOW,
        )

    def publish(self, gate=None, **changes):
        args = {
            "root_parent": self.root,
            "state_dir": self.state,
            "gate": self.gate() if gate is None else gate,
            "b4": self.b4,
            "b9": self.b9,
        }
        args.update(changes)
        return m.stage(**args)

    def denied(self, **changes):
        with self.assertRaises(
            (m.Refusal, OSError)
        ):
            self.publish(**changes)

    def test_01_complete_durable_stage(self):
        result = self.publish()
        self.assertEqual(
            result["status"],
            "CANDIDATES_STAGED_VERIFIED"
        )
        self.assertEqual(result["phase_review_count"], 4)
        self.assertEqual(self.counter, 4)

    def test_02_readback_and_replay(self):
        self.publish()
        result = self.publish()
        self.assertEqual(
            result["status"],
            "CANDIDATES_ALREADY_VERIFIED"
        )

    def test_03_journal_failure_recovery(self):
        self.denied(fail="after_journal")
        self.assertTrue(
            (self.state / "journal.json").is_file()
        )
        self.assertFalse(
            (self.state / "receipt.json").exists()
        )
        self.publish()

    def test_04_b4_failure_recovery(self):
        self.denied(fail="after_b4")
        self.assertTrue(
            (self.root / m.B4_NAME).is_dir()
        )
        self.assertFalse(
            (self.root / m.B9_NAME).exists()
        )
        self.publish()

    def test_05_b9_failure_recovery(self):
        self.denied(fail="after_b9")
        self.assertTrue(
            (self.root / m.B9_NAME).is_dir()
        )
        self.publish()

    def test_06_b4_tampering_denied(self):
        self.publish()
        target = self.root / m.B4_NAME / "source.py"
        target.write_bytes(b"tampered")
        self.denied()

    def test_07_journal_tampering_denied(self):
        self.publish()
        target = self.state / "journal.json"
        target.write_bytes(b"tampered")
        self.denied()

    def test_08_receipt_tampering_denied(self):
        self.publish()
        target = self.state / "receipt.json"
        target.write_bytes(b"tampered")
        self.denied()

    def test_09_existing_source_without_journal(self):
        (self.root / m.B4_NAME).mkdir(mode=0o700)
        self.denied()

    def test_10_modified_b4_pin_denied(self):
        self.denied(b4=self.b4 + b"x")

    def test_11_modified_b9_pin_denied(self):
        self.denied(b9=self.b9 + b"x")

    def test_12_revocation_changed_before_b9(self):
        def revoke_at_b9(name):
            if name == "before_b9":
                self.fx.rev["revoked"] = True
                self.fx.rev_raw = self.fx.sign(
                    "revocation",
                    phase.policy.REV_PREFIX,
                    self.fx.rev,
                )
            return self.fx.rev_raw

        self.read_override = revoke_at_b9
        self.denied()
        self.assertTrue(
            (self.root / m.B4_NAME).is_dir()
        )
        self.assertFalse(
            (self.root / m.B9_NAME).exists()
        )

    def test_13_changed_plan_denied(self):
        altered = self.plan()
        altered["head"] = "f" * 40
        self.denied(gate=self.gate(plan=altered))

    def test_14_nonoperational_manifests(self):
        self.publish()
        b4 = m.engine.parse(
            (self.root / m.B4_NAME /
             "manifest.json").read_bytes()
        )
        b9 = m.engine.parse(
            (self.root / m.B9_NAME /
             "manifest.json").read_bytes()
        )
        self.assertIs(
            b4["root_install_independent"], False
        )
        self.assertIs(
            b9["root_staged_independently"], False
        )
        self.assertFalse(b4["runtime_activated"])
        self.assertFalse(b9["runtime_activated"])
        self.assertFalse(
            m.capabilities()["root_install_authorized"]
        )
