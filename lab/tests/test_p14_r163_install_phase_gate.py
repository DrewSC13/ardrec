"""R163-F3: four-phase review and fail-closed negative tests."""
from __future__ import annotations

from datetime import timedelta
import base64
import unittest

from ardrec.coordination import r163_install_phase_gate as m
import test_p14_r163_single_operator_install_policy as fixture
NOW = fixture.NOW


class R163PhaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.R163PolicyTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixture.R163PolicyTests.tearDownClass()

    def setUp(self):
        self.fixture = fixture.R163PolicyTests("test_01_valid_signed_policy")
        self.fixture.setUp()
        claim = self.fixture.claim
        self.plan = {
            "schema": m.PLAN_SCHEMA,
            "session": claim["session"],
            "head": claim["head"],
            "tree": claim["tree"],
            "boot_id": claim["boot_id"],
            "operator_uid": claim["operator_uid"],
            "operator_id": claim["operator_id"],
            "inventory_sha256": claim["inventory_sha256"],
            "agent_bundle_sha256": claim["agent_bundle_sha256"],
            "source_b4_sha256": claim["source_b4_sha256"],
            "source_b9_sha256": claim["source_b9_sha256"],
            "destinations": claim["destinations"],
            "custody_mode": "SINGLE_HUMAN_OPERATOR",
            "independent_authority": False,
            "root_install_authorized": False,
            "network_traffic_authorized": False,
            "vm_start_authorized": False,
            "action": "INSTALL_B4_B9_ONLY",
            "p8": "NO-GO",
        }
        self.now = [NOW]
        self.read_count = 0

    def reader(self, phase):
        self.read_count += 1
        return self.fixture.rev_raw

    def gate(self, **kwargs):
        args = {
            "plan": self.plan,
            "trust_raw": m.canon(self.fixture.trust),
            "authorization_raw": self.fixture.auth_raw,
            "read_live_revocation": self.reader,
            "now_provider": lambda: self.now[0],
        }
        args.update(kwargs)
        return m.PhaseGate(**args)

    def test_01_complete_four_phase_chain(self):
        gate = self.gate()
        for phase in m.PHASES:
            result = gate.review(phase)
            self.assertFalse(result["root_install_authorized"])
        self.assertTrue(gate.review_history()["complete"])
        self.assertEqual(self.read_count, 4)

    def test_02_first_phase(self):
        result = self.gate().review("before_journal")
        self.assertEqual(result["sequence"], 0)
        self.assertEqual(result["previous_sha256"], m.ZERO_HASH)

    def test_03_duplicate_phase_denied(self):
        gate = self.gate()
        gate.review("before_journal")
        with self.assertRaises(m.Refusal):
            gate.review("before_journal")

    def test_04_skipped_phase_denied(self):
        with self.assertRaises(m.Refusal):
            self.gate().review("before_b9")

    def test_05_invalid_phase_denied(self):
        with self.assertRaises(m.Refusal):
            self.gate().review("open_network")

    def test_06_revocation_reread(self):
        gate = self.gate()
        gate.review("before_journal")
        gate.review("before_b4")
        self.assertEqual(self.read_count, 2)

    def test_07_revoked_between_phases(self):
        gate = self.gate()
        gate.review("before_journal")
        self.fixture.rev["revoked"] = True
        self.fixture.rev_raw = self.fixture.sign(
            "revocation", m.policy.REV_PREFIX, self.fixture.rev)
        with self.assertRaises(m.Refusal):
            gate.review("before_b4")
        self.assertEqual(len(gate.receipts), 1)

    def test_08_stale_revocation_between_phases(self):
        gate = self.gate()
        gate.review("before_journal")
        self.now[0] = NOW + timedelta(seconds=31)
        with self.assertRaises(m.Refusal):
            gate.review("before_b4")
        self.assertEqual(len(gate.receipts), 1)

    def test_09_invalid_authorization_signature(self):
        document = m.crypto.parse(self.fixture.auth_raw)
        document["signature_b64"] = base64.b64encode(
            bytes(64)).decode("ascii")
        gate = self.gate(
            authorization_raw=m.canon(document))
        with self.assertRaises(m.Refusal):
            gate.review("before_journal")

    def test_10_invalid_revocation_signature(self):
        document = m.crypto.parse(self.fixture.rev_raw)
        document["signature_b64"] = base64.b64encode(
            bytes(64)).decode("ascii")
        gate = self.gate(
            read_live_revocation=lambda _: m.canon(document))
        with self.assertRaises(m.Refusal):
            gate.review("before_journal")

    def test_11_wrong_head_denied(self):
        self.plan["head"] = "f" * 40
        with self.assertRaises(m.Refusal):
            self.gate().review("before_journal")

    def test_12_wrong_tree_denied(self):
        self.plan["tree"] = "f" * 40
        with self.assertRaises(m.Refusal):
            self.gate().review("before_journal")

    def test_13_wrong_boot_denied(self):
        self.plan["boot_id"] = "f" * 36
        with self.assertRaises(m.Refusal):
            self.gate().review("before_journal")

    def test_14_wrong_inventory_denied(self):
        self.plan["inventory_sha256"] = "f" * 64
        with self.assertRaises(m.Refusal):
            self.gate().review("before_journal")

    def test_15_wrong_operator_uid_denied(self):
        self.plan["operator_uid"] = 2000
        with self.assertRaises(m.Refusal):
            self.gate().review("before_journal")

    def test_16_wrong_agent_bundle_denied(self):
        self.plan["agent_bundle_sha256"] = "f" * 64
        with self.assertRaises(m.Refusal):
            self.gate().review("before_journal")

    def test_17_extra_plan_field_denied(self):
        self.plan["unexpected"] = True
        with self.assertRaises(m.Refusal):
            self.gate()

    def test_18_root_escalation_denied(self):
        self.plan["root_install_authorized"] = True
        with self.assertRaises(m.Refusal):
            self.gate()

    def test_19_b4_source_pin_denied(self):
        self.plan["source_b4_sha256"] = "f" * 64
        with self.assertRaises(m.Refusal):
            self.gate()

    def test_20_missing_revocation_reader_denied(self):
        with self.assertRaises(m.Refusal):
            self.gate(read_live_revocation=None)

    def test_21_revocation_reader_failure_denied(self):
        def broken(_):
            raise OSError("revocation unavailable")
        gate = self.gate(read_live_revocation=broken)
        with self.assertRaises(m.Refusal):
            gate.review("before_journal")

    def test_22_nonbyte_revocation_denied(self):
        gate = self.gate(
            read_live_revocation=lambda _: "not-bytes")
        with self.assertRaises(m.Refusal):
            gate.review("before_journal")

    def test_23_expired_between_phases(self):
        gate = self.gate()
        gate.review("before_journal")
        self.now[0] = NOW + timedelta(minutes=4)
        with self.assertRaises(m.Refusal):
            gate.review("before_b4")

    def test_24_hash_chain_tampering_detected(self):
        gate = self.gate()
        for phase in m.PHASES:
            gate.review(phase)
        receipts = list(gate.receipts)
        receipts[1]["revocation_sha256"] = "f" * 64
        with self.assertRaises(m.Refusal):
            m.verify_history(
                receipts,
                plan_sha256=gate.plan_sha256,
                authorization_sha256=m.sha(
                    self.fixture.auth_raw),
            )
