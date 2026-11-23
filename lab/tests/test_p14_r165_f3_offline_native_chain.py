"""R165-F3: integración efectiva B10/B11/B12/B13, solo fixtures."""
from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "src"),
    str(ROOT / "scripts"),
    str(ROOT / "lab/tests"),
]

from ardrec.coordination import (
    r165_f3_offline_native_chain as m,
    r129_b11_independent_a6 as b11,
    r129_b12_calibration_a9 as b12,
)
from ardrec.state import Truth
import test_p14_r129_b11_independent_a6 as b11_fixture
import test_p14_r129_b12_calibration_a9 as b12_fixture
import test_p14_r129_b13_native_a9_replay as b13_fixture


@unittest.skipIf(
    os.geteuid() == 0,
    "Los fixtures de F13 requieren usuario no root",
)
class IntegratedNativeFixture(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        b11_fixture.IndependentA6B11.setUpClass()
        b12_fixture.B12.setUpClass()

    def setUp(self):
        self.b11 = b11_fixture.IndependentA6B11(
            "test_01_real_ed25519_three_roles"
        )
        self.b11.setUp()
        self.addCleanup(self.b11.doCleanups)

        self.b12 = b12_fixture.B12(
            "test_01_two_real_ed25519_signatures"
        )
        self.b12.setUp()

        # Positivo B11 generado con root y R127 SIMULADOS
        # dentro del fixture existente. NO es una admisión real.
        self.a6 = self.b11.root_test()

        self.b12.a6 = self.a6
        self.b12.b11_trust = self.b11.trust
        self.b12.raw["head"] = self.a6["head"]
        self.b12.raw["session"] = self.a6["session"]
        self.b12.raw["case_id"] = self.a6["case_id"]
        self.b12.raw["a6_sha256"] = self.a6["sha256"]
        self.b12.recalc()

        x = self.b11.x

        self.documents = {
            "journal": x.journal,
            "handoff": x.handoff,
            "intent": x.intent,
            "receipt": x.receipt,
            "guest": x.guest,
            "qga": x.qga,
            "signed": {
                "source": self.b11.source,
                "technical": self.b11.technical,
                "revocation": self.b11.revocation,
                "witness": self.b11.witness,
                "trust": self.b11.trust,
            },
            "now": b11_fixture.NOW,
        }

        self.initial = b13_fixture.initial()
        self.context = b13_fixture.context(self.initial)

    def sources(self):
        return {
            "fixture_marker": m.FIXTURE_MARKER,
            "documentary_sources": self.documents,
            "injected_a6_copy": self.a6,
            "calibration": self.b12.cal,
            "calibration_revocation": self.b12.rev,
            "calibration_trust": self.b12.trust,
            "b11_trust": self.b11.trust,
            "catalog_sha256": self.b12.raw["catalog_sha256"],
            "initial_state": self.initial,
            "transition_context": self.context,
            "expected_generation": 0,
            "reference": "GEN_B13_1",
            "publication_event": "PUB_B13",
        }

    def execute(self):
        return m.integrate_fixture(**self.sources())

    def test_01_full_chain_executes(self):
        r = self.execute()
        self.assertEqual(r["a10_stage_count"], 6)

    def test_02_a7_exact_math_is_executed(self):
        r = self.execute()
        self.assertEqual(r["a7_math_candidate_test_only"], "11/18")
        self.assertEqual(len(r["a7_exact_preview_sha256"]), 64)
        self.assertEqual(len(r["a7_exact_interval_sha256"]), 64)

    def test_03_a6_copy_is_never_physical(self):
        r = self.execute()
        self.assertEqual(r["a6"], "ND")
        self.assertFalse(r["a6_physical_admitted"])

    def test_04_no_confirmed_risk(self):
        self.assertIsNone(self.execute()["confirmed_rf"])

    def test_05_native_a8_reducer_executes(self):
        r = self.execute()
        self.assertEqual(
            r["a8_native_transition_test"]["phase_after"],
            "DETENIDO",
        )
        self.assertFalse(
            r["a8_operational_transition_applied"]
        )

    def test_06_native_a9_preflight_without_commit(self):
        r = self.execute()
        self.assertEqual(
            r["a9_candidate_generation_test_only"], 1
        )
        self.assertIsNone(r["a9_confirmed_generation"])
        self.assertFalse(r["a9_store_committed"])

    def test_07_exact_deterministic_replay(self):
        sources = self.sources()
        report = m.integrate_fixture(**sources)
        self.assertEqual(
            report, m.integrate_fixture(**sources)
        )
        self.assertTrue(m.verify(report, **sources))

    def test_08_tampered_report_rejected(self):
        sources = self.sources()
        report = m.integrate_fixture(**sources)
        report["a9_store_committed"] = True

        with self.assertRaisesRegex(
            m.Stop, "NATIVE_CHAIN_REPLAY_MISMATCH"
        ):
            m.verify(report, **sources)

    def test_09_fixture_marker_required(self):
        args = self.sources()
        args["fixture_marker"] = "PRODUCTION"

        with self.assertRaisesRegex(
            m.Stop, "OFFLINE_FIXTURE_MARKER_REQUIRED"
        ):
            m.integrate_fixture(**args)

    def test_10_case_identity_mismatch_rejected(self):
        args = self.sources()
        copied = deepcopy(self.a6)
        copied["case_id"] = "DIFFERENT_CASE"
        copied["sha256"] = b11.sha({
            k: v for k, v in copied.items()
            if k != "sha256"
        })
        args["injected_a6_copy"] = copied

        with self.assertRaisesRegex(
            m.Stop, "A6_FIXTURE_IDENTITY_NOT_BOUND"
        ):
            m.integrate_fixture(**args)

    def test_11_corrupt_a6_hash_rejected(self):
        args = self.sources()
        copied = deepcopy(self.a6)
        copied["sha256"] = "0" * 64
        args["injected_a6_copy"] = copied

        with self.assertRaisesRegex(
            m.Stop, "A6_FIXTURE_INTEGRITY_INVALID"
        ):
            m.integrate_fixture(**args)

    def test_12_wrong_source_binding_rejected(self):
        args = self.sources()
        copied = deepcopy(self.a6)
        copied["independent_source_attestation_sha256"] = "0" * 64
        copied["sha256"] = b11.sha({
            k: v for k, v in copied.items()
            if k != "sha256"
        })
        args["injected_a6_copy"] = copied

        with self.assertRaisesRegex(
            m.Stop, "A6_FIXTURE_SIGNATURE_BINDING_INVALID"
        ):
            m.integrate_fixture(**args)

    def test_13_wrong_b11_trust_rejected(self):
        args = self.sources()
        args["b11_trust"] = self.b12.trust

        with self.assertRaisesRegex(
            m.Stop, "B11_TRUST_MISMATCH"
        ):
            m.integrate_fixture(**args)

    def test_14_invalid_calibration_signature(self):
        args = self.sources()
        cal = deepcopy(self.b12.cal)
        cal["signature_b64"] = "A" * 88
        args["calibration"] = cal

        with self.assertRaises(b12.Stop):
            m.integrate_fixture(**args)

    def test_15_revocation_rejected(self):
        args = self.sources()
        revoked = deepcopy(self.b12.rev)
        revoked["statement"]["revoked"] = True
        args["calibration_revocation"] = revoked

        with self.assertRaises(b12.Stop):
            m.integrate_fixture(**args)

    def test_16_native_service_scope_rejected(self):
        args = self.sources()
        args["initial_state"] = {}

        with self.assertRaisesRegex(
            m.Stop, "NATIVE_TEST_STATE_INVALID"
        ):
            m.integrate_fixture(**args)

    def test_17_native_event_reuse_rejected(self):
        args = self.sources()
        args["publication_event"] = "STOP_B13"

        with self.assertRaises(b12.Stop):
            m.integrate_fixture(**args)

    def test_18_no_socket_and_no_durable_store(self):
        with (
            patch(
                "socket.socket",
                side_effect=AssertionError("SOCKET_FORBIDDEN"),
            ),
            patch(
                "ardrec.persistence.DurableStore.open",
                side_effect=AssertionError("STORE_FORBIDDEN"),
            ),
            patch(
                "ardrec.persistence.DurableStore.create",
                side_effect=AssertionError("STORE_FORBIDDEN"),
            ),
        ):
            report = self.execute()
        self.assertEqual(report["p8"], "NO-GO")

    def test_19_root_operator_rejected(self):
        with patch.object(m.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(
                m.Stop, "ROOT_EXECUTION_FORBIDDEN"
            ):
                self.execute()

    def test_20_capabilities_fail_closed(self):
        capabilities = m.capabilities()
        self.assertFalse(capabilities["operational_a9"])
        self.assertFalse(capabilities["operational_a8"])
        self.assertFalse(capabilities["durable_store_opened"])
        self.assertIsNone(capabilities["confirmed_rf"])
        self.assertEqual(capabilities["p8"], "NO-GO")


if __name__ == "__main__":
    unittest.main()
