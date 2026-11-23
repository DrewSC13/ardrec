"""R165-F2: pruebas integradas B10+B11, A9 fail-closed y replay."""
from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
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
    r165_f2_a5_a10_documentary_controller as m,
    r129_b9_receipt_gate as b10,
    r129_b11_independent_a6 as b11,
)

import test_p14_r129_b11_independent_a6 as fixtures


@unittest.skipIf(
    os.geteuid() == 0,
    "Requiere usuario no root para los diarios F13",
)
class IntegratedDocumentaryGate(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        fixtures.IndependentA6B11.setUpClass()

    def setUp(self):
        self.f = fixtures.IndependentA6B11(
            "test_01_real_ed25519_three_roles"
        )
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def inputs(self, *, signed=True):
        x = self.f.x
        result = {
            "journal": x.journal,
            "handoff": x.handoff,
            "intent": x.intent,
            "receipt": x.receipt,
            "guest": x.guest,
            "qga": x.qga,
        }
        if signed:
            result["signed"] = {
                "source": self.f.source,
                "technical": self.f.technical,
                "revocation": self.f.revocation,
                "witness": self.f.witness,
                "trust": self.f.trust,
            }
            result["now"] = fixtures.NOW
        return result

    def review(self, *, signed=True):
        return m.evaluate(**self.inputs(signed=signed))

    def test_01_a5_b10_really_replayed(self):
        result = self.review(signed=False)
        self.assertEqual(
            result["a5_root_receipt_status"],
            "FTP_GUEST_CANDIDATE_ONLY",
        )
        self.assertEqual(result["a5_status"],
                         "EXPORTED_ROOT_GUEST_CANDIDATE_ONLY")

    def test_02_a6_ed25519_three_roles(self):
        result = self.review()
        self.assertTrue(
            result["a6_documentary_signatures_verified"]
        )
        self.assertIsNotNone(
            result["a6_signed_documentary_review_sha256"]
        )

    def test_03_signed_is_not_live_root(self):
        result = self.review()
        self.assertFalse(result["a6_physical_root_attested"])
        self.assertEqual(result["a6"], "ND")

    def test_04_a7_no_confirmed_rf(self):
        self.assertIsNone(
            self.review()["a7_confirmed_rf"]
        )

    def test_05_a8_not_applied(self):
        self.assertFalse(
            self.review()["a8_transition_applied"]
        )

    def test_06_a9_never_published(self):
        result = self.review()
        self.assertIsNone(result["a9_generation"])
        self.assertFalse(result["a9_durable_store_opened"])
        self.assertEqual(result["p8"], "NO-GO")

    def test_07_six_hash_linked_stages(self):
        result = self.review()
        self.assertEqual(
            [x["algorithm"] for x in result["stages"]],
            list(m.STAGES),
        )
        previous = None
        for event in result["stages"]:
            self.assertEqual(
                event["previous_event_sha256"], previous
            )
            self.assertEqual(
                event["sha256"],
                b10.digest({
                    k: v for k, v in event.items()
                    if k != "sha256"
                }),
            )
            previous = event["sha256"]
        self.assertEqual(
            previous, result["a10_event_head_sha256"]
        )

    def test_08_exact_replay(self):
        sources = self.inputs()
        result = m.evaluate(**sources)
        self.assertEqual(result, m.evaluate(**sources))
        self.assertTrue(m.verify(result, **sources))

    def test_09_forged_a6_report_rejected(self):
        sources = self.inputs()
        result = m.evaluate(**sources)
        result["a6"] = "VERDADERO"
        with self.assertRaisesRegex(
            m.Stop, "CONTROLLER_REPLAY_MISMATCH"
        ):
            m.verify(result, **sources)

    def test_10_forged_a10_event_rejected(self):
        sources = self.inputs()
        result = m.evaluate(**sources)
        result["stages"][-1]["status"] = "PUBLISHED"
        with self.assertRaises(m.Stop):
            m.verify(result, **sources)

    def test_11_forged_b9_a6_rejected(self):
        self.f.x.receipt["a6"] = "VERDADERO"
        with self.assertRaises(b10.Stop):
            self.review(signed=False)

    def test_12_invalid_source_signature_rejected(self):
        self.f.source["signature_b64"] = "A" * 88
        with self.assertRaises(b11.Stop):
            self.review()

    def test_13_revoked_authority_rejected(self):
        self.f.revocation["statement"]["revoked"] = True
        with self.assertRaises(b11.Stop):
            self.review()

    def test_14_missing_or_stale_clock_rejected(self):
        sources = self.inputs()
        sources["now"] = None
        with self.assertRaisesRegex(
            m.Stop, "SIGNED_REVIEW_CLOCK_REQUIRED"
        ):
            m.evaluate(**sources)
        sources["now"] = (
            fixtures.NOW + timedelta(seconds=100)
        )
        with self.assertRaises(b11.Stop):
            m.evaluate(**sources)

    def test_15_no_network_or_native_store(self):
        with (
            patch(
                "socket.socket",
                side_effect=AssertionError("socket forbidden"),
            ),
            patch(
                "ardrec.persistence.DurableStore.open",
                side_effect=AssertionError("store forbidden"),
            ),
            patch(
                "ardrec.persistence.DurableStore.create",
                side_effect=AssertionError("store forbidden"),
            ),
        ):
            result = self.review()
        self.assertEqual(result["p8"], "NO-GO")

    def test_16_failed_attempt_remains_unresolved(self):
        x = self.f.x
        x.receipt.update({
            "result": "NO_GO_ATTEMPT_CONSUMED",
            "error": "fixture failure",
            "guest_result_sha256": None,
            "denies_restored_and_verified": False,
        })
        sources = self.inputs(signed=False)
        sources["guest"] = None
        sources["qga"] = None
        result = m.evaluate(**sources)
        self.assertEqual(
            result["a5_status"],
            "UNRESOLVED_OR_FAILED_SINGLE_ATTEMPT",
        )
        self.assertEqual(result["a6"], "ND")
        self.assertIsNone(result["a9_generation"])

    def test_17_schema_and_capabilities(self):
        result = self.review()
        self.assertEqual(result["schema"], m.SCHEMA)
        self.assertEqual(result["a10_stage_count"], 6)
        self.assertEqual(
            result["source_kind"],
            "EXPORTED_UNTRUSTED_F13_B9_DOCUMENTS",
        )
        caps = m.capabilities()
        self.assertFalse(caps["a6_live_root_admission"])
        self.assertFalse(caps["a9_generation_published"])
        self.assertFalse(
            caps["native_a9_alternative_implemented"]
        )


if __name__ == "__main__":
    unittest.main()
