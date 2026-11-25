"""Synthetic source-bound replay projection; no physical operations."""
import copy
import unittest
import test_r278_pilot_readback as fixtures
from ardrec.coordination import pilot_readback as engine
from ardrec.coordination import pilot_controller
from ardrec.coordination import prospective_local_pilot as durable


class UnitReplayTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.PilotReadbackTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.snapshot = fixture.snapshot
        self.uid = self.snapshot.projections[0].service_scenario_id
        self.record = {"unit_id": self.uid, "plan_sha256": "b" * 64,
                       "i1_sha256": "c" * 64, "i2_sha256": "d" * 64}
        self.controller = {"unit_id": self.uid, "plan_sha256": "b" * 64,
                           "baseline_closed": False,
                           "native_t1_rejection": "authority_unverified"}
        self.report = durable.seal({"snapshot_sha256": [self.snapshot.snapshot_sha256],
            "units": [{"unit_id": self.uid, "phase": "PREPARADO",
                       "a8_decision": "CIERRE_NO_EVALUABLE_OPERACIONALMENTE",
                       "blockers": list(pilot_controller.BLOCKERS)}],
            "p7": "DRAFT_NOT_FROZEN", "p8": "NO-GO"})

    def replay(self):
        return engine.explain_unit(self.report, self.snapshot, self.record,
                                   self.controller, "a" * 64)

    def test_deterministic_support(self):
        first = self.replay()
        self.assertEqual(first, self.replay())
        guard = first["first_pending_guard"]
        self.assertEqual(guard["code"], "OPERATIONAL_BASELINE_NOT_CLOSED")
        self.assertEqual(guard["current_operational_status"], "ND")
        self.assertEqual(guard["support"][0]["document_sha256"], "c" * 64)
        self.assertIn("NATIVE_T1_REJECTION=authority_unverified", engine.render_unit_text(first))
        self.assertEqual(first["new_protocol_attempts"], 0)

    def test_reject_changed_plan(self):
        self.record["plan_sha256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "REPLAY_GUARD_BINDING_INVALID"):
            self.replay()

    def test_reject_reordered_blockers(self):
        self.report = copy.deepcopy(self.report)
        self.report["units"][0]["blockers"].reverse()
        with self.assertRaisesRegex(ValueError, "REPLAY_GUARD_BINDING_INVALID"):
            self.replay()

    def test_reject_wrong_unit(self):
        self.record["unit_id"] = "PILOT-UNKNOWN"
        with self.assertRaisesRegex(ValueError, "REPLAY_UNIT_BINDING_INVALID"):
            self.replay()

    def test_reject_wrong_snapshot(self):
        self.report["snapshot_sha256"] = ["f" * 64]
        with self.assertRaisesRegex(ValueError, "REPLAY_GUARD_BINDING_INVALID"):
            self.replay()

    def test_reject_authority_promotion(self):
        self.controller["native_t1_rejection"] = "ALLOW"
        with self.assertRaisesRegex(ValueError, "REPLAY_GUARD_BINDING_INVALID"):
            self.replay()
