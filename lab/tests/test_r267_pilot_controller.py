"""Native pilot state and authority boundary regressions."""

from dataclasses import replace
import unittest

from ardrec.coordination import (
    prospective_local_pilot as durable,
    pilot_controller as engine,
)

from ardrec.persistence.codec import pack, unpack

from ardrec.state import Truth


class PilotControllerTests(unittest.TestCase):

    def state(self):

        return engine.native_state(
            "a" * 64,
            sorted(engine.UNITS),
        )

    def test_01_native_state_valid(self):

        self.assertTrue(
            engine.verify_state(self.state())
        )

    def test_02_six_native_transition_rejections(self):

        state = self.state()

        for unit in engine.UNITS:

            self.assertEqual(
                engine.native_t1_rejection(
                    state, unit, "b" * 64
                ),
                "authority_unverified",
            )

    def test_03_native_codec_roundtrip(self):

        state = self.state()

        self.assertEqual(
            unpack(pack(state)), state
        )

    def test_04_authority_promotion_rejected(self):

        state = replace(
            self.state(),
            authority=Truth.VERDADERO,
        )

        with self.assertRaisesRegex(
            ValueError, "REVIEW_STATE_AUTHORITY_DRIFT"
        ):
            engine.verify_state(state)

    def test_05_dispatchable_state_rejected(self):

        state = replace(
            self.state(),
            simulation=False,
        )

        with self.assertRaises(ValueError):
            engine.verify_state(state)

    def test_06_duplicate_identity_rejected(self):

        ids = sorted(engine.UNITS)

        ids[-1] = ids[0]

        with self.assertRaisesRegex(
            ValueError, "NATIVE_STATE_UNIT_SET_INVALID"
        ):
            engine.native_state("a" * 64, ids)

    def test_07_source_pin_rejected(self):

        document = durable.seal({
            "scope": "TEST_ONLY",
        })

        with self.assertRaises(ValueError):
            engine.verify_seal(
                document, "b" * 64
            )

    def test_08_recovery_bound_to_original_state(self):

        state = self.state()

        report = durable.seal({
            "schema": engine.SCHEMA,
            "source_sha256": "a" * 64,
            "native_review_state": pack(state),
            "units": [
                {"unit_id": unit}
                for unit in sorted(engine.UNITS)
            ],
            "operational_dispatch": False,
            "operational_a9_publications": 0,
            "p8": "NO-GO",
        })

        self.assertEqual(
            engine.recover_state(report), state
        )

        changed = {
            key: value
            for key, value in report.items()
            if key != "sha256"
        }

        changed["source_sha256"] = "b" * 64

        with self.assertRaises(ValueError):
            engine.recover_state(
                durable.seal(changed)
            )


if __name__ == "__main__":
    unittest.main()
