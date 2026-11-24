"""R197: software-only contract regressions."""
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

from ardrec.coordination import prospective_local_pilot as m


def plan():

    return m.make_plan(
        "PILOT_FTP_" + "A" * 32,
        "a" * 40,
        "2026-11-24T12:00:00Z",
        1000,
    )


class ProspectivePilotTests(unittest.TestCase):

    def test_plan_is_explicitly_illustrative(self):

        value = plan()

        self.assertTrue(m.verify_plan(value))
        self.assertFalse(value["experimental_unit"])

        self.assertEqual(
            value["input_kind"],
            "ILLUSTRATIVE_SOFTWARE_REHEARSAL",
        )

        self.assertEqual(
            value["maximum_attempts"], 1
        )

    def test_resealed_modified_plan_rejected(self):

        value = plan()

        value.pop("sha256")
        value["initial_risk"] = "1"

        with self.assertRaises(ValueError):
            m.verify_plan(m.seal(value))

    def test_root_and_consent_rejected(self):

        with self.assertRaises(ValueError):

            m.make_plan(
                "PILOT_FTP_" + "A" * 32,
                "a" * 40,
                "2026-11-24T12:00:00Z",
                0,
            )

        with self.assertRaises(ValueError):

            m.run_local(
                Path("unused"),
                Path("unused"),
                "a" * 40,
                "INVALID",
            )

    def test_write_once(self):

        with tempfile.TemporaryDirectory() as tmp:

            path = Path(tmp) / "plan.json"

            m.write_once(path, plan())

            original = path.read_bytes()

            with self.assertRaises(FileExistsError):
                m.write_once(path, {"changed": True})

            self.assertEqual(
                path.read_bytes(),
                original,
            )

    def test_conservative_calculation(self):

        value = plan()

        intent = m.make_intent(
            value,
            "2026-11-24T12:00:01Z",
        )

        # Mock only the transport validation boundary.
        # No network and no physical evidence is claimed.
        fixture = {
            "sha256": "b" * 64,
            "started_at_utc":
                "2026-11-24T12:00:02Z",
            "completed_at_utc":
                "2026-11-24T12:00:03Z",
        }

        with patch.object(
            m.evidence,
            "verify_transport",
            return_value={"reply_code": 220},
        ):

            result = m.calculate(
                value,
                intent,
                fixture,
            )

            self.assertEqual(
                result["a6"], "ND"
            )

            self.assertIsNone(
                result["confirmed_rf"]
            )

            self.assertFalse(
                result["experimental_admission"]
            )

            self.assertEqual(
                result["candidate_interval"],
                {
                    "lower": "1/2",
                    "upper": "11/18",
                },
            )

            self.assertEqual(
                result,
                m.calculate(value, intent, fixture),
            )

            fixture["started_at_utc"] = (
                "2026-11-24T11:59:59Z"
            )

            with self.assertRaises(ValueError):

                m.calculate(
                    value,
                    intent,
                    fixture,
                )


if __name__ == "__main__":
    unittest.main()
