"""Contract tests; no physical observations are created."""

import unittest

from ardrec.coordination import prospective_local_pilot as durable
from ardrec.experiments import local_consolidation as review
from ardrec.experiments import study_cli


class ReviewTests(unittest.TestCase):

    def test_expected_case_count(self):

        self.assertEqual(
            len(review.EXPECTED_CASES),
            6,
        )

    def test_invalid_digest(self):

        for value in (None, "", "a" * 63, "z" * 64):

            self.assertFalse(
                review.valid_digest(value)
            )

    def test_valid_digest(self):

        self.assertTrue(
            review.valid_digest("a" * 64)
        )

    def test_independent_source_pin(self):

        source = durable.seal({
            "schema": review.SOURCE_SCHEMA,
        })

        with self.assertRaisesRegex(
            ValueError,
            "SOURCE_PIN_MISMATCH",
        ):

            review.review_report(
                source,
                "a" * 64,
                {},
            )

    def test_tampered_document_refused(self):

        source = durable.seal({
            "schema": review.SOURCE_SCHEMA,
        })

        pin = source["sha256"]

        source["schema"] = "INVALID"

        with self.assertRaises(ValueError):

            review.review_report(
                source,
                pin,
                {},
            )

    def test_historical_support_not_accredited(self):

        unit = {
            "origin": "R219",
            "protocol": "FTP",
            "required_supports": [
                "ACCESS_COMPARISON",
                "OPERATION_RESPONSE",
            ],
        }

        result = review.support_review(
            unit,
            {
                "required_supports":
                    unit["required_supports"],
            },
        )

        self.assertEqual(len(result), 2)

        self.assertTrue(all(
            row["status"] == "HISTORICAL_SOURCE_RETAINED"
            and not row["operationally_accredited"]
            for row in result
        ))

    def test_changed_family_supports_refused(self):

        with self.assertRaisesRegex(
            ValueError,
            "FAMILY_SUPPORT_REQUIREMENTS_CHANGED",
        ):

            review.support_review(
                {"required_supports": ["A"]},
                {"required_supports": ["B"]},
            )

    def test_cli_modes_mutually_exclusive(self):

        with self.assertRaises(SystemExit) as exc:

            study_cli.main([
                "--registro", "unused",
                "--consolidacion-local", "unused",
                "--texto",
            ])

        self.assertEqual(exc.exception.code, 2)

    def test_cli_requires_source_pin(self):

        with self.assertRaises(SystemExit) as exc:

            study_cli.main([
                "--consolidacion-local", "unused",
                "--texto",
            ])

        self.assertEqual(exc.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
