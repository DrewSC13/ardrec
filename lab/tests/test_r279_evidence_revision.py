"""R279 exact evidence repository and risk regression."""

import unittest

from ardrec.evidence import evidence_revision as engine


def source(revisions=None, selections=None):

    return {
        "scope": engine.SCOPE,
        "unit_id": "S01-MODEL",
        "configuration_sha256": "a" * 64,
        "baseline": {
            "exposure": 3,
            "probability": 3,
            "impact": 3,
            "context": [3, 3, 3],
        },
        "revisions": (
            [] if revisions is None else revisions
        ),
        "selections": (
            [] if selections is None else selections
        ),
    }


def revision(
    revision_id,
    condition="C01",
    previous=None,
    classification="POSITIVO_VALIDO",
    dimensions=None,
    probability=None,
    impact=None,
):

    if dimensions is None:

        if classification == "POSITIVO_VALIDO":
            dimensions = [4, 2, 4, 4]

        elif classification == "NEGATIVO_VALIDO":
            dimensions = [0, 0, 4, 4]

    return {
        "unit_id": "S01-MODEL",
        "configuration_sha256": "a" * 64,
        "condition_id": condition,
        "revision_id": revision_id,
        "previous_revision_id": previous,
        "classification": classification,
        "dimensions": dimensions,
        "substitution": {
            "probability": probability,
            "impact": impact,
        },
    }


def thesis_example():

    return source([
        revision("R01"),
        revision(
            "R02",
            condition="C02",
            classification="NEGATIVO_VALIDO",
            probability=2,
            impact=2,
        ),
    ])


class EvidenceRevisionTests(unittest.TestCase):

    def test_01_exact_thesis_example(self):

        report = engine.evaluate(thesis_example())

        self.assertEqual(
            report["frozen"]["initial_risk"],
            "1/2",
        )

        self.assertEqual(
            report["analysis"],
            {
                "accumulated_evidence": "3/4",
                "substituted_baseline": "1/3",
                "upper_bound": "7/12",
                "lower_adjustment_bound": "4/9",
                "recalibrated_risk": "19/36",
                "priority": "7/12",
            },
        )

        self.assertTrue(engine.verify(report))

    def test_02_equivalent_revision_counted_once(self):

        report = engine.evaluate(source([
            revision("R01"),
            revision("R02", previous="R01"),
        ]))

        self.assertEqual(
            report["equivalent_revision_count"], 1
        )

        self.assertEqual(
            report["active_model_revision_count"], 1
        )

        self.assertEqual(
            report["analysis"]["accumulated_evidence"],
            "3/4",
        )

    def test_03_revision_conflict_blocks_point(self):

        report = engine.evaluate(source([
            revision("R01"),
            revision(
                "R02",
                previous="R01",
                classification="NEGATIVO_VALIDO",
            ),
        ]))

        self.assertIn(
            "REVISION_CONFLICT:C01",
            report["pending"],
        )

        self.assertIsNone(
            report["analysis"]["recalibrated_risk"]
        )

    def test_04_explicit_model_selection(self):

        revisions = [
            revision("R01"),
            revision(
                "R02",
                previous="R01",
                classification="NEGATIVO_VALIDO",
            ),
        ]

        selection = {
            "condition_id": "C01",
            "candidate_revisions": ["R01", "R02"],
            "selected_revision": "R01",
            "justification": "Explicit synthetic model selection",
        }

        report = engine.evaluate(
            source(revisions, [selection])
        )

        self.assertEqual(report["pending"], [])

        self.assertEqual(
            report["analysis"]["accumulated_evidence"],
            "3/4",
        )

        self.assertFalse(
            report["conditions"][0][
                "resolution_authenticated"
            ]
        )

        selection["candidate_revisions"] = ["R01"]

        with self.assertRaises(ValueError):
            engine.evaluate(
                source(revisions, [selection])
            )

    def test_05_incompatible_substitutions(self):

        report = engine.evaluate(source([
            revision(
                "R01",
                classification="NEGATIVO_VALIDO",
                probability=1,
            ),
            revision(
                "R02",
                condition="C02",
                classification="NEGATIVO_VALIDO",
                probability=2,
            ),
        ]))

        self.assertIn(
            "SUBSTITUTION_CONFLICT:probability",
            report["pending"],
        )

        self.assertIsNone(
            report["analysis"]["substituted_baseline"]
        )

    def test_06_negative_does_not_erase_positive(self):

        report = engine.evaluate(thesis_example())

        self.assertEqual(
            [
                row["contribution"]
                for row in report[
                    "active_model_contributions"
                ]
            ],
            ["3/4", "0"],
        )

        self.assertEqual(
            report["analysis"]["accumulated_evidence"],
            "3/4",
        )

        self.assertEqual(
            report["substituted_components"]["exposure"],
            3,
        )

    def test_07_invalid_replacement_rejected(self):

        for classification, probability in (
            ("NEGATIVO_VALIDO", 4),
            ("POSITIVO_VALIDO", 2),
        ):

            with self.subTest(
                classification=classification
            ):

                with self.assertRaises(ValueError):

                    engine.evaluate(source([
                        revision(
                            "R01",
                            classification=classification,
                            probability=probability,
                        )
                    ]))

    def test_08_indetermination_not_zero(self):

        report = engine.evaluate(source([
            revision(
                "R01",
                classification="INCONCLUSO",
            ),
        ]))

        self.assertIsNone(
            report["analysis"]["accumulated_evidence"]
        )

        self.assertFalse(
            report["mathematical_point_available"]
        )

    def test_09_cross_context_rejected(self):

        row = revision("R01")
        row["unit_id"] = "S02-MODEL"

        with self.assertRaises(ValueError):
            engine.evaluate(source([row]))

        row = revision("R01")
        row["configuration_sha256"] = "b" * 64

        with self.assertRaises(ValueError):
            engine.evaluate(source([row]))

    def test_10_invalid_revision_chain_rejected(self):

        with self.assertRaises(ValueError):

            engine.evaluate(source([
                revision("R01"),
                revision("R02", previous="UNKNOWN"),
            ]))

        with self.assertRaises(ValueError):

            engine.evaluate(source([
                revision("R01"),
                revision("R01", previous="R01"),
            ]))

    def test_11_resealed_tampering_rejected(self):

        report = engine.evaluate(thesis_example())

        report["analysis"]["recalibrated_risk"] = "1"

        report.pop("sha256")
        report["sha256"] = engine.digest(report)

        with self.assertRaises(ValueError):
            engine.verify(report)

    def test_12_no_operational_promotion(self):

        report = engine.evaluate(thesis_example())

        self.assertEqual(report["a6"], "ND")
        self.assertIsNone(report["confirmed_rf"])
        self.assertIsNone(report["published_generation"])

        self.assertFalse(
            report["technical_truth_accredited"]
        )

        self.assertFalse(
            report["operational_authority"]
        )

        altered = thesis_example()
        altered["scope"] = "OPERATIONAL"

        with self.assertRaises(ValueError):
            engine.evaluate(altered)


if __name__ == "__main__":
    unittest.main()
