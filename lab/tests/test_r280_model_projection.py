"""R280 source-bound model acceptance tests."""

from dataclasses import replace
from fractions import Fraction as F
from pathlib import Path
import tempfile
import unittest

from ardrec.analytical import (
    AnalysisValues,
    check_frozen_compatibility,
)

from ardrec.contracts import ND

from ardrec.evidence import evidence_revision as revisions

from ardrec.analytics import model_projection as engine

from ardrec.persistence.analytical_archive import (
    AnalyticalArchive,
)

from test_r279_evidence_revision import (
    thesis_example,
    source,
    revision,
)


class ModelProjectionTests(unittest.TestCase):

    def setUp(self):

        self.report = revisions.evaluate(
            thesis_example()
        )

        self.pin = self.report["sha256"]

        projections, _, _ = engine.build_snapshot(
            self.report,
            self.pin,
        )

        self.projection = projections[0]

    def test_01_exact_source_magnitudes(self):

        a = self.projection.analysis

        self.assertEqual(
            self.projection.frozen.initial_risk,
            F(1, 2),
        )

        self.assertEqual(
            a.accumulated_evidence,
            F(3, 4),
        )

        self.assertEqual(
            a.substituted_baseline,
            F(1, 3),
        )

        self.assertEqual(
            a.recalibrated_risk,
            F(19, 36),
        )

        self.assertEqual(
            a.priority,
            F(7, 12),
        )

    def test_02_structurally_valid_false_point_rejected(self):

        # This alternative satisfies the structural
        # bounds and risk identity, but contradicts
        # the underlying R279 evidence report.

        wrong = replace(
            self.projection,
            analysis=AnalysisValues(
                accumulated_evidence=F(0),
                substituted_baseline=F(1, 2),
                upper_bound=F(1, 2),
                lower_adjustment_bound=F(1, 2),
                recalibrated_risk=F(1, 2),
                priority=F(1, 3),
            ),
        )

        with self.assertRaises(ValueError):

            engine.verify_projection(
                wrong,
                self.report,
                self.pin,
            )

    def test_03_wrong_source_pin_rejected(self):

        with self.assertRaises(ValueError):

            engine.build_snapshot(
                self.report,
                "b" * 64,
            )

    def test_04_cross_context_rejected(self):

        for changes in (
            {"service_scenario_id": "OTHER-UNIT"},
            {"configuration_sha256": "b" * 64},
            {"generation_index": 1},
        ):

            with self.subTest(changes=changes):

                with self.assertRaises(ValueError):

                    engine.verify_projection(
                        replace(
                            self.projection,
                            **changes,
                        ),
                        self.report,
                        self.pin,
                    )

    def test_05_unknown_evidence_remains_nd(self):

        conflict = revisions.evaluate(source([
            revision("R01"),
            revision(
                "R02",
                previous="R01",
                classification="NEGATIVO_VALIDO",
            ),
        ]))

        projections, _, _ = engine.build_snapshot(
            conflict,
            conflict["sha256"],
        )

        result = projections[0]

        self.assertIsInstance(
            result.analysis.accumulated_evidence,
            ND,
        )

        self.assertIsInstance(
            result.analysis.recalibrated_risk,
            ND,
        )

    def test_06_prepared_priority_is_empty(self):

        projections, _, _ = engine.build_snapshot(
            self.report,
            self.pin,
            phase="PREPARADO",
        )

        self.assertIsNone(
            projections[0].analysis.priority
        )

    def test_07_archive_reopen_and_frozen_values(self):

        with tempfile.TemporaryDirectory() as folder:

            path = Path(folder) / "archive"

            with AnalyticalArchive(
                path, create=True
            ) as archive:

                pin0 = engine.store_review(
                    archive,
                    self.report,
                    self.pin,
                    generation=0,
                )

                pin1 = engine.store_review(
                    archive,
                    self.report,
                    self.pin,
                    generation=1,
                )

                first = archive.load(pin0)
                second = archive.load(pin1)

                check_frozen_compatibility(
                    first.projections[0],
                    second.projections[0],
                )

                self.assertNotEqual(pin0, pin1)

                self.assertEqual(
                    engine.store_review(
                        archive,
                        self.report,
                        self.pin,
                    ),
                    pin0,
                )

            with AnalyticalArchive(path) as archive:

                self.assertTrue(
                    engine.verify_recovered(
                        archive.load(pin1),
                        self.report,
                        self.pin,
                        generation=1,
                    )
                )

    def test_08_resealed_false_risk_rejected(self):

        self.report["analysis"][
            "recalibrated_risk"
        ] = "1"

        self.report.pop("sha256")

        self.report["sha256"] = revisions.digest(
            self.report
        )

        with self.assertRaises(ValueError):

            engine.build_snapshot(
                self.report,
                self.report["sha256"],
            )


if __name__ == "__main__":
    unittest.main()
