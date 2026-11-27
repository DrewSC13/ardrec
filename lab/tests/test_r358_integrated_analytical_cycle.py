"""R358 integrated analytical cycle regression tests."""

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from ardrec.analytics.exact_preview import digest
from ardrec.coordination import integrated_analytical_cycle as engine
from test_r279_evidence_revision import source, revision, thesis_example


class IntegratedAnalyticalCycleTests(unittest.TestCase):

    def evaluate(self, sources):
        return engine.evaluate(sources, digest(sources))

    def positive_trajectory(self):
        return [
            source(),
            source([revision("R01")]),
        ]

    def test_01_exact_thesis_trajectory(self):
        sources = [
            source(),
            source([revision("R01")]),
            thesis_example(),
        ]

        result = self.evaluate(sources)

        self.assertEqual(
            result["generations"][0]["analysis"]["recalibrated_risk"],
            "1/2",
        )

        self.assertEqual(
            result["generations"][-1]["analysis"]["recalibrated_risk"],
            "19/36",
        )

        self.assertTrue(
            engine.verify(result, sources, digest(sources))
        )

    def test_02_equivalent_revision_not_new_sample(self):
        sources = self.positive_trajectory()

        sources.append(source([
            revision("R01"),
            revision("R02", previous="R01"),
        ]))

        result = self.evaluate(sources)

        first = result["generations"][1]
        second = result["generations"][2]

        self.assertEqual(
            first["semantic_projection_sha256"],
            second["semantic_projection_sha256"],
        )

        self.assertEqual(
            first["window"]["variations"],
            second["window"]["variations"],
        )

        self.assertEqual(
            second["window"]["repeated_projections"], 1
        )

    def test_03_conflict_and_explicit_model_resolution(self):
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
            "justification": "Explicit synthetic resolution",
        }

        sources = self.positive_trajectory()
        sources.append(source(revisions))
        sources.append(source(revisions, [selection]))

        result = self.evaluate(sources)

        conflict = result["generations"][2]
        resolved = result["generations"][3]

        self.assertIsNone(
            conflict["analysis"]["recalibrated_risk"]
        )

        self.assertIn(
            "MODEL_INDETERMINATE", conflict["reset_reasons"]
        )

        self.assertIn(
            "MODEL_POINT_RECOVERED", resolved["reset_reasons"]
        )

        self.assertEqual(
            resolved["window"]["variations"], []
        )

        self.assertEqual(
            resolved["guard"]["value"], "FALSO"
        )

    def test_04_revision_rewrite_rejected(self):
        sources = self.positive_trajectory()

        sources.append(source([
            revision("R01", dimensions=[2, 2, 4, 4]),
        ]))

        with self.assertRaisesRegex(
            ValueError, "REVISION_HISTORY_REWRITTEN"
        ):
            self.evaluate(sources)

    def test_05_frozen_context_rejected(self):
        for field, value in (
            ("unit_id", "OTHER-MODEL"),
            ("configuration_sha256", "b" * 64),
            ("baseline", {
                "exposure": 4,
                "probability": 3,
                "impact": 3,
                "context": [3, 3, 3],
            }),
        ):
            with self.subTest(field=field):
                first = source()
                second = deepcopy(first)
                second[field] = value

                with self.assertRaisesRegex(
                    ValueError, "FROZEN_CONTEXT_CHANGED"
                ):
                    self.evaluate([first, second])

    def test_06_wrong_source_pin_rejected(self):
        with self.assertRaises(ValueError):
            engine.evaluate([source()], "f" * 64)

    def test_07_resealed_false_guard_rejected(self):
        sources = self.positive_trajectory()

        result = self.evaluate(sources)
        result["generations"][-1]["guard"]["value"] = "VERDADERO"
        result.pop("sha256")
        result["sha256"] = digest(result)

        with self.assertRaisesRegex(
            ValueError, "INTEGRATED_REPLAY_MISMATCH"
        ):
            engine.verify(result, sources, digest(sources))

    def test_08_real_semantic_changes_create_window(self):
        sources = [source()]
        revisions = []

        for index in range(1, 5):
            revisions.append(revision(
                "R" + str(index),
                condition="C" + str(index),
            ))

            sources.append(source(deepcopy(revisions)))

        result = self.evaluate(sources)
        final = result["generations"][-1]

        self.assertEqual(
            final["window"]["variations"], ["0", "0", "0"]
        )

        self.assertTrue(final["window"]["window_stable"])

        self.assertEqual(
            final["ordinary_criteria"]["CV"], "ND"
        )

        self.assertIsNone(final["closure_candidate"])

    def test_09_archive_all_generations_reopen(self):
        sources = [
            source(),
            source([revision("R01")]),
            thesis_example(),
        ]

        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / "analytical"

            receipt = engine.persist(
                archive, sources, digest(sources)
            )

            self.assertEqual(
                len(receipt["snapshot_sha256"]), 3
            )

            self.assertTrue(
                engine.verify_archive(
                    archive,
                    receipt,
                    sources,
                    digest(sources),
                    receipt["sha256"],
                )
            )

            wrong = deepcopy(receipt)
            wrong["snapshot_sha256"][2] = (
                wrong["snapshot_sha256"][0]
            )
            wrong.pop("sha256")
            wrong["sha256"] = digest(wrong)

            with self.assertRaises(ValueError):
                engine.verify_archive(
                    archive,
                    wrong,
                    sources,
                    digest(sources),
                    wrong["sha256"],
                )

    def test_10_no_operational_promotion(self):
        result = self.evaluate(
            self.positive_trajectory()
        )

        self.assertFalse(result["operational_authority"])
        self.assertFalse(result["technical_truth_accredited"])
        self.assertEqual(result["physical_attempts"], 0)
        self.assertIsNone(result["confirmed_rf"])
        self.assertIsNone(result["published_generation"])
        self.assertEqual(result["experimental_admitted"], 0)

        for generation in result["generations"]:
            self.assertEqual(generation["a6"], "ND")
            self.assertEqual(generation["guard"]["value"], "FALSO")
            self.assertIsNone(generation["applied_transition"])

        self.assertEqual(result["p8"], "NO-GO")


if __name__ == "__main__":
    unittest.main()
