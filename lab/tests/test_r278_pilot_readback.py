"""A10 semantic source checks and A8 input ownership."""

import copy
import tempfile
import unittest

from pathlib import Path

import test_r276_native_pilot_archive as fixtures

from ardrec.coordination import (
    pilot_readback as engine,
    prospective_local_pilot as durable,
)

from ardrec.persistence.analytical_archive import (
    AnalyticalArchive,
    digest,
)

from ardrec.stopping import ordinary_closure as a8


class PilotReadbackTests(unittest.TestCase):

    def setUp(self):

        self.temporary = tempfile.TemporaryDirectory()

        self.addCleanup(self.temporary.cleanup)

        self.path = Path(self.temporary.name) / "archive"

        self.source = fixtures.PilotArchiveTests().snapshot()

        projections, manifest, objects = self.source

        with AnalyticalArchive(
            self.path, create=True
        ) as archive:

            pin = archive.store(
                projections,
                manifest,
                expected_manifest_sha256=digest(manifest),
                load_object=objects.__getitem__,
            )

            self.snapshot = archive.load(pin)

        self.archive_report = {
            "sha256": "a" * 64,
        }

        self.payloads = engine.index_payloads(
            self.snapshot
        )

    def report(self):

        return engine.reconstruct_closure_report(
            self.snapshot,
            self.archive_report,
        )

    def test_01_all_sources_reconstructed(self):

        report = self.report()

        self.assertEqual(len(self.payloads), 42)
        self.assertEqual(report["units_evaluated"], 6)
        self.assertEqual(
            report["ordinary_criteria_evaluated"], 24
        )

        self.assertEqual(
            engine.verify_closure_report(
                self.snapshot,
                self.archive_report,
                report,
            ),
            report,
        )

    def test_02_resealed_wrong_source_rejected(self):

        report = self.report()

        report.pop("sha256")
        report["source_r276_sha256"] = "b" * 64

        report = durable.seal(report)

        with self.assertRaises(ValueError):

            engine.verify_closure_report(
                self.snapshot,
                self.archive_report,
                report,
            )

    def test_03_resealed_criterion_change_rejected(self):

        report = self.report()

        report.pop("sha256")
        report["records"][0]["a8"]["criteria"]["LE"] = (
            "VERDADERO"
        )

        report = durable.seal(report)

        with self.assertRaises(ValueError):

            engine.verify_closure_report(
                self.snapshot,
                self.archive_report,
                report,
            )

    def test_04_operational_counter_promotion_rejected(self):

        projection = self.snapshot.projections[0]
        uid = projection.service_scenario_id

        payloads = copy.deepcopy(self.payloads)

        payloads[(uid, "execution_counters")][
            "operational_attempts"
        ] = 1

        with self.assertRaises(ValueError):

            engine.evaluate_archived_unit(
                projection, payloads
            )

    def test_05_false_convergence_rejected(self):

        projection = self.snapshot.projections[0]
        uid = projection.service_scenario_id

        payloads = copy.deepcopy(self.payloads)

        payloads[(uid, "convergence_window")][
            "confirmed_samples"
        ] = ["1/4"] * 4

        with self.assertRaises(ValueError):

            engine.evaluate_archived_unit(
                projection, payloads
            )

    def test_06_objective_promotion_rejected(self):

        projection = self.snapshot.projections[0]
        uid = projection.service_scenario_id

        payloads = copy.deepcopy(self.payloads)

        payloads[(uid, "objective_status")][
            "technical_objective_accredited"
        ] = True

        with self.assertRaises(ValueError):

            engine.evaluate_archived_unit(
                projection, payloads
            )

    def test_07_a8_history_owned_by_report(self):

        facts = {
            name: "ND"
            for name in a8.FACTS
        }

        history = [{
            "event_id": "TEST-EVENT",
            "projection_sha256": "a" * 64,
            "risk": "1/4",
            "reset": False,
        }]

        report = a8.evaluate(
            facts=facts,
            history=history,
            executions=0,
            budget=None,
            phase="PREPARADO",
        )

        history[0]["risk"] = "1/3"
        facts["safety_clear"] = "VERDADERO"

        self.assertEqual(
            report["inputs"]["history"][0]["risk"],
            "1/4",
        )

        self.assertTrue(a8.verify(report))

    def test_08_pending_work_cannot_be_ignored(self):

        projection = self.snapshot.projections[0]
        uid = projection.service_scenario_id

        payloads = copy.deepcopy(self.payloads)

        payloads[(uid, "pending_controls")][
            "blockers"
        ] = []

        with self.assertRaises(ValueError):

            engine.evaluate_archived_unit(
                projection, payloads
            )


if __name__ == "__main__":
    unittest.main()
