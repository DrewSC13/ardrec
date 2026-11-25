"""Tests of review snapshots, exact ND and reference integrity."""

from pathlib import Path
import tempfile
import unittest

from ardrec.contracts import ND

from ardrec.coordination import (
    pilot_analytical_archive as engine,
    pilot_controller,
    prospective_local_pilot as durable,
)

from ardrec.persistence.codec import pack

from ardrec.analytical_references import (
    ReferenceError,
    resolve_references,
)

from ardrec.persistence.analytical_archive import (
    AnalyticalArchive,
    digest,
)


class PilotArchiveTests(unittest.TestCase):

    def review(self):

        state = pilot_controller.native_state(
            "a" * 64,
            sorted(engine.UNITS),
        )

        units = []

        for uid in sorted(engine.UNITS):

            protocol = uid.split("-")[1]

            units.append({
                "unit_id": uid,
                "protocol": protocol,
                "profile": (
                    "CONTROL"
                    if uid.endswith("-01")
                    else "CONTRAST"
                ),
                "family_id":
                    pilot_controller.FAMILIES[protocol],
                "instance_id": uid + "-SYNTHETIC",
                "plan_sha256": "b" * 64,
                "native_state": "PREPARADO",
                "baseline_closed": False,
                "physical_dispatch_allowed": False,
                "initial_risk_candidate": "1/4",
                "normalized_criticality": "0",
                "hypothetical_rf_interval":
                    ["1/4", "5/12"],
                "required_supports": [
                    "TARGET_ATTESTATION",
                    "INTEGRITY_PROVENANCE",
                    "RESOURCE_READ",
                    "KNOWN_CONTENT_DIGEST",
                ],
                "a6": "ND",
                "confirmed_rf": None,
                "a8":
                    "PAUSAR_HASTA_EVIDENCIA_AUTORIZADA",
                "a9": "NOT_PUBLISHED",
                "blockers": list(
                    pilot_controller.BLOCKERS
                ),
            })

        return durable.seal({
            "schema": pilot_controller.SCHEMA,
            "source_sha256": "a" * 64,
            "native_review_state": pack(state),
            "units": units,
            "operational_dispatch": False,
            "operational_a9_publications": 0,
            "p8": "NO-GO",
        })

    def snapshot(self):

        return engine.build_snapshot(
            self.review(), None, 0
        )

    def test_01_complete_native_reference_set(self):

        projections, _, objects = self.snapshot()

        self.assertEqual(len(projections), 6)
        self.assertEqual(len(objects), 42)

    def test_02_unknown_not_zero(self):

        projections, _, _ = self.snapshot()

        for projection in projections:

            self.assertIsInstance(
                projection.analysis.recalibrated_risk,
                ND,
            )

            self.assertIsInstance(
                projection.analysis.accumulated_evidence,
                ND,
            )

            self.assertIsNone(
                projection.analysis.priority
            )

    def test_03_invalid_generation(self):

        with self.assertRaises(ValueError):

            engine.build_snapshot(
                self.review(), None, 2
            )

    def test_04_missing_observation(self):

        with self.assertRaises(ValueError):

            engine.build_snapshot(
                self.review(), None, 1
            )

    def test_05_operational_promotion_rejected(self):

        review = self.review()

        review = {
            key: value
            for key, value in review.items()
            if key != "sha256"
        }

        review["operational_dispatch"] = True

        with self.assertRaises(ValueError):

            engine.build_snapshot(
                durable.seal(review), None, 0
            )

    def test_06_missing_reference_rejected(self):

        projections, manifest, objects = self.snapshot()

        missing = next(iter(objects))
        del objects[missing]

        def load(pin):

            if pin not in objects:
                raise FileNotFoundError(pin)

            return objects[pin]

        with self.assertRaises(ReferenceError):

            resolve_references(
                projections,
                manifest,
                expected_manifest_sha256=digest(manifest),
                load_object=load,
            )

    def test_07_cross_reference_rejected(self):

        projections, manifest, objects = self.snapshot()

        first, second = list(objects)[:2]

        objects[first] = objects[second]

        with self.assertRaises(ReferenceError):

            resolve_references(
                projections,
                manifest,
                expected_manifest_sha256=digest(manifest),
                load_object=objects.__getitem__,
            )

    def test_08_archive_reopen_and_idempotence(self):

        snapshot = self.snapshot()

        projections, manifest, objects = snapshot

        with tempfile.TemporaryDirectory() as folder:

            path = Path(folder) / "archive"

            with AnalyticalArchive(
                path, create=True
            ) as archive:

                args = {
                    "expected_manifest_sha256":
                        digest(manifest),
                    "load_object":
                        objects.__getitem__,
                }

                pin = archive.store(
                    projections, manifest, **args
                )

                self.assertEqual(
                    archive.store(
                        projections, manifest, **args
                    ),
                    pin,
                )

            with AnalyticalArchive(path) as archive:

                result = engine.verify_readback(
                    archive, pin, snapshot
                )

                self.assertEqual(
                    result.projections, projections
                )


if __name__ == "__main__":
    unittest.main()
