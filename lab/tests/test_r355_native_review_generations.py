"""R355: synthetic generation and persistent semantic review tests."""

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_r276_native_pilot_archive as fixtures

from ardrec.analytical import ObjectReference
from ardrec.analytical_references import (
    ROLES, canonical, decode, resolve_references,
)
from ardrec.contracts import ND
from ardrec.coordination import (
    pilot_analytical_archive as engine,
    pilot_observation,
    prospective_local_pilot as durable,
)
from ardrec.coordination.native_review_semantics import (
    ReviewSemanticError,
    verify_review_semantics,
)
from ardrec.persistence.analytical_archive import (
    AnalyticalArchive, digest,
)


def synthetic_observation(review):
    """Synthetic fixture; never an accredited technical observation."""
    rows = []

    for unit in review["units"]:
        uid = unit["unit_id"]
        observed = uid in engine.CONTROLS

        i3 = None
        i6 = None

        if observed:
            i3 = {
                "status": "DEVELOPMENT_OBSERVATION",
                "unit_id": uid,
                "instance_id": unit["instance_id"],
                "plan_sha256": unit["plan_sha256"],
                "read_bytes": 35,
                "control_read_verified": True,
                "restricted_comparison_verified": False,
                "experimental_admission": False,
            }

            i6 = {
                "status": "FUNCTIONAL_RECEIPT_LINKED",
                "client_invocations": 1,
                "operational_attempt_admitted": False,
                "automatic_retry": False,
            }

        rows.append({
            "unit_id": uid,
            "protocol": unit["protocol"],
            "family_id": unit["family_id"],
            "profile": unit["profile"],
            "native_phase": "PREPARADO",
            "initial_risk": unit["initial_risk_candidate"],
            "hypothetical_rf_interval":
                unit["hypothetical_rf_interval"],
            "i3": i3,
            "i6": i6,
            "i7": [
                {
                    "support": name,
                    "status": pilot_observation.support_status(
                        name, observed
                    ),
                    "operationally_accredited": False,
                }
                for name in unit["required_supports"]
            ],
            "a6": "ND",
            "confirmed_rf": None,
            "a8": {
                "recommendation": unit["a8"],
                "applied_transition": None,
            },
            "a9": "NOT_PUBLISHED",
            "formal_pilot_admitted": False,
            "experimental_admitted": False,
        })

    return durable.seal({
        "schema": pilot_observation.SCHEMA,
        "scope": "SYNTHETIC_TEST_FIXTURE_ONLY",
        "controller_sha256": review["sha256"],
        "units": rows,
        "observations_verified": 3,
        "operational_supports_accredited": 0,
        "confirmed_rf_count": 0,
        "operational_a9_publications": 0,
        "formal_pilot_admitted": 0,
        "experimental_admitted": 0,
        "p8": "NO-GO",
    })


class NativeReviewGenerationTests(unittest.TestCase):

    def setUp(self):
        self.review = fixtures.PilotArchiveTests().review()
        self.observation = synthetic_observation(self.review)

    def snapshots(self):
        return (
            engine.build_snapshot(self.review, None, 0),
            engine.build_snapshot(
                self.review, self.observation, 1
            ),
        )

    def resolve(self, snapshot):
        projections, manifest, objects = snapshot

        return resolve_references(
            projections,
            manifest,
            expected_manifest_sha256=digest(manifest),
            load_object=objects.__getitem__,
        )

    def mutation(self, snapshot, role, change):
        projections, manifest_raw, objects = snapshot

        projections = list(projections)
        objects = dict(objects)
        manifest = decode(manifest_raw)

        p = projections[0]

        binding = next(
            b for b in manifest["bindings"]
            if b["service_scenario_id"]
                == p.service_scenario_id
            and b["role"] == role
        )

        original = binding["sha256"]
        obj = decode(objects[original])

        change(obj)

        raw = canonical(obj)
        pin = digest(raw)

        del objects[original]
        objects[pin] = raw
        binding["sha256"] = pin

        refs = list(p.references)

        refs[ROLES.index(role) - 1] = ObjectReference(
            binding["reference"], pin
        )

        projections[0] = replace(
            p, references=tuple(refs)
        )

        return (
            tuple(projections),
            canonical(manifest),
            objects,
        )

    def test_01_generation_pair_and_frozen_values(self):
        first, second = self.snapshots()

        for generation, snapshot in enumerate((first, second)):
            projections, _, objects = snapshot

            self.assertEqual(len(projections), 6)
            self.assertEqual(len(objects), 42)

            verify_review_semantics(
                projections,
                self.resolve(snapshot),
                self.review,
                self.observation if generation else None,
                generation,
            )

        for previous, current in zip(first[0], second[0]):
            self.assertEqual(previous.frozen, current.frozen)

            self.assertIsInstance(
                current.analysis.recalibrated_risk, ND
            )

            self.assertIsNone(current.analysis.priority)

    def test_02_generation_one_observation_boundary(self):
        _, second = self.snapshots()

        counters = [
            decode(raw)
            for raw in second[2].values()
            if decode(raw)["role"] == "execution_counters"
        ]

        self.assertEqual(len(counters), 6)

        observed = sum(
            obj["payload"]["development_observations"]
            for obj in counters
        )

        self.assertEqual(observed, 3)

        for obj in counters:
            self.assertEqual(
                obj["payload"]["operational_attempts"], 0
            )

    def test_03_native_persist_reopen_and_revalidate(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "archive"

            with patch.object(
                engine,
                "verify_review_semantics",
                wraps=verify_review_semantics,
            ) as gate:

                report = engine.persist_review_pair(
                    path, self.review, self.observation
                )

                self.assertEqual(gate.call_count, 4)

                self.assertEqual(
                    [call.args[-1] for call in gate.call_args_list],
                    [0, 1, 0, 1],
                )

            self.assertEqual(report["review_snapshots"], 2)

            self.assertEqual(
                report["native_reference_bindings_verified"], 84
            )

            self.assertEqual(
                report["operational_a9_publications"], 0
            )

            self.assertFalse(report["operational_dispatch"])

            with AnalyticalArchive(path) as archive:

                for generation, pin in enumerate(
                    report["snapshot_sha256"]
                ):
                    recovered = archive.load(pin)

                    verify_review_semantics(
                        recovered.projections,
                        recovered.references,
                        self.review,
                        self.observation if generation else None,
                        generation,
                    )

    def test_04_stale_mutable_role_rejected(self):
        _, second = self.snapshots()

        def make_stale(obj):
            obj["context"]["generation_index"] = 0

        changed = self.mutation(
            second, "pending_controls", make_stale
        )

        resolved = self.resolve(changed)

        with self.assertRaisesRegex(
            ReviewSemanticError,
            "STALE_OR_FUTURE_ROLE",
        ):
            verify_review_semantics(
                changed[0], resolved,
                self.review, self.observation, 1,
            )

    def test_05_rehashed_invalid_content_after_reopen(self):
        _, second = self.snapshots()

        def promote_objective(obj):
            obj["payload"][
                "technical_objective_accredited"
            ] = True

        changed = self.mutation(
            second, "objective_status", promote_objective
        )

        projections, manifest, objects = changed

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "archive"

            # Structural storage accepts consistent hashes.
            with AnalyticalArchive(path, create=True) as archive:
                pin = archive.store(
                    projections,
                    manifest,
                    expected_manifest_sha256=digest(manifest),
                    load_object=objects.__getitem__,
                )

            # Semantic verification must still reject the object.
            with AnalyticalArchive(path) as archive:
                recovered = archive.load(pin)

                with self.assertRaisesRegex(
                    ReviewSemanticError,
                    "SEMANTIC_MISMATCH",
                ):
                    verify_review_semantics(
                        recovered.projections,
                        recovered.references,
                        self.review,
                        self.observation,
                        1,
                    )

    def test_06_foreign_observation_source_rejected(self):
        _, second = self.snapshots()

        changed = {
            k: v for k, v in self.observation.items()
            if k != "sha256"
        }

        changed["controller_sha256"] = "f" * 64
        changed = durable.seal(changed)

        with self.assertRaises(ReviewSemanticError):
            verify_review_semantics(
                second[0],
                self.resolve(second),
                self.review,
                changed,
                1,
            )


if __name__ == "__main__":
    unittest.main()
