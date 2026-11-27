"""R354: semantic consistency and rehashed-object rejection."""

from dataclasses import replace
import unittest

import test_r276_native_pilot_archive as fixtures

from ardrec.analytical import ObjectReference
from ardrec.analytical_references import (
    ROLES,
    canonical,
    decode,
    resolve_references,
)
from ardrec.coordination import pilot_analytical_archive as engine
from ardrec.coordination.native_review_semantics import (
    ReviewSemanticError,
    verify_review_semantics,
)
from ardrec.persistence.analytical_archive import digest


class NativeReviewSemanticTests(unittest.TestCase):

    def setUp(self):
        self.review = fixtures.PilotArchiveTests().review()

        self.projections, self.manifest, self.objects = (
            engine.build_snapshot(self.review, None, 0)
        )

    def resolve(self, projections, manifest, objects):
        return resolve_references(
            projections,
            manifest,
            expected_manifest_sha256=digest(manifest),
            load_object=objects.__getitem__,
        )

    def test_valid_native_snapshot(self):
        resolved = self.resolve(
            self.projections,
            self.manifest,
            self.objects,
        )

        verify_review_semantics(
            self.projections,
            resolved,
            self.review,
            None,
            0,
        )

    def rehashed_payload(self, role, field, value):
        manifest = decode(self.manifest)

        uid = self.projections[0].service_scenario_id

        binding = next(
            b for b in manifest["bindings"]
            if b["service_scenario_id"] == uid
            and b["role"] == role
        )

        old_pin = binding["sha256"]

        obj = decode(self.objects[old_pin])
        obj["payload"][field] = value

        raw = canonical(obj)
        pin = digest(raw)

        binding["sha256"] = pin

        objects = dict(self.objects)
        del objects[old_pin]
        objects[pin] = raw

        projections = list(self.projections)
        p = projections[0]

        ref = ObjectReference(binding["reference"], pin)

        if role == "characterization":
            projections[0] = replace(
                p,
                frozen=replace(
                    p.frozen,
                    characterization=ref,
                ),
            )

        else:
            refs = list(p.references)
            refs[ROLES.index(role) - 1] = ref

            projections[0] = replace(
                p, references=tuple(refs)
            )

        projections = tuple(projections)

        manifest_raw = canonical(manifest)

        # Structural verification must succeed first.
        resolved = self.resolve(
            projections, manifest_raw, objects
        )

        return projections, resolved

    def test_rehashed_semantic_promotions(self):
        mutations = [
            (
                "characterization",
                "operational_baseline_closed",
                True,
            ),
            (
                "evidence_repository",
                "confirmed_evidence_count",
                1,
            ),
            (
                "execution_counters",
                "operational_attempts",
                1,
            ),
            (
                "objective_status",
                "technical_objective_accredited",
                True,
            ),
            (
                "history",
                "confirmed_rf",
                "1/2",
            ),
            (
                "convergence_window",
                "confirmed_samples",
                ["1/2"],
            ),
            (
                "pending_controls",
                "dispatch_allowed",
                True,
            ),
        ]

        for role, field, value in mutations:
            with self.subTest(role=role):

                projections, resolved = (
                    self.rehashed_payload(role, field, value)
                )

                with self.assertRaisesRegex(
                    ReviewSemanticError,
                    "SEMANTIC_MISMATCH",
                ):
                    verify_review_semantics(
                        projections,
                        resolved,
                        self.review,
                        None,
                        0,
                    )

    def test_false_is_not_integer_zero(self):
        projections, resolved = self.rehashed_payload(
            "pending_controls",
            "dispatch_allowed",
            0,
        )

        with self.assertRaises(ReviewSemanticError):
            verify_review_semantics(
                projections,
                resolved,
                self.review,
                None,
                0,
            )

    def test_changed_characterization_identity(self):
        projections, resolved = self.rehashed_payload(
            "characterization",
            "instance_id",
            "FOREIGN-SYNTHETIC-INSTANCE",
        )

        with self.assertRaises(ReviewSemanticError):
            verify_review_semantics(
                projections,
                resolved,
                self.review,
                None,
                0,
            )

    def test_missing_observation_rejected(self):
        resolved = self.resolve(
            self.projections,
            self.manifest,
            self.objects,
        )

        with self.assertRaises(ReviewSemanticError):
            verify_review_semantics(
                self.projections,
                resolved,
                self.review,
                None,
                1,
            )


if __name__ == "__main__":
    unittest.main()
