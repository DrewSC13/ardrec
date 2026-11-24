"""Synthetic vertical tests of exact risk and native durable publication.

No physical evidence accreditation, guest execution, experimental
admission or operational authority is asserted.
"""

from dataclasses import replace
from fractions import Fraction as F
from pathlib import Path
import json
import tempfile
import unittest

from ardrec.analytics.exact_preview import (
    preview_bounds,
    verify_bounds,
)

from ardrec.analytical import (
    AnalysisValues,
    ObjectReference,
    AnalyticalError,
)

from ardrec.analytical_references import (
    ROLES,
    OBJECT_FORMAT,
    MANIFEST_FORMAT,
    canonical,
)

from ardrec.coordination.r58e_evidence_risk_bridge import (
    build_unit_bridge,
    verify_unit_bridge,
)

from ardrec.evidence import r58h_ssh_family_logic as family
from ardrec.experiments import initial_assessment as initial
from ardrec.experiments import parameter_sensitivity as sensitivity

from ardrec.persistence import DurableStore
from ardrec.persistence.analytical_archive import (
    AnalyticalArchive,
    digest,
)
from ardrec.persistence.codec import StorageError

from ardrec.state import ServicePhase, Transition

from test_analytical_references import fixture
from test_persistence import INITIAL, context, reserve, outcome


WEIGHTS = ("1/3", "1/3", "1/3")
BETA = ("1/2", "1/2")

CALCULATED = initial.compute(
    2, 2, 2, (3, 3, 3)
)

R0 = CALCULATED["initial_risk"]
CN = CALCULATED["normalized_criticality"]


def model_case(*, unresolved=False, negative=False):

    spec = next(
        item for item in family.load_pinned_catalog()
        if item["id"] == "SSH-T06"
    )

    unit = {
        "family_id": spec["id"],
        "derived_case_id": "SSH-T06-S01-01",
        "assessment_index": 0,
        "session_id": "R236_SYNTHETIC",
        "phase": "PENDIENTE",
        "preconditions": {
            name: "VERDADERO"
            for name in spec["preconditions"]
        },
        "supports": {
            name: "VERDADERO"
            for name in spec["required_supports"]
        },
        "integrity": "VERDADERO",
        "provenance": "VERDADERO",
        "cleanup": "NO_APLICA",
        "outcome": (
            "OBSERVADO_NEGATIVO"
            if negative else "OBSERVADO_POSITIVO"
        ),
    }

    if unresolved:
        unit["supports"]["KNOWN_CONTENT_DIGEST"] = "ND"

    report = family.build_ssh_simulation([unit])

    if not family.verify_ssh_simulation(report):
        raise ValueError("FAMILY_REPLAY_INVALID")

    return report


def synthetic_math(dimensions):

    contributions = [
        sensitivity.contribution(item, BETA, BETA)
        for item in dimensions
    ]

    report = preview_bounds(
        R0,
        CN,
        [str(value) for value in contributions],
        R0,
        WEIGHTS,
    )

    if not verify_bounds(report):
        raise ValueError("ORACLE_REPLAY_INVALID")

    return report


def store_snapshot(archive, state, generation, *,
                   model=None, math=None, altered=False):

    template, _, _ = fixture()

    ctx = {
        "record_id": state.confirmed.record_id,
        "execution_id": state.execution_id,
        "configuration_sha256":
            state.confirmed.configuration_sha256,
        "generation_index": generation,
    }

    projections = []
    bindings = []
    objects = {}

    for service in sorted(
        state.services,
        key=lambda item: item.service_scenario_id,
    ):

        sid = service.service_scenario_id

        active_math = (
            math
            if sid == "S01" and math is not None
            else synthetic_math([])
        )

        refs = {}

        for role in ROLES:

            ref = sid + "-" + role

            origin = {
                **ctx,
                "generation_index": (
                    0 if role == "characterization"
                    else generation
                ),
            }

            payload = {
                "synthetic": True,
                "physical_authority": False,
                "experimental_admission": False,
            }

            if role == "characterization":

                payload["initial"] = CALCULATED

            elif role == "evidence_repository":

                payload["family_model"] = (
                    model if sid == "S01" else None
                )

                payload["risk_oracle"] = active_math

            elif role == "history":

                payload["hypothetical_rf"] = (
                    active_math["hypothetical_rf"]
                )

            raw = canonical({
                "format": OBJECT_FORMAT,
                "context": origin,
                "service_scenario_id": sid,
                "role": role,
                "reference": ref,
                "payload": payload,
            })

            sha = digest(raw)
            objects[sha] = raw

            refs[role] = ObjectReference(ref, sha)

            bindings.append({
                "service_scenario_id": sid,
                "role": role,
                "reference": ref,
                "sha256": sha,
            })

        accumulated = F(active_math["evidence_max"])
        calculated_rf = F(active_math["hypothetical_rf"])

        if altered and sid == "S01":
            calculated_rf = F(0)

        priority = (
            None if service.phase is ServicePhase.PREPARADO
            else (F(R0) + accumulated + F(CN)) / 3
        )

        projection = replace(
            template,
            **ctx,
            service_scenario_id=sid,
            operational_state=service.phase,
            frozen=replace(
                template.frozen,
                initial_risk=F(R0),
                normalized_criticality=F(CN),
                characterization=refs["characterization"],
            ),
            analysis=AnalysisValues(
                accumulated_evidence=accumulated,
                substituted_baseline=F(
                    active_math["replacement_risk"]
                ),
                upper_bound=F(active_math["upper"]),
                lower_adjustment_bound=F(active_math["lower"]),
                recalibrated_risk=calculated_rf,
                priority=priority,
            ),
            references=tuple(
                refs[role] for role in ROLES[1:]
            ),
        )

        projections.append(projection)

    manifest = canonical({
        "format": MANIFEST_FORMAT,
        "context": ctx,
        "bindings": sorted(
            bindings,
            key=lambda item: (
                item["service_scenario_id"],
                item["role"],
            ),
        ),
    })

    return archive.store(
        tuple(projections),
        manifest,
        expected_manifest_sha256=digest(manifest),
        load_object=objects.__getitem__,
    )


def reopen(path, archive, **kwargs):

    return DurableStore.open(
        path,
        record_id="REG-1",
        configuration_sha256="a" * 64,
        analytical_archive=archive,
        **kwargs,
    )


class NativeRiskPublicationTests(unittest.TestCase):

    def setUp(self):

        temporary = tempfile.TemporaryDirectory(
            prefix="ardrec-r236-synthetic-"
        )

        self.addCleanup(temporary.cleanup)

        self.root = Path(temporary.name)
        self.path = self.root / "store"

        self.archive = AnalyticalArchive(
            self.root / "archive",
            create=True,
        )

        self.addCleanup(self.archive.close)

    def start(self):

        sha = store_snapshot(
            self.archive,
            INITIAL,
            0,
        )

        store = DurableStore.create(
            self.path,
            INITIAL,
            analytical_archive=self.archive,
            snapshot_sha256=sha,
        )

        self.addCleanup(store.close)

        return store

    def prepare(self, store):

        store.transition(
            "S01",
            Transition.PREPARAR,
            context(store, Transition.PREPARAR),
        )

        sha = store_snapshot(
            self.archive,
            store.state,
            1,
        )

        store.publish_analytical(
            expected_generation=0,
            reference="GEN-1",
            event="PUB-1",
            snapshot_sha256=sha,
        )

        return sha

    def test_01_exact_initial_values(self):

        self.assertEqual(R0, "1/4")
        self.assertEqual(CN, "1/2")

    def test_02_catalog_positive_model(self):

        report = model_case()
        row = report["decisions"][0]

        self.assertEqual(
            row["hypothetical_result_class"],
            "POSITIVO_VALIDO",
        )

        self.assertEqual(row["a6_classification"], "ND")
        self.assertIsNone(row["technical_contribution"])
        self.assertFalse(row["technical_truth_accredited"])

    def test_03_negative_model_is_explicit(self):

        report = model_case(negative=True)

        self.assertEqual(
            report["decisions"][0]["hypothetical_result_class"],
            "NEGATIVO_VALIDO",
        )

        self.assertEqual(
            report["decisions"][0]["a6_classification"],
            "ND",
        )

    def test_04_missing_support_is_not_negative(self):

        report = model_case(unresolved=True)

        self.assertEqual(
            report["decisions"][0]["hypothetical_result_class"],
            "INCONCLUSO",
        )

    def test_05_exact_contribution(self):

        value = sensitivity.contribution(
            (3, 1, 4, 2), BETA, BETA
        )

        self.assertEqual(value, F(3, 8))

    def test_06_accumulation_maximum(self):

        report = synthetic_math([
            (3, 1, 4, 2),
            (2, 1, 3, 2),
        ])

        self.assertEqual(
            report["contributions"],
            ["3/8", "15/64"],
        )

        self.assertEqual(
            report["evidence_max"],
            "3/8",
        )

        self.assertEqual(
            report["hypothetical_rf"],
            "3/8",
        )

    def test_07_no_evidence_preserves_r0(self):

        report = synthetic_math([])

        self.assertEqual(
            report["hypothetical_rf"],
            "1/4",
        )

    def test_08_native_publication_and_readback(self):

        model = model_case()
        math = synthetic_math([(3, 1, 4, 2)])

        store = self.start()
        self.prepare(store)

        # Reuse native synthetic message fixtures and
        # the actual reservation/transition implementation.

        reserve(store)
        outcome(store)

        sha = store_snapshot(
            self.archive,
            store.state,
            2,
            model=model,
            math=math,
        )

        store.publish_analytical(
            expected_generation=1,
            reference="GEN-2",
            event="PUB-2",
            snapshot_sha256=sha,
        )

        self.assertEqual(
            store.state.confirmed.generation, 2
        )

        self.assertEqual(
            store.state.attempts[0].incorporation.generation,
            2,
        )

        self.assertEqual(
            store.analytical_snapshot_sha256, sha
        )

        head = store.head_sha256
        confirmed_state = store.state

        store.close()

        with reopen(
            self.path,
            self.archive,
            expected_head=head,
        ) as recovered:

            self.assertEqual(
                recovered.state, confirmed_state
            )

            self.assertEqual(
                recovered.analytical_snapshot_sha256,
                sha,
            )

            snapshot = recovered.analytical_snapshot

            projections = {
                item.service_scenario_id: item
                for item in snapshot.projections
            }

            self.assertEqual(
                projections["S01"].analysis.recalibrated_risk,
                F(3, 8),
            )

            self.assertEqual(
                projections["S02"].analysis.recalibrated_risk,
                F(1, 4),
            )

            self.assertEqual(
                projections["S01"].frozen.initial_risk,
                F(1, 4),
            )

            referenced = [
                json.loads(raw)
                for raw in snapshot.references.object_bytes
            ]

            record = next(
                item for item in referenced
                if item["service_scenario_id"] == "S01"
                and item["role"] == "evidence_repository"
            )

            self.assertEqual(
                record["payload"]["family_model"],
                model,
            )

            self.assertEqual(
                record["payload"]["risk_oracle"],
                math,
            )

            self.assertTrue(
                record["payload"]["synthetic"]
            )

            self.assertFalse(
                record["payload"]["physical_authority"]
            )

            self.assertEqual(
                recovered.recovery_action, "NONE"
            )

            before = recovered.head_sha256

            with self.assertRaises(StorageError):

                recovered.publish_analytical(
                    expected_generation=1,
                    reference="GEN-2",
                    event="PUB-2",
                    snapshot_sha256=sha,
                )

            self.assertEqual(
                recovered.head_sha256, before
            )

        print(
            "SYNTHETIC_NATIVE_GENERATIONS=3",
            flush=True,
        )

        print(
            "SYNTHETIC_MATHEMATICAL_READBACK=3/8",
            flush=True,
        )

        print(
            "NATIVE_DUPLICATE_PUBLICATION_REJECTED=YES",
            flush=True,
        )

    def test_09_unknown_evidence_not_published_as_zero(self):

        store = self.start()
        self.prepare(store)

        before = store.head_sha256

        bridge = build_unit_bridge(
            [{
                "service_id": "SSH_DEV",
                "case_id": "SSH-01",
                "assessment_index": 0,
                "initial_risk": R0,
                "normalized_criticality": CN,
                "replacement_risk": R0,
                "evidence": [],
            }],
            [],
            weights=WEIGHTS,
        )

        self.assertTrue(
            verify_unit_bridge(bridge)
        )

        interval = bridge["a7"]["results"][0]
        decision = bridge["decisions"][0]

        self.assertEqual(
            interval["evidence_lower"], "0"
        )

        self.assertEqual(
            interval["evidence_upper"], "1"
        )

        self.assertIsNone(
            decision["confirmed_rf"]
        )

        self.assertIsNone(
            bridge["published_generation"]
        )

        self.assertEqual(
            decision["a8_recommendation"],
            "PAUSAR_HASTA_EVIDENCIA_AUTORIZADA",
        )

        self.assertEqual(
            store.head_sha256, before
        )

    def test_10_inconsistent_projection_rejected(self):

        store = self.start()
        before = store.head_sha256

        with self.assertRaises(AnalyticalError):

            store_snapshot(
                self.archive,
                store.state,
                1,
                math=synthetic_math([(3, 1, 4, 2)]),
                altered=True,
            )

        self.assertEqual(
            store.head_sha256, before
        )

    def test_11_invalid_dimensions_rejected(self):

        with self.assertRaises(ValueError):

            synthetic_math([(5, 1, 4, 2)])

    def test_12_no_operational_claim(self):

        model = model_case()
        math = synthetic_math([(3, 1, 4, 2)])

        self.assertIsNone(
            model["published_generation"]
        )

        self.assertIsNone(
            math["confirmed_rf"]
        )

        self.assertIsNone(
            math["published_generation"]
        )

        self.assertEqual(
            math["p8_operational"],
            "NO-GO",
        )


if __name__ == "__main__":
    unittest.main()
