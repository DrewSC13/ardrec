"""R379 regression suite; exclusively synthetic fixtures."""

from copy import deepcopy
from dataclasses import replace
from fractions import Fraction
from pathlib import Path
import tempfile
import unittest

from ardrec.analytical import (
    AnalyticalProjection,
    AnalysisValues,
    FrozenValues,
    ObjectReference,
)
from ardrec.analytical_references import (
    ROLES,
    OBJECT_FORMAT,
    MANIFEST_FORMAT,
    canonical,
)
from ardrec.contracts import ND
from ardrec.state import ServicePhase
from ardrec.persistence.analytical_archive import (
    AnalyticalArchive,
)
from ardrec.coordination import (
    native_dev_snapshot_binding as engine,
)


class NativeDevSnapshotBindingTests(unittest.TestCase):

    def setUp(self):

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.path = Path(self.tmp.name) / "archive"

        self.ctx = {
            "record_id": "DEV-RECORD",
            "execution_id": "DEV-EXECUTION",
            "configuration_sha256": "a" * 64,
            "generation_index": 1,
        }

    def fixture(
        self,
        *,
        stale=False,
        promoted=False,
    ):

        objects = {}
        bindings = []
        projections = []
        characterizations = []

        baseline = ND("BASELINE_NOT_CLOSED")
        evidence = ND("EVIDENCE_NOT_ACCREDITED")

        for uid in ("DEV-01", "DEV-02"):

            refs = {}

            for role in ROLES:

                origin = dict(self.ctx)

                if role == "characterization":
                    origin["generation_index"] = 0

                if stale and role == "history":
                    origin["generation_index"] = 0

                reference = uid + ":" + role

                raw = canonical({
                    "format": OBJECT_FORMAT,
                    "context": origin,
                    "service_scenario_id": uid,
                    "role": role,
                    "reference": reference,
                    "payload": {
                        "scope": "SYNTHETIC_FIXTURE",
                        "operational_authority": False,
                    },
                })

                pin = engine.sha(raw)

                objects[pin] = raw
                refs[role] = ObjectReference(
                    reference, pin
                )

                row = {
                    "service_scenario_id": uid,
                    "role": role,
                    "reference": reference,
                    "sha256": pin,
                }

                bindings.append(row)

                if role == "characterization":

                    characterizations.append({
                        key: value
                        for key, value in row.items()
                        if key != "role"
                    })

            projection = AnalyticalProjection(
                **self.ctx,
                service_scenario_id=uid,
                operational_state=ServicePhase.PREPARADO,
                frozen=FrozenValues(
                    initial_risk=baseline,
                    normalized_criticality=baseline,
                    characterization=refs["characterization"],
                ),
                analysis=AnalysisValues(
                    accumulated_evidence=evidence,
                    substituted_baseline=baseline,
                    upper_bound=evidence,
                    lower_adjustment_bound=baseline,
                    recalibrated_risk=evidence,
                    priority=None,
                ),
                references=tuple(
                    refs[role] for role in ROLES[1:]
                ),
            )

            if promoted:

                projection = replace(
                    projection,
                    analysis=replace(
                        projection.analysis,
                        recalibrated_risk=Fraction(1, 2),
                    ),
                )

            projections.append(projection)

        manifest = canonical({
            "format": MANIFEST_FORMAT,
            "context": self.ctx,
            "bindings": sorted(
                bindings,
                key=lambda row: (
                    row["service_scenario_id"],
                    row["role"],
                ),
            ),
        })

        with AnalyticalArchive(
            self.path,
            create=True,
        ) as archive:

            pin = archive.store(
                tuple(projections),
                manifest,
                expected_manifest_sha256=
                    engine.sha(manifest),
                load_object=objects.__getitem__,
            )

        return {
            "schema": engine.SCHEMA,
            "scope": "NON_OPERATIONAL_DEV_REVIEW",
            "snapshot_sha256": pin,
            "context": deepcopy(self.ctx),
            "characterizations": characterizations,
        }

    def load(self, document, pin=None):

        raw = canonical(document)

        return engine.load_bound(
            self.path,
            binding_bytes=raw,
            expected_binding_sha256=(
                engine.sha(raw)
                if pin is None else pin
            ),
        )

    def test_01_bound_recovery(self):

        document = self.fixture()
        report = self.load(document)

        self.assertEqual(
            report["services_verified"], 2
        )

        self.assertEqual(
            report["references_verified"], 14
        )

        self.assertEqual(
            report["a6"], "ND"
        )

        self.assertIsNone(
            report["confirmed_rf"]
        )

        self.assertFalse(
            report["operational_dispatch"]
        )

        self.assertFalse(
            report["external_freshness_accredited"]
        )

        self.assertEqual(
            self.load(document), report
        )

    def test_02_wrong_binding_pin(self):

        with self.assertRaisesRegex(
            ValueError,
            "R379_BINDING_PIN_MISMATCH",
        ):
            self.load(
                self.fixture(), "f" * 64
            )

    def test_03_foreign_record(self):

        document = self.fixture()

        document["context"]["record_id"] = "FOREIGN"

        with self.assertRaisesRegex(
            ValueError,
            "R379_CONTEXT_MISMATCH:record_id",
        ):
            self.load(document)

    def test_04_foreign_execution(self):

        document = self.fixture()

        document["context"]["execution_id"] = "FOREIGN"

        with self.assertRaisesRegex(
            ValueError,
            "R379_CONTEXT_MISMATCH:execution_id",
        ):
            self.load(document)

    def test_05_foreign_configuration(self):

        document = self.fixture()

        document["context"]["configuration_sha256"] = "b" * 64

        with self.assertRaisesRegex(
            ValueError,
            "R379_CONTEXT_MISMATCH:configuration_sha256",
        ):
            self.load(document)

    def test_06_wrong_generation(self):

        document = self.fixture()

        document["context"]["generation_index"] = 0

        with self.assertRaisesRegex(
            ValueError,
            "R379_CONTEXT_MISMATCH:generation_index",
        ):
            self.load(document)

    def test_07_missing_service(self):

        document = self.fixture()

        document["characterizations"].pop()

        with self.assertRaisesRegex(
            ValueError,
            "R379_SERVICE_SCOPE_MISMATCH",
        ):
            self.load(document)

    def test_08_duplicate_service(self):

        document = self.fixture()

        document["characterizations"].append(
            deepcopy(
                document["characterizations"][0]
            )
        )

        with self.assertRaisesRegex(
            ValueError,
            "R379_DUPLICATE_SERVICE",
        ):
            self.load(document)

    def test_09_foreign_characterization(self):

        document = self.fixture()

        for key, value in (
            ("sha256", "f" * 64),
            ("reference", "FOREIGN-REFERENCE"),
        ):

            with self.subTest(field=key):

                altered = deepcopy(document)

                altered["characterizations"][0][key] = value

                with self.assertRaisesRegex(
                    ValueError,
                    "R379_CHARACTERIZATION_MISMATCH",
                ):
                    self.load(altered)

    def test_10_stale_dynamic_object(self):

        document = self.fixture(stale=True)

        with self.assertRaisesRegex(
            ValueError,
            "R379_OBJECT_GENERATION_MISMATCH",
        ):
            self.load(document)

    def test_11_numeric_risk_promotion(self):

        document = self.fixture(promoted=True)

        with self.assertRaisesRegex(
            ValueError,
            "R379_MAGNITUDE_PROMOTION",
        ):
            self.load(document)

    def test_12_missing_snapshot(self):

        document = self.fixture()

        document["snapshot_sha256"] = "f" * 64

        with self.assertRaises(FileNotFoundError):
            self.load(document)


if __name__ == "__main__":
    unittest.main()
