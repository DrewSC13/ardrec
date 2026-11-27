"""R360: native documentary provenance regression tests."""

from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest

from ardrec.analytics.exact_preview import digest
from ardrec.evidence import native_evidence_provenance as engine
from ardrec.persistence import DurableStore

unit_path = str(
    Path(__file__).resolve().parents[2] / "tests/unit"
)

sys.path.insert(0, unit_path)

try:
    import test_persistence as native
finally:
    sys.path.remove(unit_path)


class NativeEvidenceProvenanceTests(unittest.TestCase):

    def setUp(self):

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)

        self.path = Path(tmp.name) / "store"

        self.catalog = {
            "schema": engine.CATALOG_SCHEMA,
            "record_id": "REG-1",
            "execution_id": "EXE-1",
            "configuration_sha256": "a" * 64,
            "bindings": [{
                "service_scenario_id": "S01",
                "derived_case_id": "CASE-1",
                "condition_id": "COND-1",
                "profile_reference": "PROFILE-1",
                "parameters_reference": "PARAM-1",
            }],
        }

    def state(self, mode):

        with DurableStore.create(
            self.path, native.INITIAL
        ) as store:

            if mode != "initial":

                native.prepare(store)
                native.reserve(store)

                if mode in ("completed", "non_start"):

                    native.outcome(
                        store,
                        no_start=(mode == "non_start"),
                    )

                    store.publish(
                        expected_generation=1,
                        reference="GEN-2",
                        event="PUB-2",
                    )

                elif mode == "reported":

                    store.report(
                        "ATT-1",
                        deepcopy(
                            native.FIXTURES["result_completed"]
                        ),
                    )

            return store.head_sha256

    def kwargs(self, head, catalog=None):

        source = (
            self.catalog if catalog is None
            else catalog
        )

        return {
            "catalog": source,
            "expected_catalog_sha256": digest(source),
            "expected_head": head,
        }

    def build(self, head, catalog=None):

        return engine.build(
            self.path,
            **self.kwargs(head, catalog),
        )

    def test_01_empty_native_repository(self):

        report = self.build(self.state("initial"))

        self.assertEqual(report["attempts"], [])
        self.assertEqual(report["conditions"], [])
        self.assertEqual(report["a6"], "ND")

    def test_02_pending_reservation_not_linked(self):

        report = self.build(self.state("reserved"))

        self.assertEqual(
            report["attempts"][0]["status"],
            "PENDING_INCORPORATION",
        )

        self.assertEqual(
            report["documentary_links_verified"], 0
        )

    def test_03_received_result_not_incorporated(self):

        report = self.build(self.state("reported"))

        row = report["attempts"][0]

        self.assertIsNotNone(row["report_sha256"])
        self.assertIsNone(row["incorporation_event"])
        self.assertFalse(row["documentary_link_verified"])

    def test_04_native_case_condition_binding(self):

        report = self.build(self.state("completed"))

        row = report["attempts"][0]

        self.assertEqual(
            row["condition_id"], "COND-1"
        )

        self.assertEqual(
            row["incorporation_event"], "PUB-2"
        )

        self.assertEqual(
            row["incorporation_generation"], 2
        )

        self.assertEqual(
            row["declared_support_references"], ["SUP-1"]
        )

        self.assertEqual(
            row["effective_parameters_reference"],
            "EFFECTIVE-1",
        )

        self.assertEqual(
            report["documentary_links_verified"], 1
        )

        self.assertEqual(
            report["conditions"][0]["classification"], "ND"
        )

        self.assertFalse(row["support_bytes_verified"])

    def test_05_non_start_not_evidence(self):

        report = self.build(self.state("non_start"))

        self.assertEqual(
            report["attempts"][0]["status"],
            "VERIFIED_NON_START",
        )

        self.assertEqual(
            report["documentary_links_verified"], 0
        )

        self.assertEqual(report["conditions"], [])

    def test_06_missing_case_binding(self):

        head = self.state("completed")

        catalog = deepcopy(self.catalog)
        catalog["bindings"][0]["derived_case_id"] = "OTHER"

        report = self.build(head, catalog)

        self.assertEqual(
            report["attempts"][0]["status"],
            "CASE_BINDING_MISSING",
        )

        self.assertEqual(
            report["documentary_links_verified"], 0
        )

    def test_07_frozen_profile_and_parameters_rejected(self):

        head = self.state("completed")

        for field in (
            "profile_reference",
            "parameters_reference",
        ):

            with self.subTest(field=field):

                catalog = deepcopy(self.catalog)
                catalog["bindings"][0][field] = "FOREIGN"

                with self.assertRaisesRegex(
                    ValueError,
                    "FROZEN_CASE_REFERENCE_MISMATCH",
                ):
                    self.build(head, catalog)

    def test_08_ambiguous_and_foreign_catalog_rejected(self):

        head = self.state("completed")

        duplicate = deepcopy(self.catalog)

        duplicate["bindings"].append({
            **duplicate["bindings"][0],
            "condition_id": "COND-2",
        })

        with self.assertRaisesRegex(
            ValueError,
            "AMBIGUOUS_CASE_CONDITION_BINDING",
        ):
            self.build(head, duplicate)

        foreign = deepcopy(self.catalog)
        foreign["bindings"][0]["service_scenario_id"] = "OTHER"

        with self.assertRaisesRegex(
            ValueError, "FOREIGN_CATALOG_SERVICE"
        ):
            self.build(head, foreign)

        wrong_execution = deepcopy(self.catalog)
        wrong_execution["execution_id"] = "FOREIGN"

        with self.assertRaisesRegex(
            ValueError, "DURABLE_CONTEXT_MISMATCH"
        ):
            self.build(head, wrong_execution)

    def test_09_invalid_source_pins(self):

        head = self.state("completed")

        kwargs = self.kwargs(head)
        kwargs["expected_catalog_sha256"] = "f" * 64

        with self.assertRaisesRegex(
            ValueError, "CATALOG_PIN_MISMATCH"
        ):
            engine.build(self.path, **kwargs)

        with self.assertRaises(ValueError):
            self.build("f" * 64)

    def test_10_replay_and_non_promotion(self):

        head = self.state("completed")

        def contents():

            return {
                str(p.relative_to(self.path)): p.read_bytes()
                for p in self.path.rglob("*")
                if p.is_file()
            }

        before = contents()

        report = self.build(head)

        self.assertTrue(
            engine.verify(
                report,
                report["sha256"],
                self.path,
                **self.kwargs(head),
            )
        )

        self.assertEqual(report["a6"], "ND")
        self.assertIsNone(report["confirmed_rf"])
        self.assertEqual(report["support_bytes_verified"], 0)
        self.assertFalse(report["operational_dispatch"])
        self.assertIsNone(report["published_generation"])

        altered = deepcopy(report)

        altered["conditions"][0]["classification"] = (
            "POSITIVO_VALIDO"
        )

        altered.pop("sha256")
        altered["sha256"] = digest(altered)

        with self.assertRaisesRegex(
            ValueError, "PROVENANCE_REPLAY_MISMATCH"
        ):
            engine.verify(
                altered,
                altered["sha256"],
                self.path,
                **self.kwargs(head),
            )

        self.assertEqual(before, contents())
        self.assertEqual(report["p8"], "NO-GO")


if __name__ == "__main__":
    unittest.main()
