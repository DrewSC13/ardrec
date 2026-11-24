"""R228 synthetic contract tests; never study observations."""

import copy
import hashlib
import unittest

from pathlib import Path

from ardrec.coordination import local_evidence_bridge as evidence

from ardrec.experiments import (
    baseline_preparation as m,
    r148_paired_register as r148,
    r149_scenario_design as r149,
    study_cli,
)

ROOT = Path(__file__).resolve().parents[2]
CAT = (ROOT / "lab/operational-catalog-v1/catalog.json").read_bytes()


class BaselineTests(unittest.TestCase):

    def setUp(self):

        self.protocol, self.registry = r148.build(
            CAT,
            "319c693bc42499ab57dbfbe6b36415694a180c44",
        )

        self.plan, self.checklist, self.rows = r149.draft(
            CAT,
            self.protocol,
            self.registry,
        )

        self.supports = {}

        def register(raw):

            ref = hashlib.sha256(raw).hexdigest()

            self.supports[ref] = raw

            return ref

        self.row = self.rows[0]

        self.row.update({
            "chosen_family": self.row["candidate_family"],
            "case_id": "SYNTHETIC-CASE-01",
            "scenario_id": "SYNTHETIC-SCENARIO-01",
            "service_instance_id": "SYNTHETIC-SERVICE",
            "variation_reason": "Synthetic test condition only",
            "scope_authorization_sha256":
                register(b"synthetic scope"),
            "preregistration_sha256":
                register(b"synthetic preregistration"),
            "static_estimate": "0.25",
            "static_support_sha256":
                register(b"synthetic static support"),
        })

        ratings = {
            name: {
                "ordinal": 3,
                "support_sha256":
                    register(name.encode("ascii")),
                "justification":
                    "Synthetic contract test support",
            }
            for name in m.DIMENSIONS
        }

        self.entry = {
            "slot_id": self.row["slot_id"],
            "selection_sha256":
                m.sha(r149.csv_bytes(self.rows)),
            "configuration_sha256":
                register(b"synthetic configuration"),
            "ratings": ratings,
        }

    def build(self, entry=None, supports=None):

        return m.build(
            CAT,
            self.protocol,
            self.registry,
            self.plan,
            self.checklist,
            r149.csv_bytes(self.rows),
            entry,
            supports,
        )

    def calculate(self):

        return self.build(
            self.entry,
            self.supports,
        )

    def rebind(self):

        self.entry["selection_sha256"] = m.sha(
            r149.csv_bytes(self.rows)
        )

    def test_01_positions(self):

        report = self.build()

        self.assertEqual(report["planned_slots"], 54)

        self.assertEqual(report["baselines_closed"], 0)

    def test_02_exact_baseline(self):

        report = self.calculate()

        result = report["candidate"]

        self.assertEqual(
            result["calculated"]["initial_risk"],
            "1/2",
        )

        self.assertEqual(
            result["calculated"]["normalized_criticality"],
            "1/2",
        )

        self.assertEqual(result["static_estimate"], "0.25")

    def test_03_reproducibility(self):

        self.assertEqual(
            self.calculate(),
            self.calculate(),
        )

    def test_04_seals(self):

        report = self.calculate()

        self.assertTrue(
            evidence.verify_digest(report)
        )

        self.assertTrue(
            evidence.verify_digest(report["candidate"])
        )

    def test_05_no_operational_promotion(self):

        report = self.calculate()

        for record in (report, report["candidate"]):

            self.assertFalse(record["baseline_closed"])
            self.assertFalse(record["execution_authorized"])
            self.assertFalse(record["experimental_admission"])
            self.assertEqual(record["p8"], "NO-GO")

    def test_06_invalid_selection_pin(self):

        self.entry["selection_sha256"] = "a" * 64

        with self.assertRaisesRegex(
            ValueError,
            "I2_SELECTION_BINDING_INVALID",
        ):

            self.calculate()

    def test_07_unselected_position(self):

        self.entry["slot_id"] = "SSH-02"

        with self.assertRaisesRegex(
            ValueError,
            "I2_SCENARIO_NOT_SELECTED",
        ):

            self.calculate()

    def test_08_pilot_reuse(self):

        self.row["case_id"] = "PILOT-SSH-01"

        self.rebind()

        with self.assertRaisesRegex(
            ValueError,
            "PILOT_IDENTITY_REUSE_FORBIDDEN",
        ):

            self.calculate()

    def test_09_modified_support(self):

        ref = next(iter(self.supports))

        self.supports[ref] = b"modified"

        with self.assertRaisesRegex(
            ValueError,
            "I2_SUPPORT_INTEGRITY_INVALID",
        ):

            self.calculate()

    def test_10_missing_support(self):

        self.supports.pop(
            next(iter(self.supports))
        )

        with self.assertRaisesRegex(
            ValueError,
            "I2_SUPPORT_SET_INVALID",
        ):

            self.calculate()

    def test_11_invalid_ordinal(self):

        self.entry["ratings"]["exposure"]["ordinal"] = 6

        with self.assertRaises(ValueError):

            self.calculate()

    def test_12_invalid_static_scale(self):

        self.row["static_estimate"] = "1.01"

        self.rebind()

        with self.assertRaisesRegex(
            ValueError,
            "I2_STATIC_SCALE_INVALID",
        ):

            self.calculate()

    def test_13_unknown_dimension(self):

        self.entry["ratings"]["extra"] = {}

        with self.assertRaisesRegex(
            ValueError,
            "I2_DIMENSIONS_INVALID",
        ):

            self.calculate()

    def test_14_missing_justification(self):

        self.entry["ratings"]["impact"]["justification"] = ""

        with self.assertRaisesRegex(
            ValueError,
            "I2_JUSTIFICATION_INVALID",
        ):

            self.calculate()

    def test_15_input_unchanged(self):

        before = copy.deepcopy(
            (self.rows, self.entry, self.supports)
        )

        self.calculate()

        self.assertEqual(
            before,
            (self.rows, self.entry, self.supports),
        )

    def test_16_cli_requires_selection(self):

        with self.assertRaises(SystemExit) as exc:

            study_cli.main([
                "--registro", "unused",
                "--preparar-i2",
                "--json",
            ])

        self.assertEqual(exc.exception.code, 2)

    def test_17_cli_rejects_incompatible_analysis(self):

        with self.assertRaises(SystemExit) as exc:

            study_cli.main([
                "--registro", "unused",
                "--seleccion", "unused",
                "--preparar-i2",
                "--analisis-exploratorio",
                "--json",
            ])

        self.assertEqual(exc.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
