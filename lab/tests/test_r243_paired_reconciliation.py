"""Synthetic paired integration tests, never thesis observations."""

import copy
import csv
import io
import tempfile
import unittest

from pathlib import Path

from ardrec.experiments import (
    paired_reconciliation as m,
    r148_paired_register as r148,
    r149_scenario_design as r149,
    study_cli,
)

CAT = Path(
    "lab/operational-catalog-v1/catalog.json"
).read_bytes()

HEAD = "f0f693112aee73db41d86576a9692ab9ab3d1e52"


class ReconciliationTests(unittest.TestCase):

    def setUp(self):

        self.protocol, self.registry = r148.build(CAT, HEAD)

        self.plan, self.checklist, original = r149.draft(
            CAT,
            self.protocol,
            self.registry,
        )

        self.proposal = r149.csv_bytes(original)
        self.rows = copy.deepcopy(original)

    def reseal(self):

        self.registry.pop("sha256", None)
        self.registry = r148._seal(self.registry)

    def record(self, index, values=None, excluded=False):

        selected = self.rows[index]

        selected.update({
            "chosen_family": selected["candidate_family"],
            "case_id": f"synthetic-case-{index}",
            "scenario_id": f"synthetic-scenario-{index}",
            "service_instance_id": f"synthetic-service-{index}",
            "variation_reason": "Synthetic regression fixture",
            "scope_authorization_sha256": "a" * 64,
            "preregistration_sha256": "b" * 64,
            "static_estimate": values[0] if values else "0.5",
            "static_support_sha256": "c" * 64,
        })

        slot = self.registry["slots"][index]

        slot.update({
            "case_id": selected["case_id"],
            "scenario_id": selected["scenario_id"],
            "family_id": selected["chosen_family"],
            "status": (
                "EXCLUDED_UNVERIFIED"
                if excluded else "RECORDED_UNVERIFIED"
            ),
        })

        if excluded:

            slot["exclusion_reason"] = "Synthetic exclusion"
            slot["exclusion_decision_sha256"] = "d" * 64

        else:

            slot.update(zip(r148.VALUES, values))

            for key in r148.REFS:
                slot[key] = "e" * 64

            self.registry["common_scale"] = {
                "lower": "0",
                "upper": "1",
            }

        self.reseal()

    def report(self):

        return m.build(
            self.protocol,
            self.registry,
            CAT,
            self.plan,
            self.checklist,
            r149.csv_bytes(self.rows),
            self.proposal,
        )

    def test_01_empty_register_is_not_zero_risk(self):

        report = self.report()

        self.assertEqual(len(report["i8_rows"]), 54)
        self.assertEqual(report["recorded_unverified"], 0)

        self.assertIsNone(
            report["paired_summary"]["mae_ardrec"]
        )

        self.assertIsNone(
            report["paired_summary"]["wilcoxon"]["p_fraction"]
        )

        self.assertTrue(all(
            row["ardrec_estimate"] is None
            for row in report["i8_rows"]
        ))

    def test_02_exact_protocol_descriptive_results(self):

        self.record(0, ("0.8", "0.4", "0.2"))
        self.record(18, ("0.2", "0.6", "0.2"))
        self.record(36, ("0.5", "0.5", "0.2"))

        report = self.report()
        groups = report["by_protocol_descriptive"]

        self.assertEqual(groups["SSH"]["mae_static"], "3/5")
        self.assertEqual(groups["SSH"]["mae_ardrec"], "1/5")
        self.assertEqual(groups["FTP"]["mae_static"], "0/1")
        self.assertEqual(groups["FTP"]["mae_ardrec"], "2/5")
        self.assertEqual(groups["SMB"]["equal_errors"], 1)

        self.assertEqual(
            report["paired_summary"]["mae_static"], "3/10"
        )

        self.assertEqual(
            report["paired_summary"]["mae_ardrec"], "3/10"
        )

        self.assertEqual(
            report["paired_summary"]["wilcoxon"]["p_fraction"],
            "3/4",
        )

        self.assertTrue(all(
            "wilcoxon" not in group
            for group in groups.values()
        ))

    def test_03_excluded_position_has_no_measurement(self):

        self.record(0, excluded=True)

        report = self.report()
        row = report["i8_rows"][0]

        self.assertEqual(row["status"], "EXCLUDED_UNVERIFIED")
        self.assertIsNone(row["ardrec_estimate"])
        self.assertIsNone(row["difference"])
        self.assertEqual(report["recorded_unverified"], 0)

    def test_04_selection_identity_mismatch_rejected(self):

        self.record(0, ("0.8", "0.4", "0.2"))

        self.rows[0]["case_id"] = "wrong-case"

        with self.assertRaisesRegex(
            ValueError, "RECORDED_SELECTION_IDENTITY_MISMATCH"
        ):
            self.report()

    def test_05_static_estimate_mismatch_rejected(self):

        self.record(0, ("0.8", "0.4", "0.2"))

        self.rows[0]["static_estimate"] = "0.9"

        with self.assertRaisesRegex(
            ValueError, "STATIC_ESTIMATE_SELECTION_MISMATCH"
        ):
            self.report()

    def test_06_partial_selection_rejected(self):

        self.record(0, ("0.8", "0.4", "0.2"))

        self.rows[0]["service_instance_id"] = ""

        with self.assertRaisesRegex(
            ValueError, "RECORDED_SLOT_SELECTION_INCOMPLETE"
        ):
            self.report()

    def test_07_pilot_identity_reuse_rejected(self):

        self.record(0, ("0.8", "0.4", "0.2"))

        self.rows[0]["case_id"] = "PILOT-SSH-01"
        self.registry["slots"][0]["case_id"] = "PILOT-SSH-01"

        self.reseal()

        with self.assertRaisesRegex(
            ValueError, "PILOT_REUSE_FORBIDDEN"
        ):
            self.report()

    def test_08_original_proposal_tampering_rejected(self):

        self.proposal += b"\n"

        with self.assertRaisesRegex(
            ValueError, "ORIGINAL_PROPOSAL_CHANGED"
        ):
            self.report()

    def test_09_replay_and_input_immutability(self):

        self.record(0, ("0.8", "0.4", "0.2"))

        original = copy.deepcopy(self.registry)

        report = self.report()

        self.assertEqual(report, self.report())
        self.assertEqual(self.registry, original)
        self.assertEqual(report["experimental_admitted"], 0)

        self.assertFalse(
            report["confirmatory_analysis_authorized"]
        )

    def test_10_csv_preserves_all_positions(self):

        self.record(0, ("0.8", "0.4", "0.2"))

        report = self.report()

        records = list(csv.DictReader(io.StringIO(
            m.export_csv(report).decode("utf-8")
        )))

        self.assertEqual(len(records), 54)
        self.assertEqual(records[0]["difference"], "2/5")
        self.assertEqual(records[1]["ardrec_estimate"], "")

    def test_11_original_cli_accepts_populated_register(self):

        self.record(0, ("0.8", "0.4", "0.2"))

        with tempfile.TemporaryDirectory() as directory:

            root = Path(directory)

            registry = root / "registry"
            selection = root / "selection"

            r148.initialize(registry, CAT, HEAD)

            protocol, empty = r148.read(registry, CAT)

            r149.create(selection, CAT, protocol, empty)

            (selection / "selection-working.csv").write_bytes(
                r149.csv_bytes(self.rows)
            )

            (registry / "observations.json").write_bytes(
                r148.canonical(self.registry)
            )

            report = study_cli.evaluate(
                registry,
                selection,
                analysis=True,
                paired_summary=True,
            )

            self.assertEqual(
                report["paired_summary"]["pairs"], 1
            )

            self.assertFalse(
                report["confirmatory_analysis_authorized"]
            )

    def test_12_incompatible_cli_modes_rejected(self):

        with self.assertRaises(SystemExit):

            study_cli.main([
                "--registro", "unused",
                "--informe-i8",
                "--json",
            ])

        with self.assertRaises(SystemExit):

            study_cli.main([
                "--registro", "unused",
                "--csv",
            ])


if __name__ == "__main__":
    unittest.main()
