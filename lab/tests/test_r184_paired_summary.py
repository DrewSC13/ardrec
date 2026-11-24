"""R184 regression fixtures: never empirical observations."""
import unittest
from pathlib import Path

from ardrec.experiments import (
    paired_summary as summary,
    r148_paired_register as r148,
)

CAT = Path(
    "lab/operational-catalog-v1/catalog.json"
).read_bytes()

HEAD = "f0f693112aee73db41d86576a9692ab9ab3d1e52"


class R184Tests(unittest.TestCase):

    def build(self, values):

        protocol, registry = r148.build(CAT, HEAD)

        if values:
            registry["common_scale"] = {
                "lower": "0",
                "upper": "1",
            }

        for index, data in enumerate(values):

            slot = registry["slots"][index]

            slot.update({
                "status": "RECORDED_UNVERIFIED",
                "scenario_id": f"fixture-scenario-{index}",
                "case_id": f"fixture-case-{index}",
                "family_id": "SSH-T01",
            })

            slot.update(zip(r148.VALUES, data))

            for key in r148.REFS:
                slot[key] = "a" * 64

        registry.pop("sha256")
        registry["sha256"] = r148.digest(
            r148.canonical(registry)
        )

        return protocol, registry

    def result(self, values):

        protocol, registry = self.build(values)

        native, report = summary.analyze(
            protocol, registry, CAT
        )

        self.assertEqual(
            report["wilcoxon"],
            native["primary_comparison"],
        )

        self.assertFalse(
            report["confirmatory_analysis_authorized"]
        )

        self.assertEqual(report["p8"], "NO-GO")

        return report

    def test_empty(self):

        report = self.result([])

        self.assertEqual(report["pairs"], 0)
        self.assertIsNone(report["mae_static"])
        self.assertIsNone(report["mae_ardrec"])
        self.assertIsNone(report["rank_biserial"])
        self.assertIsNone(
            report["wilcoxon"]["p_fraction"]
        )

    def test_positive(self):

        report = self.result([
            ("0.8", "0.4", "0.2"),
        ])

        self.assertEqual(report["mae_static"], "3/5")
        self.assertEqual(report["mae_ardrec"], "1/5")
        self.assertEqual(report["mean_difference"], "2/5")
        self.assertEqual(report["rank_biserial"], "1/1")
        self.assertEqual(
            report["wilcoxon"]["p_fraction"], "1/2"
        )

    def test_negative(self):

        report = self.result([
            ("0.2", "0.6", "0.2"),
        ])

        self.assertEqual(report["rank_biserial"], "-1/1")
        self.assertEqual(report["favor_static"], 1)

    def test_all_zero(self):

        report = self.result([
            ("0.5", "0.5", "0.2"),
        ])

        self.assertEqual(report["equal_errors"], 1)
        self.assertEqual(report["mean_difference"], "0/1")
        self.assertIsNone(report["rank_biserial"])
        self.assertIsNone(
            report["wilcoxon"]["p_fraction"]
        )

    def test_ties_and_balanced_effect(self):

        report = self.result([
            ("0.8", "0.4", "0.2"),
            ("0.2", "0.6", "0.2"),
            ("0.5", "0.5", "0.2"),
        ])

        self.assertEqual(report["mae_static"], "3/10")
        self.assertEqual(report["mae_ardrec"], "3/10")
        self.assertEqual(report["median_difference"], "0/1")
        self.assertEqual(report["rank_biserial"], "0/1")
        self.assertEqual(report["favor_ardrec"], 1)
        self.assertEqual(report["favor_static"], 1)
        self.assertEqual(report["equal_errors"], 1)
        self.assertEqual(
            report["wilcoxon"]["p_fraction"], "3/4"
        )

    def test_report_reproducible(self):

        data = [("0.8", "0.4", "0.2")]

        self.assertEqual(
            self.result(data),
            self.result(data),
        )

    def test_unsupported_precision(self):

        with self.assertRaises(r148.Stop):
            summary.normalized("1e-49")


if __name__ == "__main__":
    unittest.main()
