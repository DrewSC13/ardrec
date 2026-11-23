"""R164-F5: integración de poblaciones y pruebas negativas."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(REPO / "src"),
    str(REPO / "scripts"),
]

from ardrec.experiments import (
    r148_paired_register as r148,
    r149_scenario_design as r149,
    r164_identity_boundary as f5,
)

import ardrec_p14_r164_f5_boundary as cli


@unittest.skipIf(
    os.geteuid() == 0,
    "R164-F5 requiere usuario no root",
)
class BoundaryTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.catalog = (
            REPO / "lab/operational-catalog-v1/catalog.json"
        ).read_bytes()

        cls.protocol, cls.registry = r148.build(
            cls.catalog,
            "a" * 40,
        )

        cls.plan, cls.checklist, cls.rows = r149.draft(
            cls.catalog, cls.protocol, cls.registry
        )

        (
            cls.unified,
            cls.trace,
            cls.model,
            cls.decision,
        ) = cli.sources_offline()

        cls.document = cls.build()

    @classmethod
    def build(cls, *, rows=None, decision=None, catalog=None):
        return f5.build(
            cls.catalog if catalog is None else catalog,
            cls.protocol,
            cls.registry,
            cls.plan,
            cls.checklist,
            r149.csv_bytes(
                cls.rows if rows is None else rows
            ),
            cls.unified,
            cls.trace,
            cls.model,
            cls.decision if decision is None else decision,
        )

    def populated(self, index=0):
        rows = deepcopy(self.rows)

        rows[index].update({
            "chosen_family":
                rows[index]["candidate_family"],
            "case_id": "candidate-" + str(index),
            "scenario_id": "scenario-" + str(index),
            "service_instance_id":
                "instance-" + str(index),
            "variation_reason":
                "Condition difference candidate " + str(index),
            "scope_authorization_sha256": "a" * 64,
            "preregistration_sha256": "a" * 64,
            "static_estimate": "5",
            "static_support_sha256": "a" * 64,
        })

        return rows

    def test_01_two_distinct_distributions(self):
        self.assertEqual(
            self.document["model_distribution"],
            {"SSH_DEV":16, "FTP_DEV":20, "SMB_DEV":18},
        )
        self.assertEqual(
            self.document["experiment_distribution"],
            {"SSH":18, "FTP":18, "SMB":18},
        )

    def test_02_54_unassigned(self):
        self.assertEqual(
            self.document["candidate_counts"],
            {"UNASSIGNED":54},
        )
        self.assertEqual(len(self.document["slots"]), 54)

    def test_03_270_offline_kernel_checks(self):
        self.assertEqual(
            self.document["model_offline_kernel_checks"], 270
        )
        self.assertEqual(
            self.document["model_case_coverage_family_count"],
            25,
        )

    def test_04_no_automatic_pairing(self):
        self.assertEqual(
            self.document["cross_population_pair_count"], 0
        )
        self.assertTrue(all(
            row["model_r109_case_id"] is None
            for row in self.document["slots"]
        ))

    def test_05_no_physical_authority(self):
        self.assertEqual(
            self.document["confirmed_physical_observations"],
            0,
        )
        self.assertFalse(
            self.document["experimental_wilcoxon_admitted"]
        )
        self.assertEqual(self.document["p8"], "NO-GO")
        self.assertEqual(self.document["a6"], "ND")

    def test_06_deterministic_replay(self):
        self.assertEqual(
            self.document, self.build()
        )
        self.assertTrue(f5.verify(
            self.document,
            self.catalog,
            self.protocol,
            self.registry,
            self.plan,
            self.checklist,
            r149.csv_bytes(self.rows),
            self.unified,
            self.trace,
            self.model,
            self.decision,
        ))

    def test_07_tampered_receipt_rejected(self):
        forged = deepcopy(self.document)
        forged["slots"][0][
            "experimental_observation_confirmed"
        ] = True

        with self.assertRaisesRegex(
            f5.Stop, "BOUNDARY_REPLAY_MISMATCH"
        ):
            f5.verify(
                forged,
                self.catalog,
                self.protocol,
                self.registry,
                self.plan,
                self.checklist,
                r149.csv_bytes(self.rows),
                self.unified,
                self.trace,
                self.model,
                self.decision,
            )

    def test_08_complete_candidate_still_unverified(self):
        result = self.build(rows=self.populated())
        self.assertEqual(
            result["candidate_counts"],
            {
                "CANDIDATE_ONLY_UNVERIFIED": 1,
                "UNASSIGNED": 53,
            },
        )
        self.assertEqual(
            result["confirmed_physical_observations"], 0
        )
        self.assertEqual(
            result["cross_population_pair_count"], 0
        )

    def test_09_partial_candidate_unverified(self):
        rows = deepcopy(self.rows)
        rows[0]["case_id"] = "partial-case"

        result = self.build(rows=rows)
        self.assertEqual(
            result["candidate_counts"],
            {
                "PARTIAL_UNVERIFIED": 1,
                "UNASSIGNED": 53,
            },
        )

    def test_10_wrong_protocol_family_rejected(self):
        rows = self.populated()
        rows[0]["chosen_family"] = "FTP-T01"

        with self.assertRaises(r149.Stop):
            self.build(rows=rows)

    def test_11_duplicate_candidate_rejected(self):
        rows = self.populated()
        rows[1] = self.populated(1)[1]
        rows[1]["case_id"] = rows[0]["case_id"]

        with self.assertRaises(r149.Stop):
            self.build(rows=rows)

    def test_12_forged_model_result_rejected(self):
        wrong = deepcopy(self.decision)
        wrong["a6_classification"] = "OBSERVADO_POSITIVO"

        with self.assertRaises(Exception):
            self.build(decision=wrong)

    def test_13_private_receipt_readback(self):
        with tempfile.TemporaryDirectory(
            prefix="r164-f5-tests-"
        ) as temporary:
            private = Path(temporary) / "f5"

            with patch.object(cli, "OUTPUT", private):
                folder, manifest = cli.persist(self.document)

                self.assertEqual(
                    manifest["report_sha256"],
                    self.document["sha256"],
                )

                self.assertEqual(
                    {p.name for p in folder.iterdir()},
                    {"report.json", "manifest.json"},
                )

                reread = r148.decode(
                    cli.a5._read_private(
                        folder / "report.json",
                        cli.MAX_BYTES,
                    )
                )

                self.assertEqual(reread, self.document)


if __name__ == "__main__":
    unittest.main()
