"""R164-F3: integración R148/R149 sin falsificar resultados."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(HERE / "scripts"))

import ardrec_p14_r164_f3_workspace as m
from ardrec.experiments import r149_scenario_design as r149

CATALOG = (
    HERE / "lab/operational-catalog-v1/catalog.json"
).read_bytes()

HEAD = "a" * 40
TREE = "b" * 40


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(
            prefix="r164-f3-test-"
        )
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name) / "workspace"

    def create(self):
        return m.prepare(self.folder, CATALOG, HEAD, TREE)

    def test_01_structure(self):
        result = self.create()
        self.assertEqual(
            {p.name for p in self.folder.iterdir()},
            m.FILES,
        )
        self.assertEqual(
            result["manifest"]["source_head"], HEAD
        )

    def test_02_54_unassigned(self):
        result = self.create()
        self.assertEqual(
            result["r148"]["statuses"]["PLANNED_UNASSIGNED"],
            54,
        )
        self.assertEqual(
            result["r149"]["statuses"]["EMPTY"], 54
        )

    def test_03_families(self):
        result = self.create()
        self.assertEqual(
            result["r149"]["candidate_family_coverage"],
            25,
        )

    def test_04_no_physical_claims(self):
        result = self.create()
        self.assertEqual(
            result["r148"]["confirmed_physical_observations"],
            0,
        )
        self.assertEqual(
            result["analysis"]["claim"],
            "EXPLORATORY_UNVERIFIED_NOT_THESIS_RESULT",
        )
        self.assertEqual(result["manifest"]["p8"], "NO-GO")

    def test_05_reject_second_prepare(self):
        self.create()
        with self.assertRaisesRegex(
            m.Stop, "FOLDER_MUST_BE_NEW"
        ):
            self.create()

    def test_06_reject_modified_manifest(self):
        self.create()
        path = self.folder / "manifest.json"
        path.write_bytes(path.read_bytes() + b"x")
        with self.assertRaises(Exception):
            m.audit(self.folder, CATALOG)

    def test_07_reject_extra_file(self):
        self.create()
        (self.folder / "extra").write_text(
            "x", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            m.Stop, "WORKSPACE_FILE_SET_INVALID"
        ):
            m.audit(self.folder, CATALOG)

    def test_08_reject_symlink_workspace(self):
        self.create()
        link = Path(self.tmp.name) / "alias"
        link.symlink_to(
            self.folder, target_is_directory=True
        )
        with self.assertRaisesRegex(
            m.Stop, "DIRECTORY_NOT_PRIVATE"
        ):
            m.audit(link, CATALOG)

    def test_09_candidate_partial_edit(self):
        self.create()
        path = (
            self.folder / "selection" /
            "selection-working.csv"
        )
        rows = r149.parse_csv(path.read_bytes())
        rows[0]["case_id"] = "case-001"
        path.write_bytes(r149.csv_bytes(rows))
        self.assertEqual(
            m.audit(self.folder, CATALOG)["r149"]
            ["statuses"]["PARTIAL"],
            1,
        )

    def test_10_reject_cross_protocol_selection(self):
        self.create()
        path = (
            self.folder / "selection" /
            "selection-working.csv"
        )
        rows = r149.parse_csv(path.read_bytes())
        rows[0]["chosen_family"] = "FTP-T01"
        path.write_bytes(r149.csv_bytes(rows))
        with self.assertRaises(Exception):
            m.audit(self.folder, CATALOG)

    def test_11_reject_catalog_drift(self):
        self.create()
        with self.assertRaisesRegex(
            m.Stop, "CATALOG_CHANGED"
        ):
            m.audit(self.folder, CATALOG + b" ")

    def test_12_reject_proposal_drift(self):
        self.create()
        path = (
            self.folder / "selection" /
            "family-proposal.csv"
        )
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(Exception):
            m.audit(self.folder, CATALOG)

    def test_13_reject_registry_drift(self):
        self.create()
        path = (
            self.folder / "register" /
            "observations.json"
        )
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(Exception):
            m.audit(self.folder, CATALOG)


if __name__ == "__main__":
    unittest.main()
