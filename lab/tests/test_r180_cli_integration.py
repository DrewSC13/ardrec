"""R180: permanent CLI integration tests; offline only."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ardrec.experiments import (
    r148_paired_register as r148,
    r149_scenario_design as r149,
)
from scripts.ardrec_p14_r58k_unified_family_demo import (
    synthetic_unified_inputs,
)

REPO = Path(__file__).resolve().parents[2]


class R180CLIIntegration(unittest.TestCase):

    def cli(self, *args):
        return subprocess.run(
            [sys.executable, "-B", "-m", "ardrec", *args],
            cwd=REPO,
            capture_output=True,
            timeout=120,
            check=False,
        )

    def test_global_help(self):
        result = self.cli("--help")
        self.assertEqual(result.returncode, 0)
        for name in (
            b"live", b"caso", b"familias", b"estudio",
            b"--durable-dev-root", b"NO-GO",
        ):
            self.assertIn(name, result.stdout)

    def test_subcommand_help(self):
        for command in (
            "live", "caso", "familias", "estudio"
        ):
            with self.subTest(command=command):
                result = self.cli(command, "--help")
                self.assertEqual(result.returncode, 0)
                self.assertIn(b"usage:", result.stdout.lower())

    def test_family_evaluation_and_replay(self):
        self.assertNotEqual(os.geteuid(), 0)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "inputs.json"
            receipt = root / "report.json"

            source.write_text(
                json.dumps(synthetic_unified_inputs()),
                encoding="utf-8",
            )

            first = self.cli(
                "familias", "--dev", "--entrada",
                str(source), "--json",
            )
            self.assertEqual(first.returncode, 0, first.stderr)

            receipt.write_bytes(first.stdout)
            doc = json.loads(first.stdout)

            self.assertEqual(doc["unit_count"], 29)
            self.assertEqual(
                doc["covered_family_count_in_batch"], 25
            )
            self.assertEqual(doc["a6_classification"], "ND")
            self.assertIsNone(doc["confirmed_final_risk"])
            self.assertIs(doc["operational_dispatch"], False)
            self.assertEqual(doc["p8_operational"], "NO-GO")

            replay = self.cli(
                "familias", "--dev", "--reproducir",
                str(receipt), "--json",
            )
            self.assertEqual(replay.returncode, 0)
            self.assertEqual(first.stdout, replay.stdout)

            doc["technical_truth_accredited"] = True
            receipt.write_text(json.dumps(doc), encoding="utf-8")

            rejected = self.cli(
                "familias", "--dev", "--reproducir",
                str(receipt), "--json",
            )
            self.assertNotEqual(rejected.returncode, 0)

    def test_explicit_dev_required(self):
        result = self.cli(
            "familias", "--entrada", "absent.json", "--json"
        )
        self.assertNotEqual(result.returncode, 0)

    def test_empty_study_readonly(self):
        self.assertNotEqual(os.geteuid(), 0)

        catalog = (
            REPO / "lab/operational-catalog-v1/catalog.json"
        ).read_bytes()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            registry_dir = root / "registry"
            selection_dir = root / "selection"

            r148.initialize(
                registry_dir,
                catalog,
                "647258bfa4c9c10c6c06aa5dd1bb58a7d7e07549",
            )

            protocol, registry = r148.read(
                registry_dir, catalog
            )

            r149.create(
                selection_dir,
                catalog,
                protocol,
                registry,
            )

            originals = {
                path: path.read_bytes()
                for folder in (registry_dir, selection_dir)
                for path in folder.iterdir()
                if path.is_file()
            }

            args = (
                "estudio", "--registro", str(registry_dir),
                "--seleccion", str(selection_dir),
                "--analisis-exploratorio", "--json",
            )

            first = self.cli(*args)
            self.assertEqual(first.returncode, 0, first.stderr)

            doc = json.loads(first.stdout)

            self.assertEqual(doc["registry"]["planned"], 54)
            self.assertEqual(
                doc["selection"]["statuses"]["EMPTY"], 54
            )
            self.assertEqual(
                doc["confirmed_physical_observations"], 0
            )
            self.assertIs(
                doc["confirmatory_analysis_authorized"], False
            )
            self.assertIsNone(
                doc["statistics"]["primary_comparison"][
                    "p_one_sided_exact"
                ]
            )

            second = self.cli(*args)
            self.assertEqual(second.returncode, 0)
            self.assertEqual(first.stdout, second.stdout)

            for path, raw in originals.items():
                self.assertEqual(path.read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
