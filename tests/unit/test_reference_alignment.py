"""Comprobar procedencia y dominio del catálogo sin ejecutar algoritmos."""

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CURRENT = "6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72"
HISTORICAL = "da959bd6ab8eb49df5c746f2bfc50df2633794a2c089a2a757ffc65ca39ae9ce"


def read(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def check_precedence(value):
    # Los booleanos no pertenecen al dominio aunque hereden de int.
    if type(value) is not int or not 1 <= value <= 4:
        raise ValueError("INVALID_PRECEDENCE")


class ReferenceAlignmentTests(unittest.TestCase):
    def test_selection_inputs_use_the_thesis_domain(self):
        catalog = read("tests/fixtures/model-reference-v1.json")
        index = catalog["candidate_columns"].index("precedence")
        for case in catalog["cases"]:
            if case["group"] != "selection":
                continue
            for row_number, candidate in enumerate(case["input"]["candidates"]):
                with self.subTest(case=case["id"], row=row_number):
                    check_precedence(candidate[index])

    def test_invalid_reference_inputs_are_rejected(self):
        fixture = read("tests/fixtures/selection-precedence-invalid-v1.json")
        self.assertEqual(fixture["source"]["sha256"], CURRENT)
        identifiers = [case["id"] for case in fixture["cases"]]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertTrue(identifiers)
        for case in fixture["cases"]:
            with self.subTest(case=case["id"]):
                with self.assertRaisesRegex(ValueError, "^INVALID_PRECEDENCE$"):
                    check_precedence(case["input"]["precedence"])
                self.assertEqual(case["expected"], {"catalog_validation": "INVALID_PRECEDENCE"})

    def test_all_valid_levels_and_exact_types(self):
        for value in (1, 2, 3, 4):
            check_precedence(value)
        for value in (1.0, 4.0, True, False, "2", None, [], {}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "^INVALID_PRECEDENCE$"):
                    check_precedence(value)

    def test_source_history_and_review_are_distinct(self):
        catalog = read("tests/fixtures/model-reference-v1.json")
        matrix = read("docs/acceptance/system-v1.json")
        link = catalog["alignment_review"]
        review = read(link["record"])
        self.assertEqual(catalog["source"], matrix["source"])
        self.assertEqual(catalog["source"]["sha256"], HISTORICAL)
        self.assertEqual(review["historical_source"], catalog["source"])
        self.assertEqual(link["reviewed_source"], review["source"])
        self.assertEqual(review["source"]["sha256"], CURRENT)
        self.assertNotEqual(CURRENT, HISTORICAL)

    def test_recorded_corrections_match_inputs_and_preserve_oracles(self):
        catalog = read("tests/fixtures/model-reference-v1.json")
        review = read(catalog["alignment_review"]["record"])
        cases = {case["id"]: case for case in catalog["cases"]}
        index = catalog["candidate_columns"].index("precedence")
        for correction in review["changes"]:
            with self.subTest(correction=correction):
                row = cases[correction["case"]]["input"]["candidates"][correction["candidate_index"]]
                self.assertEqual(row[index], correction["after"])
                check_precedence(correction["after"])
                with self.assertRaises(ValueError):
                    check_precedence(correction["before"])
        self.assertEqual(cases["REF-S01"]["expected"],
                         {"kind": "SELECTED", "service": "S02", "case": "C02"})
        self.assertEqual(cases["REF-S05"]["expected"],
                         {"kind": "SELECTED", "service": "S05", "case": "C01"})
        self.assertEqual(cases["REF-S07"]["expected"], {"kind": "NO_SELECTION"})


if __name__ == "__main__":
    unittest.main()
