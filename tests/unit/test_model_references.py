"""Auditar el catálogo de referencia sin invocar algoritmos de producción."""

from fractions import Fraction
import json
from math import gcd, lcm
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "tests/fixtures/model-reference-v1.json"


def rational(value):
    """Exigir el contrato exacto antes de construir una fracción."""
    if not isinstance(value, dict) or set(value) != {"numerator", "denominator"}:
        raise ValueError("Racional mal formado")
    n, d = value["numerator"], value["denominator"]
    if type(n) is not int or type(d) is not int or d <= 0 or gcd(abs(n), d) != 1:
        raise ValueError("Racional no canónico")
    return Fraction(n, d)


def read_catalog():
    return json.loads(CATALOG.read_text(encoding="utf-8"))


class ModelReferenceCatalogTests(unittest.TestCase):
    """Separar consistencia de referencias y verificación del modelo futuro."""

    def test_catalog_contract(self):
        catalog = read_catalog()
        cases = catalog["cases"]
        self.assertEqual(len(cases), 51)
        self.assertEqual(len({case["id"] for case in cases}), 51)
        self.assertEqual(catalog["model_verification"], "NOT_RUN")
        self.assertEqual(catalog["experimental_validation"], "NOT_RUN")
        self.assertEqual(catalog["status"], "REFERENCE_CORPUS")
        counts = {
            group: sum(case["group"] == group for case in cases)
            for group in catalog["groups"]
        }
        self.assertEqual(
            counts,
            {
                "numeric": 16,
                "rules": 9,
                "selection": 7,
                "evidence": 9,
                "transitions": 10,
            },
        )

        def inspect(value):
            self.assertNotIsInstance(value, float)
            if isinstance(value, dict):
                if "numerator" in value or "denominator" in value:
                    rational(value)
                for child in value.values():
                    inspect(child)
            elif isinstance(value, list):
                for child in value:
                    inspect(child)

        for case in cases:
            with self.subTest(case=case["id"]):
                self.assertEqual(case["production_test_status"], "NOT_RUN")
                self.assertIsInstance(case["input"], dict)
                self.assertIsInstance(case["expected"], dict)
                self.assertTrue(case["expected"])
                self.assertTrue(case["rationale"]["es"])
                self.assertTrue(case["rationale"]["en"])
                self.assertTrue(case["source_sections"])
                inspect(case)

    def test_acceptance_links(self):
        catalog = read_catalog()
        acceptance = json.loads(
            (ROOT / "docs/acceptance/system-v1.json").read_text(
                encoding="utf-8"
            )
        )
        criteria = {item["id"] for item in acceptance["criteria"]}
        self.assertEqual(catalog["source"], acceptance["source"])
        for case in catalog["cases"]:
            with self.subTest(case=case["id"]):
                self.assertTrue(case["acceptance_criteria"])
                self.assertLessEqual(
                    set(case["acceptance_criteria"]), criteria
                )
                self.assertLessEqual(
                    set(case["algorithms"]),
                    set(acceptance["algorithm_modules"]),
                )

    def test_numeric_reference_audit(self):
        # Contrastar valores literales sin importar módulos de ardrec.
        catalog = read_catalog()
        profile = catalog["numeric_profile"]
        self.assertEqual(
            [rational(value) for value in profile["beta"]],
            [Fraction(1, 2)] * 4,
        )
        self.assertEqual(
            [rational(value) for value in profile["lambda"]],
            [Fraction(1, 3)] * 3,
        )
        self.assertEqual(
            [rational(value) for value in profile["w"]],
            [Fraction(1, 3)] * 3,
        )

        for case in catalog["cases"]:
            if case["group"] != "numeric":
                continue

            with self.subTest(case=case["id"]):
                data = case["input"]
                op = case["operation"]
                expected = {
                    key: rational(value) if isinstance(value, dict) else value
                    for key, value in case["expected"].items()
                }

                if op == "baseline":
                    actual = {
                        "R0": Fraction(sum(data.values()) - 3, 12)
                    }

                elif op == "criticality":
                    _, middle, high = sorted(data["components"])
                    level = max(middle, high - 1)
                    actual = {
                        "C": level,
                        "CN": Fraction(level - 1, 4),
                    }

                elif op == "contribution":
                    reach = data["a"] + data["p"]
                    support = data["q"] + data["f"]
                    actual = {
                        "T": Fraction(reach, 8),
                        "S": Fraction(support, 8),
                        "e": Fraction(reach * support, 64),
                    }

                elif op == "substituted_baseline":
                    actual = {
                        "R0": Fraction(
                            data["x"] + data["pi"] + data["impact"] - 3,
                            12,
                        ),
                        "Rminus": Fraction(
                            data["x"]
                            + data["pi_minus"]
                            + data["impact_minus"]
                            - 3,
                            12,
                        ),
                    }

                elif op == "tolerance":
                    difference = abs(
                        rational(data["current"])
                        - rational(data["previous"])
                    )
                    actual = {
                        "difference": difference,
                        "within_tolerance": (
                            difference <= rational(data["epsilon"])
                        ),
                    }

                elif op == "recalibration":
                    # La escala entera común evita cualquier redondeo.
                    values = [
                        rational(data[key])
                        for key in ("R0", "Et", "CN", "Rminus")
                    ]
                    scale = lcm(*(value.denominator for value in values))
                    b, e, c, m = [
                        int(value * scale) for value in values
                    ]
                    denominator = 3 * scale

                    upper = (
                        3 * b if e == 0
                        else max(3 * b, b + e + c)
                    )
                    lower = max(3 * m, min(3 * b, b + m + c))
                    risk = upper + lower - 3 * b

                    self.assertTrue(
                        0 <= 3 * m <= lower <= risk <= upper <= denominator
                    )
                    actual = {
                        "PA": Fraction(b + e + c, denominator),
                        "Kplus": Fraction(b + e + c, denominator),
                        "Kminus": Fraction(b + m + c, denominator),
                        "U": Fraction(upper, denominator),
                        "D": Fraction(lower, denominator),
                        "Rf": Fraction(risk, denominator),
                    }

                else:
                    self.fail(f"Operación numérica no auditada: {op}")

                self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
