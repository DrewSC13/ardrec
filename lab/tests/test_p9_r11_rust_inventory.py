"""P9-R11-R02: inventario exacto, sin ensanchar la aceptación histórica."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'ardrec_r11_traceability_gate', ROOT / 'scripts/verificar_trazabilidad_actual.py'
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError('traceability_checker_unavailable')
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def actual_inventory() -> dict[str, str]:
    out: dict[str, str] = {}
    for source in (ROOT / 'crates/ardrec-executor/src').rglob('*.rs'):
        for name in re.findall(r'#\[test\]\s*fn\s+(\w+)\s*\(',
                               source.read_text(encoding='utf-8')):
            key = source.relative_to(ROOT).as_posix() + '::' + name
            if key in out:
                raise AssertionError('duplicate_rust_test:' + key)
            out[key] = name
    return out


class P9R11InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        registry = json.loads(
            (ROOT / 'docs/traceability/development-v2.json').read_text(encoding='utf-8')
        )
        cls.checks = {item['id']: item for item in registry['test_inventory']}
        cls.observed = actual_inventory()

    def test_exact_historical_p8_and_p9_inventory(self):
        result = CHECKER.verify_p8_rust_inventory(self.observed, self.checks)
        self.assertEqual(result['historical_rust_tests'], 73)
        self.assertEqual(result['p8_r53_r54_rust_tests'], 24)
        self.assertEqual(result['p9_r11_rust_tests'], 2)
        self.assertEqual(result['current_rust_lib_tests'], 99)
        self.assertFalse(result['historical_inventory_changed'])

    def test_missing_r11_method_fails_closed(self):
        minus = dict(self.observed)
        del minus['crates/ardrec-executor/src/p9_r11_witness_probe.rs::parses_stat_with_inner_parentheses']
        with self.assertRaisesRegex(ValueError, 'Inventario Rust incompleto'):
            CHECKER.verify_p8_rust_inventory(minus, self.checks)

    def test_extra_rust_method_fails_closed(self):
        plus = dict(self.observed)
        plus['crates/ardrec-executor/src/p9_r11_witness_probe.rs::invented'] = 'invented'
        with self.assertRaisesRegex(ValueError, 'Inventario Rust incompleto'):
            CHECKER.verify_p8_rust_inventory(plus, self.checks)

    def test_renamed_r11_method_fails_closed(self):
        shifted = dict(self.observed)
        key = 'crates/ardrec-executor/src/p9_r11_witness_probe.rs::parses_uid_without_accepting_missing_data'
        shifted.pop(key)
        shifted[key + '_renamed'] = 'parses_uid_without_accepting_missing_data_renamed'
        with self.assertRaisesRegex(ValueError, 'Inventario Rust incompleto'):
            CHECKER.verify_p8_rust_inventory(shifted, self.checks)


if __name__ == '__main__':
    unittest.main()
