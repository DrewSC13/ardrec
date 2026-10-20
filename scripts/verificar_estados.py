#!/usr/bin/env python3
"""Comprobar contratos de estado sin ejecutar herramientas ni publicar generaciones."""

import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main():
    if sys.version_info[:3] != (3, 14, 7):
        raise RuntimeError("Se requiere Python 3.14.7, conforme al entorno fijado")
    fixture = ROOT / "tests/fixtures/messages-v2.json"
    before = hashlib.sha256(fixture.read_bytes()).hexdigest()
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests/unit"), pattern="test_state.py")
    expected = suite.countTestCases()
    if expected != 44:
        raise RuntimeError(f"Cantidad inesperada de pruebas de estado: {expected}")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.skipped or result.testsRun != expected:
        raise RuntimeError("Las pruebas de estado no se ejecutaron íntegramente")
    if hashlib.sha256(fixture.read_bytes()).hexdigest() != before:
        raise RuntimeError("Los mensajes de referencia cambiaron")
    print(json.dumps({
        "component": "state_models", "source": "TESIS ARDREC", "python": "3.14.7",
        "test_methods": result.testsRun, "service_states": 8,
        "service_transition_variants": 11, "origin_transition_pairs": 88,
        "local_state_model_verification": "PASS", "protocol_fixtures_unchanged": True,
        "durable_reconciliation": "PENDING", "system_functional_acceptance": "PENDING",
        "algorithm_tests": "NOT_RUN", "experimental_validation": "NOT_RUN",
    }, ensure_ascii=False, indent=2))
    print("ARDREC_STATE_MODEL_TESTS=PASS")
    print(f"ARDREC_STATE_TEST_METHODS={result.testsRun}")
    print("ARDREC_STATE_CONFIRMED_GENERATION_PRESERVED=PASS")
    print("ARDREC_STATE_UNCERTAINTY_BLOCKS=PASS")
    print("ARDREC_STATE_TERMINAL_GUARDS=PASS")
    print("ARDREC_ALGORITHM_TESTS=NOT_RUN")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"ARDREC_STATE_MODEL_TESTS=FAIL: {error}", file=sys.stderr)
        sys.exit(1)
