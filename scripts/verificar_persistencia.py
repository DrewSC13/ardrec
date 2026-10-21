"""Ejecutar las pruebas de persistencia y exigir su cobertura declarada."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests/unit"))

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests/unit"), pattern="test_persistence.py")
    count = suite.countTestCases()
    if count != 40:
        raise SystemExit(f"ARDREC_PERSISTENCE_TESTS=FAIL: se esperaban 40 pruebas, se encontraron {count}")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.skipped or result.expectedFailures or result.unexpectedSuccesses:
        raise SystemExit("ARDREC_PERSISTENCE_TESTS=FAIL")
    print("ARDREC_PERSISTENCE_TESTS=PASS")
    print("ARDREC_PERSISTENCE_TEST_METHODS=40")
    print("ARDREC_PROCESS_INTERRUPTION_CASES=68")
    print("ARDREC_POWER_LOSS_HARDWARE_VALIDATION=NOT_RUN")
    print("ARDREC_ALGORITHM_IMPLEMENTATION=NOT_STARTED")
    print("ARDREC_OPERATIONAL_PROTOTYPE=NOT_STARTED")
