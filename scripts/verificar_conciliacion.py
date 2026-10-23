#!/usr/bin/env python3
"""Ejecutar las pruebas de conciliación sin depender de PYTHONPATH heredado."""

from pathlib import Path
import sys
import unittest

root = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(root / "src"), str(root / "tests/unit")]
suite = unittest.defaultTestLoader.discover(str(root / "tests/unit"), pattern="test_reconciliation.py")
result = unittest.TextTestRunner(verbosity=2).run(suite)
if result.testsRun != 35 or not result.wasSuccessful() or result.skipped:
    raise SystemExit("ARDREC_RECONCILIATION_TESTS=FAIL")
print("ARDREC_RECONCILIATION_TESTS=PASS")
print("ARDREC_RECONCILIATION_TEST_METHODS=35")
print("ARDREC_RECONCILIATION_SIGKILL_CASES=28")
print("ARDREC_REAL_EXECUTOR_TESTS=NOT_RUN")
