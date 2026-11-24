"""R168-F10: comprobacion exacta de derivaciones historicas R115."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
import ardrec_p14_r115_f17_merge_gate as gate


class StrictR168Derivative(unittest.TestCase):

    def sandbox(self):
        temp = tempfile.TemporaryDirectory(prefix="r168-f10-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        lock = json.loads((REPO / gate.LOCK).read_bytes())

        paths = set(lock["source_sha256"])
        paths.update((gate.LOCK, gate.CATALOG, gate.CI, gate.DOC))

        for name in paths:
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / name, destination)

        return root

    def test_01_exact_derivative_passes(self):
        result = gate.evaluate(self.sandbox())
        self.assertEqual(result["source_integrity"], "PASS_58")
        self.assertEqual(result["p8"], "NO-GO")

    def test_02_historical_lock_remains_unchanged(self):
        lock = json.loads((REPO / gate.LOCK).read_bytes())
        self.assertEqual(lock["source_count"], 58)

        for name, pair in gate.R168_WHOLE_SOURCE_VARIANT.items():
            self.assertEqual(lock["source_sha256"][name], pair[0])
            self.assertNotEqual(pair[0], pair[1])

    def test_03_every_derivative_is_exact(self):
        import hashlib

        for name, (_, expected) in gate.R168_WHOLE_SOURCE_VARIANT.items():
            with self.subTest(name=name):
                actual = hashlib.sha256((REPO / name).read_bytes()).hexdigest()
                self.assertEqual(actual, expected)

    def test_04_any_derivative_mutation_rejected(self):
        for name in gate.R168_WHOLE_SOURCE_VARIANT:
            with self.subTest(name=name):
                root = self.sandbox()
                target = root / name
                target.write_bytes(target.read_bytes() + b"\nTAMPER\n")

                with self.assertRaisesRegex(
                    gate.GateFailure, "SOURCE_DRIFT"
                ):
                    gate.evaluate(root)

    def test_05_rewriting_historical_pin_rejected(self):
        root = self.sandbox()
        lock_path = root / gate.LOCK
        lock = json.loads(lock_path.read_bytes())

        name = next(iter(gate.R168_WHOLE_SOURCE_VARIANT))
        lock["source_sha256"][name] = (
            gate.R168_WHOLE_SOURCE_VARIANT[name][1]
        )
        lock_path.write_text(json.dumps(lock), encoding="utf-8")

        with self.assertRaisesRegex(
            gate.GateFailure, "SOURCE_DRIFT"
        ):
            gate.evaluate(root)


if __name__ == "__main__":
    unittest.main()
