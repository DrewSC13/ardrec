"""R168-F11: rechazo de variantes R115 no autorizadas por R116."""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

import ardrec_p14_r116_f13_merge_gate as gate


class ExactR116Derivative(unittest.TestCase):

    def sandbox(self):
        tmp = tempfile.TemporaryDirectory(prefix="r168-f11-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        lock = json.loads((REPO / gate.LOCK).read_bytes())

        files = set(lock["source_sha256"])
        files.update((gate.LOCK, gate.CATALOG, gate.CI, gate.DOC))

        for name in files:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / name, target)

        return root

    def rejected(self, root, reason):
        with self.assertRaisesRegex(gate.GateFailure, reason):
            gate.evaluate(root)

    def test_01_full_signed_derivative_admitted(self):
        result = gate.evaluate(self.sandbox())
        self.assertEqual(
            result["source_integrity"],
            "PASS_87_PLUS_CI_SEPARATE",
        )
        self.assertEqual(result["p8"], "NO-GO")
        self.assertEqual(result["a6"], "ND")

    def test_02_r115_gate_exact_hash(self):
        raw = (REPO / gate.R162_GATE_PATH).read_bytes()
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            gate.R168_F10_GATE_SHA256,
        )

    def test_03_r115_gate_mutation_rejected(self):
        root = self.sandbox()
        target = root / gate.R162_GATE_PATH
        target.write_bytes(target.read_bytes() + b"\nALTERED\n")
        self.rejected(root, "SOURCE_DRIFT")

    def test_04_incomplete_derivative_rejected(self):
        for name in gate.R168_F10_REQUIRED_FIVE:
            with self.subTest(name=name):
                root = self.sandbox()
                target = root / name
                target.write_bytes(target.read_bytes() + b"\nALTERED\n")
                self.rejected(root, "SOURCE_DRIFT")

    def test_05_historical_pin_rewrite_rejected(self):
        root = self.sandbox()
        path = root / gate.LOCK
        lock = json.loads(path.read_bytes())
        lock["source_sha256"][gate.R162_GATE_PATH] = (
            gate.R168_F10_GATE_SHA256
        )
        path.write_text(json.dumps(lock), encoding="utf-8")
        self.rejected(root, "R115_GATE_HISTORICAL_PIN_CHANGED")

    def test_06_p8_go_still_rejected(self):
        root = self.sandbox()
        path = root / gate.LOCK
        lock = json.loads(path.read_bytes())
        lock["p8"] = "GO"
        path.write_text(json.dumps(lock), encoding="utf-8")
        self.rejected(root, "UNSAFE_LOCK:p8")


if __name__ == "__main__":
    unittest.main()
