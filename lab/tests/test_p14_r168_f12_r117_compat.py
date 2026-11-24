
"""R168-F12: variante exacta del inventario R116, sin autoridad root."""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import ardrec_p14_r117_f4_dispatch_audit as f4
import ardrec_p14_r117_f5_root_candidate as f5

class StrictRootLock(unittest.TestCase):

    def fixture(self):
        t = tempfile.TemporaryDirectory(prefix="r168-f12-")
        self.addCleanup(t.cleanup)
        root = Path(t.name)
        for rel in (f4.LOCK, f4.MANIFEST):
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, target)
        return root

    def test_01_f4_current_derivative(self):
        result = f4.audit_offline(ROOT)
        self.assertEqual(result["p8"], "NO-GO")
        self.assertEqual(result["root_f3_immutable_source_count"], 33)

    def test_02_f5a_candidate(self):
        payload, lock = f5.checked_sources(ROOT)
        self.assertEqual(len(lock["files"]), 33)
        self.assertEqual(len(payload), 38)

    def test_03_unknown_hash_denied(self):
        root = self.fixture()
        path = root / f4.LOCK
        path.write_bytes(path.read_bytes() + b"ALTERED")
        with self.assertRaisesRegex(f4.Stop, "HISTORIC_33_LOCK_DRIFT"):
            f4.audit_offline(root)

    def test_04_rewritten_historical_pin_denied(self):
        root = self.fixture()
        path = root / f4.MANIFEST
        obj = json.loads(path.read_bytes())
        obj["historical_f3_lock_sha256"] = f4.R168_DERIVED_LOCK_SHA
        path.write_text(json.dumps(obj))
        with self.assertRaisesRegex(f4.Stop, "HISTORIC_33_MANIFEST_PIN_DRIFT"):
            f4.audit_offline(root)

    def test_05_unapproved_f5a_lock_denied(self):
        root = self.fixture()
        path = root / f4.LOCK
        obj = json.loads(path.read_bytes())
        name = "runtime/ardrec/coordination/r115_f7_controlled_boot.py"
        assert name in obj["files"]
        obj["files"][name] = "0" * 64
        path.write_text(json.dumps(obj), encoding="utf-8")
        with self.assertRaisesRegex(f5.Stop, "R117_F4_DISPATCH_INVALID"):
            f5.checked_sources(root)

    def test_06_network_authority_denied(self):
        root = self.fixture()
        path = root / f4.MANIFEST
        obj = json.loads(path.read_bytes())
        obj["network_traffic"] = True
        path.write_text(json.dumps(obj))
        with self.assertRaisesRegex(f4.Stop, "DISPATCH_MANIFEST_CHANGED"):
            f4.audit_offline(root)

if __name__ == "__main__":
    unittest.main()
