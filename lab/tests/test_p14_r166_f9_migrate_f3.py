"""R166-F9: pruebas aisladas de alcance, CLI y reversión."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/ardrec_p14_r166_f9_migrate_f3.py"
SPEC = importlib.util.spec_from_file_location("r166_f9_migrate", SCRIPT)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class R166F9Tests(unittest.TestCase):

    def test_01_fixed_scope(self):
        self.assertEqual(
            m.BRANCH,
            "feat/ardrec-a1-a10-cierre-integral-v1"
        )
        self.assertEqual(len(m.TWO), 2)
        self.assertEqual(m.F3.parent, m.ROOT)
        self.assertEqual(m.CANDIDATE.parent, m.ROOT)
        self.assertEqual(m.ARCHIVE.parent, m.ROOT)

    def test_02_hash_and_canonical_json(self):
        self.assertEqual(
            m.sha(b""),
            hashlib.sha256(b"").hexdigest()
        )
        self.assertEqual(
            m.canon({"z": 1, "a": 2}),
            b'{"a":2,"z":1}\n'
        )

    def test_03_allowed_source_paths(self):
        self.assertEqual(
            m.source_path("root-pilot.py"),
            "scripts/ardrec_p14_r116_f3_root_pilot.py"
        )
        self.assertEqual(
            m.source_path("runtime/ardrec/coordination/example.py"),
            "src/ardrec/coordination/example.py"
        )

    def test_04_path_traversal_rejected(self):
        for name in ("../etc/shadow", "/etc/passwd",
                     "runtime/ardrec/coordination/../secret.py"):
            with self.subTest(name=name):
                with self.assertRaises(m.Stop):
                    m.source_path(name)

    def test_05_root_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original"
            link = root / "linked"
            original.write_bytes(b"test")
            link.symlink_to(original)
            with self.assertRaises(m.Stop):
                m.root_file(link)
            with self.assertRaises(m.Stop):
                m.directory(link)

    def test_06_apply_without_exact_consent_rejected(self):
        with patch.object(sys, "argv", [
            "operator", "--apply", "--confirm", "YES"
        ]), patch.object(m, "migrate") as migrate:
            self.assertEqual(m.main(), 23)
            migrate.assert_not_called()

    def test_07_inspection_never_migrates(self):
        with patch.object(sys, "argv", [
            "operator", "--inspect"
        ]), patch.object(m, "preflight",
                         return_value=("test-head", {}, {})), \
             patch.object(m, "migrate") as migrate:
            self.assertEqual(m.main(), 0)
            migrate.assert_not_called()

    def test_08_apply_requires_exact_consent(self):
        with patch.object(sys, "argv", [
            "operator", "--apply",
            "--confirm", "AUTORIZO_MIGRAR_SOLO_F3"
        ]), patch.object(m, "migrate") as migrate:
            self.assertEqual(m.main(), 0)
            migrate.assert_called_once_with()

    def simulate(self, failure):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        root = Path(temporary.name)
        old = root / "f3"
        candidate = root / "candidate"
        archive = root / "archive"

        old.mkdir()
        (old / "old-marker").write_text("old")

        def stage():
            candidate.mkdir()
            (candidate / "new-marker").write_text("new")

        guard = (
            m.Stop("SYNTHETIC_POST_PROMOTION_FAILURE")
            if failure else None
        )

        with patch.object(m, "F3", old), \
             patch.object(m, "CANDIDATE", candidate), \
             patch.object(m, "ARCHIVE", archive), \
             patch.object(m, "preflight",
                          return_value=("head", {}, {})), \
             patch.object(m.runpy, "run_path",
                          return_value={"stage": stage}), \
             patch.object(m, "compare_bundle"), \
             patch.object(m, "root_file",
                          return_value=b"synthetic-catalog"), \
             patch.object(m, "signed_source",
                          return_value=b"synthetic-catalog"), \
             patch.object(m, "deny_check",
                          side_effect=guard), \
             patch.object(m, "fsync_dir"):

            if failure:
                with self.assertRaises(m.Stop):
                    m.migrate()
            else:
                m.migrate()

        return old, archive

    def test_09_success_preserves_old_f3(self):
        current, archive = self.simulate(False)
        self.assertEqual(
            (current / "new-marker").read_text(), "new"
        )
        self.assertEqual(
            (archive / "previous-f3" / "old-marker").read_text(),
            "old"
        )
        result = json.loads((archive / "result.json").read_text())
        self.assertEqual(result["result"], "PASS")
        self.assertFalse(result["f1_modified"])
        self.assertEqual(result["p8"], "NO-GO")

    def test_10_failure_restores_old_f3(self):
        current, archive = self.simulate(True)
        self.assertEqual(
            (current / "old-marker").read_text(), "old"
        )
        self.assertEqual(
            (archive / "rejected-new-f3" / "new-marker").read_text(),
            "new"
        )


if __name__ == "__main__":
    unittest.main()
