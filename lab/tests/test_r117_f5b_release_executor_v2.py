"""R117 root executor static safety regression."""
import ast
from pathlib import Path
import unittest

SOURCE = (
    Path(__file__).resolve().parents[2] /
    "scripts/ardrec_r117_f5b_release_executor_v2.py"
)


class RootExecutorV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text()
        cls.tree = ast.parse(cls.source)

    def test_01_source_compiles(self):
        compile(self.source, str(SOURCE), "exec")

    def test_02_exact_candidate_head(self):
        self.assertIn(
            "1521f3af69e7875f6c79a60d7a905e5fbffdcba1",
            self.source,
        )

    def test_03_exact_candidate_sha(self):
        self.assertIn(
            "fd75683758681684447d5f3c59c249d8077de914aa324b5c880a6fa23d03b11a",
            self.source,
        )

    def test_04_two_root_public_keys(self):
        self.assertIn(
            "r117-authorities-v1/approval-public.pem",
            self.source,
        )
        self.assertIn(
            "r117-authorities-v1/revocation-public.pem",
            self.source,
        )

    def test_05_explicit_authorization(self):
        self.assertIn(
            "--i-authorize-source-only-release",
            self.source,
        )

    def test_06_no_automatic_boot_code(self):
        names = {
            node.func.id
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
        }
        self.assertNotIn("boot", names)
        self.assertNotIn("start_vm", names)

    def test_07_persistent_ledger(self):
        self.assertIn(
            "O_EXCL", self.source
        )
        self.assertIn(
            "AUTHORIZATION-LEDGER-v2", self.source
        )

    def test_08_physical_preflight_required(self):
        self.assertIn(
            "check_physical_deny()", self.source
        )

    def test_09_transaction_engine_used(self):
        self.assertIn(
            "installed = txn.install(", self.source
        )

    def test_10_no_git_runtime_dependency(self):
        self.assertNotIn(
            '"/usr/bin/git"', self.source
        )


if __name__ == "__main__":
    unittest.main()
