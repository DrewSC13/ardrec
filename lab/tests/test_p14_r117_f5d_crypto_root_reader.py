"""F5D-A: real ephemeral Ed25519 and safe file-descriptor tests."""
from datetime import datetime, timezone
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / (
    "scripts/ardrec_p14_r117_f5d_crypto_root_reader.py"
)

spec = importlib.util.spec_from_file_location(
    "ardrec_f5d_a", SCRIPT
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class CryptoAndRootReaderTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(
            prefix="ardrec-f5d-a-tests-"
        )
        cls.folder = Path(cls.temp.name)
        cls.now = datetime(
            2026, 11, 20, 22, 31, 0,
            tzinfo=timezone.utc,
        )
        cls.head = "a" * 40
        cls.candidate = "b" * 64

        def run(args):
            p = subprocess.run(
                [m.OPENSSL, *args],
                capture_output=True,
                check=False,
                stdin=subprocess.DEVNULL,
                timeout=10,
            )
            if p.returncode:
                raise RuntimeError(
                    "OPENSSL_TEST_SETUP_FAILED: " +
                    p.stderr.decode("utf-8", "replace")[:150]
                )

        for role in ("release", "revocation"):
            private = cls.folder / (role + ".private.pem")
            public = cls.folder / (role + ".public.pem")
            run([
                "genpkey", "-algorithm", "Ed25519",
                "-out", str(private),
            ])
            run([
                "pkey", "-in", str(private),
                "-pubout", "-out", str(public),
            ])

        cls.release_public = (
            cls.folder / "release.public.pem"
        ).read_bytes()
        cls.revocation_public = (
            cls.folder / "revocation.public.pem"
        ).read_bytes()

        cls.approval = {
            "schema":
                "ARDREC-R117-F5B-ROOT-INSTALL-APPROVAL-v1",
            "head": cls.head,
            "candidate_sha256": cls.candidate,
            "valid_from": "2026-11-20T22:30:00Z",
            "valid_until": "2026-11-20T22:35:00Z",
            "purpose": "INSTALL_SOURCE_ONLY",
            "authority": "ephemeral-release-test",
            "p8": "NO-GO",
        }

        cls.revocation = {
            "schema": m.REVOCATION_SCHEMA,
            "head": cls.head,
            "candidate_sha256": cls.candidate,
            "issued_at": "2026-11-20T22:30:30Z",
            "valid_until": "2026-11-20T22:31:30Z",
            "revoked": False,
            "authority": "ephemeral-revocation-test",
            "p8": "NO-GO",
        }

        import json

        def canonical(obj):
            return (
                json.dumps(
                    obj, sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ) + "\n"
            ).encode("ascii")

        cls.canonical = staticmethod(canonical)
        cls.approval_raw = canonical(cls.approval)
        cls.revocation_raw = canonical(cls.revocation)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def sign(self, role, message):
        message_path = self.folder / "sign-message.bin"
        signature_path = self.folder / "sign-result.bin"

        message_path.write_bytes(message)

        p = subprocess.run(
            [
                m.OPENSSL, "pkeyutl", "-sign", "-rawin",
                "-inkey", str(
                    self.folder / (role + ".private.pem")
                ),
                "-in", str(message_path),
                "-out", str(signature_path),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(
            p.returncode, 0,
            p.stderr.decode("utf-8", "replace"),
        )
        return signature_path.read_bytes()

    def statements(self, *,
                   approval=None, revocation=None,
                   head=None,
                   approval_public=None,
                   revocation_public=None):
        a = self.canonical(
            self.approval if approval is None
            else approval
        )
        r = self.canonical(
            self.revocation if revocation is None
            else revocation
        )

        return m.verify_statements(
            self.head if head is None else head,
            self.candidate,
            a,
            self.sign("release", m.APPROVAL_PREFIX + a),
            self.release_public if approval_public is None
            else approval_public,
            r,
            self.sign(
                "revocation",
                m.REVOCATION_PREFIX + r,
            ),
            self.revocation_public if revocation_public is None
            else revocation_public,
            now=self.now,
            repo=REPO,
        )

    def tree(self):
        root = Path(tempfile.mkdtemp(
            prefix="fixture-root-",
            dir=str(self.folder),
        ))
        os.chmod(root, 0o700)

        nested = root / "runtime"
        nested.mkdir(mode=0o700)
        os.chmod(nested, 0o700)

        (root / "a.txt").write_bytes(b"alpha")
        (nested / "b.txt").write_bytes(b"beta")

        os.chmod(root / "a.txt", 0o600)
        os.chmod(nested / "b.txt", 0o600)

        return root

    def test_fixtures_have_independent_directories(self):
        first = self.tree()
        second = self.tree()

        self.assertNotEqual(first, second)
        self.assertTrue(first.is_dir())
        self.assertTrue(second.is_dir())
        self.assertEqual(
            (first / "a.txt").read_bytes(), b"alpha"
        )
        self.assertEqual(
            (second / "a.txt").read_bytes(), b"alpha"
        )

    def read(self, root):
        fd = os.open(root, m.FLAGS_DIR)
        try:
            return m.read_tree_fd(
                fd,
                {"a.txt", "runtime/b.txt"},
                uid=os.geteuid(),
            )
        finally:
            os.close(fd)

    def test_real_ed25519_independent_signatures(self):
        result = self.statements()
        self.assertEqual(result["approval_ed25519"], "VERIFIED")
        self.assertEqual(result["revocation_ed25519"], "VERIFIED")
        self.assertIs(result["boot_authorized"], False)

    def test_modified_message_rejected(self):
        raw = self.approval_raw
        sig = self.sign("release", m.APPROVAL_PREFIX + raw)
        with self.assertRaises(m.Stop):
            m.ed25519_verify(
                self.release_public,
                m.APPROVAL_PREFIX + raw + b"x",
                sig,
            )

    def test_wrong_public_key_rejected(self):
        raw = self.approval_raw
        sig = self.sign("release", m.APPROVAL_PREFIX + raw)
        with self.assertRaises(m.Stop):
            m.ed25519_verify(
                self.revocation_public,
                m.APPROVAL_PREFIX + raw,
                sig,
            )

    def test_wrong_signature_length_rejected(self):
        with self.assertRaises(m.Stop):
            m.ed25519_verify(
                self.release_public, b"hello",
                b"\x00" * 63,
            )

    def test_revoked_statement_rejected(self):
        document = dict(self.revocation)
        document["revoked"] = True
        with self.assertRaises(m.Stop):
            self.statements(revocation=document)

    def test_stale_revocation_rejected(self):
        document = dict(self.revocation)
        document["issued_at"] = "2026-11-20T22:20:00Z"
        document["valid_until"] = "2026-11-20T22:21:00Z"
        with self.assertRaises(m.Stop):
            self.statements(revocation=document)

    def test_wrong_head_rejected(self):
        with self.assertRaises(m.Stop):
            self.statements(head="c" * 40)

    def test_wrong_candidate_rejected(self):
        document = dict(self.approval)
        document["candidate_sha256"] = "c" * 64
        with self.assertRaises(m.Stop):
            self.statements(approval=document)

    def test_root_directory_reader_accepts_exact_tree(self):
        root = self.tree()
        result = self.read(root)
        self.assertEqual(
            result,
            {
                "a.txt": b"alpha",
                "runtime/b.txt": b"beta",
            },
        )

    def test_extra_file_rejected(self):
        root = self.tree()
        extra = root / "extra.txt"
        extra.write_bytes(b"extra")
        os.chmod(extra, 0o600)
        with self.assertRaises(m.Stop):
            self.read(root)

    def test_missing_file_rejected(self):
        root = self.tree()
        (root / "a.txt").unlink()
        with self.assertRaises(m.Stop):
            self.read(root)

    def test_symbolic_link_rejected(self):
        root = self.tree()
        (root / "a.txt").unlink()
        (root / "a.txt").symlink_to(
            root / "runtime/b.txt"
        )
        with self.assertRaises((m.Stop, OSError)):
            self.read(root)

    def test_insecure_file_permissions_rejected(self):
        root = self.tree()
        os.chmod(root / "a.txt", 0o644)
        with self.assertRaises(m.Stop):
            self.read(root)

    def test_insecure_directory_permissions_rejected(self):
        root = self.tree()
        os.chmod(root / "runtime", 0o755)
        with self.assertRaises(m.Stop):
            self.read(root)

    def test_hardlink_rejected(self):
        root = self.tree()
        target = root.parent / (
            root.name + "-hardlink.txt"
        )
        os.link(root / "a.txt", target)
        with self.assertRaises(m.Stop):
            self.read(root)

    def test_wrong_owner_rejected(self):
        root = self.tree()
        fd = os.open(root, m.FLAGS_DIR)
        try:
            with self.assertRaises(m.Stop):
                m.read_tree_fd(
                    fd,
                    {"a.txt", "runtime/b.txt"},
                    uid=os.geteuid() + 1,
                )
        finally:
            os.close(fd)

if __name__ == "__main__":
    unittest.main()
