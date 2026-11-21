"""R117-F5D-B integration tests: FD + F5C + genuine Ed25519."""
from datetime import datetime, timezone
from io import BytesIO
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / (
    "scripts/ardrec_p14_r117_f5d_b_integrated_attestation.py"
)

spec = importlib.util.spec_from_file_location(
    "f5d_b_test_module", SOURCE
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class IntegratedSnapshotTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.c, cls.d = m.modules(REPO)
        cls.a, cls.b = cls.c.modules(REPO)

        cls.keys = tempfile.TemporaryDirectory(
            prefix="ardrec-f5d-b-test-keys-"
        )
        cls.keydir = Path(cls.keys.name)

        for name in ("approval", "revocation"):
            private = cls.keydir / (name + ".private.pem")
            public = cls.keydir / (name + ".public.pem")

            cls.openssl(
                "genpkey", "-algorithm", "Ed25519",
                "-out", str(private)
            )
            cls.openssl(
                "pkey", "-in", str(private),
                "-pubout", "-out", str(public)
            )

        cls.approval_key = (
            cls.keydir / "approval.public.pem"
        ).read_bytes()

        cls.revocation_key = (
            cls.keydir / "revocation.public.pem"
        ).read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    @staticmethod
    def openssl(*args):
        result = subprocess.run(
            ["/usr/bin/openssl", *args],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
        if result.returncode:
            raise RuntimeError(
                "OPENSSL_TEST_FAILED:" +
                result.stderr.decode(
                    "utf-8", "replace"
                )[:200]
            )

    @classmethod
    def sign(cls, role, raw):
        message = cls.keydir / (role + ".message.bin")
        signature = cls.keydir / (role + ".signature.bin")

        message.write_bytes(raw)

        cls.openssl(
            "pkeyutl", "-sign", "-rawin",
            "-inkey",
            str(cls.keydir / (role + ".private.pem")),
            "-in", str(message),
            "-out", str(signature),
        )

        return signature.read_bytes()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="ardrec-f5d-b-snapshot-"
        )
        self.addCleanup(self.temp.cleanup)

        self.folder = Path(self.temp.name)
        self.now = datetime(
            2026, 11, 20, 22, 31, 0,
            tzinfo=timezone.utc,
        )
        self.head = "a" * 40

        self.candidate = self.a.candidate(
            self.head, repo=REPO
        )

        with zipfile.ZipFile(
            BytesIO(self.candidate)
        ) as archive:
            pilot = {
                name: archive.read(name)
                for name in archive.namelist()
            }

        approval = {
            "schema": self.b.APPROVAL_SCHEMA,
            "head": self.head,
            "candidate_sha256":
                self.a.sha(self.candidate),
            "valid_from": "2026-11-20T22:30:00Z",
            "valid_until": "2026-11-20T22:35:00Z",
            "purpose": "INSTALL_SOURCE_ONLY",
            "authority": "ephemeral-test-approval",
            "p8": "NO-GO",
        }
        approval_raw = self.a.canonical(approval)

        receipt = self.b.release_receipt(
            self.a, self.head,
            pilot["manifest.json"], repo=REPO
        )
        receipt_raw = self.a.canonical(receipt)

        release = {
            "receipt.json": receipt_raw,
            "approval.json": approval_raw,
            "approval.sig": self.sign(
                "approval",
                self.d.APPROVAL_PREFIX + approval_raw,
            ),
        }

        intent = {
            "schema": self.c.INTENT_SCHEMA,
            "head": self.head,
            "candidate_sha256":
                self.a.sha(self.candidate),
            "approval_sha256": self.a.sha(approval_raw),
            "status": "SOURCE_INSTALL_ATTEMPT",
            "p8": "NO-GO",
        }

        complete = {
            "schema": self.c.COMPLETE_SCHEMA,
            "head": self.head,
            "pilot_manifest_sha256":
                self.a.sha(pilot["manifest.json"]),
            "receipt_sha256": self.a.sha(receipt_raw),
            "approved_install": True,
            "boot_permit_issued": False,
            "network_connections": 0,
            "vm_starts": 0,
            "p8": "NO-GO",
        }

        journal = {
            **self.c.JOURNAL_MARKERS,
            "intent.json": self.a.canonical(intent),
            "complete.json": self.a.canonical(complete),
        }

        self.revocation = {
            "schema": self.d.REVOCATION_SCHEMA,
            "head": self.head,
            "candidate_sha256":
                self.a.sha(self.candidate),
            "issued_at": "2026-11-20T22:30:30Z",
            "valid_until": "2026-11-20T22:31:30Z",
            "revoked": False,
            "authority": "ephemeral-test-revocation",
            "p8": "NO-GO",
        }

        self.revocation_raw = self.a.canonical(
            self.revocation
        )
        self.revocation_sig = self.sign(
            "revocation",
            self.d.REVOCATION_PREFIX +
            self.revocation_raw,
        )

        self.pilot = self.tree(
            "pilot", pilot, extra_empty=("authority",)
        )
        self.release = self.tree("release", release)
        self.journal = self.tree("journal", journal)

    def tree(self, name, files, extra_empty=()):
        root = self.folder / name
        root.mkdir(mode=0o700)
        os.chmod(root, 0o700)

        for relative, raw in files.items():
            path = root
            components = Path(relative).parts

            for component in components[:-1]:
                path = path / component
                if not path.exists():
                    path.mkdir(mode=0o700)
                os.chmod(path, 0o700)

            target = root / relative
            with target.open("xb") as stream:
                stream.write(raw)
            os.chmod(target, 0o600)

        for relative in extra_empty:
            path = root / relative
            path.mkdir(mode=0o700)
            os.chmod(path, 0o700)

        return root

    def check(self, **kwargs):
        descriptors = [
            os.open(path, self.d.FLAGS_DIR)
            for path in (
                self.pilot, self.release, self.journal
            )
        ]

        try:
            return m.verify_fd_snapshot(
                kwargs.get("head", self.head),
                kwargs.get("candidate", self.candidate),
                *descriptors,
                kwargs.get(
                    "approval_key", self.approval_key
                ),
                kwargs.get(
                    "revocation_raw", self.revocation_raw
                ),
                kwargs.get(
                    "revocation_sig", self.revocation_sig
                ),
                kwargs.get(
                    "revocation_key", self.revocation_key
                ),
                now=self.now,
                uid=kwargs.get("uid", os.geteuid()),
                repo=REPO,
            )
        finally:
            for fd in descriptors:
                os.close(fd)

    def rejected(self, **kwargs):
        with self.assertRaises(m.Stop):
            self.check(**kwargs)

    def change(self, folder, name, raw):
        (folder / name).write_bytes(raw)

    def test_integrated_positive(self):
        result = self.check()
        self.assertEqual(
            result["structural_closure"], "CONSISTENT"
        )
        self.assertEqual(result["files_verified"], 39)
        self.assertEqual(
            result["approval_ed25519"],
            "VERIFIED_SUPPLIED_KEY",
        )
        self.assertIs(
            result["root_release_accepted"], False
        )
        self.assertIs(result["boot_authorized"], False)
        self.assertEqual(result["p8"], "NO-GO")

    def test_missing_completion(self):
        (self.journal / "complete.json").unlink()
        self.rejected()

    def test_missing_publication_marker(self):
        (
            self.journal / "release-visible.once"
        ).unlink()
        self.rejected()

    def test_modified_pilot_source(self):
        target = self.pilot / "root-pilot.py"
        self.change(
            self.pilot, "root-pilot.py",
            target.read_bytes() + b"# changed\n"
        )
        self.rejected()

    def test_modified_receipt(self):
        self.change(
            self.release, "receipt.json", b"{}\n"
        )
        self.rejected()

    def test_modified_approval(self):
        self.change(
            self.release, "approval.json", b"{}\n"
        )
        self.rejected()

    def test_modified_approval_signature(self):
        self.change(
            self.release, "approval.sig",
            b"\x00" * 64
        )
        self.rejected()

    def test_wrong_approval_public_key(self):
        self.rejected(
            approval_key=self.revocation_key
        )

    def test_revoked_statement(self):
        data = dict(self.revocation)
        data["revoked"] = True
        raw = self.a.canonical(data)
        signature = self.sign(
            "revocation",
            self.d.REVOCATION_PREFIX + raw
        )
        self.rejected(
            revocation_raw=raw,
            revocation_sig=signature,
        )

    def test_expired_revocation(self):
        data = dict(self.revocation)
        data["issued_at"] = "2026-11-20T22:20:00Z"
        data["valid_until"] = "2026-11-20T22:21:00Z"
        raw = self.a.canonical(data)
        signature = self.sign(
            "revocation",
            self.d.REVOCATION_PREFIX + raw
        )
        self.rejected(
            revocation_raw=raw,
            revocation_sig=signature,
        )

    def test_same_key_for_both_statements(self):
        signature = self.sign(
            "approval",
            self.d.REVOCATION_PREFIX +
            self.revocation_raw
        )
        self.rejected(
            revocation_sig=signature,
            revocation_key=self.approval_key,
        )

    def test_modified_revocation_signature(self):
        self.rejected(
            revocation_sig=b"\x00" * 64
        )

    def test_wrong_head(self):
        self.rejected(head="b" * 40)

    def test_wrong_candidate(self):
        self.rejected(
            candidate=self.candidate + b"changed"
        )

    def test_extra_pilot_file(self):
        target = self.pilot / "unexpected.txt"
        target.write_bytes(b"not allowed")
        os.chmod(target, 0o600)
        self.rejected()

    def test_extra_authority_file(self):
        target = self.pilot / "authority" / "permit.json"
        target.write_bytes(b"{}\n")
        os.chmod(target, 0o600)
        self.rejected()

    def test_symlink_rejected(self):
        target = self.pilot / "root-pilot.py"
        target.unlink()
        target.symlink_to(self.pilot / "catalog.json")
        self.rejected()

    def test_insecure_permissions(self):
        target = self.pilot / "root-pilot.py"
        os.chmod(target, 0o644)
        self.rejected()

    def test_hardlink_rejected(self):
        target = self.folder / "hardlink-outside.txt"
        os.link(
            self.pilot / "root-pilot.py",
            target,
        )
        self.rejected()

    def test_wrong_owner(self):
        self.rejected(uid=os.geteuid() + 1)

if __name__ == "__main__":
    unittest.main()
