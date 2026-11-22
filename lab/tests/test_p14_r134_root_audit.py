"""R134: auditoría criptográfica y fallo cerrado."""

from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ardrec.coordination import r130_b17_r6b3_root_candidate as source

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/ardrec_p14_r134_independent_root_installer.py"

spec = importlib.util.spec_from_file_location("ardrec_r134_audit", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

HEAD = "118906392855a240342365373485c92670516194"
TREE = "55fb247cfa9e22f15ffed198dcf8f81a78a6d145"
BOOT = "00000000-0000-4000-8000-000000000000"
NOW = datetime(2026, 11, 22, 3, 0, 5, tzinfo=timezone.utc)


def openssl(*args):
    result = subprocess.run(
        ["/usr/bin/openssl", *map(str, args)],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("TEST_CRYPTO_ERROR")
    return result.stdout


class AuditTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(
            prefix="ardrec-r134-test-only-"
        )
        cls.folder = Path(cls.temp.name)
        cls.keys = {}

        for name in ("install", "revoke", *(f"u{i}" for i in range(10))):
            private = cls.folder / (name + ".key")
            public = cls.folder / (name + ".pub")
            openssl(
                "genpkey", "-algorithm", "ED25519", "-out", private
            )
            openssl(
                "pkey", "-in", private, "-pubout", "-out", public
            )
            cls.keys[name] = (
                private,
                public.read_text(encoding="ascii"),
            )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def key(self, name):
        return {
            "key_id": "r134.test." + name,
            "public_key_pem": self.keys[name][1],
        }

    def sign(self, statement, name, prefix):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            message = root / "message"
            signature = root / "signature"
            message.write_bytes(prefix + m.canon(statement))
            openssl(
                "pkeyutl", "-sign",
                "-inkey", self.keys[name][0],
                "-rawin", "-in", message,
                "-out", signature,
            )
            raw = signature.read_bytes()

        return {
            "statement": copy.deepcopy(statement),
            "signer_key_id": "r134.test." + name,
            "signature_b64": base64.b64encode(raw).decode(),
        }

    def setUp(self):
        lock, b4, b9 = source.from_repository(REPO)
        _, drafts = source.review_pair(lock, b4, b9)

        self.payload = {}

        for prefix, names in (
            ("B4", m.FILES_B4),
            ("B9", m.FILES_B9),
        ):
            for name in names:
                if name.endswith(".json"):
                    self.payload[prefix + "/" + name] = m.canon({
                        "schema": "TEST_ONLY",
                        "filename": name,
                    })

        mb4 = source.parse(drafts["manifest-b4.draft.json"])
        mb9 = source.parse(drafts["manifest-b9.draft.json"])

        mb4["approved_head"] = HEAD
        mb4["root_install_independent"] = True

        mb9["approved_head"] = HEAD
        mb9["root_staged_independently"] = True

        self.payload.update({
            "B4/root-controller.py": b4,
            "B9/root-executor.py": b9,
            "B4/manifest.json": m.canon(mb4),
            "B9/manifest.json": m.canon(mb9),
            "B9/lock": b"ARDREC-R128-B9-ROOT-LOCK" + bytes([10]),
        })

        inventory = {
            name: m.sha(raw)
            for name, raw in sorted(self.payload.items())
        }

        self.trust = {
            "schema": m.TRUST_SCHEMA,
            "installation_signer": self.key("install"),
            "revocation_signer": self.key("revoke"),
        }

        self.upstream = [self.key(f"u{i}") for i in range(10)]

        self.statement = {
            "schema": m.APPROVAL_SCHEMA,
            "release_id": "r134.test.release",
            "source_head": HEAD,
            "source_tree": TREE,
            "agent_sha256": m.sha(SCRIPT.read_bytes()),
            "inventory_sha256": m.sha(m.canon(inventory)),
            "b4_sha256": m.B4_SHA,
            "b9_sha256": m.B9_SHA,
            "targets": m.TARGETS,
            "boot_id": BOOT,
            "valid_from": "2026-11-22T03:00:00Z",
            "valid_until": "2026-11-22T03:04:00Z",
            "purpose": "INDEPENDENT_INSTALL_SOURCE_ONLY_NO_ACTIVATION",
            "one_time": True,
            "automatic_network": False,
            "p8": "NO-GO",
        }

        self.approval = self.sign(
            self.statement, "install", m.APPROVAL_PREFIX
        )

        self.rev_statement = {
            "schema": m.REVOCATION_SCHEMA,
            "release_id": self.statement["release_id"],
            "approval_sha256": m.sha(m.canon(self.approval)),
            "issued_at": "2026-11-22T03:00:00Z",
            "valid_until": "2026-11-22T03:00:40Z",
            "revoked": False,
            "reason_code": "CURRENT_CLEAR",
        }

        self.revocation = self.sign(
            self.rev_statement, "revoke", m.REVOCATION_PREFIX
        )

    def resign_approval(self):
        self.approval = self.sign(
            self.statement, "install", m.APPROVAL_PREFIX
        )

    def resign_revocation(self):
        self.revocation = self.sign(
            self.rev_statement, "revoke", m.REVOCATION_PREFIX
        )

    def review(self):
        return m.review_signed_bundle(
            payload=self.payload,
            approval=self.approval,
            revocation=self.revocation,
            trust=self.trust,
            expected_head=HEAD,
            expected_tree=TREE,
            expected_agent_sha=m.sha(SCRIPT.read_bytes()),
            expected_boot=BOOT,
            upstream=self.upstream,
            now=NOW,
        )

    def denied(self, reason):
        with self.assertRaisesRegex(m.Stop, reason):
            self.review()

    def test_01_valid_documentary_review(self):
        result = self.review()
        self.assertEqual(result["cryptographic_review"], "PASS")
        self.assertFalse(result["root_install_authorized"])

    def test_02_b4_changed(self):
        self.payload["B4/root-controller.py"] += b"x"
        self.denied("B4_SOURCE_PIN_INVALID")

    def test_03_b9_changed(self):
        self.payload["B9/root-executor.py"] += b"x"
        self.denied("B9_SOURCE_PIN_INVALID")

    def test_04_missing_file(self):
        del self.payload["B4/grant.json"]
        self.denied("BUNDLE_INVENTORY_INVALID")

    def test_05_wrong_b4_manifest(self):
        self.payload["B4/manifest.json"] = m.canon({"bad": True})
        self.denied("B4_MANIFEST_INVALID")

    def test_06_wrong_b9_manifest(self):
        self.payload["B9/manifest.json"] = m.canon({"bad": True})
        self.denied("B9_MANIFEST_INVALID")

    def test_07_wrong_lock(self):
        self.payload["B9/lock"] = b"invalid"
        self.denied("B9_LOCK_INVALID")

    def test_08_wrong_head(self):
        self.statement["source_head"] = "0" * 40
        self.resign_approval()
        self.denied("APPROVAL_SCOPE_INVALID")

    def test_09_wrong_tree(self):
        self.statement["source_tree"] = "0" * 40
        self.resign_approval()
        self.denied("APPROVAL_SCOPE_INVALID")

    def test_10_wrong_agent(self):
        self.statement["agent_sha256"] = "0" * 64
        self.resign_approval()
        self.denied("APPROVAL_SCOPE_INVALID")

    def test_11_wrong_boot(self):
        self.statement["boot_id"] = (
            "11111111-1111-4111-8111-111111111111"
        )
        self.resign_approval()
        self.denied("APPROVAL_SCOPE_INVALID")

    def test_12_forged_signature(self):
        self.approval["signature_b64"] = base64.b64encode(
            bytes(64)
        ).decode()
        self.denied("ED25519_SIGNATURE_INVALID")

    def test_13_revoked(self):
        self.rev_statement["revoked"] = True
        self.resign_revocation()
        self.denied("RELEASE_REVOKED_OR_UNBOUND")

    def test_14_stale_revocation(self):
        self.rev_statement["issued_at"] = "2026-11-22T02:59:00Z"
        self.resign_revocation()
        self.denied("REVOCATION_NOT_CURRENT")

    def test_15_approval_expired(self):
        self.statement["valid_until"] = "2026-11-22T03:00:04Z"
        self.resign_approval()
        self.denied("APPROVAL_NOT_CURRENT")

    def test_16_signer_reused(self):
        self.trust["revocation_signer"] = self.key("install")
        self.denied("SIGNERS_NOT_DISTINCT")

    def test_17_upstream_conflict(self):
        self.upstream[0] = self.key("install")
        self.denied("SIGNERS_NOT_DISTINCT")

    def test_18_inventory_mismatch(self):
        self.statement["inventory_sha256"] = "0" * 64
        self.resign_approval()
        self.denied("APPROVAL_SCOPE_INVALID")

    def test_19_cli_fail_closed(self):
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--audit-root"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"DENY_NO_OPERATION", result.stderr)

    def test_20_capabilities(self):
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--capabilities"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn(b'"root_install_implemented":false', result.stdout)


if __name__ == "__main__":
    unittest.main()
