"""R133: firmas, revocación, inventario y recuperación privada."""

from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

from ardrec.coordination import (
    r133_install_release_gate as m,
)
from ardrec.coordination import (
    r132_install_recovery as recovery,
)
from ardrec.coordination import (
    r130_b17_r6b3_root_candidate as source,
)

REPO = Path(__file__).resolve().parents[2]
HEAD = "95a6d57b8241101c7a8fa3aedc07fb779b088d9f"
TREE = "a" * 40
AGENT = "b" * 64
BOOT = "00000000-0000-4000-8000-000000000000"
NOW = datetime(2026, 11, 22, 3, 0, 5, tzinfo=timezone.utc)


def openssl(*args):
    completed = subprocess.run(
        ["/usr/bin/openssl", *map(str, args)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=10,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            "TEST_OPENSSL_FAILED:"
            + completed.stderr.decode(errors="replace")[:180]
        )
    return completed.stdout


class ReleaseGateTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(
            prefix="ardrec-r133-test-keys-only-"
        )
        cls.folder = Path(cls.temp.name)
        cls.keys = {}

        for role in ("install", "revoke", *(
            f"upstream{i}" for i in range(10)
        )):
            private = cls.folder / (role + ".key")
            public = cls.folder / (role + ".pub")

            openssl(
                "genpkey", "-algorithm", "ED25519",
                "-out", private,
            )
            openssl(
                "pkey", "-in", private,
                "-pubout", "-out", public,
            )

            cls.keys[role] = {
                "private": private,
                "public": public.read_text(encoding="ascii"),
            }

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def signer(self, role):
        return {
            "key_id": "r133.test." + role,
            "public_key_pem": self.keys[role]["public"],
        }

    def sign(self, document, role, prefix):
        with tempfile.TemporaryDirectory(
            prefix="ardrec-r133-sign-test-"
        ) as folder:
            root = Path(folder)
            message = root / "message.bin"
            signature = root / "signature.bin"

            message.write_bytes(prefix + source.canon(document))

            openssl(
                "pkeyutl", "-sign",
                "-inkey", self.keys[role]["private"],
                "-rawin", "-in", message,
                "-out", signature,
            )

            raw = signature.read_bytes()

        return {
            "statement": copy.deepcopy(document),
            "signer_key_id": "r133.test." + role,
            "signature_b64": base64.b64encode(raw).decode("ascii"),
        }

    def setUp(self):
        lock, b4, b9 = source.from_repository(REPO)
        _, drafts = source.review_pair(lock, b4, b9)

        self.payload = {
            name: source.canon({
                "schema": "ARDREC-R133-TEST-ONLY",
                "name": name,
            })
            for name in m.FILES
            if name.endswith(".json")
        }

        b4_manifest = source.parse(
            drafts["manifest-b4.draft.json"]
        )
        b4_manifest["approved_head"] = HEAD
        b4_manifest["root_install_independent"] = True

        b9_manifest = source.parse(
            drafts["manifest-b9.draft.json"]
        )
        b9_manifest["approved_head"] = HEAD
        b9_manifest["root_staged_independently"] = True

        self.payload.update({
            "B4/root-controller.py": b4,
            "B9/root-executor.py": b9,
            "B4/manifest.json": source.canon(b4_manifest),
            "B9/manifest.json": source.canon(b9_manifest),
            "B9/lock": b"ARDREC-R128-B9-ROOT-LOCK\n",
        })

        inventory = m.inventory(REPO, self.payload, HEAD)

        self.trust = {
            "schema": m.TRUST_SCHEMA,
            "installation_signer": self.signer("install"),
            "revocation_signer": self.signer("revoke"),
        }

        self.upstream = [
            self.signer(f"upstream{i}")
            for i in range(10)
        ]

        self.statement = {
            "schema": m.APPROVAL_SCHEMA,
            "release_id": "r133.test.release01",
            "source_head": HEAD,
            "source_tree": TREE,
            "agent_sha256": AGENT,
            "inventory_sha256": inventory["inventory_sha256"],
            "b4_sha256": source.B4_SHA,
            "b9_sha256": source.B9_SHA,
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
            "approval_sha256": m.digest(m.canon(self.approval)),
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
        return m.review(
            REPO,
            self.payload,
            self.approval,
            self.revocation,
            self.trust,
            now=NOW,
            head=HEAD,
            tree=TREE,
            agent_sha256=AGENT,
            boot_id=BOOT,
            upstream_signers=self.upstream,
        )

    def denied(self, reason):
        with self.assertRaisesRegex((m.Stop, ValueError), reason):
            self.review()

    def test_01_valid_documentary_signatures(self):
        verdict = self.review()
        self.assertEqual(verdict["cryptographic_review"], "PASS")
        self.assertFalse(verdict["root_install_authorized"])
        self.assertFalse(verdict["independent_root_trust_anchored"])

    def test_02_b4_tampered(self):
        self.payload["B4/root-controller.py"] += b"x"
        self.denied("B4_SOURCE_DRIFT")

    def test_03_b9_tampered(self):
        self.payload["B9/root-executor.py"] += b"x"
        self.denied("B9_SOURCE_DRIFT")

    def test_04_missing_file(self):
        del self.payload["B4/grant.json"]
        self.denied("OPERATIONAL_FILE_SET_INVALID")

    def test_05_unexpected_file(self):
        self.payload["B4/unexpected.json"] = b"{}\n"
        self.denied("OPERATIONAL_FILE_SET_INVALID")

    def test_06_noncanonical_document(self):
        self.payload["B4/contract.json"] = b"{}"
        self.denied("DOCUMENT_NONCANONICAL")

    def test_07_b4_manifest_mismatch(self):
        d = source.parse(self.payload["B4/manifest.json"])
        d["approved_head"] = "0" * 40
        self.payload["B4/manifest.json"] = source.canon(d)
        self.denied("B4_OPERATIONAL_MANIFEST_INVALID")

    def test_08_b9_manifest_mismatch(self):
        d = source.parse(self.payload["B9/manifest.json"])
        d["approved_head"] = "0" * 40
        self.payload["B9/manifest.json"] = source.canon(d)
        self.denied("B9_OPERATIONAL_MANIFEST_INVALID")

    def test_09_lock_invalid(self):
        self.payload["B9/lock"] = b"changed\n"
        self.denied("B9_LOCK_INVALID")

    def test_10_signature_tamper(self):
        self.approval["signature_b64"] = base64.b64encode(
            bytes(64)
        ).decode("ascii")
        self.denied("SIGNATURE_NOT_VERIFIED")

    def test_11_approval_expired(self):
        self.statement["valid_until"] = "2026-11-22T03:00:04Z"
        self.resign_approval()
        self.denied("RELEASE_APPROVAL_EXPIRED_OR_INVALID")

    def test_12_wrong_head(self):
        self.statement["source_head"] = "0" * 40
        self.resign_approval()
        self.denied("RELEASE_SCOPE_INVALID")

    def test_13_wrong_tree(self):
        self.statement["source_tree"] = "0" * 40
        self.resign_approval()
        self.denied("RELEASE_SCOPE_INVALID")

    def test_14_wrong_agent(self):
        self.statement["agent_sha256"] = "0" * 64
        self.resign_approval()
        self.denied("RELEASE_SCOPE_INVALID")

    def test_15_wrong_boot(self):
        self.statement["boot_id"] = (
            "11111111-1111-4111-8111-111111111111"
        )
        self.resign_approval()
        self.denied("RELEASE_SCOPE_INVALID")

    def test_16_signed_revocation(self):
        self.rev_statement["revoked"] = True
        self.resign_revocation()
        self.denied("RELEASE_REVOKED_OR_UNBOUND")

    def test_17_stale_revocation(self):
        self.rev_statement["issued_at"] = (
            "2026-11-22T02:59:00Z"
        )
        self.resign_revocation()
        self.denied("RELEASE_REVOCATION_STALE")

    def test_18_wrong_approval_binding(self):
        self.rev_statement["approval_sha256"] = "0" * 64
        self.resign_revocation()
        self.denied("RELEASE_REVOKED_OR_UNBOUND")

    def test_19_install_and_revocation_signers_reused(self):
        self.trust["revocation_signer"] = copy.deepcopy(
            self.trust["installation_signer"]
        )
        self.denied("INSTALL_SIGNERS_NOT_DISTINCT")

    def test_20_install_signer_conflicts_upstream(self):
        self.upstream[0] = copy.deepcopy(
            self.trust["installation_signer"]
        )
        self.denied("INSTALL_SIGNER_CONFLICT")

    def test_21_revoker_conflicts_upstream(self):
        self.upstream[0] = copy.deepcopy(
            self.trust["revocation_signer"]
        )
        self.denied("INSTALL_SIGNER_CONFLICT")

    def test_22_duplicate_upstream_id(self):
        self.upstream[1]["key_id"] = self.upstream[0]["key_id"]
        self.denied("UPSTREAM_SIGNERS_DUPLICATED")

    def test_23_duplicate_upstream_key(self):
        self.upstream[1]["public_key_pem"] = (
            self.upstream[0]["public_key_pem"]
        )
        self.denied("UPSTREAM_SIGNERS_DUPLICATED")

    def test_24_wrong_inventory_binding(self):
        self.statement["inventory_sha256"] = "0" * 64
        self.resign_approval()
        self.denied("RELEASE_SCOPE_INVALID")

    def test_25_capabilities_no_root(self):
        result = m.capabilities()
        self.assertFalse(result["root_install_available"])
        self.assertFalse(result["can_open_traffic"])

    def test_26_semantic_boundary_explicit(self):
        result = self.review()
        self.assertFalse(
            result["operational_document_semantics_validated"]
        )
        self.assertFalse(
            result["source_commit_verified_against_local_git"]
        )

    def test_27_revocation_expired(self):
        self.rev_statement["valid_until"] = (
            "2026-11-22T03:00:04Z"
        )
        self.resign_revocation()
        self.denied("RELEASE_REVOCATION_STALE")


class PublishedRecoveryTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)

    def apply(self, fault=None):
        return recovery.apply(REPO, self.parent, fault=fault)

    def test_28_missing_b4_published_file(self):
        self.apply()
        path = self.parent / "installed-b4/root-controller.py"
        path.unlink()
        with self.assertRaisesRegex(
            recovery.Stop, "PUBLISHED_FILE_SET_CHANGED"
        ):
            self.apply()

    def test_29_missing_b9_published_file(self):
        self.apply()
        path = self.parent / "installed-b9/root-executor.py"
        path.unlink()
        with self.assertRaisesRegex(
            recovery.Stop, "PUBLISHED_FILE_SET_CHANGED"
        ):
            self.apply()

    def test_30_missing_b4_published_directory(self):
        self.apply()
        source_dir = self.parent / "installed-b4"
        source_dir.rename(self.parent / "moved-b4")
        with self.assertRaisesRegex(
            recovery.Stop,
            "PUBLISHED_PAIR_INCOMPLETE_AFTER_RECEIPT",
        ):
            self.apply()

    def test_31_missing_b9_published_directory(self):
        self.apply()
        source_dir = self.parent / "installed-b9"
        source_dir.rename(self.parent / "moved-b9")
        with self.assertRaisesRegex(
            recovery.Stop,
            "PUBLISHED_PAIR_INCOMPLETE_AFTER_RECEIPT",
        ):
            self.apply()

    def test_32_b9_without_b4_before_receipt(self):
        with self.assertRaisesRegex(
            recovery.Stop, "INJECTED_AFTER_B9"
        ):
            self.apply("after_b9")

        (self.parent / "installed-b4").rename(
            self.parent / "moved-b4"
        )

        with self.assertRaisesRegex(
            recovery.Stop, "B9_PUBLISHED_WITHOUT_B4"
        ):
            self.apply()


if __name__ == "__main__":
    unittest.main()
