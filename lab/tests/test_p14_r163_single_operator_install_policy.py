"""R163 policy tests: ephemeral test keys; no root or network operations."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest

from ardrec.coordination import r163_single_operator_install_policy as m

HEAD = "a" * 40
TREE = "b" * 40
BOOT = "00000000-0000-4000-8000-000000000001"
NOW = datetime(2026, 11, 22, 21, 0, 0, tzinfo=timezone.utc)


def utc(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class R163PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.keys = {}

        for name in ("authorization", "revocation"):
            private = cls.root / (name + ".key")
            public = cls.root / (name + ".pub")

            subprocess.run([
                "/usr/bin/openssl", "genpkey",
                "-algorithm", "ED25519",
                "-out", str(private)
            ], check=True, capture_output=True)

            subprocess.run([
                "/usr/bin/openssl", "pkey",
                "-in", str(private), "-pubout",
                "-out", str(public)
            ], check=True, capture_output=True)

            cls.keys[name] = {
                "private": private,
                "public": public.read_text()
            }

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def sign(self, name, prefix, statement):
        message = self.root / (name + ".message")
        signature = self.root / (name + ".signature")
        message.write_bytes(prefix + m.canonical(statement))

        subprocess.run([
            "/usr/bin/openssl", "pkeyutl", "-sign",
            "-inkey", str(self.keys[name]["private"]),
            "-rawin", "-in", str(message),
            "-out", str(signature)
        ], check=True, capture_output=True)

        return m.canonical({
            "statement": statement,
            "signer_key_id": self.trust[name + "_signer"]["key_id"],
            "signature_b64": base64.b64encode(
                signature.read_bytes()
            ).decode("ascii")
        })

    def setUp(self):
        self.trust = {
            "schema": m.TRUST_SCHEMA,
            "authorization_signer": {
                "key_id": "r163-test-authorization",
                "public_key_pem": self.keys["authorization"]["public"],
            },
            "revocation_signer": {
                "key_id": "r163-test-revocation",
                "public_key_pem": self.keys["revocation"]["public"],
            },
        }

        self.claim = {
            "schema": m.AUTH_SCHEMA,
            "session": "0011223344556677",
            "head": HEAD,
            "tree": TREE,
            "boot_id": BOOT,
            "operator_uid": 1000,
            "operator_id": "test-operator",
            "custody_mode": "SINGLE_HUMAN_OPERATOR",
            "independent_authority": False,
            "claims_verified_signer_independence": False,
            "source_b4_sha256": m.crypto.B4_SHA,
            "source_b9_sha256": m.crypto.B9_SHA,
            "inventory_sha256": "c" * 64,
            "agent_bundle_sha256": "d" * 64,
            "action": "INSTALL_B4_B9_ONLY",
            "destinations": list(m.crypto.DESTINATIONS),
            "valid_from": utc(NOW-timedelta(seconds=30)),
            "valid_until": utc(NOW+timedelta(minutes=3)),
            "one_shot": True,
            "network_traffic_authorized": False,
            "vm_start_authorized": False,
            "automatic_execution_authorized": False,
            "grants_root_privileges": False,
            "root_authority_bootstrap_required": True,
            "p8": "NO-GO",
        }
        self.reissue()

    def reissue(self):
        self.auth_raw = self.sign(
            "authorization", m.AUTH_PREFIX, self.claim
        )
        self.rev = {
            "schema": m.REV_SCHEMA,
            "session": self.claim["session"],
            "authorization_sha256": m.sha(self.auth_raw),
            "issued_at": utc(NOW),
            "valid_until": utc(NOW+timedelta(seconds=30)),
            "revoked": False,
            "reason_code": "ACTIVE",
        }
        self.rev_raw = self.sign(
            "revocation", m.REV_PREFIX, self.rev
        )

    def verify(self, **overrides):
        arguments = dict(
            trust_raw=m.canonical(self.trust),
            authorization_raw=self.auth_raw,
            revocation_raw=self.rev_raw,
            head=HEAD, tree=TREE, boot_id=BOOT,
            inventory_sha256="c"*64,
            agent_bundle_sha256="d"*64,
            operator_uid=1000,
            operator_id="test-operator",
            now=NOW,
        )
        arguments.update(overrides)
        return m.validate(**arguments)

    def denied(self, **overrides):
        with self.assertRaises((ValueError, OSError)):
            self.verify(**overrides)

    def test_01_valid_signed_policy(self):
        result = self.verify()
        self.assertTrue(result["signature_cryptographically_verified"])
        self.assertFalse(result["root_install_authorized"])

    def test_02_wrong_uid(self):
        self.denied(operator_uid=2000)

    def test_03_wrong_head(self):
        self.denied(head="f"*40)

    def test_04_wrong_tree(self):
        self.denied(tree="e"*40)

    def test_05_bad_signature(self):
        document = m.crypto.parse(self.auth_raw)
        document["signature_b64"] = base64.b64encode(
            bytes(64)
        ).decode("ascii")
        self.denied(authorization_raw=m.canonical(document))

    def test_06_unauthorized_action(self):
        self.claim["action"] = "RUN_FTP"
        self.reissue()
        self.denied()

    def test_07_false_independence(self):
        self.claim["independent_authority"] = True
        self.reissue()
        self.denied()

    def test_08_expired_authorization(self):
        self.denied(now=NOW+timedelta(minutes=4))

    def test_09_stale_revocation(self):
        self.denied(now=NOW+timedelta(seconds=31))

    def test_10_revoked(self):
        self.rev["revoked"] = True
        self.rev_raw = self.sign(
            "revocation", m.REV_PREFIX, self.rev
        )
        self.denied()

    def test_11_revocation_not_bound(self):
        self.rev["authorization_sha256"] = "f"*64
        self.rev_raw = self.sign(
            "revocation", m.REV_PREFIX, self.rev
        )
        self.denied()

    def test_12_signing_key_reuse(self):
        self.trust["revocation_signer"] = dict(
            self.trust["authorization_signer"]
        )
        self.denied()
