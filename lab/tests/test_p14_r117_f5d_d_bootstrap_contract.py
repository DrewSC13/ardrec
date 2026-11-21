"""F5D-D offline contract tests, ephemeral private keys only."""
from datetime import datetime, timezone
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2] / "scripts/ardrec_p14_r117_f5d_d_bootstrap_contract.py"
spec = importlib.util.spec_from_file_location("f5dd", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class BootstrapContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.working = tempfile.TemporaryDirectory(prefix="ardrec-f5dd-tests-")
        cls.home = Path(cls.working.name)
        cls.now = datetime(2026, 11, 20, 22, 31, tzinfo=timezone.utc)
        cls.head = "a" * 40
        for role in ("bootstrap", "approval", "revocation"):
            priv = cls.home / (role + ".priv.pem")
            pub = cls.home / (role + ".pub.pem")
            cls.openssl("genpkey", "-algorithm", "Ed25519", "-out", str(priv))
            cls.openssl("pkey", "-in", str(priv), "-pubout", "-out", str(pub))
        cls.keys = {role: (cls.home / (role + ".pub.pem")).read_bytes()
                    for role in ("bootstrap", "approval", "revocation")}

    @classmethod
    def tearDownClass(cls):
        cls.working.cleanup()

    @staticmethod
    def openssl(*args):
        proc = subprocess.run([m.OPENSSL, *args], stdin=subprocess.DEVNULL,
                              capture_output=True, check=False, timeout=10)
        if proc.returncode:
            raise RuntimeError("OPENSSL_SETUP_FAILED:" + proc.stderr.decode()[:120])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="src-", dir=self.home)
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        for idx, name in enumerate(m.FILES):
            path = self.repo / name
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_bytes((f"unit-{idx}\n").encode())
        self.policy = {
            "schema": m.SCHEMA,
            "head": self.head,
            "source_sha256": m.source_hashes(self.repo),
            "bootstrap_public_sha256": m.sha(self.keys["bootstrap"]),
            "approval_public_sha256": m.sha(self.keys["approval"]),
            "revocation_public_sha256": m.sha(self.keys["revocation"]),
            "valid_from": "2026-11-20T22:30:00Z",
            "valid_until": "2026-11-20T22:35:00Z",
            "purpose": "SOURCE_ATTESTATION_ONLY",
            "policy_path": m.POLICY_PATH,
            "root_path": m.ROOT_PATH,
            "install_authorized": False,
            "boot_authorized": False,
            "network_authorized": False,
            "a6": "ND", "p8": "NO-GO",
        }

    def sign(self, raw):
        msg = self.repo / "message.bin"
        out = self.repo / "signature.bin"
        msg.write_bytes(m.PREFIX + raw)
        self.openssl("pkeyutl", "-sign", "-rawin", "-inkey",
                     str(self.home / "bootstrap.priv.pem"), "-in", str(msg),
                     "-out", str(out))
        return out.read_bytes()

    def check(self, *, policy=None, raw=None, sig=None,
              bootstrap=None, approval=None, revocation=None, head=None, now=None, pin=None):
        if raw is None:
            raw = m.canonical(self.policy if policy is None else policy)
        if sig is None:
            sig = self.sign(raw)
        bootstrap = self.keys["bootstrap"] if bootstrap is None else bootstrap
        return m.verify_contract(
            raw, sig, bootstrap,
            m.sha(self.keys["bootstrap"]) if pin is None else pin,
            self.keys["approval"] if approval is None else approval,
            self.keys["revocation"] if revocation is None else revocation,
            self.head if head is None else head,
            now=self.now if now is None else now,
            repo=self.repo,
        )

    def denied(self, **kwargs):
        with self.assertRaises(m.Stop):
            self.check(**kwargs)

    def test_valid_signed_policy_stays_no_go(self):
        result = self.check()
        self.assertEqual(result["files_verified"], 10)
        self.assertFalse(result["root_release_accepted"])
        self.assertFalse(result["host_root_provenance_attested"])
        self.assertFalse(result["independent_trust_provisioned"])
        self.assertEqual(result["p8"], "NO-GO")

    def test_tampered_signature_rejected(self):
        self.denied(sig=b"\x00" * 64)

    def test_wrong_bootstrap_key_rejected(self):
        self.denied(bootstrap=self.keys["approval"])

    def test_wrong_pinned_hash_rejected(self):
        self.denied(pin="f" * 64)

    def test_wrong_approval_key_rejected(self):
        self.denied(approval=self.keys["revocation"])

    def test_reused_authority_key_rejected(self):
        self.denied(revocation=self.keys["approval"])

    def test_excessive_privilege_rejected(self):
        d = dict(self.policy)
        d["boot_authorized"] = True
        self.denied(policy=d)

    def test_wrong_purpose_rejected(self):
        d = dict(self.policy)
        d["purpose"] = "BOOT_AND_NETWORK"
        self.denied(policy=d)

    def test_wrong_paths_rejected(self):
        d = dict(self.policy)
        d["root_path"] = "/tmp/ardrec"
        self.denied(policy=d)

    def test_expired_policy_rejected(self):
        self.denied(now=datetime(2026, 11, 20, 22, 35, tzinfo=timezone.utc))

    def test_wrong_head_rejected(self):
        self.denied(head="b" * 40)

    def test_source_bytes_changed_rejected(self):
        (self.repo / m.FILES[0]).write_bytes(b"tamper\n")
        self.denied()

    def test_source_missing_rejected(self):
        (self.repo / m.FILES[0]).unlink()
        with self.assertRaises((m.Stop, FileNotFoundError)):
            self.check()

    def test_source_symlink_rejected(self):
        original = self.repo / m.FILES[0]
        original.unlink()
        original.symlink_to(self.repo / m.FILES[1])
        self.denied()

    def test_duplicate_json_key_rejected(self):
        self.denied(raw=b'{"head":"a","head":"b"}\n')

    def test_noncanonical_json_rejected(self):
        self.denied(raw=m.canonical(self.policy).rstrip(b"\n"))

    def test_unexpected_policy_field_rejected(self):
        d = dict(self.policy)
        d["extra"] = "value"
        self.denied(policy=d)

    def test_future_policy_rejected(self):
        d = dict(self.policy)
        d["valid_from"] = "2026-11-20T22:32:00Z"
        self.denied(policy=d)

    def test_large_validity_window_rejected(self):
        d = dict(self.policy)
        d["valid_until"] = "2026-11-20T23:30:00Z"
        self.denied(policy=d)

if __name__ == "__main__":
    unittest.main()
