"""R106 pure and durable test contract; no VM, sudo, or network operations."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / "src"), str(REPO / "scripts")]
from ardrec.coordination import r59d_a5_result_intake as a5
from ardrec.coordination import r106_ssh_case_provenance as r106
import ardrec_p14_r104_prototype as r104
import ardrec_p14_r106_ssh_case_bridge as cli


class R106BridgeTests(unittest.TestCase):
    def test_real_r105_source_matches_pinned_bytes(self):
        path = REPO / "crates/ardrec-executor/src/r105_ssh_kexinit_loopback.rs"
        self.assertEqual(
            a5.sha(path.read_bytes()), r106.R105_SOURCE_PIN
        )

    @classmethod
    def setUpClass(cls):
        cls.report = r104.build(54)
        cls.source_manifest = {
            "schema": r106.R104_SCHEMA,
            "case_count": 54,
            "report_sha256": cls.report["sha256"],
            "a6_classification": "ND", "p8_operational": "NO-GO",
        }
        cls.source_manifest["sha256"] = a5.digest(cls.source_manifest)
        cls.observation = {
            "schema": r106.R105_SCHEMA,
            "transport": "REAL_TCP_IPV4_LOOPBACK_ONLY",
            "server_identification": "SSH-2.0-ARDREC_R105_FIXTURE",
            "identification_sha256": r106.R105_SERVER_SHA,
            "kexinit_sha256": r106.R105_KEX_SHA,
            "kexinit_bytes": 160,
            "offered_kex_algorithms": ["curve25519-sha256"],
            "offered_host_key_algorithms": ["ssh-ed25519"],
            "elapsed_ms": 2,
            "tcp_connections": 1,
            "client_identifications_sent": 1,
            "keys_negotiated": False,
            "authenticated": False,
            "remote_commands": 0,
            "a5_operational_attempts": 0,
            "a6_classification": "ND",
            "a7_confirmed_rf": None,
            "evidence_accredited": False,
            "dispatch_allowed": False,
            "p8_operational": "NO-GO",
        }
        cls.review = {
            "schema": r106.F11_SCHEMA,
            "target": "ardrec-r33-dev-ssh",
            "original_result_sha256": r106.F11_R103_RESULT,
            "physical_hook_denial_recorded": True,
            "virsh_start_rejected": True,
            "watcher_finalization_defect_confirmed": True,
            "original_strict_acceptance": "FAIL_PRESERVED",
            "independent_boot_lifecycle_attested": False,
            "new_start_attempts": 0,
            "p8_operational": "NO-GO",
            "authorized_dispatch": False,
        }
        cls.review["sha256"] = a5.digest(cls.review)

    def create_link(self):
        return r106.build(self.report, self.source_manifest,
                          self.observation, self.review,
                          f11_expected_sha=self.review["sha256"])

    def test_pure_link_is_reproducible(self):
        self.assertEqual(self.create_link(), self.create_link())

    def test_case_identity_not_rust_fixture_claim(self):
        result = self.create_link()
        self.assertEqual(result["case_identity"]["derived_case_id"],
                         "SSH-T01-S01-01")
        self.assertEqual(result["case_binding_kind"],
                         "SYNTHETIC_IDENTITY_ASSOCIATION_ONLY")

    def test_no_accreditation_or_dispatch(self):
        value = self.create_link()
        self.assertEqual(value["a6_classification"], "ND")
        self.assertFalse(value["dispatch_allowed"])
        self.assertIsNone(value["a7_confirmed_rf"])
        self.assertEqual(value["p8_operational"], "NO-GO")
        self.assertEqual(value["a5_operational_starts"], 0)

    def test_r105_false_authentication_rejected(self):
        bad = dict(self.observation, authenticated=True)
        with self.assertRaises(r106.ProvenanceError):
            r106.verify_r105(bad)

    def test_r105_invalid_kexinit_rejected(self):
        bad = dict(self.observation, kexinit_sha256="0" * 64)
        with self.assertRaises(r106.ProvenanceError):
            r106.verify_r105(bad)

    def test_r105_extra_field_rejected(self):
        bad = dict(self.observation, approved=True)
        with self.assertRaises(r106.ProvenanceError):
            r106.verify_r105(bad)

    def test_r105_boolean_counter_rejected(self):
        bad = dict(self.observation, remote_commands=False)
        with self.assertRaises(r106.ProvenanceError):
            r106.verify_r105(bad)

    def test_r103_original_fail_must_stay_fail(self):
        bad = dict(self.review, original_strict_acceptance="PASS")
        bad["sha256"] = a5.digest({k: v for k, v in bad.items() if k != "sha256"})
        with self.assertRaises(r106.ProvenanceError):
            r106.verify_f11(bad, expected_sha=bad["sha256"])

    def test_f11_pin_mismatch_rejected(self):
        with self.assertRaises(r106.ProvenanceError):
            r106.verify_f11(self.review)

    def test_wrong_case_family_is_rejected(self):
        bad = deepcopy(self.report)
        for entry in bad["decisions"]:
            if entry["derived_case_id"] == "SSH-T01-S01-01":
                entry["family_id"] = "SSH-T02"
                break
        with self.assertRaises(r106.ProvenanceError):
            r106.select_case(bad, self.source_manifest)

    def test_changed_link_not_replayable(self):
        bad = self.create_link()
        bad["a6_classification"] = "OBSERVADO_POSITIVO"
        bad["sha256"] = a5.digest({k: v for k, v in bad.items() if k != "sha256"})
        with self.assertRaises(r106.ProvenanceError):
            r106.verify_link(bad, self.report, self.source_manifest,
                             self.observation, self.review,
                             f11_expected_sha=self.review["sha256"])

    def test_private_durable_replay_and_modified_bytes(self):
        # This test uses a synthetic F11 object and therefore cannot call
        # production persist() with its mandatory R103-F5 pinned digest.
        link = self.create_link()
        manifest = cli.manifest_for(link, self.observation)
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, doc in (("bridge.json", link),
                              ("observation.json", self.observation),
                              ("manifest.json", manifest)):
                a5._store_once(root / name, a5.canonical(doc) + b"\n",
                               a5.MAX_SUPPORT)
            self.assertEqual({p.name for p in root.iterdir()}, cli.FILES)
            self.assertEqual(cli.document(root, "bridge.json"), link)
            with (root / "bridge.json").open("ab") as output:
                output.write(b"x")
            self.assertNotEqual((root / "bridge.json").read_bytes(),
                                a5.canonical(link) + b"\n")
            with self.assertRaises(ValueError):
                cli.document(root, "bridge.json")


if __name__ == "__main__":
    unittest.main()
