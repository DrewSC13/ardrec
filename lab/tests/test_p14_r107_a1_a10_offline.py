"""R107 offline 54-case, ten-stage provenance and private replay adversarial tests."""
from __future__ import annotations

from copy import deepcopy
import io
from contextlib import redirect_stdout
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / "src"), str(REPO / "scripts")]

from ardrec.coordination import r59d_a5_result_intake as a5
from ardrec.coordination import r106_ssh_case_provenance as r106
from ardrec.coordination import r107_offline_a1_a10_orchestrator as r107
import ardrec_p14_r104_prototype as r104
import ardrec_p14_r106_ssh_case_bridge as cli106
import ardrec_p14_r107_a1_a10_offline as cli107


class R107OrchestratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory(prefix="ardrec-r107-test-")
        cls.report = r104.build(54)
        _, cls.m104 = r104.persist(cls.report, Path(cls.tmp.name))
        cls.obs = {
            "schema": r106.R105_SCHEMA,
            "transport": "REAL_TCP_IPV4_LOOPBACK_ONLY",
            "server_identification": "SSH-2.0-ARDREC_R105_FIXTURE",
            "identification_sha256": r106.R105_SERVER_SHA,
            "kexinit_sha256": r106.R105_KEX_SHA,
            "kexinit_bytes": 160,
            "offered_kex_algorithms": ["curve25519-sha256"],
            "offered_host_key_algorithms": ["ssh-ed25519"],
            "elapsed_ms": 2, "tcp_connections": 1,
            "client_identifications_sent": 1,
            "keys_negotiated": False, "authenticated": False,
            "remote_commands": 0, "a5_operational_attempts": 0,
            "a6_classification": "ND", "a7_confirmed_rf": None,
            "evidence_accredited": False,
            "dispatch_allowed": False, "p8_operational": "NO-GO",
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
        cls.link = r106.build(cls.report, cls.m104, cls.obs, cls.review,
                              f11_expected_sha=cls.review["sha256"])
        cls.m106 = cli106.manifest_for(cls.link, cls.obs)
        cls.trace = r107.build(cls.report, cls.m104, cls.link, cls.m106)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_54_window_25_families_and_three_services(self):
        self.assertEqual(self.trace["case_window_count"], 54)
        self.assertEqual(self.trace["family_count"], 25)
        self.assertEqual(self.trace["count_by_service"], r107.COUNTS)

    def test_all_ten_status_stages_for_each_case(self):
        self.assertEqual(self.trace["stage_status_count"], 540)
        self.assertTrue(all(
            [step["algorithm"] for step in row["stages"]] == list(r107.ALGORITHMS)
            for row in self.trace["cases"]
        ))

    def test_one_r106_case_only_and_no_guest_claim(self):
        selected = [d for d in self.trace["cases"]
                    if d["r106_provenance_association_only"]]
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["derived_case_id"], "SSH-T01-S01-01")
        self.assertFalse(self.trace["ssh_fixture_is_guest_evidence"])

    def test_a5_a6_a7_a8_a9_p8_never_promoted(self):
        self.assertFalse(self.trace["a1_a10_operational_implementation_complete"])
        self.assertEqual(self.trace["a5_operational_starts"], 0)
        self.assertEqual(self.trace["a6_classification"], "ND")
        self.assertIsNone(self.trace["a7_confirmed_rf"])
        self.assertEqual(self.trace["a8_applied_transitions"], 0)
        self.assertEqual(self.trace["a9_published_generations"], 0)
        self.assertFalse(self.trace["operational_dispatch"])
        self.assertEqual(self.trace["p8_operational"], "NO-GO")

    def test_build_reproducible_and_stage_hash_bound_to_case(self):
        self.assertEqual(self.trace,
                         r107.build(self.report, self.m104, self.link, self.m106))
        self.assertNotEqual(self.trace["cases"][0]["stages"][0]["event_sha256"],
                            self.trace["cases"][1]["stages"][0]["event_sha256"])

    def test_mutation_even_if_rehashed_is_rejected(self):
        bad = deepcopy(self.trace)
        bad["cases"][0]["a6_classification"] = "OBSERVADO_POSITIVO"
        bad["cases"][0]["case_sha256"] = a5.digest({
            k: v for k, v in bad["cases"][0].items() if k != "case_sha256"})
        bad["sha256"] = a5.digest({k: v for k, v in bad.items() if k != "sha256"})
        with self.assertRaises(r107.OrchestrationError):
            r107.verify_trace(bad, self.report, self.m104, self.link, self.m106)

    def test_stage_chain_mutation_is_rejected(self):
        bad = deepcopy(self.trace)
        bad["cases"][3]["stages"][4]["source_sha256"] = "0" * 64
        with self.assertRaises(r107.OrchestrationError):
            r107.verify_trace(bad, self.report, self.m104, self.link, self.m106)

    def test_wrong_r106_link_not_accepted(self):
        link = deepcopy(self.link)
        link["r104_manifest_sha256"] = "f" * 64
        link["sha256"] = a5.digest({k: v for k, v in link.items() if k != "sha256"})
        with self.assertRaises(r107.OrchestrationError):
            r107.build(self.report, self.m104, link, self.m106)

    def test_r105_pin_change_with_rehashed_receipts_denied(self):
        link = deepcopy(self.link)
        manifest = deepcopy(self.m106)
        link["r105_rust_source_sha256"] = "f" * 64
        link["sha256"] = a5.digest({k: v for k, v in link.items() if k != "sha256"})
        manifest["link_sha256"] = link["sha256"]
        manifest["r105_rust_source_sha256"] = "f" * 64
        manifest["sha256"] = a5.digest({k: v for k, v in manifest.items()
                                        if k != "sha256"})
        with self.assertRaises(r107.OrchestrationError):
            r107.build(self.report, self.m104, link, manifest)

    def test_r104_report_or_manifest_drift_rejected(self):
        bad = deepcopy(self.m104)
        bad["case_count"] = 29
        bad["sha256"] = a5.digest({k: v for k, v in bad.items() if k != "sha256"})
        with self.assertRaises(r107.OrchestrationError):
            r107.build(self.report, bad, self.link, self.m106)

    def test_private_durable_persistence_and_reopen(self):
        with TemporaryDirectory(prefix="ardrec-r107-persist-") as tmp:
            session, trace, manifest = cli107.persist(
                self.report, self.m104, self.link, self.m106, Path(tmp))
            self.assertEqual(
                (trace, manifest), cli107.verify(
                    session, self.report, self.m104, self.link, self.m106))
            self.assertEqual({p.name for p in session.iterdir()}, cli107.FILES)
            self.assertEqual(manifest["p8_operational"], "NO-GO")

    def test_private_tampering_detected(self):
        with TemporaryDirectory(prefix="ardrec-r107-tamper-") as tmp:
            session, _, _ = cli107.persist(
                self.report, self.m104, self.link, self.m106, Path(tmp))
            with (session / "trace.json").open("ab") as stream:
                stream.write(b"x")
            with self.assertRaises(ValueError):
                cli107.verify(session, self.report, self.m104, self.link, self.m106)

    def test_summary_and_table_have_54_rows(self):
        with io.StringIO() as capture, redirect_stdout(capture):
            cli107.display(Path("/tmp/read-only-example"), self.trace,
                           cli107.manifest_for(self.trace), table=True)
            content = capture.getvalue()
        self.assertEqual(content.count("R107_TABLE_ROW="), 54)
        self.assertIn("R107_A1_A10_IMPLEMENTATION_COMPLETE=FALSE", content)
        self.assertIn("R107_P8=NO-GO", content)

    def test_unknown_case_detail_denied(self):
        with io.StringIO() as capture, redirect_stdout(capture):
            with self.assertRaises(r107.OrchestrationError):
                cli107.display(Path("/tmp/read-only-example"), self.trace,
                               cli107.manifest_for(self.trace),
                               case_id="CASE_" + "0" * 48)


if __name__ == "__main__":
    unittest.main()
