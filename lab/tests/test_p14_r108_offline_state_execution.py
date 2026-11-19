"""R108: executable counterfactual T8/T9/T10 with fail-closed durable replay."""
from __future__ import annotations

from copy import deepcopy
import io
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / "src"), str(REPO / "scripts")]

from ardrec.coordination import r59d_a5_result_intake as a5
from ardrec.coordination import r58u_counterfactual_pause_recovery as r58u
from ardrec.coordination import r106_ssh_case_provenance as r106
from ardrec.coordination import r107_offline_a1_a10_orchestrator as r107
from ardrec.coordination import r108_offline_state_execution as r108
import ardrec_p14_r104_prototype as cli104
import ardrec_p14_r106_ssh_case_bridge as cli106
import ardrec_p14_r108_counterfactual_state as cli108


class R108ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = TemporaryDirectory(prefix="ardrec-r108-test-")
        cls.r104 = cli104.build(54)
        _, cls.m104 = cli104.persist(cls.r104, Path(cls.temp.name))
        observation = {
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
        f11 = {
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
        f11["sha256"] = a5.digest(f11)
        link = r106.build(cls.r104, cls.m104, observation, f11,
                          f11_expected_sha=f11["sha256"])
        m106 = cli106.manifest_for(link, observation)
        cls.trace = r107.build(cls.r104, cls.m104, link, m106)
        cls.result = r108.build(cls.trace)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_54_windows_and_25_families(self):
        self.assertEqual(self.result["case_window_count"], 54)
        self.assertEqual(self.result["families_covered"], 25)
        self.assertEqual(len({c["family_id"] for c in self.result["cases"]}), 25)

    def test_72_executed_model_events(self):
        self.assertEqual(len(self.result["events"]), 72)
        self.assertEqual(self.result["counterfactual_transitions_executed"], 72)
        self.assertEqual(self.result["model_event_count"], 72)

    def test_exact_counterfactual_phase_distribution(self):
        self.assertEqual(self.result["model_phase_counts"],
                         {"PAUSADO": 18, "PENDIENTE": 18, "DETENIDO": 18})

    def test_existing_transition_semantics_executed(self):
        self.assertEqual(r108._transitions(0)[0][0], "T8")
        self.assertEqual([t[0] for t in r108._transitions(1)], ["T8", "T9"])
        self.assertEqual(r108._transitions(2)[0][0], "T10")
        self.assertEqual(r108.model.SCHEMA, r58u.SCHEMA)

    def test_no_operational_promotion_or_guest_traffic(self):
        for name in ("a3_operational_transitions_applied",
                     "a5_operational_starts", "a8_operational_transitions_applied",
                     "a9_published_generations", "vm_starts", "host_mutations"):
            self.assertEqual(self.result[name], 0)
        self.assertFalse(self.result["dispatch_allowed"])
        self.assertFalse(self.result["independent_case_authority_attested"])
        self.assertEqual(self.result["p8_operational"], "NO-GO")
        self.assertEqual(self.result["a6_classification"], "ND")
        self.assertIsNone(self.result["a7_confirmed_rf"])
        self.assertFalse(self.result["a1_a10_operational_implementation_complete"])

    def test_events_hash_chained_and_bijective(self):
        previous = None
        for index, event in enumerate(self.result["events"], 1):
            self.assertEqual(event["event_number"], index)
            self.assertEqual(event["previous_event_sha256"], previous)
            self.assertEqual(event["sha256"], a5.digest({
                k: v for k, v in event.items() if k != "sha256"}))
            previous = event["sha256"]
        self.assertEqual(previous, self.result["model_event_head_sha256"])

    def test_replay_deterministic(self):
        self.assertEqual(self.result, r108.build(self.trace))
        self.assertTrue(r108.verify(self.result, self.trace))

    def test_permuted_r107_cases_remains_deterministic(self):
        reordered = deepcopy(self.trace)
        reordered["cases"].reverse()
        reordered["sha256"] = a5.digest({
            k: v for k, v in reordered.items() if k != "sha256"})
        changed = r108.build(reordered)
        self.assertEqual(changed["cases"], self.result["cases"])
        self.assertEqual(changed["events"], self.result["events"])
        self.assertNotEqual(changed["r107_trace_sha256"],
                            self.result["r107_trace_sha256"])
        self.assertNotEqual(changed["sha256"], self.result["sha256"])

    def test_terminal_detained_cannot_resume(self):
        stopped = {"phase": "DETENIDO", "revision": 1,
                   "wait_ref": None, "pause_ref": None, "stop_cause": "CONTROL"}
        _, refs, cause = r108._transitions(0)[0]
        with self.assertRaises(ValueError):
            r58u._evolve(stopped, "T8", refs, cause)

    def test_resume_requires_matching_reference(self):
        paused = {"phase": "PAUSADO", "revision": 1,
                  "wait_ref": "SIM_WAIT_001", "pause_ref": "SIM_PAUSE_001",
                  "stop_cause": None}
        _, refs, _ = r108._transitions(1)[1]
        self.assertEqual(r58u._evolve(paused, "T9", refs, None)["phase"],
                         "PENDIENTE")
        wrong = dict(refs, wait_resolved="SIM_WAIT_WRONG")
        with self.assertRaises(ValueError):
            r58u._evolve(paused, "T9", wrong, None)

    def test_bad_guard_schema_denied(self):
        _, refs, _ = r108._transitions(0)[0]
        with self.assertRaises(ValueError):
            r58u._validate_refs("T8", {"pause_authorized": refs["pause_authorized"]}, None)

    def test_event_tamper_even_with_rehash_denied(self):
        tampered = deepcopy(self.result)
        tampered["events"][0]["after_phase"] = "ACTIVO"
        tampered["events"][0]["sha256"] = a5.digest({
            k: v for k, v in tampered["events"][0].items() if k != "sha256"})
        tampered["sha256"] = a5.digest({
            k: v for k, v in tampered.items() if k != "sha256"})
        with self.assertRaises(ValueError):
            r108.verify(tampered, self.trace)

    def test_r107_case_tamper_denied(self):
        bad = deepcopy(self.trace)
        bad["cases"][0]["case_id_a7"] = "CASE_FAKE"
        bad["sha256"] = a5.digest({k: v for k, v in bad.items() if k != "sha256"})
        with self.assertRaises(ValueError):
            r108.build(bad)

    def test_forged_source_authority_rejected(self):
        bad = deepcopy(self.trace)
        bad["a5_operational_starts"] = 1
        bad["sha256"] = a5.digest({k: v for k, v in bad.items() if k != "sha256"})
        with self.assertRaises(ValueError):
            r108.build(bad)

    def test_private_durable_replay(self):
        with TemporaryDirectory(prefix="ardrec-r108-private-") as temp:
            session, report, manifest = cli108.persist(self.trace, Path(temp))
            self.assertEqual((report, manifest), cli108.verify(session, self.trace))
            self.assertEqual({p.name for p in session.iterdir()}, cli108.FILES)
            self.assertEqual({p.stat().st_mode & 0o777 for p in session.iterdir()}, {0o600})
            self.assertEqual(session.stat().st_mode & 0o777, 0o700)

    def test_private_file_tampering_rejected(self):
        with TemporaryDirectory(prefix="ardrec-r108-tamper-") as temp:
            session, _, _ = cli108.persist(self.trace, Path(temp))
            path = session / "model.json"
            path.write_bytes(path.read_bytes()[:-1] + b" ")
            with self.assertRaises(ValueError):
                cli108.verify(session, self.trace)

    def test_session_extra_file_rejected(self):
        with TemporaryDirectory(prefix="ardrec-r108-inventory-") as temp:
            session, _, _ = cli108.persist(self.trace, Path(temp))
            (session / "unexpected.txt").write_text("x", encoding="ascii")
            with self.assertRaises(ValueError):
                cli108.verify(session, self.trace)

    def test_console_is_explicit_model(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli108.show(Path("/tmp/fixture"), self.result,
                        cli108.manifest_for(self.result))
        text = buf.getvalue()
        self.assertIn("R108_MODEL_TRANSITIONS=72", text)
        self.assertIn("R108_OPERATIONAL_TRANSITIONS=0", text)
        self.assertIn("R108_P8=NO-GO", text)


if __name__ == "__main__":
    unittest.main()
