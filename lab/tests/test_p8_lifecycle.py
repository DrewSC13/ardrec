"""P8-R6: only synthetic, in-memory claims; no host artifact or live authority."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "verify_p8_lifecycle.py"
spec = importlib.util.spec_from_file_location("ardrec_p8_r6", SOURCE)
assert spec is not None and spec.loader is not None
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)


def baseline():
    material = {
        "status": "SYNTHETIC_FD_BYTES_MATCH_DECLARATION_ONLY", "relative_path": "bin/mock",
        "observed_sha256": hashlib.sha256(b"ARDREC mock only").hexdigest(),
        "observed_bytes": len(b"ARDREC mock only"), "uid": 1000, "mode": 0o600,
        "provenance_verified": False, "future_identity_guaranteed": False,
        "authorization": False, "dispatch_allowed": False,
    }
    obs = {
        "status": "SYNTHETIC_MATERIAL_OBSERVATIONS_ONLY_DENY_ALL", "observed_materials": 1,
        "observations": [material], "declared_versions_not_verified": True,
        "trusted_pin_provenance": False, "case_authorized": False, "dispatch_allowed": False,
    }
    context = {
        "schema_version": "1.0", "stage": "dev", "service_id": "dev-svc-ssh-01",
        "scenario_id": "dev-scn-ssh-01", "case_id": "SSH-T01-S01-01",
        "profile_id": "SSH-T01-BASE", "target_ref": "ref:synthetic/dev/target-01",
        "authorization_ref": "ref:synthetic/dev/auth-01",
        "cleanup_plan_ref": "ref:synthetic/dev/cleanup-01",
        "budget_sha256": hashlib.sha256(b"not a real budget").hexdigest(),
        "material_epoch": 4, "authorization_revision": 2, "material_observation": obs,
    }
    request = {
        "schema_version": "1.0", "stage": "dev", "case_id": context["case_id"],
        "profile_id": context["profile_id"], "snapshot_sha256": V.context_fingerprint(context),
        "material_epoch": 4, "authorization_revision": 2,
        "issued_at_utc": "2026-11-08T14:00:00Z",
        "not_before_utc": "2026-11-08T14:30:00Z",
        "not_after_utc": "2026-11-08T15:30:00Z",
        "checked_at_utc": "2026-11-08T15:00:00Z",
        "issuer_claim": "SYNTHETIC_UNVERIFIED",
        "revocation_claim": "UNKNOWN_UNVERIFIED",
        "clock_claim": "SYNTHETIC_UNTRUSTED",
        "dispatch_requested": False, "cleanup_receipt_ref": None,
    }
    return context, request, []


def invalidator(c, kind="AUTHORIZATION_REVOKED", when="2026-11-08T14:40:00Z", sequence=1):
    return {"sequence": sequence, "kind": kind, "observed_at_utc": when,
            "snapshot_sha256": V.context_fingerprint(c),
            "material_epoch": c["material_epoch"],
            "authorization_revision": c["authorization_revision"]}


class LifecycleOracleTests(unittest.TestCase):
    def setUp(self):
        self.c, self.r, self.events = baseline()

    def check_reject(self, expected=""):
        with self.assertRaises(V.LifecycleError) as cm:
            V.assess_synthetic_lifecycle(self.c, self.r, self.events)
        if expected:
            self.assertIn(expected, str(cm.exception))

    def test_consistent_synthetic_claim_denied(self):
        d = V.assess_synthetic_lifecycle(self.c, self.r, self.events)
        self.assertTrue(d["synthetic_claims_coherent"])
        self.assertEqual(d["status"], "SYNTHETIC_PRECONDITIONS_CONSISTENT_DENY_ALL")
        self.assertFalse(d["operational_authorization"])
        self.assertFalse(d["dispatch_allowed"])
        self.assertEqual(d["real_cases_authorized"], 0)
        self.assertIn("PRIVATE_ISSUER_UNVERIFIED", d["deny_reasons"])

    def test_digest_domain_separated(self):
        self.assertNotEqual(V.context_fingerprint(self.c),
                            hashlib.sha256(json.dumps(self.c, sort_keys=True).encode()).hexdigest())

    def test_canonical_dict_order(self):
        other = dict(reversed(list(self.c.items())))
        self.assertEqual(V.context_fingerprint(other), V.context_fingerprint(self.c))

    def test_diagnostic_stable(self):
        a = V.assess_synthetic_lifecycle(self.c, self.r, self.events)
        b = V.assess_synthetic_lifecycle(deepcopy(self.c), deepcopy(self.r), [])
        self.assertEqual(a, b)

    def test_r5_deny_only_shape(self):
        self.assertEqual(len(V.KNOWN_PROFILES), 29)
        self.assertEqual(self.c["material_observation"]["observed_materials"], 1)

    def test_observation_claim_promoted_denied(self):
        self.c["material_observation"]["case_authorized"] = True
        self.check_reject("R5 observation")

    def test_observation_future_identity_promoted_denied(self):
        self.c["material_observation"]["observations"][0]["future_identity_guaranteed"] = True
        self.check_reject("material:")

    def test_observation_material_provenance_claim_denied(self):
        self.c["material_observation"]["observations"][0]["provenance_verified"] = True
        self.check_reject("material:")

    def test_issuer_claim_not_authentic(self):
        self.r["issuer_claim"] = "VERIFIED_ISSUER"
        self.check_reject("public claims")

    def test_clock_claim_not_authentic(self):
        self.r["clock_claim"] = "TRUSTED_UTC"
        self.check_reject("public claims")

    def test_revocation_claim_not_authentic(self):
        self.r["revocation_claim"] = "NOT_REVOKED_VERIFIED"
        self.check_reject("public claims")

    def test_dispatch_true_denied(self):
        self.r["dispatch_requested"] = True
        self.check_reject("public claims")

    def test_cleanup_early_receipt_denied(self):
        self.r["cleanup_receipt_ref"] = "ref:synthetic/dev/receipt"
        self.check_reject("public claims")

    def test_window_just_before_validity(self):
        self.r["checked_at_utc"] = "2026-11-08T14:29:59Z"
        out = V.assess_synthetic_lifecycle(self.c, self.r, [])
        self.assertIn("NOT_YET_WITHIN_CLAIMED_WINDOW", out["deny_reasons"])
        self.assertFalse(out["synthetic_claims_coherent"])

    def test_window_start_inclusive_but_denied(self):
        self.r["checked_at_utc"] = self.r["not_before_utc"]
        out = V.assess_synthetic_lifecycle(self.c, self.r, [])
        self.assertTrue(out["synthetic_claims_coherent"])
        self.assertFalse(out["operational_authorization"])

    def test_window_end_exclusive(self):
        self.r["checked_at_utc"] = self.r["not_after_utc"]
        out = V.assess_synthetic_lifecycle(self.c, self.r, [])
        self.assertIn("EXPIRED_CLAIMED_WINDOW", out["deny_reasons"])

    def test_window_one_second_before_end(self):
        self.r["checked_at_utc"] = "2026-11-08T15:29:59Z"
        self.assertTrue(V.assess_synthetic_lifecycle(self.c, self.r, [])["synthetic_claims_coherent"])

    def test_issuance_after_not_before_denied(self):
        self.r["issued_at_utc"] = "2026-11-08T14:30:01Z"
        self.check_reject("interval")

    def test_window_reversed_denied(self):
        self.r["not_after_utc"] = "2026-11-08T13:00:00Z"
        self.check_reject("interval")

    def test_window_equal_bounds_denied(self):
        self.r["not_after_utc"] = self.r["not_before_utc"]
        self.check_reject("interval")

    def test_synthetic_day_window_accepted_but_denied(self):
        self.r["not_before_utc"] = "2026-11-08T00:00:00Z"
        self.r["issued_at_utc"] = "2026-11-07T23:59:59Z"
        self.r["not_after_utc"] = "2026-11-09T00:00:00Z"
        self.assertFalse(V.assess_synthetic_lifecycle(self.c, self.r, [])["dispatch_allowed"])

    def test_synthetic_too_long_window_denied(self):
        self.r["not_after_utc"] = "2026-11-09T14:30:01Z"
        self.check_reject("interval")

    def test_no_events_not_proof_non_revoked(self):
        out = V.assess_synthetic_lifecycle(self.c, self.r, [])
        self.assertFalse(out["revocation_verified"])
        self.assertIn("REVOCATION_STATUS_UNVERIFIED", out["deny_reasons"])

    def test_revocation_latched(self):
        self.events.append(invalidator(self.c))
        out = V.assess_synthetic_lifecycle(self.c, self.r, self.events)
        self.assertFalse(out["synthetic_claims_coherent"])
        self.assertIn("INVALIDATED_AUTHORIZATION_REVOKED", out["deny_reasons"])

    def test_event_order_multiple(self):
        self.events = [invalidator(self.c, "MATERIAL_CHANGED", sequence=1),
                       invalidator(self.c, "AUTHORIZATION_REVOKED", "2026-11-08T14:45:00Z", 2)]
        out = V.assess_synthetic_lifecycle(self.c, self.r, self.events)
        self.assertIn("INVALIDATED_MATERIAL_CHANGED", out["deny_reasons"])
        self.assertIn("INVALIDATED_AUTHORIZATION_REVOKED", out["deny_reasons"])

    def test_event_duplicate_sequence_denied(self):
        self.events = [invalidator(self.c), invalidator(self.c, sequence=1,
                       when="2026-11-08T14:45:00Z")]
        self.check_reject("sequence")

    def test_event_sequence_gap_denied(self):
        self.events = [invalidator(self.c, sequence=2)]
        self.check_reject("sequence")

    def test_event_nonmonotonic_time_denied(self):
        self.events = [invalidator(self.c), invalidator(self.c, sequence=2,
                       when="2026-11-08T14:39:59Z")]
        self.check_reject("non-monotonic")

    def test_event_equal_time_denied(self):
        self.events = [invalidator(self.c), invalidator(self.c, sequence=2)]
        self.check_reject("non-monotonic")

    def test_event_future_denied(self):
        self.events = [invalidator(self.c, when="2026-11-08T16:00:00Z")]
        self.check_reject("future")

    def test_event_other_context_denied(self):
        e = invalidator(self.c)
        e["snapshot_sha256"] = "f" * 64
        self.events = [e]
        self.check_reject("other snapshot")

    def test_event_old_epoch_denied(self):
        e = invalidator(self.c)
        e["material_epoch"] -= 1
        self.events = [e]
        self.check_reject("other snapshot")

    def test_event_old_revision_denied(self):
        e = invalidator(self.c)
        e["authorization_revision"] -= 1
        self.events = [e]
        self.check_reject("other snapshot")

    def test_event_restore_kind_denied(self):
        self.events = [invalidator(self.c, "RESTORED")]
        self.check_reject("forbidden restoration")

    def test_event_unbounded_denied(self):
        self.events = [invalidator(self.c) for _ in range(65)]
        self.check_reject("bounded")

    def test_event_boolean_sequence_denied(self):
        self.events = [invalidator(self.c)]
        self.events[0]["sequence"] = True
        self.check_reject("sequence")

    def test_request_context_changed_requires_new_fingerprint(self):
        self.c["target_ref"] = "ref:synthetic/dev/other-target"
        self.check_reject("fingerprint mismatch")

    def test_request_old_epoch_denied(self):
        self.r["material_epoch"] -= 1
        self.check_reject("stale material")

    def test_request_old_revision_denied(self):
        self.r["authorization_revision"] -= 1
        self.check_reject("stale material")

    def test_cross_case_request_denied(self):
        self.r["case_id"] = "SSH-T01-S01-02"
        self.check_reject("cross-binding")

    def test_cross_profile_request_denied(self):
        self.r["profile_id"] = "SSH-T02-BASE"
        self.check_reject("cross-binding")

    def test_cross_stage_request_denied(self):
        self.r["stage"] = "pilot"
        self.check_reject("cross-binding")

    def test_context_changed_material_byte_requires_new_fingerprint(self):
        self.c["material_observation"]["observations"][0]["observed_sha256"] = "a" * 64
        self.check_reject("fingerprint mismatch")

    def test_context_changed_budget_requires_new_fingerprint(self):
        self.c["budget_sha256"] = "b" * 64
        self.check_reject("fingerprint mismatch")

    def test_context_changed_epoch_requires_new_fingerprint(self):
        self.c["material_epoch"] += 1
        self.check_reject("fingerprint mismatch")

    def test_context_changed_auth_revision_requires_new_fingerprint(self):
        self.c["authorization_revision"] += 1
        self.check_reject("fingerprint mismatch")

    def test_context_changed_cleanup_requires_new_fingerprint(self):
        self.c["cleanup_plan_ref"] = "ref:synthetic/dev/cleanup-02"
        self.check_reject("fingerprint mismatch")

    def test_context_changed_service_requires_new_fingerprint(self):
        self.c["service_id"] = "dev-svc-ssh-02"
        self.check_reject("fingerprint mismatch")

    def test_context_changed_scenario_requires_new_fingerprint(self):
        self.c["scenario_id"] = "dev-scn-ssh-02"
        self.check_reject("fingerprint mismatch")

    def test_context_changed_auth_ref_requires_new_fingerprint(self):
        self.c["authorization_ref"] = "ref:synthetic/dev/auth-02"
        self.check_reject("fingerprint mismatch")

    def test_new_snapshot_still_denied(self):
        self.c["budget_sha256"] = "b" * 64
        self.r["snapshot_sha256"] = V.context_fingerprint(self.c)
        out = V.assess_synthetic_lifecycle(self.c, self.r, [])
        self.assertTrue(out["synthetic_claims_coherent"])
        self.assertFalse(out["operational_authorization"])

    def test_public_evidence_extra_field_denied(self):
        self.r["private_issuer_verified"] = True
        self.check_reject("unknown/missing")

    def test_validity_with_noncanonical_offset_denied(self):
        self.r["checked_at_utc"] = "2026-11-08T15:00:00+00:00"
        self.check_reject("canonical UTC")

    def test_validity_with_fraction_denied(self):
        self.r["checked_at_utc"] = "2026-11-08T15:00:00.000Z"
        self.check_reject("canonical UTC")

    def test_invalid_date_denied(self):
        self.r["issued_at_utc"] = "2026-02-30T14:00:00Z"
        self.check_reject("invalid calendar")

    def test_invalid_time_60_denied(self):
        self.r["issued_at_utc"] = "2026-11-08T14:00:60Z"
        self.check_reject("invalid calendar")

    def test_wrong_material_uid_type_denied(self):
        self.c["material_observation"]["observations"][0]["uid"] = True
        self.check_reject("material uid")

    def test_wrong_material_bytes_bool_denied(self):
        self.c["material_observation"]["observations"][0]["observed_bytes"] = True
        self.check_reject("bounded positive")

    def test_duplicate_material_path_denied(self):
        second = deepcopy(self.c["material_observation"]["observations"][0])
        self.c["material_observation"]["observations"].append(second)
        self.c["material_observation"]["observed_materials"] = 2
        self.check_reject("duplicate path")

    def test_material_count_mismatch_denied(self):
        self.c["material_observation"]["observed_materials"] = 2
        self.check_reject("material count")

    def test_cross_stage_synthetic_target_ref_denied(self):
        self.c["target_ref"] = "ref:synthetic/pilot/target-01"
        self.check_reject("cross-stage")

    def test_ref_path_traversal_denied(self):
        self.c["target_ref"] = "ref:synthetic/dev/a/../target-01"
        self.check_reject("unsafe")

    def test_case_profile_variant_mismatch_denied(self):
        self.c["case_id"] = "FTP-T01-S01-01"
        self.check_reject("context case/profile")

    def test_unknown_profile_denied(self):
        self.c["profile_id"] = "SSH-T99-BASE"
        self.check_reject("profile not in")

    def test_material_path_absolute_denied(self):
        self.c["material_observation"]["observations"][0]["relative_path"] = "/usr/bin/sh"
        self.check_reject("noncanonical")

    def test_material_path_traversal_denied(self):
        self.c["material_observation"]["observations"][0]["relative_path"] = "bin/../mock"
        self.check_reject("noncanonical")

    def test_material_world_writable_denied(self):
        self.c["material_observation"]["observations"][0]["mode"] = 0o666
        self.check_reject("material mode")

    def test_material_sha_uppercase_denied(self):
        self.c["material_observation"]["observations"][0]["observed_sha256"] = "ABCDEF" * 10 + "ABCD"
        self.check_reject("sha256")

    def test_material_noncanonical_observation_status_denied(self):
        self.c["material_observation"]["observations"][0]["status"] = "AUTHORIZED"
        self.check_reject("material:")

    def test_material_boolean_dispatch_denied(self):
        self.c["material_observation"]["dispatch_allowed"] = True
        self.check_reject("R5 observation")

    def test_count_bool_denied(self):
        self.c["material_observation"]["observed_materials"] = True
        self.check_reject("material count")

    def test_context_epoch_bool_denied(self):
        self.c["material_epoch"] = True
        self.check_reject("bounded positive")

    def test_request_revision_bool_denied(self):
        self.r["authorization_revision"] = True
        self.check_reject("stale material")

    def test_event_list_as_dict_denied(self):
        self.events = {}
        self.check_reject("bounded list")

    def test_source_no_process_spawn_or_network(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("import subprocess", source)
        self.assertNotIn("import socket", source)
        self.assertNotIn("os.system(", source)
        self.assertNotIn("Popen(", source)

    def test_upstream_symlink_parent_denied(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            other = root / "other"
            other.mkdir()
            (root / "lab").symlink_to(other, target_is_directory=True)
            with self.assertRaisesRegex(V.LifecycleError, "symbolic link"):
                V.check_upstream(root)

    def test_repository_contract_baseline_fixture(self):
        root = Path(__file__).resolve().parents[2]  # project root, in installed repo
        self.assertTrue((root / V.CONTRACT).is_file())
        with patch.object(V, "check_upstream", return_value={"status":"MOCKED_ONLY"}):
            out = V.verify_repository(root)
        self.assertEqual(out["status"], "PASS_P8_R6_SYNTHETIC_LIFECYCLE_DENY_ALL")

    def test_repository_rejects_fabricated_authorization(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / V.CONTRACT).parent.mkdir(parents=True)
            (root / V.TRACE).parent.mkdir(parents=True)
            source = Path(__file__).resolve().parents[2]
            contract = json.loads((source / V.CONTRACT).read_text())
            trace = json.loads((source / V.TRACE).read_text())
            contract["dispatch_allowed"] = True
            (root / V.CONTRACT).write_text(json.dumps(contract))
            (root / V.TRACE).write_text(json.dumps(trace))
            with patch.object(V, "check_upstream", return_value={}):
                with self.assertRaisesRegex(V.LifecycleError, "contract"):
                    V.verify_repository(root)

    def test_repository_rejects_fabricated_postmerge_ci(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / V.CONTRACT).parent.mkdir(parents=True)
            (root / V.TRACE).parent.mkdir(parents=True)
            source = Path(__file__).resolve().parents[2]
            contract = json.loads((source / V.CONTRACT).read_text())
            trace = json.loads((source / V.TRACE).read_text())
            trace["verification"]["postmerge_ci"] = "SUCCESS"
            (root / V.CONTRACT).write_text(json.dumps(contract))
            (root / V.TRACE).write_text(json.dumps(trace))
            with patch.object(V, "check_upstream", return_value={}):
                with self.assertRaisesRegex(V.LifecycleError, "traceability"):
                    V.verify_repository(root)

    def test_repository_rejects_duplicate_json_fields(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / V.CONTRACT).parent.mkdir(parents=True)
            (root / V.CONTRACT).write_text('{"schema_version":"1.0","schema_version":"1.0"}')
            (root / V.TRACE).parent.mkdir(parents=True)
            (root / V.TRACE).write_text("{}")
            with patch.object(V, "check_upstream", return_value={}):
                with self.assertRaisesRegex(V.LifecycleError, "duplicate JSON key"):
                    V.verify_repository(root)


# Deliberately distinct unittest methods: each invalidation kind gets an isolated
# independent oracle test. No timing dependency or random data is used.
for _event_kind in sorted(V.INVALIDATION_KINDS):
    def _case(self, kind=_event_kind):
        c, req, _ = baseline()
        result = V.assess_synthetic_lifecycle(c, req, [invalidator(c, kind)])
        self.assertFalse(result["synthetic_claims_coherent"])
        self.assertIn("INVALIDATED_" + kind, result["deny_reasons"])
        self.assertFalse(result["operational_authorization"])
        self.assertFalse(result["dispatch_allowed"])
    setattr(LifecycleOracleTests, "test_invalidation_" + _event_kind.lower(), _case)


if __name__ == "__main__":
    unittest.main()
