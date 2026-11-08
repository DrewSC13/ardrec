"""ARDREC P8-R4 synthetic-only contract oracles; no VM, network or subprocess."""
from __future__ import annotations

import copy
import hashlib
import json
import importlib.util
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "verify_p8_binding_contract.py"
spec = importlib.util.spec_from_file_location("ardrec_p8_r4", SOURCE)
assert spec and spec.loader
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)

# Handwritten case and profile test oracle (no source P8 validator injected).
COMMON = ["SCOPE_APPROVED", "LAB_ISOLATION_CONFIRMED", "DESTINATION_AUTHORIZED", "CLIENT_COMPATIBLE"]


def make_case(write=False):
    stage = "dev"
    family = "FTP-T08" if write else "SSH-T01"
    proto = "ftp" if write else "ssh"
    variant = "WRITE" if write else None
    profile_id = "FTP-T08-WRITE" if write else "SSH-T01-BASE"
    slots = (["authorization_ref", "target_ref", "session_ref", "control_resource_ref",
              "restricted_resource_ref", "operation_ref", "cleanup_ref"] if write else
             ["authorization_ref", "target_ref", "port_ref", "host_key_ref", "transport_policy_ref"])
    supports = (["TARGET_ATTESTATION", "INTEGRITY_PROVENANCE", "ACCESS_COMPARISON", "OPERATION_RESPONSE",
                 "MARKER_CREATED", "MARKER_VERIFIED", "CLEANUP_CONFIRMED"] if write else
                ["TARGET_ATTESTATION", "INTEGRITY_PROVENANCE", "TRANSPORT_NEGOTIATION", "HOST_KEY_MATCH"])
    acceptance = (["ACCESS_COMPARISON", "OPERATION_RESPONSE", "MARKER_CREATED", "MARKER_VERIFIED",
                   "CLEANUP_CONFIRMED"] if write else ["TRANSPORT_NEGOTIATION", "HOST_KEY_MATCH"])
    guards = COMMON + (["SESSION_AUTHENTICATED", "REFERENCE_BASELINE_PREPARED",
                        "RESTRICTED_RESOURCE_PREDEFINED", "WRITE_FIXTURE_PREPARED", "CLEANUP_VERIFIABLE"]
                       if write else ["SERVICE_READY", "HOST_KEY_PREDEFINED"])
    cleanup = "VERIFY_THEN_REMOVE_MARKER" if write else "NO_MUTATION"
    caseid = family + "-S01-01"
    scenario = "dev-scn-0001"
    service = "dev-svc-0001"
    auth_ref = "ref:private/dev/authorizations/alpha"
    target_ref = "ref:private/dev/targets/alpha"
    cleanup_ref = "ref:private/dev/cleanup/plan"
    params = {s: f"ref:private/dev/materials/{s}" for s in slots}
    params["authorization_ref"] = auth_ref
    params["target_ref"] = target_ref
    if "cleanup_ref" in params:
        params["cleanup_ref"] = cleanup_ref
    p8 = {
        "profile_id": profile_id, "family_id": family, "protocol": proto,
        "variant": variant, "precedence": 4 if write else 1,
        "required_material_parameter_slots": slots, "required_preconditions": guards,
        "required_supports": supports, "required_acceptance_supports": acceptance,
        "cleanup": cleanup, "status": "BLOCKED_UNBOUND_NO_EXECUTION",
        "binding": {name: None for name in sorted(set(V.BIND_FIELDS) | {"cleanup_receipt_ref"})},
    }
    derivation = {
        "status": "DRAFT_NOT_AUTHORIZED", "execution_enabled": False,
        "stage": stage, "scenario_id": scenario, "case_id": caseid,
        "source_family": family, "variant": variant, "precedence": p8["precedence"],
        "parameter_refs": params.copy(), "preconditions": guards.copy(),
        "required_supports": supports.copy(), "acceptance_supports": acceptance.copy(),
        "cleanup": cleanup,
    }
    manifest = {"stage": stage, "services": [{"id": service, "protocol": proto,
               "network_id": f"ardrec-{stage}-{proto}"}], "scenarios": [{"id": scenario, "service_id": service}]}
    cleanup_plan = {
        "policy": cleanup, "plan_ref": cleanup_ref,
        "marker_ref": "ref:private/dev/markers/alpha" if write else None,
        "removal_plan_ref": "ref:private/dev/cleanup/removal" if write else None,
        "independent_verification_ref": "ref:private/dev/cleanup/independent" if write else None,
    }
    material = {
        "executable_absolute_path": "/usr/bin/fake-client", "executable_sha256": "a"*64,
        "executable_version": "0.0.0-fixture", "argv_typed_vector": [
            {"kind": "literal", "value": "--fake-no-run"},
            {"kind": "material_slot", "value": "target_ref"}],
        "working_directory": "/tmp/ardrec-fixture", "environment_allowlist": {"LANG": "C"},
        "auxiliary_executables": [], "case_authorization_ref": auth_ref,
        "approved_target_ref": target_ref,
        "fixed_resource_budget": {
            "ordinary_attempts": 1, "additional_attempts": 0, "timeout_ms": 5000,
            "max_stdout_bytes": 1024, "max_stderr_bytes": 1024,
            "max_transfer_bytes": 64 if write else 0, "max_operations": 1, "max_requests": 1,
            "max_memory_mib": 128},
        "capture_policy_ref": "ref:private/dev/capture/alpha",
    }
    auth = {
        "authorization_ref": auth_ref, "issuer_ref": "ref:private/dev/issuers/owner",
        "operator_ref": "ref:private/dev/operators/assigned", "stage": stage,
        "service_id": service, "scenario_id": scenario, "case_id": caseid,
        "profile_id": profile_id, "approved_target_ref": target_ref,
        "action_scope": profile_id, "issued_at_utc": "2026-11-07T00:00:00Z",
        "not_before_utc": "2026-11-08T00:00:00Z",
        "not_after_utc": "2026-11-09T00:00:00Z",
        "revocation_ref": "ref:private/dev/revocations/alpha",
        "approval_state": "PROPOSED_NOT_VERIFIED", "revocation_state": "UNKNOWN",
    }
    prop = {
        "schema_version": "1.0", "stage": stage, "service_id": service,
        "scenario_id": scenario, "case_id": caseid,
        "profile_id": profile_id, "family_id": family, "protocol": proto,
        "variant": variant, "precedence": p8["precedence"],
        "material_parameter_refs": params, "preconditions_observed": {
            name: {"value": "ND", "support_ref": None} for name in guards},
        "binding_candidate": material, "authorization_candidate": auth,
        "cleanup_plan": cleanup_plan, "post_execution_receipt_ref": None,
    }
    return prop, derivation, p8, manifest


def build_synthetic_repo(root):
    """Synthetic stub for *unit tests only*, NOT a replacement for real P8 R3."""
    src = root / V.R3_VALIDATOR
    src.parent.mkdir(parents=True, exist_ok=True)
    fake = (
        "def verify_from_repo(root):\n"
        "    return {'status': 'VERIFIED_DECLARATIONS_ONLY_NO_EXECUTION',\n"
        "            'gate': {'authorization': False, 'dispatch_allowed': False,\n"
        "                     'real_executor_available': False},\n"
        "            'counts': {'families': 25, 'profiles': 29,\n"
        "                       'registered_scenarios': 0, 'real_derived_cases': 0}}\n"
    )
    src.write_text(fake)
    for rel in (V.CONTRACT, V.TRACE):
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes((SOURCE.parents[1] / rel).read_bytes())
    return hashlib.sha256(src.read_bytes()).hexdigest()



class ContractTests(unittest.TestCase):
    def setUp(self):
        self.prop, self.case, self.profile, self.stage = make_case()

    def review(self):
        return V.assess_synthetic_candidate(self.prop, self.case, self.profile, self.stage)

    def reject(self, pattern):
        with self.assertRaisesRegex(V.BindingContractError, pattern):
            self.review()

    def test_nominal_draft_is_never_authorized(self):
        x = self.review()
        self.assertEqual(x["status"], "SYNTHETIC_STRUCTURAL_REVIEW_ONLY_NOT_AUTHORIZED")
        self.assertFalse(x["dispatch_allowed"])
        self.assertFalse(x["real_authorization"])
        self.assertFalse(x["is_experimental_unit"])
        self.assertEqual(set(x["unmet_preconditions"]), set(self.profile["required_preconditions"]))

    def test_mutation_draft_is_never_authorized(self):
        self.prop, self.case, self.profile, self.stage = make_case(write=True)
        x = self.review()
        self.assertFalse(x["dispatch_allowed"])
        self.assertEqual(x["cleanup_receipt_status"], "POST_EXECUTION_UNAVAILABLE")

    def test_declared_true_still_not_trusted(self):
        for key in self.prop["preconditions_observed"]:
            self.prop["preconditions_observed"][key] = {
                "value": "VERDADERO", "support_ref": "ref:private/dev/supports/synthetic"}
        x = self.review()
        self.assertEqual(x["unmet_preconditions"], [])
        self.assertFalse(x["dispatch_allowed"])
        self.assertEqual(x["authorization_status"], "UNVERIFIED_PRIVATE_ISSUER_AND_REVOCATION")

    def test_false_preserved_as_unmet(self):
        self.prop["preconditions_observed"][COMMON[0]]["value"] = "FALSO"
        self.assertIn(COMMON[0], self.review()["unmet_preconditions"])

    def test_unverified_digest_is_not_attestation(self):
        self.assertEqual(self.review()["executable_hash_status"], "DECLARED_NOT_VERIFIED_AGAINST_BYTES")

    def test_no_registered_scenario_denied(self):
        self.stage["scenarios"] = []
        self.reject("service-scenario not registered")

    def test_no_registered_service_denied(self):
        self.stage["services"] = []
        self.reject("service-scenario not registered")

    def test_foreign_stage_denied(self):
        self.prop["stage"] = "pilot"
        self.reject("cross-stage manifest")

    def test_foreign_service_id_denied(self):
        self.prop["service_id"] = "pilot-svc-0001"
        self.reject("service-scenario not registered")

    def test_mismatched_scenario_service_denied(self):
        self.stage["scenarios"][0]["service_id"] = "dev-svc-other"
        self.reject("mismatched scenario/service")

    def test_mismatched_service_protocol_denied(self):
        self.stage["services"][0]["protocol"] = "ftp"
        self.reject("mismatched scenario/service")

    def test_mismatched_network_denied(self):
        self.stage["services"][0]["network_id"] = "ardrec-dev-ftp"
        self.reject("mismatched scenario/service")

    def test_cross_family_denied(self):
        self.prop["family_id"] = "FTP-T01"
        self.reject("family/variant mismatch")

    def test_cross_variant_denied(self):
        self.prop["variant"] = "WRITE"
        self.reject("derived case mismatch")

    def test_changed_precedence_denied(self):
        self.prop["precedence"] = 4
        self.reject("derived case mismatch")

    def test_mutated_source_requirements_denied(self):
        self.profile["required_supports"].append("FORGED")
        self.reject("requirements altered")

    def test_missing_material_denied(self):
        self.prop["material_parameter_refs"].pop("host_key_ref")
        self.reject("material slots")

    def test_cross_stage_material_denied(self):
        self.prop["material_parameter_refs"]["port_ref"] = "ref:private/pilot/ports/one"
        self.reject("outside stage privacy")

    def test_parameter_substitution_denied(self):
        self.prop["material_parameter_refs"]["port_ref"] = "ref:private/dev/materials/other-port"
        self.reject("parameters changed")

    def test_unknown_extra_field_denied(self):
        self.prop["allow_execute"] = True
        self.reject("missing/unknown fields")

    def test_p8_premature_promotion_denied(self):
        self.profile["binding"]["executable_sha256"] = "b"*64
        self.reject("base profile already promoted")

    def test_p7_unauthorized_promotion_denied(self):
        self.case["status"] = "AUTHORIZED"
        self.reject("derived case must remain a draft")

    def test_undeclared_argv_slot_denied(self):
        self.prop["binding_candidate"]["argv_typed_vector"][1]["value"] = "password_ref"
        self.reject("foreign material slot")

    def test_shell_binary_denied(self):
        self.prop["binding_candidate"]["executable_absolute_path"] = "/bin/bash"
        self.reject("shell forbidden")

    def test_relative_binary_denied(self):
        self.prop["binding_candidate"]["executable_absolute_path"] = "fake-client"
        self.reject("absolute path")

    def test_path_traversal_denied(self):
        self.prop["binding_candidate"]["working_directory"] = "/tmp/../root"
        self.reject("noncanonical path")

    def test_noncanonical_slashes_denied(self):
        self.prop["binding_candidate"]["working_directory"] = "/tmp//dir"
        self.reject("noncanonical path")

    def test_hash_not_hex_denied(self):
        self.prop["binding_candidate"]["executable_sha256"] = "y"*64
        self.reject("digest form")

    def test_invalid_version_denied(self):
        self.prop["binding_candidate"]["executable_version"] = "bad version; cmd"
        self.reject("invalid")

    def test_string_shell_command_vector_denied(self):
        self.prop["binding_candidate"]["argv_typed_vector"] = "--all; true"
        self.reject("bounded typed vector")

    def test_newline_arg_denied(self):
        self.prop["binding_candidate"]["argv_typed_vector"][0]["value"] = "--foo\nsh"
        self.reject("unsafe literal")

    def test_unsupported_environment_denied(self):
        self.prop["binding_candidate"]["environment_allowlist"] = {"LD_PRELOAD": "/tmp/code.so"}
        self.reject("unsafe inherited")

    def test_auxiliary_unhashed_denied(self):
        self.prop["binding_candidate"]["auxiliary_executables"] = [{
            "absolute_path": "/usr/bin/other", "sha256": None, "version": "1.0"}]
        self.reject("digest form")

    def test_auxiliary_duplicate_denied(self):
        h = {"absolute_path": "/usr/bin/other", "sha256": "a"*64, "version": "1.0"}
        self.prop["binding_candidate"]["auxiliary_executables"] = [h, copy.deepcopy(h)]
        self.reject("repeated/self")

    def test_auxiliary_shell_denied(self):
        self.prop["binding_candidate"]["auxiliary_executables"] = [{
            "absolute_path": "/bin/sh", "sha256": "a"*64, "version": "1.0"}]
        self.reject("shell forbidden")

    def test_bool_attempts_denied(self):
        self.prop["binding_candidate"]["fixed_resource_budget"]["ordinary_attempts"] = True
        self.reject("exactly one")

    def test_second_attempt_denied(self):
        self.prop["binding_candidate"]["fixed_resource_budget"]["additional_attempts"] = 1
        self.reject("unapproved repetitions")

    def test_negative_budget_denied(self):
        self.prop["binding_candidate"]["fixed_resource_budget"]["timeout_ms"] = -1
        self.reject("finite integer")

    def test_excessive_timeout_denied(self):
        self.prop["binding_candidate"]["fixed_resource_budget"]["timeout_ms"] = 100_000
        self.reject("finite integer")

    def test_unbounded_output_denied(self):
        self.prop["binding_candidate"]["fixed_resource_budget"]["max_stdout_bytes"] = None
        self.reject("finite integer")

    def test_cross_stage_target_denied(self):
        self.prop["binding_candidate"]["approved_target_ref"] = "ref:private/pilot/targets/alpha"
        self.reject("outside stage privacy")

    def test_authorization_case_mismatch_denied(self):
        self.prop["authorization_candidate"]["case_id"] = "SSH-T01-S05-01"
        self.reject("case identity mismatch")

    def test_authorization_scope_mismatch_denied(self):
        self.prop["authorization_candidate"]["action_scope"] = "FTP-T01-BASE"
        self.reject("action scope mismatch")

    def test_authorization_material_ref_mismatch_denied(self):
        self.prop["material_parameter_refs"]["authorization_ref"] = "ref:private/dev/authorizations/other"
        self.case["parameter_refs"]["authorization_ref"] = "ref:private/dev/authorizations/other"
        self.reject("material authorization reference mismatch")

    def test_target_identity_mismatch_denied(self):
        self.prop["authorization_candidate"]["approved_target_ref"] = "ref:private/dev/targets/other"
        self.reject("target scope mismatch")

    def test_issuer_grant_claim_denied(self):
        self.prop["authorization_candidate"]["approval_state"] = "APPROVED"
        self.reject("fabricated approval")

    def test_revocation_unverified_denied(self):
        self.prop["authorization_candidate"]["revocation_state"] = "NOT_REVOKED"
        self.reject("fabricated approval")

    def test_expired_ordered_dates_denied(self):
        self.prop["authorization_candidate"]["not_after_utc"] = "2026-11-07T00:00:00Z"
        self.reject("invalid time window")

    def test_wrong_timezone_denied(self):
        self.prop["authorization_candidate"]["not_after_utc"] = "2026-11-09T00:00:00+00:00"
        self.reject("canonical UTC")

    def test_invalid_date_denied(self):
        self.prop["authorization_candidate"]["not_after_utc"] = "2026-02-30T00:00:00Z"
        self.reject("invalid calendar date")

    def test_wrong_cleanup_policy_denied(self):
        self.prop["cleanup_plan"]["policy"] = "VERIFY_THEN_REMOVE_MARKER"
        self.reject("wrong policy")

    def test_early_receipt_denied(self):
        self.prop["post_execution_receipt_ref"] = "ref:private/dev/cleanup/forged-receipt"
        self.reject("future receipt")

    def test_synthetic_mutation_without_independent_verifier_denied(self):
        self.prop, self.case, self.profile, self.stage = make_case(write=True)
        self.prop["cleanup_plan"]["independent_verification_ref"] = None
        self.reject("invalid symbolic reference")

    def test_synthetic_mutation_reused_verifier_denied(self):
        self.prop, self.case, self.profile, self.stage = make_case(write=True)
        self.prop["cleanup_plan"]["independent_verification_ref"] = self.prop["cleanup_plan"]["marker_ref"]
        self.reject("plan and verifier must be distinct")

    def test_synthetic_mutation_missing_support_denied(self):
        self.prop, self.case, self.profile, self.stage = make_case(write=True)
        self.profile["required_supports"].remove("CLEANUP_CONFIRMED")
        self.case["required_supports"].remove("CLEANUP_CONFIRMED")
        self.reject("missing post-execution supports")

    def test_synthetic_mutation_zero_transfer_budget_denied(self):
        self.prop, self.case, self.profile, self.stage = make_case(write=True)
        self.prop["binding_candidate"]["fixed_resource_budget"]["max_transfer_bytes"] = 0
        self.reject("nonzero transfer bound")

    def test_synthetic_mutation_material_cleanup_mismatch_denied(self):
        self.prop, self.case, self.profile, self.stage = make_case(write=True)
        self.prop["cleanup_plan"]["plan_ref"] = "ref:private/dev/cleanup/forged-plan"
        self.reject("material cleanup plan mismatch")

    def test_true_without_support_denied(self):
        self.prop["preconditions_observed"][COMMON[0]] = {"value": "VERDADERO", "support_ref": None}
        self.reject("invalid symbolic reference")

    def test_false_with_support_denied(self):
        self.prop["preconditions_observed"][COMMON[0]] = {
            "value": "FALSO", "support_ref": "ref:private/dev/supports/false"}
        self.reject("unsupported false/ND")

    def test_unsupported_trivalent_denied(self):
        self.prop["preconditions_observed"][COMMON[0]]["value"] = True
        self.reject("invalid trivalent")

    def test_schema_duplicate_json_keys_denied(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "a.json"
            p.write_text('{"a":1,"a":2}')
            with self.assertRaisesRegex(V.BindingContractError, "duplicate JSON key"):
                V._read_json(Path(t), "a.json")

    def test_repository_contract_accepts_only_synthetic_deny_baseline(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            forged_stub_sha = build_synthetic_repo(root)
            with patch.object(V, "R3_VALIDATOR_SHA256", forged_stub_sha):
                report = V.verify_repository(root)
            self.assertEqual(report["status"], "PASS_P8_R4_CONTRACT_ONLY_DENY_ALL")
            self.assertFalse(report["dispatch_allowed"])
            self.assertEqual(report["approved_profiles"], 0)

    def test_repository_contract_rejects_fabricated_public_authorization(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            forged_stub_sha = build_synthetic_repo(root)
            target = root / V.CONTRACT
            d = json.loads(target.read_text())
            d["approved_profiles"] = 1
            target.write_text(json.dumps(d))
            with patch.object(V, "R3_VALIDATOR_SHA256", forged_stub_sha):
                with self.assertRaisesRegex(V.BindingContractError, "fictitious"):
                    V.verify_repository(root)

    def test_repository_contract_rejects_fabricated_postmerge_ci(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            forged_stub_sha = build_synthetic_repo(root)
            target = root / V.TRACE
            d = json.loads(target.read_text())
            d["verification"]["new_main_ci"] = "SUCCESS"
            target.write_text(json.dumps(d))
            with patch.object(V, "R3_VALIDATOR_SHA256", forged_stub_sha):
                with self.assertRaisesRegex(V.BindingContractError, "future CI"):
                    V.verify_repository(root)

    def test_repository_contract_rejects_fabricated_experimental_units(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            forged_stub_sha = build_synthetic_repo(root)
            target = root / V.TRACE
            d = json.loads(target.read_text())
            d["scope"]["real_derived_cases"] = 54
            target.write_text(json.dumps(d))
            with patch.object(V, "R3_VALIDATOR_SHA256", forged_stub_sha):
                with self.assertRaisesRegex(V.BindingContractError, "fabricated operational"):
                    V.verify_repository(root)

    def test_versioned_contract_is_deny_only(self):
        contract_path = SOURCE.parent / "p8-binding-contract-v1" / "contract.json"
        d = json.loads(contract_path.read_text(encoding="utf-8"))
        self.assertEqual(d["base_commit"], V.PARENT_COMMIT)
        self.assertEqual(d["pre_execution_fields"], sorted(V.BIND_FIELDS))
        self.assertEqual(d["post_execution_field"], "cleanup_receipt_ref")
        self.assertEqual(d["public_candidate_records"], 0)
        self.assertEqual(d["approved_profiles"], 0)
        self.assertIs(d["dispatch_enabled"], False)

    def test_untrusted_upstream_source_is_not_imported(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            src = root / "lab" / "verify_p8_readiness.py"
            src.parent.mkdir(parents=True)
            src.write_text("from pathlib import Path\nPath('MALICIOUS_SENTINEL').touch()\n")
            with self.assertRaisesRegex(V.BindingContractError, "source hash mismatch"):
                V.verify_repository(root)
            self.assertFalse((root / "MALICIOUS_SENTINEL").exists())

    def test_contract_schema_source_only(self):
        self.assertEqual(len(V.BIND_FIELDS), 11)
        self.assertNotIn("cleanup_receipt_ref", V.BIND_FIELDS)
        self.assertEqual(len(V.AUTH_FIELDS), 16)
        self.assertFalse(self.review()["dispatch_allowed"])


if __name__ == "__main__":
    unittest.main()
