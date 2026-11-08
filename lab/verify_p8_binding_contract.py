#!/usr/bin/env python3
"""P8 R4: read-only binding/authorization proposal grammar; DENY ONLY.

Public entry point attests the unchanged, zero-case P6/P7/P8 repository baseline.
The separate pure `assess_synthetic_candidate` function tests future contract shape.
Neither function verifies actual bytes, issuer authority, or lab isolation; neither
can grant execution. Never pass secrets or private dossiers to this public CLI.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any

PARENT_COMMIT = "5855ac8956b1672c698919e3c8c87b2cfa1c1823"
THESIS_SHA256 = "6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72"
P7_SHA256 = "5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e"
P8_SHA256 = "fe0fae200ac031622d27020b77d38bd18a22e3ffaa0dd0f57ec4e9f01f284ce3"
R3_VALIDATOR = "lab/verify_p8_readiness.py"
R3_VALIDATOR_SHA256 = "677af5bb68f618aabd3e5b1535159703f7f035303cc4b07f793280f2a070169f"
CONTRACT = "lab/p8-binding-contract-v1/contract.json"
TRACE = "docs/traceability/p8-binding-r4.json"
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
REF_RE = re.compile(r"^ref:[a-zA-Z0-9][a-zA-Z0-9._:/-]{2,127}$")
STAGES = ("dev", "pilot", "exp")
CLEANUP = ("NO_MUTATION", "VERIFY_THEN_REMOVE_MARKER")
ENV_FIXED = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
BIND_FIELDS = frozenset({
    "executable_absolute_path", "executable_sha256", "executable_version",
    "argv_typed_vector", "working_directory", "environment_allowlist",
    "auxiliary_executables", "case_authorization_ref", "approved_target_ref",
    "fixed_resource_budget", "capture_policy_ref",
})
BUDGET_FIELDS = frozenset({
    "ordinary_attempts", "additional_attempts", "timeout_ms", "max_stdout_bytes",
    "max_stderr_bytes", "max_transfer_bytes", "max_operations", "max_requests",
    "max_memory_mib",
})
AUTH_FIELDS = frozenset({
    "authorization_ref", "issuer_ref", "operator_ref", "stage", "service_id",
    "scenario_id", "case_id", "profile_id", "approved_target_ref", "action_scope",
    "issued_at_utc", "not_before_utc", "not_after_utc", "revocation_ref",
    "approval_state", "revocation_state",
})
PROPOSAL_FIELDS = frozenset({
    "schema_version", "stage", "service_id", "scenario_id", "case_id",
    "profile_id", "family_id", "protocol", "variant", "precedence",
    "material_parameter_refs", "preconditions_observed", "binding_candidate",
    "authorization_candidate", "cleanup_plan", "post_execution_receipt_ref",
})
CLEANUP_FIELDS = frozenset({
    "policy", "plan_ref", "marker_ref", "removal_plan_ref", "independent_verification_ref",
})
VALID_OBSERVATIONS = {"VERDADERO", "FALSO", "ND"}


class BindingContractError(ValueError):
    """Untrusted proposal conflicts with a source contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BindingContractError(message)


def exact(obj: Any, keys: frozenset[str] | set[str], label: str) -> None:
    require(type(obj) is dict and set(obj) == set(keys), f"{label}: missing/unknown fields")


def reference(value: Any, label: str, *, stage: str | None = None) -> str:
    require(type(value) is str and bool(REF_RE.fullmatch(value)) and ".." not in value,
            f"{label}: invalid symbolic reference")
    if stage is not None:
        require(value.startswith(f"ref:private/{stage}/"), f"{label}: outside stage privacy scope")
    return value


def absolute_path(value: Any, label: str, *, executable: bool = False) -> str:
    require(type(value) is str and value.startswith("/") and "\\" not in value and
            not any(ord(x) < 32 or ord(x) == 127 for x in value) and len(value) <= 512,
            f"{label}: invalid absolute path")
    p = PurePosixPath(value)
    require(str(p) == value and ".." not in p.parts and "." not in value.split("/") and
            "//" not in value and len(p.parts) > 1, f"{label}: noncanonical path")
    if executable:
        require(p.name not in ("sh", "bash", "dash", "zsh", "ksh", "fish", "cmd.exe", "powershell.exe"),
                f"{label}: shell forbidden")
    return value


def sha(value: Any, label: str) -> str:
    require(type(value) is str and bool(SHA_RE.fullmatch(value)), f"{label}: digest form")
    # This attests only the *syntax*. A future AL-07 trusted resolver must hash actual bytes.
    return value


def positive_int(value: Any, label: str, maximum: int, *, allow_zero: bool = False) -> int:
    require(type(value) is int and (0 if allow_zero else 1) <= value <= maximum,
            f"{label}: finite integer limit required")
    return value


def utc(value: Any, label: str) -> datetime:
    require(type(value) is str and bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value)),
            f"{label}: canonical UTC required")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as e:
        raise BindingContractError(f"{label}: invalid calendar date") from e
    return parsed


def verify_budget(budget: Any) -> None:
    exact(budget, BUDGET_FIELDS, "budget")
    require(type(budget["ordinary_attempts"]) is int and budget["ordinary_attempts"] == 1,
            "budget: exactly one ordinary attempt")
    require(type(budget["additional_attempts"]) is int and budget["additional_attempts"] == 0,
            "budget: no unapproved repetitions")
    positive_int(budget["timeout_ms"], "budget.timeout_ms", 60_000)
    positive_int(budget["max_stdout_bytes"], "budget.max_stdout_bytes", 1_048_576)
    positive_int(budget["max_stderr_bytes"], "budget.max_stderr_bytes", 1_048_576)
    positive_int(budget["max_transfer_bytes"], "budget.max_transfer_bytes", 1_048_576, allow_zero=True)
    positive_int(budget["max_operations"], "budget.max_operations", 100)
    positive_int(budget["max_requests"], "budget.max_requests", 100)
    positive_int(budget["max_memory_mib"], "budget.max_memory_mib", 1_024)


def verify_binding(candidate: Any, proposal: dict[str, Any]) -> None:
    exact(candidate, BIND_FIELDS, "binding candidate")
    stage = proposal["stage"]
    absolute_path(candidate["executable_absolute_path"], "binary", executable=True)
    sha(candidate["executable_sha256"], "binary.sha256")
    require(type(candidate["executable_version"]) is str and
            bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,79}", candidate["executable_version"])),
            "binary.version: invalid")
    absolute_path(candidate["working_directory"], "working_directory")
    argv = candidate["argv_typed_vector"]
    require(type(argv) is list and 1 <= len(argv) <= 64, "argv: bounded typed vector required")
    for idx, token in enumerate(argv):
        exact(token, {"kind", "value"}, f"argv[{idx}]")
        if token["kind"] == "literal":
            value = token["value"]
            require(type(value) is str and 0 < len(value) <= 256 and
                    not any(ord(x) < 32 or ord(x) == 127 for x in value), "argv: unsafe literal")
        elif token["kind"] == "material_slot":
            require(type(token["value"]) is str and token["value"] in proposal["material_parameter_refs"],
                    "argv: foreign material slot")
        else:
            raise BindingContractError("argv: unknown token type")
    env = candidate["environment_allowlist"]
    require(type(env) is dict and all(key in ENV_FIXED and value == ENV_FIXED[key]
                                      for key, value in env.items()), "environment: unsafe inherited or arbitrary key")
    helpers = candidate["auxiliary_executables"]
    require(type(helpers) is list and len(helpers) <= 12, "auxiliaries: invalid list")
    paths = set()
    for h in helpers:
        exact(h, {"absolute_path", "sha256", "version"}, "auxiliary")
        path = absolute_path(h["absolute_path"], "auxiliary.path", executable=True)
        sha(h["sha256"], "auxiliary.sha256")
        require(type(h["version"]) is str and
                bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,79}", h["version"])),
                "auxiliary.version")
        require(path not in paths and path != candidate["executable_absolute_path"],
                "auxiliaries: repeated/self binary")
        paths.add(path)
    reference(candidate["case_authorization_ref"], "binding.authorization", stage=stage)
    reference(candidate["approved_target_ref"], "binding.target", stage=stage)
    reference(candidate["capture_policy_ref"], "binding.capture", stage=stage)
    verify_budget(candidate["fixed_resource_budget"])


def verify_authorization(auth: Any, proposal: dict[str, Any]) -> None:
    exact(auth, AUTH_FIELDS, "authorization envelope")
    stage = proposal["stage"]
    for name in ("authorization_ref", "issuer_ref", "operator_ref", "approved_target_ref", "revocation_ref"):
        reference(auth[name], "authorization." + name, stage=stage)
    for name in ("stage", "service_id", "scenario_id", "case_id", "profile_id"):
        require(auth[name] == proposal[name], "authorization: case identity mismatch " + name)
    require(auth["authorization_ref"] == proposal["binding_candidate"]["case_authorization_ref"],
            "authorization: binding reference mismatch")
    require(auth["approved_target_ref"] == proposal["binding_candidate"]["approved_target_ref"] ==
            proposal["material_parameter_refs"].get("target_ref"), "authorization: target scope mismatch")
    require(auth["action_scope"] == proposal["profile_id"], "authorization: action scope mismatch")
    require(proposal["material_parameter_refs"].get("authorization_ref") == auth["authorization_ref"],
            "authorization: material authorization reference mismatch")
    issued = utc(auth["issued_at_utc"], "authorization.issued")
    start = utc(auth["not_before_utc"], "authorization.not_before")
    stop = utc(auth["not_after_utc"], "authorization.not_after")
    require(issued <= start < stop, "authorization: invalid time window")
    # No on-host clock or trusted issuer is queried here. This is NOT validity evidence.
    require(auth["approval_state"] == "PROPOSED_NOT_VERIFIED" and
            auth["revocation_state"] == "UNKNOWN", "authorization: fabricated approval/revocation status")


def verify_cleanup(clean: Any, proposal: dict[str, Any], profile: dict[str, Any]) -> None:
    exact(clean, CLEANUP_FIELDS, "cleanup plan")
    stage = proposal["stage"]
    require(clean["policy"] == profile["cleanup"] and clean["policy"] in CLEANUP,
            "cleanup: wrong policy")
    reference(clean["plan_ref"], "cleanup.plan", stage=stage)
    if clean["policy"] == "NO_MUTATION":
        require(clean["marker_ref"] is None and clean["removal_plan_ref"] is None and
                clean["independent_verification_ref"] is None,
                "cleanup: marker operation on non-mutation profile")
    else:
        for name in ("marker_ref", "removal_plan_ref", "independent_verification_ref"):
            reference(clean[name], "cleanup." + name, stage=stage)
        require(len({clean["marker_ref"], clean["removal_plan_ref"],
                     clean["independent_verification_ref"]}) == 3,
                "cleanup: plan and verifier must be distinct")
        require({"MARKER_CREATED", "MARKER_VERIFIED", "CLEANUP_CONFIRMED"}.issubset(
                set(profile["required_supports"])), "cleanup: missing post-execution supports")
    if "cleanup_ref" in proposal["material_parameter_refs"]:
        require(proposal["material_parameter_refs"]["cleanup_ref"] == clean["plan_ref"],
                "cleanup: material cleanup plan mismatch")
    if "marker_ref" in proposal["material_parameter_refs"]:
        require(proposal["material_parameter_refs"]["marker_ref"] == clean["marker_ref"],
                "cleanup: material marker mismatch")
    require(proposal["post_execution_receipt_ref"] is None,
            "cleanup: future receipt cannot authorize a prospective case")


def assess_synthetic_candidate(proposal: dict[str, Any], trusted_case: dict[str, Any],
                               profile: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    """Pure semantic oracle. Input authority is an external assumption in tests ONLY.

    A caller-controlled `trusted_case`, `profile` or manifest is NOT trustworthy.
    The real intake MUST obtain them from independently verified files/P7 derivation
    and repeat the actual AL-07 material/issuer/isolation checks before any approval.
    This routine NEVER returns permission or creates an executable invocation.
    """
    exact(proposal, PROPOSAL_FIELDS, "candidate")
    require(proposal["schema_version"] == "1.0", "candidate: version")
    stage = proposal["stage"]
    require(type(stage) is str and stage in STAGES, "candidate: unknown stage")
    require(type(manifest) is dict and manifest.get("stage") == stage, "P6: cross-stage manifest")
    require(type(profile) is dict and profile.get("status") == "BLOCKED_UNBOUND_NO_EXECUTION" and
            type(profile.get("binding")) is dict and all(x is None for x in profile["binding"].values()),
            "P8: base profile already promoted")
    require(type(trusted_case) is dict and trusted_case.get("status") == "DRAFT_NOT_AUTHORIZED" and
            trusted_case.get("execution_enabled") is False, "P7: derived case must remain a draft")
    for name in ("stage", "scenario_id", "case_id", "variant", "precedence"):
        require(proposal[name] == trusted_case.get(name), "P7: derived case mismatch " + name)
    require(proposal["family_id"] == trusted_case.get("source_family") and
            proposal["profile_id"] == profile.get("profile_id") and
            proposal["family_id"] == profile.get("family_id") and
            proposal["protocol"] == profile.get("protocol") and
            proposal["variant"] == profile.get("variant") and
            proposal["precedence"] == profile.get("precedence"), "P7/P8: family/variant mismatch")
    require(type(manifest.get("services")) is list and type(manifest.get("scenarios")) is list,
            "P6: missing services/scenarios")
    services = [s for s in manifest["services"] if type(s) is dict and s.get("id") == proposal["service_id"]]
    scenarios = [s for s in manifest["scenarios"] if type(s) is dict and s.get("id") == proposal["scenario_id"]]
    require(len(services) == len(scenarios) == 1, "P6: service-scenario not registered")
    require(proposal["service_id"].startswith(stage + "-svc-") and
            proposal["scenario_id"].startswith(stage + "-scn-") and
            scenarios[0].get("service_id") == proposal["service_id"] and
            services[0].get("protocol") == proposal["protocol"] and
            services[0].get("network_id") == f"ardrec-{stage}-{proposal['protocol']}",
            "P6: mismatched scenario/service/protocol/stage")
    params = proposal["material_parameter_refs"]
    exact(params, set(profile["required_material_parameter_slots"]), "material slots")
    for name, value in params.items():
        reference(value, "material." + name, stage=stage)
    require(params == trusted_case.get("parameter_refs"), "P7: material parameters changed from derived case")
    require(profile["required_preconditions"] == trusted_case.get("preconditions") and
            profile["required_supports"] == trusted_case.get("required_supports") and
            profile["required_acceptance_supports"] == trusted_case.get("acceptance_supports") and
            profile["cleanup"] == trusted_case.get("cleanup"),
            "P7/P8: requirements altered")
    observations = proposal["preconditions_observed"]
    exact(observations, set(profile["required_preconditions"]), "preconditions")
    incomplete = []
    for name, entry in observations.items():
        exact(entry, {"value", "support_ref"}, "precondition." + name)
        require(type(entry["value"]) is str and entry["value"] in VALID_OBSERVATIONS,
                "precondition: invalid trivalent observation")
        if entry["value"] == "VERDADERO":
            reference(entry["support_ref"], "precondition.support", stage=stage)
        else:
            require(entry["support_ref"] is None, "precondition: unsupported false/ND evidence claim")
            incomplete.append(name)
    verify_binding(proposal["binding_candidate"], proposal)
    verify_authorization(proposal["authorization_candidate"], proposal)
    verify_cleanup(proposal["cleanup_plan"], proposal, profile)
    if profile["cleanup"] == "VERIFY_THEN_REMOVE_MARKER":
        require(proposal["binding_candidate"]["fixed_resource_budget"]["max_transfer_bytes"] > 0,
                "budget: mutating marker requires finite nonzero transfer bound")
    return {
        "status": "SYNTHETIC_STRUCTURAL_REVIEW_ONLY_NOT_AUTHORIZED",
        "case_id": proposal["case_id"],
        "profile_id": proposal["profile_id"],
        "stage": stage,
        "unmet_preconditions": sorted(incomplete),
        "executable_hash_status": "DECLARED_NOT_VERIFIED_AGAINST_BYTES",
        "authorization_status": "UNVERIFIED_PRIVATE_ISSUER_AND_REVOCATION",
        "budget_status": "CANDIDATE_NUMBERS_NOT_PILOT_FROZEN",
        "cleanup_receipt_status": "POST_EXECUTION_UNAVAILABLE",
        "real_authorization": False,
        "dispatch_allowed": False,
        "is_experimental_unit": False,
    }


def _read_json(root: Path, rel: str) -> dict[str, Any]:
    root = root.resolve(strict=True)
    path = root
    for segment in PurePosixPath(rel).parts:
        path = path / segment
        require(not path.is_symlink(), "repository: symlink encountered")
    require(path.is_file() and path.resolve().is_relative_to(root), "repository: invalid path")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        d: dict[str, Any] = {}
        for k, v in pairs:
            require(k not in d, "repository: duplicate JSON key")
            d[k] = v
        return d

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)


def verify_repository(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    upstream_path = root / R3_VALIDATOR
    require(upstream_path.is_file() and not upstream_path.is_symlink(), "P8 R3 verifier unavailable")
    require(hashlib.sha256(upstream_path.read_bytes()).hexdigest() == R3_VALIDATOR_SHA256,
            "P8 R3 verifier source hash mismatch")
    spec = importlib.util.spec_from_file_location("ardrec_p8_r4_r3", upstream_path)
    require(spec is not None and spec.loader is not None, "P8 R3 verifier cannot be loaded")
    mod = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = previous
    baseline = mod.verify_from_repo(root)
    require(baseline["status"] == "VERIFIED_DECLARATIONS_ONLY_NO_EXECUTION" and
            baseline["gate"] == {"authorization": False, "dispatch_allowed": False,
                                 "real_executor_available": False} and
            baseline["counts"]["registered_scenarios"] == 0, "P8 R3 baseline no longer valid")
    contract = _read_json(root, CONTRACT)
    exact(contract, {"schema_version", "increment", "roadmap_step", "base_commit", "thesis_sha256",
                     "p7_sha256", "p8_sha256", "record_status", "source_sections", "authoritative_case_sources",
                     "pre_execution_fields", "post_execution_field", "authorization_lifecycle",
                     "trust_boundaries", "public_candidate_records", "approved_profiles", "dispatch_enabled",
                     "pending_findings", "pending_development_obligations"}, "R4 contract")
    require(contract["schema_version"] == "1.0" and contract["increment"] == "P8-R4" and
            contract["roadmap_step"] == 8 and contract["base_commit"] == PARENT_COMMIT and
            contract["thesis_sha256"] == THESIS_SHA256 and
            contract["p7_sha256"] == P7_SHA256 and contract["p8_sha256"] == P8_SHA256,
            "R4 contract: invalid source anchors")
    require(contract["record_status"] == "CONTRACT_ONLY_UNBOUND_NO_AUTHORIZATION" and
            contract["source_sections"] == ["3.7.5", "3.9.2"] and
            contract["authoritative_case_sources"] == [
                "lab/scenario-separation-v1/dev.json", "lab/scenario-separation-v1/pilot.json",
                "lab/scenario-separation-v1/exp.json", "lab/operational-catalog-v1/catalog.json",
                "lab/execution-profiles-v1/profiles.json"], "R4 contract: changed case provenance")
    require(contract["pre_execution_fields"] == sorted(BIND_FIELDS) and
            contract["post_execution_field"] == "cleanup_receipt_ref" and
            contract["authorization_lifecycle"] == ["PROPOSED_NOT_VERIFIED", "PRIVATE_VERIFICATION_PENDING",
                "CASE_APPROVAL_PENDING", "EXPIRED_OR_REVOKED_BLOCKS", "DISPATCH_NOT_AVAILABLE_IN_P8_R4"],
            "R4 contract: future cleanup receipt treated as admission")
    require(contract["trust_boundaries"] == [
        "P6_P7_P8_VALIDATED_SOURCES_REQUIRED", "PUBLIC_CANDIDATE_NEVER_PRIVATE_AUTHORITY",
        "DECLARED_HASH_NOT_A_FILE_DIGEST_VERIFICATION", "ISSUER_REVOCATION_AND_CLOCK_UNVERIFIED",
        "AL07_RUNTIME_IDENTITY_AND_PERMISSIONS_PENDING", "AL06_ANALYTIC_EVIDENCE_SEPARATE",
        "PILOT_LIMITS_NOT_FROZEN", "CLEANUP_RECEIPT_ONLY_POST_EXECUTION",
        "NO_SHELL_NO_SPAWN_NO_NETWORK_NO_SECRET_MATERIALIZATION"],
        "R4 contract: weakened trust boundary")
    require(type(contract["public_candidate_records"]) is int and contract["public_candidate_records"] == 0 and
            type(contract["approved_profiles"]) is int and contract["approved_profiles"] == 0 and
            contract["dispatch_enabled"] is False and contract["pending_findings"] == ["AL-06", "AL-07"] and
            type(contract["pending_development_obligations"]) is int and
            contract["pending_development_obligations"] == 7, "R4 contract: fictitious evidence or authorization")
    trace = _read_json(root, TRACE)
    exact(trace, {"schema_version", "roadmap_step", "increment", "status", "base_commit",
                  "thesis_sha256", "source_sections", "p7_sha256", "p8_sha256", "scope",
                  "verification", "boundaries", "open_findings", "open_development_obligations"},
          "R4 traceability")
    require(trace["schema_version"] == "1.0" and trace["roadmap_step"] == 8 and
            trace["increment"] == "P8-R4-SYNTHETIC-PER-CASE-BINDING-CONTRACT" and
            trace["status"] == "SOURCE_PROPOSAL_NOT_INTEGRATED" and
            trace["base_commit"] == PARENT_COMMIT and trace["thesis_sha256"] == THESIS_SHA256 and
            trace["source_sections"] == ["3.7.5", "3.9.2"] and
            trace["p7_sha256"] == P7_SHA256 and trace["p8_sha256"] == P8_SHA256,
            "R4 traceability: altered sources or unjustified status")
    require(trace["scope"] == {
        "family_definitions": 25, "profile_slots": 29,
        "real_registered_scenarios": 0, "real_derived_cases": 0,
        "approved_execution_profiles": 0, "dispatch_enabled": False,
        "physical_laboratory": "NOT_TOUCHED"},
        "R4 traceability: fabricated operational inventory")
    require(trace["verification"] == {
        "candidate_oracles": "PASS_68_SYNTHETIC_PACKAGING_CONTAINER_ONLY",
        "original_contract_baseline": "NOT_REEXECUTED_IN_USER_REPO_YET",
        "new_pr_ci": "NOT_RUN", "new_main_ci": "NOT_APPLICABLE_UNMERGED"} and
        trace["boundaries"] == ["NO_ISSUER_AUTHENTICATION", "NO_BINARY_BYTE_VERIFICATION",
            "NO_RUNTIME_DISPATCH", "NO_PRIVATE_EVIDENCE_COMMITTED", "NO_PILOT_FREEZE",
            "NO_EXPERIMENTAL_ACCEPTANCE"] and
        trace["open_findings"] == ["AL-06", "AL-07"] and
        type(trace["open_development_obligations"]) is int and
        trace["open_development_obligations"] == 7,
        "R4 traceability: future CI or findings falsely closed")
    return {
        "status": "PASS_P8_R4_CONTRACT_ONLY_DENY_ALL",
        "base_commit": PARENT_COMMIT,
        "families": baseline["counts"]["families"],
        "slots": baseline["counts"]["profiles"],
        "real_cases": baseline["counts"]["real_derived_cases"],
        "approved_profiles": 0,
        "dispatch_allowed": False,
        "physical_tests": "NOT_RUN",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ARDREC P8-R4 public read-only contract gate")
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = ap.parse_args(argv)
    try:
        print(json.dumps(verify_repository(args.root), ensure_ascii=False, sort_keys=True))
        return 0  # Success denotes a VALID DENIAL contract, never permission.
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print("ARDREC_P8_R4=FAIL_CLOSED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
