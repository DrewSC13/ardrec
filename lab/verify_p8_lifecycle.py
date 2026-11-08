#!/usr/bin/env python3
"""ARDREC P8-R6: purely synthetic, deny-only lifecycle and invalidation oracle.

Context, clock and events are ALL untrusted public test inputs. This module never
calls a tool/VM/network, never loads secret authorities, and never grants execution.
Event absence cannot establish non-revocation; event claims are not signed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any

BASE = "61f978a8cda7315dd09f66f4e3d63d99a6d7ee4c"
THESIS = "6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72"
R5_SOURCE = "lab/verify_p8_material_attestation.py"
R5_SOURCE_SHA256 = "3355c54171c80f4f6f54124996b76c7263240dbd559d2a95ba721fad7e69aa3e"
R5_CONTRACT = "lab/p8-material-attestation-v1/contract.json"
R5_CONTRACT_SHA256 = "908e8ad7ae6c1c05ac9edbba641ada72619578d21996e3c279bde41bf9579693"
CONTRACT = "lab/p8-lifecycle-v1/contract.json"
TRACE = "docs/traceability/p8-lifecycle-r6.json"
HEX = re.compile(r"^[0-9a-f]{64}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
PROFILE = re.compile(r"^(SSH|FTP|SMB)-T\d{2}-(BASE|CONTROL|DATA|READ|WRITE|SIGNING|ENCRYPTION)$")
CASE = re.compile(r"^(SSH|FTP|SMB)-T\d{2}-S\d{2,4}-\d{2}$")
REF = re.compile(r"^ref:synthetic/(dev|pilot|exp)/[A-Za-z0-9][A-Za-z0-9_./-]{2,100}$")
REL = re.compile(r"^[A-Za-z0-9._+/-]{1,255}$")
STAGES = frozenset(("dev", "pilot", "exp"))
MAX_EVENTS = 64
MAX_VALIDITY_SECONDS = 86_400  # Synthetic test bound; NOT an operational policy.
MAX_MATERIALS = 13
MAX_TEST_FILE_BYTES = 1_048_576
KNOWN_PROFILES = frozenset(
    [f"SSH-T{i:02d}-BASE" for i in range(1, 9)] +
    [f"FTP-T{i:02d}-BASE" for i in (1, 3, 4, 5, 6, 7)] +
    ["FTP-T02-CONTROL", "FTP-T02-DATA", "FTP-T08-READ", "FTP-T08-WRITE"] +
    [f"SMB-T{i:02d}-BASE" for i in (1, 2, 4, 5, 6, 7, 8)] +
    ["SMB-T03-SIGNING", "SMB-T03-ENCRYPTION", "SMB-T09-READ", "SMB-T09-WRITE"]
)
CONTEXT_FIELDS = frozenset({
    "schema_version", "stage", "service_id", "scenario_id", "case_id", "profile_id",
    "target_ref", "authorization_ref", "cleanup_plan_ref", "budget_sha256",
    "material_epoch", "authorization_revision", "material_observation",
})
REQUEST_FIELDS = frozenset({
    "schema_version", "stage", "case_id", "profile_id", "snapshot_sha256",
    "material_epoch", "authorization_revision", "issued_at_utc", "not_before_utc",
    "not_after_utc", "checked_at_utc", "issuer_claim", "revocation_claim",
    "clock_claim", "dispatch_requested", "cleanup_receipt_ref",
})
EVENT_FIELDS = frozenset({
    "sequence", "kind", "observed_at_utc", "snapshot_sha256", "material_epoch",
    "authorization_revision",
})
OBSERVATION_FIELDS = frozenset({
    "status", "observed_materials", "observations", "declared_versions_not_verified",
    "trusted_pin_provenance", "case_authorized", "dispatch_allowed",
})
MATERIAL_FIELDS = frozenset({
    "status", "relative_path", "observed_sha256", "observed_bytes", "uid", "mode",
    "provenance_verified", "future_identity_guaranteed", "authorization", "dispatch_allowed",
})
INVALIDATION_KINDS = frozenset({
    "AUTHORIZATION_REVOKED", "AUTHORIZATION_EXPIRED", "MATERIAL_CHANGED",
    "BUDGET_CHANGED", "TARGET_CHANGED", "ISSUER_CHANGED", "PROFILE_CHANGED",
    "SCENARIO_CHANGED", "POLICY_CHANGED", "CLEANUP_CHANGED", "CLOCK_ROLLBACK",
    "EVIDENCE_INVALIDATED", "AUTHORIZATION_SUPERSEDED",
})
EXPECTED_INVALIDATION_KINDS = sorted(INVALIDATION_KINDS)
EXPECTED_BOUNDARIES = [
    "PUBLIC_CONTEXT_AND_EVENTS_UNTRUSTED", "SYNTHETIC_CLOCK_NEVER_TRUSTED_TIME",
    "EVENT_ABSENCE_NEVER_PROVES_NON_REVOCATION", "R5_FD_BYTES_NOT_REAL_PROVENANCE",
    "DETERMINISTIC_DOMAIN_SEPARATED_CONTEXT_FINGERPRINT",
    "MUTATIONS_REQUIRE_NEW_CONTEXT_AND_EXTERNAL_REAUTHORIZATION",
    "TERMINAL_INVALIDATIONS_CANNOT_BE_CLEARED_IN_THIS_MODEL",
    "NO_SIGNED_ISSUER_OR_PRIVATE_REVOCATION_REGISTRY", "NO_RUNTIME_TOCTOU_PROTECTION",
    "NO_SPAWN_NO_NETWORK_NO_CREDENTIALS_NO_VM", "NO_DISPATCH_OR_EXPERIMENT",
]


class LifecycleError(ValueError):
    """Malformed, inconsistent or unsafe public synthetic input; fail closed."""


def require(cond: bool, message: str) -> None:
    if not cond:
        raise LifecycleError(message)


def exact(obj: Any, fields: frozenset[str] | set[str], name: str) -> dict[str, Any]:
    require(type(obj) is dict and set(obj) == set(fields), f"{name}: unknown/missing fields")
    return obj


def sha256_form(value: Any, name: str) -> str:
    require(type(value) is str and HEX.fullmatch(value) is not None, name + ": invalid sha256")
    return value


def positive(value: Any, name: str, upper: int) -> int:
    require(type(value) is int and 1 <= value <= upper, name + ": bounded positive integer required")
    return value


def timestamp(value: Any, name: str) -> datetime:
    require(type(value) is str and DATE.fullmatch(value) is not None,
            name + ": canonical UTC required")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise LifecycleError(name + ": invalid calendar instant") from exc


def symbolic_ref(value: Any, stage: str, name: str) -> str:
    require(type(value) is str and REF.fullmatch(value) is not None and
            value.startswith("ref:synthetic/" + stage + "/") and
            ".." not in value and "//" not in value and "/./" not in value,
            name + ": unsafe or cross-stage synthetic ref")
    return value


def path_form(value: Any) -> str:
    require(type(value) is str and REL.fullmatch(value) is not None and
            not value.startswith("/") and "//" not in value and "\\" not in value and
            1 <= len(value.split("/")) <= 16 and
            all(part not in ("", ".", "..") for part in value.split("/")),
            "observation: noncanonical relative material")
    return value


def canonical_sha(label: str, obj: Any) -> str:
    data = json.dumps(obj, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(b"ARDREC:P8-R6:" + label.encode("ascii") + b"\0" + data).hexdigest()


def validate_observation(observation: Any) -> None:
    o = exact(observation, OBSERVATION_FIELDS, "R5 observation claim")
    require(o["status"] == "SYNTHETIC_MATERIAL_OBSERVATIONS_ONLY_DENY_ALL" and
            o["declared_versions_not_verified"] is True and
            o["trusted_pin_provenance"] is False and
            o["case_authorized"] is False and o["dispatch_allowed"] is False,
            "R5 observation: must remain an untrusted synthetic denial")
    materials = o["observations"]
    require(type(materials) is list and 1 <= len(materials) <= MAX_MATERIALS and
            type(o["observed_materials"]) is int and o["observed_materials"] == len(materials),
            "R5 observation: invalid material count")
    seen: set[str] = set()
    for index, item in enumerate(materials):
        m = exact(item, MATERIAL_FIELDS, f"material {index}")
        require(m["status"] == "SYNTHETIC_FD_BYTES_MATCH_DECLARATION_ONLY" and
                m["provenance_verified"] is False and m["future_identity_guaranteed"] is False and
                m["authorization"] is False and m["dispatch_allowed"] is False,
                "material: cannot promote R5 observation to trusted authority")
        p = path_form(m["relative_path"])
        require(p not in seen, "material: duplicate path")
        seen.add(p)
        sha256_form(m["observed_sha256"], "material bytes")
        positive(m["observed_bytes"], "material bytes", MAX_TEST_FILE_BYTES)
        require(type(m["uid"]) is int and m["uid"] >= 0, "material uid")
        require(type(m["mode"]) is int and 0 <= m["mode"] <= 0o777 and
                (m["mode"] & 0o022) == 0 and (m["mode"] & 0o6000) == 0,
                "material mode")


def validate_context(context: Any) -> dict[str, Any]:
    c = exact(context, CONTEXT_FIELDS, "context")
    require(c["schema_version"] == "1.0", "context schema")
    stage = c["stage"]
    require(type(stage) is str and stage in STAGES, "context stage")
    require(type(c["profile_id"]) is str and PROFILE.fullmatch(c["profile_id"]) is not None and
            c["profile_id"] in KNOWN_PROFILES, "context profile not in P8")
    require(type(c["case_id"]) is str and CASE.fullmatch(c["case_id"]) is not None and
            c["case_id"].startswith("-".join(c["profile_id"].split("-", 2)[:2]) + "-"),
            "context case/profile mismatch")
    for name, prefix in (("service_id", stage + "-svc-"),
                         ("scenario_id", stage + "-scn-")):
        value = c[name]
        require(type(value) is str and value.startswith(prefix) and
                re.fullmatch(r"[a-z0-9-]{10,100}", value) is not None,
                name + ": invalid stage-scoped identity")
    for name in ("target_ref", "authorization_ref", "cleanup_plan_ref"):
        symbolic_ref(c[name], stage, name)
    sha256_form(c["budget_sha256"], "budget")
    positive(c["material_epoch"], "material_epoch", 2**31 - 1)
    positive(c["authorization_revision"], "authorization_revision", 2**31 - 1)
    validate_observation(c["material_observation"])
    return c


def context_fingerprint(context: Any) -> str:
    """Hash of a test-only identity tuple, not an authorization token."""
    return canonical_sha("CONTEXT", validate_context(context))


def assess_synthetic_lifecycle(context: Any, request: Any, events: Any) -> dict[str, Any]:
    c = validate_context(context)
    r = exact(request, REQUEST_FIELDS, "request")
    require(r["schema_version"] == "1.0", "request schema")
    digest = context_fingerprint(c)
    require(r["snapshot_sha256"] == digest, "request: fingerprint mismatch or stale context")
    for name in ("stage", "case_id", "profile_id"):
        require(r[name] == c[name], "request: cross-binding " + name)
    require(type(r["material_epoch"]) is int and r["material_epoch"] == c["material_epoch"] and
            type(r["authorization_revision"]) is int and
            r["authorization_revision"] == c["authorization_revision"],
            "request: stale material epoch or authorization revision")
    require(r["issuer_claim"] == "SYNTHETIC_UNVERIFIED" and
            r["revocation_claim"] == "UNKNOWN_UNVERIFIED" and
            r["clock_claim"] == "SYNTHETIC_UNTRUSTED" and
            r["dispatch_requested"] is False and r["cleanup_receipt_ref"] is None,
            "request: public claims must not assert authority, clock trust or dispatch")
    issued = timestamp(r["issued_at_utc"], "issued_at")
    before = timestamp(r["not_before_utc"], "not_before")
    after = timestamp(r["not_after_utc"], "not_after")
    checked = timestamp(r["checked_at_utc"], "checked_at")
    require(issued <= before < after and after - before <= timedelta(seconds=MAX_VALIDITY_SECONDS),
            "request: invalid synthetic validity interval")
    require(type(events) is list and len(events) <= MAX_EVENTS, "event ledger: bounded list required")
    reasons = ["PRIVATE_ISSUER_UNVERIFIED", "REVOCATION_STATUS_UNVERIFIED",
               "CLOCK_SOURCE_UNTRUSTED", "NO_EXECUTOR_DISPATCH"]
    if checked < before:
        reasons.append("NOT_YET_WITHIN_CLAIMED_WINDOW")
    if checked >= after:
        reasons.append("EXPIRED_CLAIMED_WINDOW")
    previous: datetime | None = None
    for i, item in enumerate(events):
        e = exact(item, EVENT_FIELDS, "event")
        require(type(e["sequence"]) is int and e["sequence"] == i + 1,
                "event: non-contiguous/duplicate sequence")
        require(type(e["kind"]) is str and e["kind"] in INVALIDATION_KINDS,
                "event: forbidden restoration or unknown kind")
        require(e["snapshot_sha256"] == digest and
                type(e["material_epoch"]) is int and
                e["material_epoch"] == c["material_epoch"] and
                type(e["authorization_revision"]) is int and
                e["authorization_revision"] == c["authorization_revision"],
                "event: other snapshot or revision")
        moment = timestamp(e["observed_at_utc"], "event timestamp")
        require(moment <= checked and (previous is None or moment > previous),
                "event: future or non-monotonic timestamp")
        previous = moment
        reasons.append("INVALIDATED_" + e["kind"])
    coherent = checked >= before and checked < after and not events
    return {
        "status": "SYNTHETIC_PRECONDITIONS_CONSISTENT_DENY_ALL" if coherent else
                  "SYNTHETIC_EXPIRED_OR_INVALIDATED_DENY_ALL",
        "synthetic_claims_coherent": coherent,
        "snapshot_sha256": digest,
        "diagnostic_sha256": canonical_sha("DIAGNOSTIC", {"context": c, "request": r, "events": events}),
        "deny_reasons": sorted(set(reasons)),
        "public_time_trusted": False,
        "private_issuer_verified": False,
        "revocation_verified": False,
        "material_future_identity_guaranteed": False,
        "real_cases_authorized": 0,
        "dispatch_allowed": False,
        "operational_authorization": False,
    }


def _read_json(root: Path, rel: str) -> dict[str, Any]:
    current = root
    for segment in rel.split("/"):
        require(segment not in ("", ".", ".."), "repository unsafe relative path")
        current = current / segment
        require(not current.is_symlink(), "repository symlink")
    require(current.is_file(), "repository contract not present")

    def no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "repository duplicate JSON key")
            result[key] = value
        return result

    return json.loads(current.read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_pairs)


def check_upstream(root: Path) -> dict[str, Any]:
    for rel, expected in ((R5_SOURCE, R5_SOURCE_SHA256), (R5_CONTRACT, R5_CONTRACT_SHA256)):
        p = root
        for segment in rel.split("/"):
            require(segment not in ("", ".", ".."), "R5 source path not canonical")
            p = p / segment
            require(not p.is_symlink(), "R5 upstream symbolic link denied")
        require(p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest() == expected,
                "R5 immutable source anchor mismatch: " + rel)
    p = root / R5_SOURCE
    spec = importlib.util.spec_from_file_location("ardrec_p8_r6_r5", p)
    require(spec is not None and spec.loader is not None, "R5 import unavailable")
    module = importlib.util.module_from_spec(spec)
    old = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = old
    result = module.verify_repository(root)
    require(result["status"] == "PASS_P8_R5_SYNTHETIC_FD_CONTRACT_DENY_ALL" and
            result["profiles"] == 29 and result["real_artifacts_inspected"] == 0 and
            result["real_cases_authorized"] == 0 and result["dispatch_allowed"] is False,
            "R5 baseline changed or mistakenly promoted")
    return result


def verify_repository(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    require(root.is_dir(), "repository root not a directory")
    check_upstream(root)
    c = exact(_read_json(root, CONTRACT), {
        "schema_version", "increment", "roadmap_step", "base_commit", "thesis_sha256",
        "source_sections", "r5_validator_sha256", "r5_contract_sha256", "status",
        "input_scope", "max_events", "max_validity_seconds", "max_materials",
        "invalidation_kinds", "trust_boundaries", "synthetic_cases", "real_cases",
        "private_authorities_verified", "real_artifacts_inspected", "dispatch_allowed",
        "open_findings", "open_development_obligations",
    }, "R6 contract")
    require(c["schema_version"] == "1.0" and
            c["increment"] == "P8-R6-SYNTHETIC-LIFECYCLE-INVALIDATION" and
            type(c["roadmap_step"]) is int and c["roadmap_step"] == 8 and
            c["base_commit"] == BASE and c["thesis_sha256"] == THESIS and
            c["source_sections"] == ["3.7.5", "3.9.2"] and
            c["r5_validator_sha256"] == R5_SOURCE_SHA256 and
            c["r5_contract_sha256"] == R5_CONTRACT_SHA256 and
            c["status"] == "SYNTHETIC_TEMPORAL_REVOCATION_DENY_ALL" and
            c["input_scope"] == "IN_MEMORY_SYNTHETIC_RECORDS_ONLY" and
            type(c["max_events"]) is int and c["max_events"] == MAX_EVENTS and
            type(c["max_validity_seconds"]) is int and
            c["max_validity_seconds"] == MAX_VALIDITY_SECONDS and
            type(c["max_materials"]) is int and c["max_materials"] == MAX_MATERIALS and
            c["invalidation_kinds"] == EXPECTED_INVALIDATION_KINDS and
            c["trust_boundaries"] == EXPECTED_BOUNDARIES and
            type(c["synthetic_cases"]) is int and c["synthetic_cases"] == 0 and
            type(c["real_cases"]) is int and c["real_cases"] == 0 and
            type(c["private_authorities_verified"]) is int and
            c["private_authorities_verified"] == 0 and
            type(c["real_artifacts_inspected"]) is int and
            c["real_artifacts_inspected"] == 0 and c["dispatch_allowed"] is False and
            c["open_findings"] == ["AL-06", "AL-07"] and
            type(c["open_development_obligations"]) is int and
            c["open_development_obligations"] == 7,
            "R6 contract: changed scope, authority or deny-only invariant")
    t = exact(_read_json(root, TRACE), {
        "schema_version", "roadmap_step", "increment", "status", "base_commit",
        "thesis_sha256", "source_sections", "r5_source_sha256", "scope",
        "verification", "open_findings", "open_development_obligations",
    }, "R6 trace")
    require(t["schema_version"] == "1.0" and type(t["roadmap_step"]) is int and
            t["roadmap_step"] == 8 and
            t["increment"] == "P8-R6-SYNTHETIC-REVOCATION-LIFECYCLE" and
            t["status"] == "SOURCE_ONLY_NOT_INTEGRATED" and
            t["base_commit"] == BASE and t["thesis_sha256"] == THESIS and
            t["source_sections"] == ["3.7.5", "3.9.2"] and
            t["r5_source_sha256"] == R5_SOURCE_SHA256 and
            t["scope"] == {"profile_slots": 29, "real_scenarios": 0,
                          "real_cases": 0, "trusted_issuer_records": 0,
                          "runtime_revocation_checks": 0, "real_files_checked": 0,
                          "dispatch_allowed": False, "physical_laboratory": "NOT_TOUCHED"} and
            t["verification"] == {"synthetic_lifecycle_tests": "PENDING_CI",
                                  "local_user_repo": "PENDING",
                                  "remote_pr_ci": "NOT_RUN",
                                  "postmerge_ci": "NOT_APPLICABLE_UNMERGED"} and
            t["open_findings"] == ["AL-06", "AL-07"] and
            type(t["open_development_obligations"]) is int and
            t["open_development_obligations"] == 7,
            "R6 traceability: fabricated authority, CI or experimental outcomes")
    return {
        "status": "PASS_P8_R6_SYNTHETIC_LIFECYCLE_DENY_ALL", "base_commit": BASE,
        "profiles": 29, "real_cases_authorized": 0,
        "real_materials_inspected": 0, "dispatch_allowed": False,
        "physical_laboratory": "NOT_TOUCHED",
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="P8 R6 strict deny-only synthetic lifecycle audit")
    p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    opt = p.parse_args(argv)
    try:
        print(json.dumps(verify_repository(opt.root), ensure_ascii=False, sort_keys=True))
        return 0  # Means that the denial invariant holds, not that anything was authorized.
    except (OSError, RuntimeError, ValueError, TypeError, KeyError,
            ImportError, json.JSONDecodeError) as exc:
        print("ARDREC_P8_R6=FAIL_CLOSED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
