#!/usr/bin/env python3
"""P8 R3: trusted, read-only readiness inventory, ALWAYS denial-only.

This is not a process supervisor, authorization service, hash verifier for
actual binaries, nor a replacement for lab/verify_execution_profiles.py.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

BASE_COMMIT = "29b6fcf741ff7092730a49c6d2c6d5f53b9adabb"
THESIS_SHA256 = "6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72"
P7_SHA256 = "5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e"
P8_SHA256 = "fe0fae200ac031622d27020b77d38bd18a22e3ffaa0dd0f57ec4e9f01f284ce3"
P7 = "lab/operational-catalog-v1/catalog.json"
P8 = "lab/execution-profiles-v1/profiles.json"
P8_VALIDATOR = "lab/verify_execution_profiles.py"
P6_STAGE_FILES = {stage: f"lab/scenario-separation-v1/{stage}.json" for stage in ("dev", "pilot", "exp")}
REQUIRED_STAGES = ("dev", "pilot", "exp")
CORE_GUARDS = frozenset({"SCOPE_APPROVED", "LAB_ISOLATION_CONFIRMED", "DESTINATION_AUTHORIZED", "CLIENT_COMPATIBLE"})
PRE_EXECUTION_BINDINGS = (
    "executable_absolute_path", "executable_sha256", "executable_version",
    "argv_typed_vector", "working_directory", "environment_allowlist",
    "auxiliary_executables", "case_authorization_ref", "approved_target_ref",
    "fixed_resource_budget", "capture_policy_ref",
)
POST_EXECUTION_BINDINGS = ("cleanup_receipt_ref",)
ALL_BINDINGS = PRE_EXECUTION_BINDINGS + POST_EXECUTION_BINDINGS
EXPECTED_VARIANTS = {
    "FTP-T02": {"CONTROL", "DATA"},
    "FTP-T08": {"READ", "WRITE"},
    "SMB-T03": {"SIGNING", "ENCRYPTION"},
    "SMB-T09": {"READ", "WRITE"},
}
EXPECTED_COUNTS = {"ssh": 8, "ftp": 10, "smb": 11}
NO_DISPATCH = "BLOCKED_UNBOUND_NO_EXECUTION"


class ContractError(ValueError):
    """A new observation conflicts with the known P6/P7/P8 contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def exact_dict(obj: Any, keys: set[str], name: str) -> None:
    require(type(obj) is dict and set(obj) == keys, f"{name}: changed/missing keys")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_strict(root: Path, rel: str) -> Any:
    """Load public registry without symlinks, traversal or duplicate JSON keys."""
    require(type(rel) is str and rel and not Path(rel).is_absolute() and ".." not in Path(rel).parts, "path traversal")
    path = root
    for part in Path(rel).parts:
        path = path / part
        require(not path.is_symlink(), f"symlink: {rel}")
    require(path.is_file() and path.resolve().is_relative_to(root), f"missing/outside: {rel}")

    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in out, f"duplicate JSON key: {key}")
            out[key] = value
        return out

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_keys)


def check_inventory(p7: dict[str, Any], p8: dict[str, Any], stages: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Independent boundary checks; does not grant approvals on any input."""
    require(type(p7) is dict and type(p8) is dict, "catalog types")
    require(type(p7.get("families")) is list and len(p7["families"]) == 25, "P7 families must be 25")
    require(type(p8.get("profiles")) is list and len(p8["profiles"]) == 29, "P8 slots must be 29")
    require(p7.get("thesis_sha256") == THESIS_SHA256 and p8.get("thesis_sha256") == THESIS_SHA256,
            "thesis version mismatch")
    require(p7.get("execution_enabled") is False and p8.get("execution_enabled") is False,
            "execution flag unexpectedly enabled")
    require(p8.get("profile_frozen") is False and p8.get("pilot_limits_frozen") is False and
            p8.get("physical_isolation_verified") is False, "unsupported readiness promotion")
    require(type(p8.get("cases_authorized")) is int and p8["cases_authorized"] == 0 and
            type(p8.get("real_cases")) is int and p8["real_cases"] == 0, "unauthorized case count")
    require(type(stages) is dict and set(stages) == set(REQUIRED_STAGES), "stage set mismatch")
    stage_counts = {}
    for stage in REQUIRED_STAGES:
        data = stages[stage]
        require(type(data) is dict and data.get("stage") == stage, f"{stage}: stage identity mismatch")
        stage_counts[stage] = {}
        for kind in ("services", "scenarios", "cases", "executions", "attempts", "artifacts", "units"):
            rows = data.get(kind)
            require(type(rows) is list, f"{stage}.{kind}: missing array")
            stage_counts[stage][kind] = len(rows)
        # This R3 version is anchored to the zero-inventory baseline. Future populated
        # manifests require a new version and provenance review, not a false readiness pass.
        require(all(v == 0 for v in stage_counts[stage].values()),
                f"{stage}: material inventory changed; do not reuse zero-case P8 proof")
    fam = {}
    for f in p7["families"]:
        require(type(f) is dict and type(f.get("id")) is str and f["id"] not in fam, "duplicate P7 family")
        fam[f["id"]] = f
    require(len(fam) == 25, "P7 duplicate families")
    ids = set()
    by_protocol = {key: 0 for key in EXPECTED_COUNTS}
    variant_groups: dict[str, set[str]] = {}
    rows = []
    for entry in p8["profiles"]:
        require(type(entry) is dict, "invalid P8 profile")
        name = entry.get("profile_id")
        family = entry.get("family_id")
        require(type(name) is str and name not in ids, "duplicate/missing P8 profile id")
        ids.add(name)
        require(family in fam and entry.get("protocol") == fam[family]["protocol"],
                f"{name}: foreign family or protocol")
        protocol = entry["protocol"]
        require(protocol in by_protocol, f"{name}: invalid protocol")
        by_protocol[protocol] += 1
        variant = entry.get("variant")
        require(variant is None or type(variant) is str, f"{name}: invalid variant")
        require(name == family + "-" + (variant or "BASE"), f"{name}: inconsistent variant identity")
        variant_groups.setdefault(family, set()).add(variant or "BASE")
        guard = entry.get("required_preconditions")
        supports = entry.get("required_supports")
        accepted = entry.get("required_acceptance_supports")
        require(type(guard) is list and CORE_GUARDS.issubset(set(guard)),
                f"{name}: missing common guards")
        require(type(supports) is list and type(accepted) is list and set(accepted).issubset(set(supports)),
                f"{name}: acceptance supports not contained in required supports")
        require(entry.get("status") == NO_DISPATCH, f"{name}: unexpected enabled status")
        binding = entry.get("binding")
        exact_dict(binding, set(ALL_BINDINGS), f"{name}.binding")
        require(all(v is None for v in binding.values()), f"{name}: attempted binding promotion")
        clean = entry.get("cleanup")
        require(clean in ("NO_MUTATION", "VERIFY_THEN_REMOVE_MARKER"), f"{name}: undefined cleanup")
        if (family, variant) in (("FTP-T08", "WRITE"), ("SMB-T09", "WRITE")) or family in (
            "SSH-T07", "FTP-T07", "SMB-T08"
        ):
            require(clean == "VERIFY_THEN_REMOVE_MARKER" and
                    {"MARKER_CREATED", "MARKER_VERIFIED", "CLEANUP_CONFIRMED"}.issubset(set(supports)),
                    f"{name}: mutation must require cleanup and independent support")
        rows.append({
            "profile_id": name,
            "family_id": family,
            "protocol": protocol,
            "variant": variant,
            "precedence": entry.get("precedence"),
            "minimum_action_es": fam[family].get("minimum_action_es"),
            "required_material_slots": entry.get("required_material_parameter_slots"),
            "required_preconditions": guard,
            "required_supports": supports,
            "required_acceptance_supports": accepted,
            "cleanup_policy": clean,
            "pre_execution_unbound": list(PRE_EXECUTION_BINDINGS),
            "post_execution_receipt_unavailable": list(POST_EXECUTION_BINDINGS),
            "specification": "REGISTERED_UNBOUND",
            "artifact_binding": "NOT_VERIFIED",
            "case_authorization": "NOT_GRANTED",
            "dispatch": "DENIED",
        })
    require(by_protocol == EXPECTED_COUNTS, "profile protocol allocation mismatch")
    require(set(variant_groups) == set(fam), "missing family variant")
    for family, variants in variant_groups.items():
        require(variants == EXPECTED_VARIANTS.get(family, {"BASE"}),
                f"{family}: incorrect variant split")
    return {
        "schema_version": "1.0",
        "source_commit": BASE_COMMIT,
        "thesis_sha256": THESIS_SHA256,
        "p7_sha256": P7_SHA256,
        "p8_sha256": P8_SHA256,
        "status": "VERIFIED_DECLARATIONS_ONLY_NO_EXECUTION",
        "gate": {"authorization": False, "dispatch_allowed": False, "real_executor_available": False},
        "counts": {"families": 25, "profiles": 29, "by_protocol": by_protocol,
                   "registered_scenarios": 0, "real_derived_cases": 0, "authorized_profiles": 0},
        "stages": stage_counts,
        "pre_execution_binding_fields": list(PRE_EXECUTION_BINDINGS),
        "post_execution_receipt_fields": list(POST_EXECUTION_BINDINGS),
        "pending_gates": [
            "REGISTER_REAL_DEVELOPMENT_SCENARIOS_WITH_PROVENANCE",
            "DERIVE_CASES_FROM_P6_REGISTERED_SCENARIOS",
            "VERIFY_ACTUAL_EXECUTABLE_AND_AUXILIARY_BYTES_VERSIONS_AND_PERMISSIONS",
            "BIND_TOOL_SPECIFIC_TYPED_ARGV_AND_MATERIAL_PARAMETERS",
            "VERIFY_TARGET_SCOPE_AND_PRIVATE_CASE_AUTHORIZATION",
            "FIX_FINITE_RESOURCE_BUDGETS_AND_CAPTURE_POLICIES",
            "VERIFY_PHYSICAL_ISOLATION_AND_AL07_RUNTIME_CUSTODY",
            "PLAN_CLEANUP_BEFORE_EXECUTION; VERIFY_RECEIPT_AFTER_EXECUTION",
        ],
        "open_findings": ["AL-06", "AL-07"],
        "open_residual_obligations": 7,
        "profiles": rows,
    }


def verify_from_repo(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    require(sha256_file(root / P7) == P7_SHA256, "P7 exact baseline bytes differ")
    require(sha256_file(root / P8) == P8_SHA256, "P8 exact baseline bytes differ")
    # Delegate every historical P6/P7/P8 structural, hash and semantic rule
    # to the existing strict anchored validator; never weaken it.
    entry = root / P8_VALIDATOR
    require(entry.is_file() and not entry.is_symlink(), "historical verifier absent or symlink")
    spec = importlib.util.spec_from_file_location("ardrec_p8_r3_historical_gate", entry)
    require(spec is not None and spec.loader is not None, "cannot load anchored P8 verifier")
    module = importlib.util.module_from_spec(spec)
    old = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = old
    upstream = module.validate(root)
    require(upstream.get("status") == "PASS_P8_UNBOUND_PROFILE_SLOTS_ONLY", "historical P8 verification failed")
    p7 = load_strict(root, P7)
    p8 = load_strict(root, P8)
    stages = {k: load_strict(root, rel) for k, rel in P6_STAGE_FILES.items()}
    report = check_inventory(p7, p8, stages)
    report["baseline_validation"] = upstream["status"]
    return report


def format_markdown(report: dict[str, Any]) -> str:
    header = (
        "# ARDREC P8 — Matriz de preparación (solo lectura)\n\n"
        "Resultado: **29 posiciones declaradas; cero autorizadas; cero despachos**. "
        "La columna de salida es informativa y no habilita herramientas.\n\n"
        "| Perfil | Protocolo | Prec. | Acción P7 | Precondiciones | Soportes | Limpieza | Estado |\n"
        "|---|---|---:|---|---:|---:|---|---|"
    )
    lines = [header]
    for p in report["profiles"]:
        action = p["minimum_action_es"] or "NO_DESCRITA"
        action = action.replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| `{p['profile_id']}` | {p['protocol'].upper()} | {p['precedence']} | "
            f"{action} | {len(p['required_preconditions'])} | {len(p['required_supports'])} | "
            f"{p['cleanup_policy']} | BLOQUEADO |"
        )
    lines.append("\nNo hay herramientas, rutas, comandos, presupuestos, autorizaciones ni recibos reales vinculados.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="P8 read-only, deny-only readiness audit")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    opts = parser.parse_args(argv)
    try:
        report = verify_from_repo(opts.root)
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) if opts.format == "json" else
              format_markdown(report))
        return 0  # Validated denial state, never an authorization token.
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("ARDREC_P8_R3_READINESS=FAIL_CLOSED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
