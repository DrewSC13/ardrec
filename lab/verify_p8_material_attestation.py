#!/usr/bin/env python3
"""ARDREC P8-R5: controlled temporary-file byte oracle and deny-only repo check.

No process spawn, VM, credential lookup, network, authorization, or production
artifact resolution. Test-owned temporary files ONLY. A matching digest proves
what was read through an fd during one observation, *not* provenance, authority,
filesystem custody, or immutability until a later process start.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

BASE = "2030ef4fe24e3595cfb365853912548ff3294056"
THESIS = "6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72"
R4_SOURCE = "lab/verify_p8_binding_contract.py"
R4_SOURCE_SHA256 = "7099a37f36096b0a50db08a88e34539b7269c9f6ee002b57f163cede0aed472a"
R4_CONTRACT = "lab/p8-binding-contract-v1/contract.json"
R4_CONTRACT_SHA256 = "e558574fdd4a32ce82dbb2417b1f5b695e445b8d8c2d9d4a1861b21a2527923b"
CONTRACT = "lab/p8-material-attestation-v1/contract.json"
TRACE = "docs/traceability/p8-material-attestation-r5.json"
MAX_BYTES = 1_048_576  # Deliberately TEST-FIXTURE bound, not a product binary cap.
MAX_HELPERS = 12
HEX_SHA = re.compile(r"^[0-9a-f]{64}$")
REL = re.compile(r"^[A-Za-z0-9._+/-]{1,255}$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,79}$")
PROFILE = re.compile(r"^(SSH|FTP|SMB)-T\d{2}-(BASE|CONTROL|DATA|READ|WRITE|SIGNING|ENCRYPTION)$")
CASE = re.compile(r"^(SSH|FTP|SMB)-T\d{2}-S\d{2,4}-\d{2}$")
REFERENCE = re.compile(r"^ref:private/(dev|pilot|exp)/[A-Za-z0-9._/-]{3,120}$")
STAGES = ("dev", "pilot", "exp")
KNOWN_PROFILES = frozenset(
    [f"SSH-T{i:02d}-BASE" for i in range(1, 9)] +
    [f"FTP-T{i:02d}-BASE" for i in (1, 3, 4, 5, 6, 7)] +
    ["FTP-T02-CONTROL", "FTP-T02-DATA", "FTP-T08-READ", "FTP-T08-WRITE"] +
    [f"SMB-T{i:02d}-BASE" for i in (1, 2, 4, 5, 6, 7, 8)] +
    ["SMB-T03-SIGNING", "SMB-T03-ENCRYPTION", "SMB-T09-READ", "SMB-T09-WRITE"]
)
EXPECTED_CHECKS = [
    "STRICT_RELATIVE_PATH", "NO_SYMLINK_COMPONENTS", "REGULAR_SINGLE_LINK_FILE", "OWNER_UID",
    "NO_GROUP_OR_WORLD_WRITE", "NO_SETUID_OR_SETGID", "BOUND_EXACT_LENGTH",
    "SHA256_OF_OBSERVED_FD_BYTES", "MATCH_DECLARED_HASH_AND_SIZE", "FD_PRE_POST_STABILITY",
    "PATH_POST_OBSERVATION_STABILITY", "BINDING_EXECUTABLE_AND_HELPERS_AGAINST_SNAPSHOT",
]
EXPECTED_UNVERIFIED = [
    "TRUSTED_ROOT_CUSTODY", "TRUSTED_PIN_PROVENANCE", "SIGNATURE_AND_ISSUER_AUTHORITY",
    "EXECUTABLE_VERSION_FROM_TRUSTED_INVENTORY", "REAL_LAB_BINARY_INSTALLATIONS",
    "FILESYSTEM_MOUNT_AND_KERNEL_POLICIES", "TOCTOU_BETWEEN_OBSERVATION_AND_FUTURE_USE",
    "PROTECTED_FD_TRANSFER_TO_RUST", "AL07_RUNTIME_SECURITY", "AL06_ANALYTIC_EVIDENCE",
    "PILOT_LIMITS_AND_PHYSICAL_ISOLATION",
]


class AttestationError(ValueError):
    """Invalid proposal, unsafe local fixture path or inconsistent observation."""


def require(predicate: bool, explanation: str) -> None:
    if not predicate:
        raise AttestationError(explanation)


def exact(value: Any, fields: set[str], name: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == fields, f"{name}: unexpected/missing fields")
    return value


def validate_relative(value: Any) -> tuple[str, ...]:
    require(type(value) is str and REL.fullmatch(value) is not None and
            "//" not in value and "\\" not in value and not value.startswith("/") and
            value not in (".", "..") and len(value.split("/")) <= 16 and
            all(p not in ("", ".", "..") for p in value.split("/")),
            "unsafe relative material path")
    return tuple(value.split("/"))


def validate_sha(value: Any, name: str) -> str:
    require(type(value) is str and HEX_SHA.fullmatch(value) is not None, f"{name}: bad sha256 form")
    return value


def validate_size(value: Any) -> int:
    require(type(value) is int and 0 < value <= MAX_BYTES,
            "size: positive and bounded test fixture required")
    return value


def metadata(file_stat: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (file_stat.st_dev, file_stat.st_ino, file_stat.st_uid, file_stat.st_gid,
            file_stat.st_mode, file_stat.st_size, file_stat.st_mtime_ns,
            file_stat.st_ctime_ns)


def _safe_directory(st: os.stat_result, uid: int, label: str) -> None:
    require(stat.S_ISDIR(st.st_mode), f"{label}: not a directory")
    require(st.st_uid == uid, f"{label}: wrong owner")
    require(st.st_mode & 0o022 == 0, f"{label}: writable by group/other")


def _safe_regular(st: os.stat_result, uid: int) -> None:
    require(stat.S_ISREG(st.st_mode), "material must be regular file")
    require(st.st_nlink == 1, "hardlink ambiguous material")
    require(st.st_uid == uid, "material owner changed")
    require(st.st_mode & 0o022 == 0, "material writable by group/other")
    require(st.st_mode & 0o6000 == 0, "setuid/setgid material forbidden")
    validate_size(st.st_size)


def attest_test_owned_file(root: Path, rel: str, expected_sha: str, expected_size: int,
                           *, expected_uid: int | None = None) -> dict[str, Any]:
    """Read one TEST-OWNED regular file via pinned O_NOFOLLOW file descriptors.

    The caller must own and control `root`: this function does not establish that
    claim. No path re-opening/dispatch follows the observation. Test fixture sizes
    are capped to avoid accidental scanning of host binaries or confidential data.
    """
    parts = validate_relative(rel)
    expected_sha = validate_sha(expected_sha, "expected")
    expected_size = validate_size(expected_size)
    uid = os.getuid() if expected_uid is None else expected_uid
    require(type(uid) is int and uid >= 0 and uid == os.getuid(),
            "synthetic fixture must belong to active tester")
    root = Path(root)
    require(root.is_absolute() and not root.is_symlink(), "root must be absolute and not symlink")
    descriptors: list[int] = []
    try:
        dflags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        base_fd = os.open(root, dflags)
        descriptors.append(base_fd)
        _safe_directory(os.fstat(base_fd), uid, "fixture root")
        parent_fd = base_fd
        for part in parts[:-1]:
            parent_fd = os.open(part, dflags, dir_fd=parent_fd)
            descriptors.append(parent_fd)
            _safe_directory(os.fstat(parent_fd), uid, "material parent")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        ffd = os.open(parts[-1], flags, dir_fd=parent_fd)
        descriptors.append(ffd)
        before = os.fstat(ffd)
        _safe_regular(before, uid)
        require(before.st_size == expected_size, "declared material length mismatch")
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(ffd, min(64 * 1024, MAX_BYTES + 1 - total))
            if not block:
                break
            total += len(block)
            require(total <= MAX_BYTES, "material exceeded bounded fixture")
            digest.update(block)
        after = os.fstat(ffd)
        require(metadata(before) == metadata(after), "file metadata changed during observation")
        require(total == before.st_size == expected_size, "material length changed during read")
        observed = digest.hexdigest()
        require(observed == expected_sha, "declared digest mismatch with observed bytes")
        # Verify that the final component still names the inode read above.
        named = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        require(metadata(named) == metadata(after), "name-to-inode link changed after observation")
        return {
            "status": "SYNTHETIC_FD_BYTES_MATCH_DECLARATION_ONLY", "relative_path": rel,
            "observed_sha256": observed, "observed_bytes": total, "uid": uid,
            "mode": stat.S_IMODE(after.st_mode), "provenance_verified": False,
            "future_identity_guaranteed": False, "authorization": False, "dispatch_allowed": False,
        }
    except (OSError, OverflowError) as exc:
        raise AttestationError("material path or read denied: " + type(exc).__name__) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def check_synthetic_bundle(root: Path, proposal: dict[str, Any], pin: dict[str, Any]) -> dict[str, Any]:
    """Reconcile an untrusted proposed binary/auxiliary list with an untrusted pin.

    This checks consistency and bytes only. Even two matching *untrusted* sources
    cannot become private authorizations. The real AL-07 root of trust is absent.
    """
    exact(proposal, {"schema_version", "stage", "profile_id", "case_id", "binary", "auxiliaries",
                     "authorization_state", "dispatch_allowed"}, "proposal")
    exact(pin, {"schema_version", "stage", "profile_id", "case_id", "binary", "auxiliaries",
                "provenance_ref", "trusted_source_attested"}, "pin")
    require(proposal["schema_version"] == pin["schema_version"] == "1.0", "schema version mismatch")
    require(proposal["stage"] == pin["stage"] and proposal["stage"] in STAGES, "cross-stage bundle")
    require(proposal["profile_id"] == pin["profile_id"] and
            type(pin["profile_id"]) is str and PROFILE.fullmatch(pin["profile_id"]) is not None and
            pin["profile_id"] in KNOWN_PROFILES,
            "cross-profile bundle")
    require(proposal["case_id"] == pin["case_id"] and type(pin["case_id"]) is str and
            CASE.fullmatch(pin["case_id"]) is not None and
            pin["case_id"].startswith(pin["profile_id"].split("-", 2)[0] + "-" +
                                      pin["profile_id"].split("-", 2)[1] + "-"),
            "cross-case bundle")
    require(proposal["authorization_state"] == "UNVERIFIED_PROPOSAL" and
            proposal["dispatch_allowed"] is False, "public proposal cannot authorize")
    require(pin["trusted_source_attested"] is False, "synthetic pin cannot claim trusted source")
    provenance = pin["provenance_ref"]
    require(type(provenance) is str and REFERENCE.fullmatch(provenance) is not None and
            provenance.startswith("ref:private/" + pin["stage"] + "/") and
            ".." not in provenance and "//" not in provenance and
            "/./" not in provenance, "provenance scope mismatch")
    seen: set[str] = set()

    def verify_one(kind: str, left: Any, right: Any) -> dict[str, Any]:
        exact(left, {"relative_path", "sha256", "version"}, kind + ".proposal")
        exact(right, {"relative_path", "sha256", "version", "size_bytes"}, kind + ".pin")
        require(left["relative_path"] == right["relative_path"] and
                left["sha256"] == right["sha256"] and
                left["version"] == right["version"] and
                type(left["version"]) is str and VERSION.fullmatch(left["version"]) is not None,
                kind + ": changed proposed pin")
        rel = left["relative_path"]
        validate_relative(rel)
        require(rel not in seen, "duplicate material path")
        seen.add(rel)
        return attest_test_owned_file(root, rel, right["sha256"], right["size_bytes"])

    primary = verify_one("binary", proposal["binary"], pin["binary"])
    helpers_a = proposal["auxiliaries"]
    helpers_b = pin["auxiliaries"]
    require(type(helpers_a) is list and type(helpers_b) is list and
            len(helpers_a) == len(helpers_b) and len(helpers_a) <= MAX_HELPERS,
            "auxiliaries: length mismatch or unbounded")
    helpers = [verify_one(f"auxiliary.{i}", left, right)
               for i, (left, right) in enumerate(zip(helpers_a, helpers_b))]
    return {
        "status": "SYNTHETIC_MATERIAL_OBSERVATIONS_ONLY_DENY_ALL", "observed_materials": 1 + len(helpers),
        "observations": [primary, *helpers], "declared_versions_not_verified": True,
        "trusted_pin_provenance": False, "case_authorized": False, "dispatch_allowed": False,
    }


def _read_json(root: Path, rel: str) -> dict[str, Any]:
    path = root / rel
    require(path.is_file() and not path.is_symlink(), "repository contract file absent or unsafe")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in obj, "duplicate JSON key")
            obj[key] = value
        return obj

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)


def verify_repository(root: Path) -> dict[str, Any]:
    """Reject any attempt to promote the baseline while no private authority exists."""
    root = root.resolve(strict=True)
    for path, expected in ((R4_SOURCE, R4_SOURCE_SHA256), (R4_CONTRACT, R4_CONTRACT_SHA256)):
        current = root / path
        require(current.is_file() and not current.is_symlink() and
                hashlib.sha256(current.read_bytes()).hexdigest() == expected,
                "R4 source contract bytes altered")
    spec = importlib.util.spec_from_file_location("ardrec_p8_r5_r4", root / R4_SOURCE)
    require(spec is not None and spec.loader is not None, "R4 verifier unavailable")
    mod = importlib.util.module_from_spec(spec)
    previous_flag = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = previous_flag
    r4 = mod.verify_repository(root)
    require(r4["status"] == "PASS_P8_R4_CONTRACT_ONLY_DENY_ALL" and
            r4["dispatch_allowed"] is False and r4["real_cases"] == 0 and
            r4["approved_profiles"] == 0 and r4["slots"] == 29, "R4 no longer deny-only baseline")
    conf = _read_json(root, CONTRACT)
    exact(conf, {"schema_version", "increment", "roadmap_step", "base_commit", "thesis_sha256",
                 "source_sections", "r4_validator_sha256", "r4_contract_sha256", "status",
                 "inspection_scope", "read_only", "no_process_spawn", "no_network",
                 "no_private_registry_in_repo", "max_synthetic_file_bytes", "max_auxiliaries",
                 "checks", "unverified", "real_artifacts_inspected", "real_cases_authorized",
                 "dispatch_allowed", "open_findings", "open_development_obligations"}, "R5 contract")
    require(conf["schema_version"] == "1.0" and
            conf["increment"] == "P8-R5-SYNTHETIC-MATERIAL-ATTESTATION" and
            type(conf["roadmap_step"]) is int and conf["roadmap_step"] == 8 and
            conf["base_commit"] == BASE and conf["thesis_sha256"] == THESIS and
            conf["source_sections"] == ["3.7.5", "3.9.2"] and
            conf["r4_validator_sha256"] == R4_SOURCE_SHA256 and
            conf["r4_contract_sha256"] == R4_CONTRACT_SHA256 and
            conf["status"] == "SYNTHETIC_FD_BYTE_OBSERVATION_ONLY_NO_AUTHORIZATION" and
            conf["inspection_scope"] == "TEST_OWNED_TEMPORARY_REGULAR_FILES_ONLY" and
            conf["read_only"] is True and conf["no_process_spawn"] is True and
            conf["no_network"] is True and conf["no_private_registry_in_repo"] is True and
            type(conf["max_synthetic_file_bytes"]) is int and
            conf["max_synthetic_file_bytes"] == MAX_BYTES and
            type(conf["max_auxiliaries"]) is int and conf["max_auxiliaries"] == MAX_HELPERS and
            conf["checks"] == EXPECTED_CHECKS and conf["unverified"] == EXPECTED_UNVERIFIED and
            type(conf["real_artifacts_inspected"]) is int and conf["real_artifacts_inspected"] == 0 and
            type(conf["real_cases_authorized"]) is int and conf["real_cases_authorized"] == 0 and
            conf["dispatch_allowed"] is False and
            conf["open_findings"] == ["AL-06", "AL-07"] and
            type(conf["open_development_obligations"]) is int and
            conf["open_development_obligations"] == 7,
            "R5 contract: changed anchors/guard or fabricated real attestation")
    trace = _read_json(root, TRACE)
    exact(trace, {"schema_version", "roadmap_step", "increment", "status", "base_commit",
                  "thesis_sha256", "source_sections", "r4_source_sha256", "scope", "verification",
                  "open_findings", "open_development_obligations"}, "R5 trace")
    require(trace["schema_version"] == "1.0" and trace["roadmap_step"] == 8 and
            trace["increment"] == "P8-R5-FD-TEST-FIXTURE-ATTESTATION" and
            trace["status"] == "SOURCE_ONLY_NOT_INTEGRATED" and
            trace["base_commit"] == BASE and trace["thesis_sha256"] == THESIS and
            trace["source_sections"] == ["3.7.5", "3.9.2"] and
            trace["r4_source_sha256"] == R4_SOURCE_SHA256 and
            trace["scope"] == {"profile_slots": 29, "real_scenarios": 0, "real_cases": 0,
                               "actual_tools_pinned": 0, "private_approvals_verified": 0,
                               "dispatch_allowed": False, "physical_laboratory": "NOT_TOUCHED"} and
            trace["verification"] == {"synthetic_fd_tests": "PENDING_CI",
                                      "local_user_repo": "PENDING",
                                      "remote_pr_ci": "NOT_RUN",
                                      "postmerge_ci": "NOT_APPLICABLE_UNMERGED"} and
            trace["open_findings"] == ["AL-06", "AL-07"] and
            type(trace["open_development_obligations"]) is int and
            trace["open_development_obligations"] == 7,
            "R5 traceability misstates verified operations")
    return {"status": "PASS_P8_R5_SYNTHETIC_FD_CONTRACT_DENY_ALL", "base_commit": BASE,
            "profiles": 29, "real_artifacts_inspected": 0, "real_cases_authorized": 0,
            "dispatch_allowed": False, "physical_laboratory": "NOT_TOUCHED"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="P8-R5 contract baseline audit; NO real file scanning")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        print(json.dumps(verify_repository(args.root), ensure_ascii=False, sort_keys=True))
        return 0  # Means the *denial invariant* is intact, not authorization.
    except (OSError, ValueError, TypeError, KeyError, ImportError, json.JSONDecodeError) as exc:
        print("ARDREC_P8_R5=FAIL_CLOSED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
