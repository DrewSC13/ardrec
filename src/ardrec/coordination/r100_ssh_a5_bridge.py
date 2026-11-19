"""R100: bridge between verified R99 local TCP and A5 NO_START.

An SSH identification is not effective SSH configuration evidence.
No A5 operational execution, A6 accreditation, risk confirmation or P8 grant.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from ardrec.coordination import r59d_a5_result_intake as a5

SCHEMA = "ardrec-r100-rust-ssh-a5-a6-bridge-v1"
R99_SCHEMA = "ardrec-r99-local-tcp-ssh-identification-v1"
BANNER = b"SSH-2.0-ARDREC_R99_LOCAL\r\n"
CONFIG_SENTINEL = a5.sha(b"R100_EFFECTIVE_CONFIGURATION_NOT_ACQUIRED")
R99_SOURCE = (
    Path(__file__).resolve().parents[3]
    / "crates/ardrec-executor/src/r99_ssh_loopback.rs"
)
FIELDS = frozenset({
    "schema", "transport", "identification", "banner_sha256",
    "bytes_received", "elapsed_ms", "tcp_connections",
    "ssh_authentication", "remote_commands",
    "a5_operational_attempts", "a6_classification",
    "rf_confirmed", "evidence_accredited", "dispatch_allowed",
    "p8_operational",
})
MANIFEST_FIELDS = frozenset({
    "schema", "session_id", "service_id", "family_id",
    "derived_case_id", "assessment_index", "attempt_id",
    "configuration_status", "method_executed",
    "r99_source_sha256", "rust_binary_sha256",
    "observation_sha256", "a5_report_sha256",
    "a5_physical_start_accredited", "a6_classification",
    "a6_technical_truth_accredited", "a7_confirmed_rf",
    "operational_dispatch", "p8_operational", "sha256",
})


class BridgeError(ValueError):
    """Fail-closed R100 validation error."""


def need(condition: bool, code: str) -> None:
    if not condition:
        raise BridgeError(code)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return a5.canonical(value) + b"\n"


def observation_valid(value: object) -> bool:
    need(
        type(value) is dict and set(value) == FIELDS,
        "R99_OBSERVATION_SCHEMA",
    )
    v = value
    need(
        v["schema"] == R99_SCHEMA
        and v["transport"] == "REAL_TCP_IPV4_LOOPBACK_ONLY"
        and v["identification"] == "SSH-2.0-ARDREC_R99_LOCAL"
        and v["banner_sha256"] == sha(BANNER)
        and type(v["bytes_received"]) is int
        and v["bytes_received"] == len(BANNER)
        and type(v["elapsed_ms"]) is int
        and 0 <= v["elapsed_ms"] <= 10000
        and type(v["tcp_connections"]) is int
        and v["tcp_connections"] == 1,
        "R99_TRANSPORT_MISMATCH",
    )
    need(
        v["ssh_authentication"] is False
        and type(v["remote_commands"]) is int
        and v["remote_commands"] == 0
        and type(v["a5_operational_attempts"]) is int
        and v["a5_operational_attempts"] == 0
        and v["a6_classification"] == "ND"
        and v["rf_confirmed"] is None
        and v["evidence_accredited"] is False
        and v["dispatch_allowed"] is False
        and v["p8_operational"] == "NO-GO",
        "R99_UNAUTHORIZED_CLAIMS",
    )
    return True


def intent_for(session_id: str) -> dict:
    need(
        type(session_id) is str
        and re.fullmatch(r"R100_[A-F0-9]{12}", session_id) is not None,
        "SESSION_ID_INVALID",
    )
    return a5.build_intent(
        service_id="SSH_DEV",
        session_id=session_id,
        family_id="SSH-T01",
        derived_case_id="SSH-T01-S01-01",
        assessment_index=0,
        attempt_id="ATT_" + session_id,
        configuration_sha256=CONFIG_SENTINEL,
        method_id="SSH_EFFECTIVE_CONFIG_READONLY",
    )


def private_root(root: Path) -> None:
    need(
        isinstance(root, Path) and root.is_absolute()
        and root.is_dir() and not root.is_symlink(),
        "PRIVATE_ROOT_INVALID",
    )
    info = root.stat()
    need(
        info.st_uid == os.getuid()
        and stat.S_ISDIR(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o700,
        "PRIVATE_ROOT_PERMISSIONS",
    )


def write_once(path: Path, raw: bytes) -> None:
    need(
        0 < len(raw) <= 65536 and not path.is_symlink(),
        "PRIVATE_WRITE_INVALID",
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def read_private(path: Path) -> bytes:
    need(
        path.is_file() and not path.is_symlink(),
        "PRIVATE_READ_INVALID",
    )
    info = path.stat()
    need(
        info.st_uid == os.getuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
        and 0 < info.st_size <= 65536,
        "PRIVATE_FILE_MODE_OR_SIZE",
    )
    return path.read_bytes()


def strict_json(raw: bytes) -> dict:
    def pairs(items):
        obj = {}
        for key, value in items:
            need(key not in obj, "JSON_DUPLICATE_KEY")
            obj[key] = value
        return obj

    doc = json.loads(raw, object_pairs_hook=pairs)
    need(type(doc) is dict, "JSON_OBJECT_REQUIRED")
    need(raw == canonical(doc), "JSON_NOT_CANONICAL")
    return doc


def create(root: Path, observation: dict,
           binary_sha256: str, session_id: str) -> dict:
    private_root(root)
    observation_valid(observation)
    need(
        type(binary_sha256) is str
        and re.fullmatch(r"[a-f0-9]{64}", binary_sha256) is not None,
        "BINARY_SHA_INVALID",
    )

    intent = intent_for(session_id)

    # Save real local TCP observation independently of A5.
    raw_observation = canonical(observation)
    write_once(root / "tcp-observation.json", raw_observation)

    # The planned effective-configuration method DID NOT execute.
    # Therefore the A5 receipt is strictly NO_START.
    receipt = a5.make_receipt(intent)
    stored = a5.persist_candidate(root, intent, receipt, b"")

    need(
        stored["status"] == "CREATED"
        and stored["a6_classification"] == "ND",
        "A5_FIRST_PERSIST_INVALID",
    )

    manifest = {
        "schema": SCHEMA,
        "session_id": session_id,
        "service_id": "SSH_DEV",
        "family_id": "SSH-T01",
        "derived_case_id": "SSH-T01-S01-01",
        "assessment_index": 0,
        "attempt_id": intent["attempt_id"],
        "configuration_status": "NOT_COLLECTED",
        "method_executed": False,
        "r99_source_sha256": sha(R99_SOURCE.read_bytes()),
        "rust_binary_sha256": binary_sha256,
        "observation_sha256": sha(raw_observation),
        "a5_report_sha256": stored["report_sha256"],
        "a5_physical_start_accredited": False,
        "a6_classification": "ND",
        "a6_technical_truth_accredited": False,
        "a7_confirmed_rf": None,
        "operational_dispatch": False,
        "p8_operational": "NO-GO",
    }
    manifest["sha256"] = a5.digest(manifest)

    write_once(root / "MANIFEST.json", canonical(manifest))
    return verify(root)


def verify(root: Path) -> dict:
    private_root(root)
    manifest = strict_json(read_private(root / "MANIFEST.json"))

    need(
        set(manifest) == MANIFEST_FIELDS
        and manifest.get("schema") == SCHEMA,
        "MANIFEST_SCHEMA_INVALID",
    )

    without_hash = {
        k: v for k, v in manifest.items() if k != "sha256"
    }
    need(
        manifest["sha256"] == a5.digest(without_hash),
        "MANIFEST_DIGEST_INVALID",
    )

    observation_raw = read_private(root / "tcp-observation.json")
    observation = strict_json(observation_raw)
    observation_valid(observation)

    need(
        sha(observation_raw) == manifest["observation_sha256"],
        "OBSERVATION_HASH_MISMATCH",
    )
    need(
        sha(R99_SOURCE.read_bytes())
            == manifest["r99_source_sha256"],
        "R99_SOURCE_CHANGED",
    )

    intent = intent_for(manifest["session_id"])

    need(
        manifest["service_id"] == intent["service_id"]
        and manifest["family_id"] == intent["family_id"]
        and manifest["derived_case_id"] == intent["derived_case_id"]
        and type(manifest["assessment_index"]) is int
        and manifest["assessment_index"]
            == intent["assessment_index"]
        and manifest["attempt_id"] == intent["attempt_id"]
        and manifest["configuration_status"] == "NOT_COLLECTED"
        and manifest["method_executed"] is False,
        "A5_IDENTITY_OR_METHOD_MISMATCH",
    )

    a5_doc = a5.verify_stored_candidate(
        root, manifest["a5_report_sha256"]
    )

    need(
        a5_doc["intent"] == intent
        and a5_doc["receipt"]["declared_outcome"] == "NO_START"
        and a5_doc["status"] == "DECLARED_NO_START_NO_A5"
        and a5_doc["a5_physical_start_accredited"] is False
        and a5_doc["a6_classification"] == "ND"
        and a5_doc["a7_confirmed_rf"] is None
        and a5_doc["operational_dispatch"] is False
        and a5_doc["p8_operational"] == "NO-GO",
        "A5_A6_BOUNDARY_INVALID",
    )

    need(
        manifest["a5_physical_start_accredited"] is False
        and manifest["a6_classification"] == "ND"
        and manifest["a6_technical_truth_accredited"] is False
        and manifest["a7_confirmed_rf"] is None
        and manifest["operational_dispatch"] is False
        and manifest["p8_operational"] == "NO-GO",
        "MANIFEST_FALSE_AUTHORITY",
    )

    expected_files = {
        "MANIFEST.json",
        "tcp-observation.json",
        "r59d-a5-" + manifest["a5_report_sha256"] + ".json",
    }
    need(
        {p.name for p in root.iterdir()} == expected_files,
        "PRIVATE_INVENTORY_CHANGED",
    )

    return manifest
