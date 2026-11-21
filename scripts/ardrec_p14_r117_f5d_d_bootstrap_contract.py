#!/usr/bin/env python3
"""F5D-D: verify an independently signed, source-only bootstrap contract.

Never grants root provenance, deployment, boot, networking or P8.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[1]
FILES = (
    "scripts/ardrec_p14_r117_f5_root_candidate.py",
    "scripts/ardrec_p14_r117_f5b_root_stage.py",
    "scripts/ardrec_p14_r117_f5c_transaction_closure.py",
    "scripts/ardrec_p14_r117_f5d_crypto_root_reader.py",
    "scripts/ardrec_p14_r117_f5d_b_integrated_attestation.py",
    "scripts/ardrec_p14_r117_f5d_c_root_boundary.py",
    "scripts/ardrec_p14_r117_f5d_d_bootstrap_contract.py",
    "src/ardrec/coordination/r117_f4_controlled_boot.py",
    "src/ardrec/coordination/r117_f4_runner_ftp_boot.py",
    "src/ardrec/coordination/r117_f4_root_release.py",
)
PREFIX = b"ARDREC-R117-F5D-D-BOOTSTRAP-SOURCE-ONLY-v1\x00"
SCHEMA = "ARDREC-R117-F5D-D-BOOTSTRAP-CONTRACT-v1"
POLICY_PATH = "/etc/ardrec/r117-f5d-d-bootstrap-v1"
ROOT_PATH = "/var/lib/ardrec"
OPENSSL = "/usr/bin/openssl"
FIELDS = frozenset((
    "schema", "head", "source_sha256", "bootstrap_public_sha256",
    "approval_public_sha256", "revocation_public_sha256",
    "valid_from", "valid_until", "purpose", "policy_path",
    "root_path", "install_authorized", "boot_authorized",
    "network_authorized", "a6", "p8",
))
class Stop(ValueError):
    pass

def need(check, code):
    if not check:
        raise Stop(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(obj):
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")

def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "DUPLICATE_JSON_FIELD")
        result[key] = value
    return result

def parse(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 8192,
         "POLICY_BYTES_INVALID")
    try:
        obj = json.loads(raw, object_pairs_hook=unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(
                             Stop("JSON_NONFINITE")))
        need(type(obj) is dict and canonical(obj) == raw,
             "POLICY_NONCANONICAL")
    except (UnicodeError, TypeError, ValueError, OverflowError) as exc:
        raise Stop("POLICY_PARSE_REJECTED") from exc
    return obj

def utc(value):
    need(type(value) is str and re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value), "TIME_FORMAT_INVALID")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Stop("INVALID_UTC_TIME") from exc

def source_hashes(repo):
    need(repo.is_dir() and not repo.is_symlink(), "REPO_MISSING")
    result = {}
    for item in FILES:
        path = repo
        for component in Path(item).parts:
            path = path / component
            need(not path.is_symlink(), "SOURCE_SYMLINK_" + item)
        st = path.stat()
        need(stat.S_ISREG(st.st_mode) and st.st_size > 0 and
             st.st_size <= 200000 and st.st_nlink == 1,
             "SOURCE_FILE_INVALID_" + item)
        result[item] = sha(path.read_bytes())
    return result

def verify_ed25519(public, message, signature):
    need(type(public) is bytes and 0 < len(public) <= 4096 and
         type(message) is bytes and 0 < len(message) <= 8192 and
         type(signature) is bytes and len(signature) == 64,
         "SIGNATURE_INPUT_INVALID")
    with tempfile.TemporaryDirectory(prefix="ardrec-f5dd-verify-") as td:
        paths = [Path(td) / n for n in ("key.pem", "message", "signature")]
        for path, value in zip(paths, (public, message, signature)):
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(value)
        run = subprocess.run([OPENSSL, "pkeyutl", "-verify", "-rawin",
                              "-pubin", "-inkey", str(paths[0]),
                              "-sigfile", str(paths[2]), "-in", str(paths[1])],
                             stdin=subprocess.DEVNULL, capture_output=True,
                             timeout=10, check=False, env={"PATH": "/usr/bin:/bin",
                                                           "LC_ALL": "C"})
        need(run.returncode == 0, "BOOTSTRAP_SIGNATURE_INVALID")

def verify_contract(raw, signature, bootstrap_public, trusted_key_sha,
                    approval_public, revocation_public, head, *, now, repo=REPO):
    """Verify only signed source identity against *supplied* trust pin.

    The caller's trust pin is NOT proof of independent provisioning.
    """
    need(type(head) is str and re.fullmatch("[0-9a-f]{40}", head),
         "HEAD_INVALID")
    need(type(now) is datetime and now.tzinfo is not None and
         now.utcoffset().total_seconds() == 0, "TIME_NOT_UTC")
    need(type(trusted_key_sha) is str and
         re.fullmatch("[0-9a-f]{64}", trusted_key_sha), "TRUST_PIN_INVALID")
    need(type(bootstrap_public) is bytes and
         sha(bootstrap_public) == trusted_key_sha, "BOOTSTRAP_KEY_PIN_MISMATCH")
    need(type(approval_public) is bytes and type(revocation_public) is bytes and
         bootstrap_public != approval_public and
         bootstrap_public != revocation_public and
         approval_public != revocation_public,
         "AUTHORITY_KEYS_NOT_INDEPENDENT")
    policy = parse(raw)
    need(set(policy) == FIELDS, "POLICY_FIELDS_CHANGED")
    need(policy["schema"] == SCHEMA and policy["head"] == head and
         policy["purpose"] == "SOURCE_ATTESTATION_ONLY" and
         policy["policy_path"] == POLICY_PATH and
         policy["root_path"] == ROOT_PATH and
         policy["a6"] == "ND" and policy["p8"] == "NO-GO" and
         policy["install_authorized"] is False and
         policy["boot_authorized"] is False and
         policy["network_authorized"] is False,
         "POLICY_SCOPE_INVALID")
    need(policy["bootstrap_public_sha256"] == trusted_key_sha and
         policy["approval_public_sha256"] == sha(approval_public) and
         policy["revocation_public_sha256"] == sha(revocation_public),
         "POLICY_KEY_BINDING_INVALID")
    start, end = utc(policy["valid_from"]), utc(policy["valid_until"])
    need(start <= now < end and 0 < (end-start).total_seconds() <= 600,
         "POLICY_TIME_OUT_OF_SCOPE")
    need(policy["source_sha256"] == source_hashes(repo),
         "POLICY_SOURCE_DRIFT")
    verify_ed25519(bootstrap_public, PREFIX + raw, signature)
    return {
        "schema": "ARDREC-R117-F5D-D-SOURCE-REVIEW-v1",
        "head": head,
        "files_verified": len(FILES),
        "bootstrap_signature": "VERIFIED_AGAINST_SUPPLIED_PIN",
        "source_sha256": sha(raw),
        "host_root_provenance_attested": False,
        "independent_trust_provisioned": False,
        "transaction_durability_attested": False,
        "root_release_accepted": False,
        "install_authorized": False,
        "boot_authorized": False,
        "network_authorized": False,
        "a6": "ND", "p8": "NO-GO",
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", required=True, action="store_true")
    parser.parse_args()
    try:
        need(os.geteuid() != 0, "OFFLINE_ROOT_FORBIDDEN")
        checks = source_hashes(REPO)
        need(len(checks) == 10, "SOURCE_DISCOVERY_DRIFT")
        print("R117_F5D_D_OFFLINE=PASS_10_PINNABLE_SOURCES")
        print("R117_F5D_D_SIGNATURE=TEST_SUITE_REQUIRED")
        print("R117_F5D_D_EXTERNAL_TRUST=NOT_PROVISIONED")
        print("R117_F5D_D_ROOT=NOT_INSTALLED")
        print("R117_F5D_D_APPLY=BLOCKED_IN_F5B")
        print("R117_F5D_D_A6=ND")
        print("R117_F5D_D_P8=NO-GO")
        return 0
    except (Stop, OSError, ValueError, TypeError) as exc:
        print("R117_F5D_D_STOP=" + type(exc).__name__ + ":" + str(exc)[:140])
        print("R117_F5D_D_P8=NO-GO")
        return 23

if __name__ == "__main__":
    raise SystemExit(main())
