#!/usr/bin/env python3
"""R117-F5D-B: integrate F5C closure and F5D-A crypto/FD checks.

Caller-provided directory descriptors and public keys are NOT
trusted deployment provenance. No root release, boot or P8 grant.
"""
from __future__ import annotations

import argparse
from datetime import datetime
from io import BytesIO
import importlib.util
import os
from pathlib import Path
import subprocess
import zipfile

REPO = Path(__file__).resolve().parents[1]
F5C = "scripts/ardrec_p14_r117_f5c_transaction_closure.py"
F5D = "scripts/ardrec_p14_r117_f5d_crypto_root_reader.py"

class Stop(ValueError):
    pass

def need(ok, code):
    if not ok:
        raise Stop(code)

def load(repo, relative, name):
    path = repo / relative
    need(path.is_file() and not path.is_symlink(),
         "INTEGRATION_SOURCE_MISSING")

    spec = importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None,
         "INTEGRATION_MODULE_INVALID")

    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

def modules(repo=REPO):
    return (
        load(repo, F5C, "r117_f5d_b_closure"),
        load(repo, F5D, "r117_f5d_b_crypto"),
    )

def verify_fd_snapshot(
    head, candidate,
    pilot_fd, release_fd, journal_fd,
    approval_public_key,
    revocation_raw, revocation_signature,
    revocation_public_key,
    *, now, uid=0, repo=REPO,
):
    """Integrate exact FD reads, structural closure and signatures.

    Inputs are caller-controlled. A passing result does NOT prove
    root directory provenance or trusted-key provisioning.
    """
    need(type(uid) is int and uid >= 0 and
         uid == os.geteuid(),
         "INSPECTION_UID_MISMATCH")
    need(type(now) is datetime,
         "INSPECTION_TIME_REQUIRED")

    closure, crypto = modules(repo)
    builder, _ = closure.modules(repo)

    try:
        builder.audit(
            candidate, repo=repo, expected_head=head
        )

        with zipfile.ZipFile(
            BytesIO(candidate)
        ) as archive:
            names = archive.namelist()

        need(
            len(names) == len(set(names)) == 39,
            "CANDIDATE_FILE_COUNT_INVALID",
        )

        pilot = crypto.read_tree_fd(
            pilot_fd,
            set(names),
            uid=uid,
            empty_dirs={"authority"},
        )

        release = crypto.read_tree_fd(
            release_fd,
            set(closure.RELEASE_FILES),
            uid=uid,
        )

        journal = crypto.read_tree_fd(
            journal_fd,
            set(closure.JOURNAL_FILES),
            uid=uid,
        )

        structural = closure.validate(
            head, candidate, pilot, release, journal,
            repo=repo,
        )

        cryptographic = crypto.verify_statements(
            head,
            builder.sha(candidate),
            release["approval.json"],
            release["approval.sig"],
            approval_public_key,
            revocation_raw,
            revocation_signature,
            revocation_public_key,
            now=now,
            repo=repo,
        )

        need(
            structural["structural_closure"] ==
                "CONSISTENT"
            and structural["file_count"] == 39
            and structural["source_count"] == 36
            and cryptographic["approval_ed25519"] ==
                "VERIFIED"
            and cryptographic["revocation_ed25519"] ==
                "VERIFIED"
            and cryptographic["separate_keys"] is True
            and cryptographic["revoked"] is False
            and structural["boot_authorized"] is False
            and cryptographic["boot_authorized"] is False,
            "INTEGRATED_BOUNDARY_NOT_SATISFIED",
        )

    except (
        OSError, ValueError, RuntimeError, KeyError,
        TypeError, zipfile.BadZipFile,
        subprocess.TimeoutExpired,
    ) as exc:
        raise Stop(
            "INTEGRATED_SNAPSHOT_REJECTED"
        ) from exc

    return {
        "schema":
            "ARDREC-R117-F5D-B-INTEGRATED-SNAPSHOT-v1",
        "head": head,
        "candidate_sha256": builder.sha(candidate),
        "files_verified": 39,
        "source_files_verified": 36,
        "fd_tree_check": "PASS_CALLER_SUPPLIED_FDS",
        "structural_closure": "CONSISTENT",
        "approval_ed25519": "VERIFIED_SUPPLIED_KEY",
        "revocation_ed25519": "VERIFIED_SUPPLIED_KEY",
        "separate_keys": True,
        "root_ownership_attested": False,
        "trusted_key_provenance_attested": False,
        "transaction_durability_attested": False,
        "root_release_accepted": False,
        "boot_authorized": False,
        "network_authorized": False,
        "a6": "ND",
        "p8": "NO-GO",
    }

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline", required=True, action="store_true"
    )
    parser.parse_args(argv)

    try:
        need(os.geteuid() != 0,
             "OFFLINE_UNPRIVILEGED_ONLY")

        closure, crypto = modules()
        builder, _ = closure.modules(REPO)
        candidate = builder.candidate(
            "a" * 40, repo=REPO
        )
        builder.audit(
            candidate, repo=REPO,
            expected_head="a" * 40
        )

        need(callable(crypto.verify_statements) and
             callable(crypto.read_tree_fd) and
             callable(closure.validate),
             "COMPONENT_INTERFACE_MISSING")

        print("R117_F5D_B_OFFLINE=PASS_COMPONENT_BOUNDARIES")
        print("R117_F5D_B_INTEGRATION=TEST_SUITE_REQUIRED")
        print("R117_F5D_B_ROOT_ORIGIN=NOT_ATTESTED")
        print("R117_F5D_B_TRUST_ANCHORS=NOT_PROVISIONED")
        print("R117_F5D_B_APPLY=BLOCKED_IN_F5B")
        print("R117_F5D_B_VM_STARTS=0")
        print("R117_F5D_B_NETWORK_CONNECTIONS=0")
        print("R117_F5D_B_A6=ND")
        print("R117_F5D_B_P8=NO-GO")
        return 0

    except (
        Stop, OSError, ValueError, RuntimeError,
        KeyError, TypeError, zipfile.BadZipFile,
    ) as error:
        print(
            "R117_F5D_B_STOP=" +
            type(error).__name__ + ":" +
            str(error)[:160]
        )
        print("R117_F5D_B_P8=NO-GO")
        return 23

if __name__ == "__main__":
    raise SystemExit(main())
