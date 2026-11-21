#!/usr/bin/env python3
"""R117-F5D-C: descriptor boundary without root authorization.

Caller-supplied FDs do not establish host provenance.
No privileged entrypoint or operational permission is issued.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import re
import stat

REPO = Path(__file__).resolve().parents[1]
INTEGRATION = (
    "scripts/ardrec_p14_r117_f5d_b_integrated_attestation.py"
)

TXN_PATTERN = re.compile(
    r"\.r117-f5b-transaction-[0-9a-f]{24}\Z"
)

PILOT = "r117-f4-ftp-pilot-root-v1"
RELEASE = "r117-f4-boot-release-v1"

TRUST_FILES = frozenset({
    "approval.pem",
    "revocation.pem",
    "revocation.json",
    "revocation.sig",
})

FLAGS_DIR = (
    os.O_RDONLY | os.O_DIRECTORY |
    os.O_NOFOLLOW | os.O_CLOEXEC
)

class Stop(ValueError):
    pass

def need(value, code):
    if not value:
        raise Stop(code)

def load(repo):
    path = repo / INTEGRATION
    need(
        path.is_file() and not path.is_symlink(),
        "INTEGRATION_SOURCE_MISSING",
    )
    spec = importlib.util.spec_from_file_location(
        "r117_f5dc_integration", path
    )
    need(
        spec is not None and spec.loader is not None,
        "INTEGRATION_IMPORT_INVALID",
    )
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

def directory(fd, uid):
    st = os.fstat(fd)
    need(
        stat.S_ISDIR(st.st_mode)
        and st.st_uid == uid
        and stat.S_IMODE(st.st_mode) == 0o700,
        "TREE_DIRECTORY_UNTRUSTED",
    )

def child_dir(parent_fd, name, uid):
    need(
        type(name) is str
        and re.fullmatch(r"[A-Za-z0-9_.-]+", name)
        and name not in (".", ".."),
        "DIRECTORY_COMPONENT_INVALID",
    )
    fd = os.open(
        name, FLAGS_DIR, dir_fd=parent_fd
    )
    try:
        directory(fd, uid)
        return fd
    except BaseException:
        os.close(fd)
        raise

def transaction_name(root_fd):
    names = [
        name for name in os.listdir(root_fd)
        if name.startswith(
            ".r117-f5b-transaction-"
        )
    ]
    need(
        len(names) == 1,
        "TRANSACTION_COUNT_NOT_ONE",
    )
    need(
        TXN_PATTERN.fullmatch(names[0]) is not None,
        "TRANSACTION_NAME_INVALID",
    )
    return names[0]

def verify_fd_boundary(
    root_fd, trust_fd, head, candidate, *,
    now, uid, repo=REPO, verifier=None,
    module=None,
):
    """Check one closed snapshot using FD and signed evidence.

    All descriptors and trust keys are still caller-supplied.
    The result never attests host root provenance.
    """
    need(
        type(uid) is int
        and uid >= 0
        and uid == os.geteuid(),
        "CALLER_UID_NOT_CURRENT",
    )
    need(
        type(head) is str
        and re.fullmatch("[0-9a-f]{40}", head),
        "HEAD_INVALID",
    )

    directory(root_fd, uid)
    directory(trust_fd, uid)

    integration = (
        module if module is not None
        else load(repo)
    )

    closure, crypto = integration.modules(repo)

    trust = crypto.read_tree_fd(
        trust_fd, set(TRUST_FILES), uid=uid
    )

    txn = transaction_name(root_fd)
    handles = []

    try:
        for name in (PILOT, RELEASE, txn):
            handles.append(
                child_dir(root_fd, name, uid)
            )

        check = (
            verifier if verifier is not None
            else integration.verify_fd_snapshot
        )

        result = check(
            head, candidate, *handles,
            trust["approval.pem"],
            trust["revocation.json"],
            trust["revocation.sig"],
            trust["revocation.pem"],
            now=now,
            uid=uid,
            repo=repo,
        )

        need(
            type(result) is dict
            and result.get("head") == head
            and result.get("p8") == "NO-GO"
            and result.get("boot_authorized") is False
            and result.get("network_authorized") is False
            and result.get("root_release_accepted") is False
            and result.get("root_ownership_attested") is False
            and result.get(
                "trusted_key_provenance_attested"
            ) is False
            and result.get(
                "transaction_durability_attested"
            ) is False
            and result.get("files_verified") == 39,
            "INTEGRATION_OUTPUT_UNTRUSTED",
        )

        return {
            "schema":
                "ARDREC-R117-F5D-C-DESCRIPTOR-BOUNDARY-v1",
            "head": head,
            "files_verified": 39,
            "fd_snapshot_consistent": True,
            "host_root_provenance_attested": False,
            "independent_trust_provisioned": False,
            "transaction_durability_attested": False,
            "root_release_accepted": False,
            "boot_authorized": False,
            "network_authorized": False,
            "a6": "ND",
            "p8": "NO-GO",
        }
    finally:
        for fd in reversed(handles):
            os.close(fd)

def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        required=True,
    )
    parser.parse_args(argv)

    try:
        need(
            os.geteuid() != 0,
            "ROOT_EXECUTION_FORBIDDEN",
        )
        integration = load(REPO)
        need(
            callable(integration.verify_fd_snapshot),
            "INTEGRATION_INTERFACE_MISSING",
        )

        print(
            "R117_F5D_C_OFFLINE="
            "PASS_BOUNDARY_COMPONENTS"
        )
        print(
            "R117_F5D_C_ROOT_ORIGIN=NOT_ATTESTED"
        )
        print(
            "R117_F5D_C_EXTERNAL_TRUST=NOT_PROVISIONED"
        )
        print(
            "R117_F5D_C_APPLY=BLOCKED_IN_F5B"
        )
        print("R117_F5D_C_VM_STARTS=0")
        print("R117_F5D_C_NETWORK_CONNECTIONS=0")
        print("R117_F5D_C_A6=ND")
        print("R117_F5D_C_P8=NO-GO")
        return 0

    except (
        Stop, OSError, ValueError,
        TypeError, RuntimeError,
    ) as exc:
        print(
            "R117_F5D_C_STOP=" +
            type(exc).__name__ + ":" +
            str(exc)[:160]
        )
        print("R117_F5D_C_P8=NO-GO")
        return 23

if __name__ == "__main__":
    raise SystemExit(main())
