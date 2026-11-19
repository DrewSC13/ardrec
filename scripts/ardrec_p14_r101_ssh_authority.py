#!/usr/bin/env python3
"""R101: create or verify a non-authorizing SSH scope proposal."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import os
import secrets
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ardrec.coordination import r101_ssh_authority as gate

R100_LAB = Path(
    "/home/cicada/ardrec-lab/r100-ssh-a5-bridge-v1"
)
R101_LAB = Path(
    "/home/cicada/ardrec-lab/r101-ssh-authority-v1"
)


def run() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--r100-case", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--create", action="store_true")
    mode.add_argument("--verify", type=Path)
    args = parser.parse_args()

    gate.need(os.geteuid() != 0, "ROOT_FORBIDDEN")
    gate.need(
        Path.cwd().resolve() == ROOT,
        "WRONG_REPOSITORY",
    )

    case_root = args.r100_case
    gate.need(
        case_root.is_absolute()
        and case_root.parent == R100_LAB
        and case_root.name.startswith("case-")
        and not case_root.is_symlink(),
        "R100_PATH_OUT_OF_SCOPE",
    )

    if args.create:
        R101_LAB.mkdir(
            mode=0o700, parents=True, exist_ok=True
        )
        gate.a5._private_root(R101_LAB)

        new_root = Path(
            tempfile.mkdtemp(
                prefix="review-", dir=R101_LAB
            )
        )
        request = gate.make_proposal(
            case_root,
            request_id="REQ_" + secrets.token_hex(12).upper(),
            not_before_utc=datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            ttl_seconds=120,
        )
        result = gate.persist(
            case_root, new_root, request
        )
        gate.need(
            result == gate.verify_stored(
                case_root, new_root
            ),
            "REPLAY_FAILED",
        )
        print("R101_CREATE=PASS_DURABLE_DENY_REVIEW")
        print("R101_REPLAY=PASS_NO_EXECUTION")
    else:
        new_root = args.verify
        gate.need(
            new_root.is_absolute()
            and new_root.parent == R101_LAB
            and new_root.name.startswith("review-"),
            "REVIEW_PATH_OUT_OF_SCOPE",
        )
        result = gate.verify_stored(case_root, new_root)
        print("R101_VERIFY=PASS_READONLY")

    print("R101_REQUEST_ID=" + result["request_id"])
    print("R101_R100_MANIFEST=" + result["r100_manifest_sha256"])
    print("R101_REVIEW_SHA256=" + result["sha256"])
    print("R101_AUTHORIZED=FALSE")
    print("R101_DISPATCH_ALLOWED=FALSE")
    print("R101_A5_OPERATIONAL_STARTS=0")
    print("R101_A6=ND")
    print("R101_REVIEW_ROOT=" + str(new_root))
    print("R101_VM_STARTS=0")
    print("R101_HOST_MUTATIONS=0")
    print("R101_P8=NO-GO")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except Exception as exc:
        print(
            "R101_STOP="
            + type(exc).__name__
            + ":" + str(exc)[:150]
        )
        raise SystemExit(4)
