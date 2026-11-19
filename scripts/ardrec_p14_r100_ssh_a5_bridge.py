#!/usr/bin/env python3
"""R100: one local Rust TCP observation and durable A5 NO_START."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ardrec.coordination import r100_ssh_a5_bridge as bridge

LAB = Path("/home/cicada/ardrec-lab/r100-ssh-a5-bridge-v1")
BINARY = ROOT / "target/debug/examples/r99_ssh_loopback"


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def observe():
    need(
        BINARY.is_file() and not BINARY.is_symlink(),
        "R99_RUST_BINARY_MISSING",
    )
    info = BINARY.stat()
    need(
        stat.S_ISREG(info.st_mode)
        and info.st_size <= 100_000_000
        and info.st_mode & 0o111,
        "R99_BINARY_INVALID",
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(5)
        port = server.getsockname()[1]
        errors = []

        def serve():
            try:
                client, address = server.accept()
                with client:
                    need(address[0] == "127.0.0.1",
                         "CLIENT_NOT_LOOPBACK")
                    client.sendall(bridge.BANNER)
            except Exception as exc:
                errors.append(str(exc)[:100])

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        cp = subprocess.run(
            [str(BINARY), str(port)],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8,
            check=False,
            close_fds=True,
        )
        worker.join(timeout=6)

    need(not worker.is_alive() and not errors,
         "OWNED_SERVER_FAILURE")
    need(
        cp.returncode == 0
        and len(cp.stdout) <= 8192
        and not cp.stderr,
        "RUST_CLIENT_FAILURE",
    )

    observation = json.loads(cp.stdout)
    bridge.observation_valid(observation)
    return observation, hashlib.sha256(BINARY.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--create", action="store_true")
    mode.add_argument("--verify", type=Path)
    args = parser.parse_args()

    need(os.geteuid() != 0, "ROOT_NOT_ALLOWED")
    need(Path.cwd().resolve() == ROOT, "WRONG_REPOSITORY")

    if args.create:
        LAB.mkdir(parents=True, mode=0o700, exist_ok=True)
        bridge.private_root(LAB)

        session_id = "R100_" + secrets.token_hex(6).upper()
        folder = Path(tempfile.mkdtemp(prefix="case-", dir=LAB))

        observation, binary_sha = observe()
        result = bridge.create(
            folder, observation, binary_sha, session_id
        )

        # Idempotent re-open, without another TCP connection.
        replay = bridge.verify(folder)
        need(result == replay, "R100_REPLAY_CHANGED")
        print("R100_RUST_TCP=PASS_REAL_LOOPBACK")
        print("R100_RUST_BINARY_SHA256=" + binary_sha)
        print("R100_TRANSPORT_OBSERVATION=PASS_HASH_BOUND")
        print("R100_A5_RECEIPT=PASS_DURABLE_NO_START")
        print("R100_A5_METHOD_EXECUTED=FALSE")
        print("R100_A6=ND")
        print("R100_REPLAY=PASS_NO_NEW_CONNECTION")
        print("R100_SESSION=" + str(folder))

    else:
        folder = args.verify
        need(
            folder.is_absolute()
            and folder.parent == LAB
            and folder.name.startswith("case-"),
            "VERIFY_PATH_OUTSIDE_PRIVATE_LAB",
        )
        result = bridge.verify(folder)
        print("R100_REPLAY=PASS_READONLY")
        print("R100_SESSION=" + str(folder))

    print("R100_MANIFEST_SHA256=" + result["sha256"])
    print("R100_R99_SOURCE_SHA256=" + result["r99_source_sha256"])
    print("R100_OPERATIONAL_DISPATCH=FALSE")
    print("R100_VM_STARTS=0")
    print("R100_HOST_SECURITY_MUTATIONS=0")
    print("R100_P8=NO-GO")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            "R100_STOP="
            + type(exc).__name__ + ":" + str(exc)[:160]
        )
        raise SystemExit(4)
