#!/usr/bin/env python3
"""R99: servidor local propio + cliente Rust, recibo privado."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import threading

ROOT = Path("/home/cicada/Development/GitHub/ardrec")
LAB = Path("/home/cicada/ardrec-lab/r99-ssh-loopback-v1")
BINARY = ROOT / "target/debug/examples/r99_ssh_loopback"
BANNER = b"SSH-2.0-ARDREC_R99_LOCAL\r\n"


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise RuntimeError(reason)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(doc: dict) -> bytes:
    return (
        json.dumps(
            doc, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ) + "\n"
    ).encode("utf-8")


def main() -> int:
    need(os.geteuid() != 0, "ROOT_FORBIDDEN")
    need(Path.cwd().resolve() == ROOT, "WRONG_REPOSITORY")

    need(
        BINARY.is_file() and not BINARY.is_symlink(),
        "RUST_EXAMPLE_MISSING",
    )
    st = BINARY.stat()
    need(
        stat.S_ISREG(st.st_mode)
        and st.st_mode & 0o111
        and st.st_size <= 100_000_000,
        "RUST_BINARY_INVALID",
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(5)

        port = server.getsockname()[1]
        errors: list[str] = []

        def serve() -> None:
            try:
                connection, address = server.accept()
                with connection:
                    need(
                        address[0] == "127.0.0.1",
                        "UNEXPECTED_CLIENT",
                    )
                    connection.sendall(BANNER)
            except Exception as error:
                errors.append(type(error).__name__)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()

        result = subprocess.run(
            [str(BINARY), str(port)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8,
            check=False,
            cwd=ROOT,
        )

        worker.join(timeout=6)

        need(not worker.is_alive() and not errors,
             "LOCAL_SERVER_FAILED")
        need(result.returncode == 0, "RUST_CLIENT_FAILED")
        need(not result.stderr, "RUST_CLIENT_STDERR")
        need(len(result.stdout) < 8192, "RUST_OUTPUT_LIMIT")

        observation = json.loads(result.stdout)

    need(
        observation.get("transport")
            == "REAL_TCP_IPV4_LOOPBACK_ONLY"
        and observation.get("identification")
            == "SSH-2.0-ARDREC_R99_LOCAL"
        and observation.get("banner_sha256") == sha(BANNER)
        and observation.get("bytes_received") == len(BANNER)
        and observation.get("tcp_connections") == 1
        and observation.get("a5_operational_attempts") == 0
        and observation.get("a6_classification") == "ND"
        and observation.get("rf_confirmed") is None
        and observation.get("evidence_accredited") is False
        and observation.get("dispatch_allowed") is False
        and observation.get("p8_operational") == "NO-GO",
        "R99_RESULT_CONTRACT_INVALID",
    )

    LAB.mkdir(mode=0o700, parents=True, exist_ok=True)
    need(
        not LAB.is_symlink()
        and LAB.stat().st_uid == os.getuid()
        and stat.S_IMODE(LAB.stat().st_mode) == 0o700,
        "PRIVATE_PARENT_INVALID",
    )

    folder = Path(
        tempfile.mkdtemp(prefix="run-", dir=LAB)
    )
    receipt = {
        "schema": "ardrec-r99-rust-local-transport-smoke-v1",
        "result": "PASS_REAL_TCP_LOOPBACK",
        "binary_sha256": sha(BINARY.read_bytes()),
        "server_banner_sha256": sha(BANNER),
        "rust_observation": observation,
        "vm_starts": 0,
        "host_security_mutations": 0,
        "physical_ssh_target_contacted": False,
        "a6_classification": "ND",
        "rf_confirmed": None,
        "p8_operational": "NO-GO",
    }

    raw = canonical(receipt)
    path = folder / "summary.json"

    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())

    print("R99_REAL_TCP_LOOPBACK=PASS")
    print("R99_SSH_BANNER_SHA256=" + sha(BANNER))
    print("R99_RUST_BINARY_SHA256=" + receipt["binary_sha256"])
    print("R99_A5_OPERATIONAL=NOT_AUTHORIZED")
    print("R99_A6=ND")
    print("R99_RF_CONFIRMED=NULL")
    print("R99_VM_STARTS=0")
    print("R99_HOST_SECURITY_MUTATIONS=0")
    print("R99_SESSION=" + str(folder))
    print("R99_RECEIPT_SHA256=" + sha(raw))
    print("R99_P8=NO-GO")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(
            "R99_STOP="
            + type(error).__name__
            + ":" + str(error)[:140]
        )
        raise SystemExit(4)
