#!/usr/bin/env python3
"""R105: demonstracion SSHv2 KEXINIT real SOLO loopback con fixture local."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from threading import Thread

REPO = Path(__file__).resolve().parents[1]
CLIENT = b"SSH-2.0-ARDREC_R105_LOCAL\r\n"
SERVER = b"SSH-2.0-ARDREC_R105_FIXTURE\r\n"


def packet() -> bytes:
    names = (
        b"curve25519-sha256", b"ssh-ed25519", b"aes128-ctr", b"aes128-ctr",
        b"hmac-sha2-256", b"hmac-sha2-256", b"none", b"none", b"", b"",
    )
    payload = b"\x14" + bytes(16)
    for name in names:
        payload += len(name).to_bytes(4, "big") + name
    payload += bytes(5)
    padding = (8 - ((5 + len(payload)) % 8)) % 8
    if padding < 4:
        padding += 8
    size = 1 + len(payload) + padding
    return size.to_bytes(4, "big") + bytes([padding]) + payload + bytes(padding)


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--offline-local-fixture", action="store_true", required=True)
    args = cli.parse_args()
    if not args.offline_local_fixture or Path.cwd().resolve() != REPO:
        print("R105_STOP=REPO_AND_MODE_REQUIRED")
        return 4

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    errors: list[str] = []
    accepted: list[bytes] = []

    def serve() -> None:
        try:
            with listener:
                conn, address = listener.accept()
                with conn:
                    conn.settimeout(5)
                    if address[0] != "127.0.0.1":
                        raise ValueError("NON_LOOPBACK")
                    buf = bytearray()
                    while not buf.endswith(b"\n") and len(buf) <= 255:
                        item = conn.recv(1)
                        if not item:
                            raise ValueError("PREMATURE_CLIENT_EOF")
                        buf.extend(item)
                    accepted.append(bytes(buf))
                    conn.sendall(SERVER + packet())
        except Exception as exc:
            errors.append(type(exc).__name__ + ":" + str(exc)[:120])

    worker = Thread(target=serve, daemon=True)
    worker.start()
    command = [
        "cargo", "run", "--quiet", "--locked", "--offline", "--example",
        "r105_ssh_kexinit_loopback", "--", str(port),
    ]
    try:
        cp = subprocess.run(
            command, cwd=REPO, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=90, check=False,
            env={**os.environ, "CARGO_TERM_COLOR": "never"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print("R105_STOP=RUST_EXECUTION:" + type(exc).__name__)
        return 4
    worker.join(timeout=6)
    if cp.returncode != 0 or worker.is_alive() or errors:
        print("R105_STOP=FIXTURE_OR_RUST_FAILURE")
        print("R105_CARGO_RC=" + str(cp.returncode))
        print("R105_ERROR=" + ",".join(errors)[:200])
        print("R105_STDERR=" + cp.stderr.decode("utf-8", "replace")[:500].replace("\n", " "))
        return 4
    try:
        report = json.loads(cp.stdout)
    except (UnicodeError, ValueError):
        print("R105_STOP=INVALID_RUST_JSON")
        return 4
    safe = (
        accepted == [CLIENT]
        and report.get("schema") == "ardrec-r105-sshv2-loopback-kexinit-v1"
        and report.get("transport") == "REAL_TCP_IPV4_LOOPBACK_ONLY"
        and report.get("server_identification") == "SSH-2.0-ARDREC_R105_FIXTURE"
        and report.get("identification_sha256") == hashlib.sha256(SERVER).hexdigest()
        and report.get("kexinit_sha256") == hashlib.sha256(packet()).hexdigest()
        and report.get("offered_kex_algorithms") == ["curve25519-sha256"]
        and report.get("offered_host_key_algorithms") == ["ssh-ed25519"]
        and report.get("tcp_connections") == 1
        and report.get("client_identifications_sent") == 1
        and report.get("keys_negotiated") is False
        and report.get("authenticated") is False
        and report.get("remote_commands") == 0
        and report.get("a5_operational_attempts") == 0
        and report.get("a6_classification") == "ND"
        and report.get("a7_confirmed_rf") is None
        and report.get("evidence_accredited") is False
        and report.get("dispatch_allowed") is False
        and report.get("p8_operational") == "NO-GO"
    )
    if not safe:
        print("R105_STOP=CONTRACT_INVARIANT")
        return 4
    print("R105_TCP_LOOPBACK=PASS")
    print("R105_SERVER_IDENTIFICATION=PASS")
    print("R105_KEXINIT_PACKET=PASS")
    print("R105_KEXINIT_SHA256=" + report["kexinit_sha256"])
    print("R105_SSH_KEY_NEGOTIATION=NOT_EXECUTED")
    print("R105_A6=ND")
    print("R105_P8=NO-GO")
    print("R105_RESULT=REAL_LOCAL_KEXINIT_OBSERVED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
