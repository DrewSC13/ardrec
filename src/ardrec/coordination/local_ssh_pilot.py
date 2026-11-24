"""R192: actual local SSH transport observation.

Separate from historical VM operational contracts.
No authentication, external network or privileged installation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import socket
import stat
import subprocess
import tempfile
import time

from datetime import datetime, timezone
from pathlib import Path


SCHEMA = "ARDREC-R192-LOCAL-SSH-PILOT-v1"

SSHD = Path("/usr/sbin/sshd")
KEYGEN = Path("/usr/bin/ssh-keygen")

CONFIRMATION = "AUTORIZO_PILOTO_SSH_LOCAL"

TIMEOUT = 5.0
MAX_RECEIVE = 512


def need(condition, reason):

    if not condition:
        raise ValueError(reason)


def utc():

    return datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def canonical(value):

    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def digest(raw):

    return hashlib.sha256(raw).hexdigest()


def trusted_binary(path):

    real = path.resolve(strict=True)

    info = real.stat()

    need(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and not info.st_mode & 0o022
        and not info.st_mode & 0o6000
        and os.access(real, os.X_OK),
        "SYSTEM_BINARY_UNTRUSTED",
    )

    need(
        0 < info.st_size <= 64 * 1024 * 1024,
        "SYSTEM_BINARY_SIZE_INVALID",
    )

    return {
        "path": str(real),
        "sha256": digest(real.read_bytes()),
    }


def parse_banner(raw):

    need(
        type(raw) is bytes
        and 0 < len(raw) <= MAX_RECEIVE,
        "BANNER_SIZE_INVALID",
    )

    line = raw.split(b"\n", 1)[0]

    need(
        b"\n" in raw
        and line.endswith(b"\r")
        and len(line) + 1 <= 255,
        "BANNER_TERMINATOR_OR_LENGTH_INVALID",
    )

    line = line[:-1]

    need(
        re.fullmatch(
            rb"SSH-2\.0-[!-~]+(?: [ -~]+)?",
            line,
        ) is not None,
        "SSH_IDENTIFICATION_INVALID",
    )

    return line.decode("ascii")


def local_pair():

    listener = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    client = None
    peer = None

    try:

        listener.settimeout(TIMEOUT)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        address = listener.getsockname()

        client = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        client.settimeout(TIMEOUT)
        client.connect(address)

        peer, origin = listener.accept()

        need(
            origin == client.getsockname()
            and peer.getsockname() == address
            and client.getpeername() == address
            and address[0] == "127.0.0.1"
            and origin[0] == "127.0.0.1",
            "LOCAL_CONNECTION_IDENTITY_MISMATCH",
        )

        peer.setblocking(True)

        return client, peer

    except BaseException:

        if client is not None:
            client.close()

        if peer is not None:
            peer.close()

        raise

    finally:

        # Close listening socket before starting the SSH daemon.
        listener.close()


def receive_banner(client):

    buffer = bytearray()

    deadline = time.monotonic() + TIMEOUT

    while (
        len(buffer) < MAX_RECEIVE
        and b"\n" not in buffer
    ):

        remaining = deadline - time.monotonic()

        need(
            remaining > 0,
            "SSH_BANNER_TIMEOUT",
        )

        client.settimeout(remaining)

        chunk = client.recv(
            min(128, MAX_RECEIVE - len(buffer))
        )

        if not chunk:
            break

        buffer.extend(chunk)

    raw = bytes(buffer)

    return parse_banner(raw), raw


def group_exists(pid):

    try:
        os.killpg(pid, 0)
        return True

    except ProcessLookupError:
        return False


def stop_process(process):

    try:

        if group_exists(process.pid):

            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass

        if group_exists(process.pid):

            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        process.wait(timeout=2)

        deadline = time.monotonic() + 2

        while group_exists(process.pid):

            if time.monotonic() >= deadline:
                return False

            time.sleep(0.05)

        return True

    except (OSError, subprocess.TimeoutExpired):

        return False


def ssh_config(folder):

    return (
        f"HostKey {folder / 'host_ed25519'}\n"
        f"PidFile {folder / 'sshd.pid'}\n"
        "UsePAM no\n"
        "PasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\n"
        "PubkeyAuthentication no\n"
        "HostbasedAuthentication no\n"
        "GSSAPIAuthentication no\n"
        "PermitEmptyPasswords no\n"
        "PermitRootLogin no\n"
        "AllowTcpForwarding no\n"
        "AllowAgentForwarding no\n"
        "X11Forwarding no\n"
        "PermitTunnel no\n"
        "PermitTTY no\n"
        "PermitUserRC no\n"
        "PermitUserEnvironment no\n"
        "MaxSessions 0\n"
        "MaxAuthTries 1\n"
        "LoginGraceTime 5\n"
        "LogLevel ERROR\n"
    )


def run(confirmation):

    need(
        os.geteuid() != 0,
        "ROOT_EXECUTION_FORBIDDEN",
    )

    need(
        confirmation == CONFIRMATION,
        "EXPLICIT_CONSENT_REQUIRED",
    )

    report = {
        "schema": SCHEMA,
        "started_at_utc": utc(),
        "scope": "SELF_OWNED_LOCAL_EPHEMERAL_SSH",
        "human_operators": 1,
        "operator_uid": os.geteuid(),
        "independent_human_authority": False,
        "source_kind": "ACTUAL_LOCAL_OS_PROCESS",
        "status": "NOT_EXECUTED",
        "actual_sshd_started": False,
        "tcp_connections_established": 0,
        "client_application_bytes_sent": 0,
        "banner": None,
        "banner_sha256": None,
        "received_bytes": 0,
        "process_cleanup_verified": False,
        "temporary_workspace_removed": False,
        "historical_vm_access": False,
        "historical_contracts_changed": False,
        "authentication_attempts": 0,
        "remote_commands": 0,
        "physical_a5_admitted": False,
        "a6": "ND",
        "confirmed_rf": None,
        "operational_a9_published": False,
        "experimental_observations_admitted": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    }

    if not SSHD.is_file() or not KEYGEN.is_file():

        report["status"] = "SYSTEM_OPENSSH_UNAVAILABLE"

        report["completed_at_utc"] = utc()
        report["sha256"] = digest(canonical(report))

        return report

    process = None
    client = None
    peer = None

    cleanup = True

    try:

        report["sshd_binary"] = trusted_binary(SSHD)
        report["keygen_binary"] = trusted_binary(KEYGEN)

        with tempfile.TemporaryDirectory(
            prefix="ardrec-r192-"
        ) as temporary:

            folder = Path(temporary)

            need(
                stat.S_IMODE(folder.stat().st_mode)
                == 0o700,
                "PRIVATE_WORKSPACE_REQUIRED",
            )

            env = {
                "PATH": "/usr/bin:/bin:/usr/sbin",
                "LANG": "C",
                "LC_ALL": "C",
                "HOME": temporary,
            }

            subprocess.run(
                [
                    str(KEYGEN),
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(folder / "host_ed25519"),
                ],
                check=True,
                timeout=TIMEOUT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
            )

            config = folder / "sshd_config"

            config.write_text(
                ssh_config(folder),
                encoding="ascii",
            )

            config.chmod(0o600)

            report["configuration_sha256"] = digest(
                config.read_bytes()
            )

            report["ephemeral_public_key_sha256"] = digest(
                (
                    folder / "host_ed25519.pub"
                ).read_bytes()
            )

            try:

                client, peer = local_pair()

                report["tcp_connections_established"] = 1

                report["local_address"] = "127.0.0.1"

                report["local_port"] = (
                    client.getpeername()[1]
                )

                process = subprocess.Popen(
                    [
                        str(SSHD),
                        "-i",
                        "-e",
                        "-f",
                        str(config),
                    ],
                    stdin=peer,
                    stdout=peer,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    start_new_session=True,
                    cwd=temporary,
                    env=env,
                )

                report["actual_sshd_started"] = True

                peer.close()
                peer = None

                banner, raw = receive_banner(client)

                report["banner"] = banner
                report["banner_sha256"] = digest(
                    banner.encode("ascii")
                )

                report["received_bytes"] = len(raw)
                report["received_sha256"] = digest(raw)
                report["received_hex"] = raw.hex()

                report["status"] = (
                    "LOCAL_SSH_IDENTIFICATION_OBSERVED"
                )

            finally:

                if client is not None:
                    client.close()

                if peer is not None:
                    peer.close()

                if process is not None:

                    cleanup = stop_process(process)

                report["process_cleanup_verified"] = cleanup

        report["temporary_workspace_removed"] = (
            not folder.exists()
        )

    except (
        OSError,
        ValueError,
        subprocess.SubprocessError,
    ) as exc:

        report["status"] = "LOCAL_PILOT_INCOMPLETE"

        report["error_type"] = type(exc).__name__
        report["error_code"] = str(exc)[:160]

    if not cleanup:

        report["status"] = "PROCESS_CLEANUP_UNVERIFIED"

    if (
        report["status"] ==
        "LOCAL_SSH_IDENTIFICATION_OBSERVED"
        and not report["temporary_workspace_removed"]
    ):

        report["status"] = "WORKSPACE_CLEANUP_UNVERIFIED"

    report["completed_at_utc"] = utc()
    report["sha256"] = digest(canonical(report))

    return report


def main(argv=None):

    parser = argparse.ArgumentParser(
        description=__doc__,
    )

    parser.add_argument(
        "--confirm",
        required=True,
    )

    parser.add_argument(
        "--json",
        action="store_true",
        required=True,
    )

    args = parser.parse_args(argv)

    report = run(args.confirm)

    print(canonical(report).decode("ascii"))

    if (
        report["status"] ==
        "LOCAL_SSH_IDENTIFICATION_OBSERVED"
    ):

        return 0

    if (
        report["status"] ==
        "SYSTEM_OPENSSH_UNAVAILABLE"
    ):

        return 3

    return 4


if __name__ == "__main__":
    raise SystemExit(main())
