"""R194: bounded local FTP and SMB transport observations.

Not a vulnerability scanner or historical operational executor.
No login, file transfer or experimental admission.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import subprocess
import tempfile
import time

from pathlib import Path

from . import local_ssh_pilot as ssh


SCHEMA = "ARDREC-R194-LOCAL-PROTOCOL-PILOT-v1"
CONFIRM = "AUTORIZO_PILOTO_FTP_SMB_LOCAL"

MAX_FTP = 4096
MAX_SMB = 16384
TIMEOUT = 5.0

BUSYBOX = Path("/usr/bin/busybox")
VSFTPD = Path("/usr/sbin/vsftpd")
SMBD = Path("/usr/sbin/smbd")
BWRAP = Path("/usr/bin/bwrap")

DIALECTS = (0x0202, 0x0210)


def need(condition, reason):

    if not condition:
        raise ValueError(reason)


def parse_ftp(raw):

    need(
        type(raw) is bytes
        and 0 < len(raw) <= MAX_FTP
        and raw.endswith(b"\r\n"),
        "FTP_RESPONSE_INVALID",
    )

    lines = raw[:-2].split(b"\r\n")

    need(
        all(
            len(line) <= 512
            and all(32 <= c <= 126 for c in line)
            for line in lines
        ),
        "FTP_RESPONSE_FORMAT_INVALID",
    )

    if len(lines) == 1:

        need(
            lines[0].startswith(b"220 "),
            "FTP_GREETING_NOT_220",
        )

    else:

        need(
            lines[0].startswith(b"220-")
            and lines[-1].startswith(b"220 "),
            "FTP_MULTILINE_INVALID",
        )

    return {
        "reply_code": 220,
        "lines": [
            line.decode("ascii")
            for line in lines
        ],
    }


def smb_request():

    # Standard SMB2 NEGOTIATE only.
    header = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",
        64,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        bytes(16),
    )

    body = struct.pack(
        "<HHHHI16sIHH",
        36,
        len(DIALECTS),
        1,
        0,
        0,
        bytes.fromhex(
            "41524452454344455650494c4f543031"
        ),
        0,
        0,
        0,
    )

    payload = header + body + struct.pack(
        "<HH",
        *DIALECTS,
    )

    return len(payload).to_bytes(4, "big") + payload


def parse_smb(raw):

    need(
        type(raw) is bytes
        and 132 <= len(raw) <= MAX_SMB + 4,
        "SMB_RESPONSE_SIZE_INVALID",
    )

    need(
        raw[0] == 0
        and int.from_bytes(raw[:4], "big") ==
            len(raw) - 4,
        "SMB_FRAME_INVALID",
    )

    payload = raw[4:]

    need(
        payload[:4] == b"\xfeSMB"
        and struct.unpack_from(
            "<H", payload, 4
        )[0] == 64,
        "SMB_HEADER_INVALID",
    )

    status = struct.unpack_from(
        "<I", payload, 8
    )[0]

    command = struct.unpack_from(
        "<H", payload, 12
    )[0]

    flags = struct.unpack_from(
        "<I", payload, 16
    )[0]

    message_id = struct.unpack_from(
        "<Q", payload, 24
    )[0]

    need(
        status == 0
        and command == 0
        and flags & 1
        and message_id == 0,
        "SMB_NEGOTIATE_NOT_SUCCESSFUL",
    )

    size, security_mode, dialect = (
        struct.unpack_from(
            "<HHH", payload, 64
        )
    )

    need(
        size == 65
        and dialect in DIALECTS,
        "SMB_NEGOTIATE_BODY_INVALID",
    )

    security_offset, security_length = (
        struct.unpack_from(
            "<HH", payload, 120
        )
    )

    if security_length:

        need(
            security_offset >= 128
            and security_offset +
                security_length <= len(payload),
            "SMB_SECURITY_BUFFER_INVALID",
        )

    return {
        "command": "SMB2_NEGOTIATE",
        "status": 0,
        "dialect": f"0x{dialect:04x}",
        "security_mode": security_mode,
    }


def read_exact(client, count, deadline):

    data = bytearray()

    while len(data) < count:

        remaining = deadline - time.monotonic()

        need(
            remaining > 0,
            "RESPONSE_TIMEOUT",
        )

        client.settimeout(remaining)

        chunk = client.recv(
            count - len(data)
        )

        need(
            bool(chunk),
            "RESPONSE_TRUNCATED",
        )

        data.extend(chunk)

    return bytes(data)


def receive_ftp(client):

    deadline = time.monotonic() + TIMEOUT
    data = bytearray()

    while len(data) < MAX_FTP:

        data.extend(
            read_exact(client, 1, deadline)
        )

        if data.endswith(b"\r\n"):

            lines = bytes(data).split(b"\r\n")

            if lines[-2].startswith(b"220 "):

                raw = bytes(data)

                return raw, parse_ftp(raw)

            if (
                len(lines) == 2
                and not lines[0].startswith(b"220-")
            ):

                raise ValueError(
                    "FTP_GREETING_NOT_220"
                )

    raise ValueError(
        "FTP_RESPONSE_LIMIT_REACHED"
    )


def receive_smb(client):

    deadline = time.monotonic() + TIMEOUT

    header = read_exact(
        client, 4, deadline
    )

    length = int.from_bytes(
        header, "big"
    )

    need(
        header[0] == 0
        and 128 <= length <= MAX_SMB,
        "SMB_FRAME_LENGTH_INVALID",
    )

    raw = header + read_exact(
        client, length, deadline
    )

    return raw, parse_smb(raw)


def ftp_config():

    return (
        "listen=NO\n"
        "listen_ipv6=NO\n"
        "anonymous_enable=NO\n"
        "local_enable=NO\n"
        "write_enable=NO\n"
        "download_enable=NO\n"
        "dirlist_enable=NO\n"
        "port_enable=NO\n"
        "pasv_enable=NO\n"
        "run_as_launching_user=YES\n"
        "tcp_wrappers=NO\n"
        "xferlog_enable=NO\n"
        "idle_session_timeout=5\n"
        "data_connection_timeout=5\n"
    )


def smb_config():

    return """[global]
server role = standalone server
workgroup = ARDREC
netbios name = ARDRECPILOT
interfaces = 127.0.0.1
bind interfaces only = yes
disable netbios = yes
smb ports = 14445
server min protocol = SMB2_02
server max protocol = SMB2_10
map to guest = Never
load printers = no
disable spoolss = yes
printing = bsd
printcap name = /dev/null
usershare max shares = 0
private dir = /work/private
state directory = /work/state
cache directory = /work/cache
lock directory = /work/lock
pid directory = /work/pid
log file = /work/log.smbd
log level = 0
passdb backend = tdbsam
"""


def sandbox(folder, command):

    info = ssh.trusted_binary(BWRAP)

    return info, [
        str(BWRAP),
        "--unshare-all",
        "--die-with-parent",
        "--cap-drop", "ALL",
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/run",
        "--tmpfs", "/tmp",
        "--bind", str(folder), "/work",
        "--chdir", "/work",
        "--setenv", "HOME", "/work",
        "--",
        *command,
    ]


def select_ftp():

    if BUSYBOX.is_file():

        ssh.trusted_binary(BUSYBOX)

        result = subprocess.run(
            [str(BUSYBOX), "--list"],
            capture_output=True,
            check=False,
            timeout=TIMEOUT,
            stdin=subprocess.DEVNULL,
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
            },
        )

        if (
            result.returncode == 0
            and len(result.stdout) <= 65536
            and b"ftpd" in result.stdout.splitlines()
        ):

            return "BUSYBOX_FTPD", BUSYBOX

    if VSFTPD.is_file():

        return "VSFTPD", VSFTPD

    return None, None


def evaluate(protocol):

    need(
        protocol in ("FTP", "SMB"),
        "PROTOCOL_INVALID",
    )

    need(
        os.geteuid() != 0,
        "ROOT_EXECUTION_FORBIDDEN",
    )

    result = {
        "protocol": protocol,
        "started_at_utc": ssh.utc(),
        "status": "NOT_EXECUTED",
        "implementation": None,
        "process_started": False,
        "tcp_connections": 0,
        "client_application_bytes": 0,
        "authentication_attempts": 0,
        "file_operations": 0,
        "historical_vm_access": False,
        "received_hex": None,
        "received_sha256": None,
        "parsed_response": None,
        "process_cleanup_verified": True,
        "workspace_removed": True,
        "sandbox_requested": False,
        "sandbox_isolation_independently_attested": False,
        "a6": "ND",
        "confirmed_rf": None,
        "experimental_admission": False,
    }

    process = None
    client = peer = None
    folder = None
    tmp = None

    try:

        if protocol == "FTP":

            implementation, binary = select_ftp()

        else:

            implementation = "SAMBA_SMBD"
            binary = SMBD

        if binary is None or not binary.is_file():

            result["status"] = (
                "DEPENDENCY_UNAVAILABLE"
            )

            return result

        result["implementation"] = implementation
        result["binary"] = ssh.trusted_binary(binary)

        if (
            implementation != "BUSYBOX_FTPD"
            and not BWRAP.is_file()
        ):

            result["status"] = (
                "SANDBOX_DEPENDENCY_UNAVAILABLE"
            )

            return result

        tmp = tempfile.TemporaryDirectory(
            prefix="ardrec-r194-"
        )

        folder = Path(tmp.name)

        result["workspace_removed"] = False

        if implementation == "BUSYBOX_FTPD":

            # No write option and no login command sent.
            command = [
                str(binary),
                "ftpd",
                str(folder),
            ]

        elif implementation == "VSFTPD":

            cfg = ftp_config()

            (folder / "vsftpd.conf").write_text(
                cfg, encoding="ascii"
            )

            result["configuration_sha256"] = (
                ssh.digest(cfg.encode("ascii"))
            )

            result["sandbox_requested"] = True

            info, command = sandbox(
                folder,
                [
                    str(binary),
                    "/work/vsftpd.conf",
                ],
            )

            result["sandbox_binary"] = info

        else:

            for name in (
                "private", "state",
                "cache", "lock", "pid",
            ):

                (folder / name).mkdir(
                    mode=0o700
                )

            cfg = smb_config()

            (folder / "smb.conf").write_text(
                cfg, encoding="ascii"
            )

            result["configuration_sha256"] = (
                ssh.digest(cfg.encode("ascii"))
            )

            result["sandbox_requested"] = True

            info, command = sandbox(
                folder,
                [
                    str(binary),
                    "--no-process-group",
                    "--configfile=/work/smb.conf",
                    "--log-basename=/work",
                ],
            )

            result["sandbox_binary"] = info

        client, peer = ssh.local_pair()

        result["tcp_connections"] = 1
        result["local_address"] = "127.0.0.1"

        with tempfile.TemporaryFile() as diagnostics:

            try:

                process = subprocess.Popen(
                    command,
                    stdin=peer,
                    stdout=peer,
                    stderr=diagnostics,
                    close_fds=True,
                    start_new_session=True,
                    cwd=str(folder),
                    env={
                        "PATH": "/usr/bin:/bin:/usr/sbin",
                        "LANG": "C",
                        "LC_ALL": "C",
                        "HOME": str(folder),
                    },
                )

                result["process_started"] = True

                peer.close()
                peer = None

                if protocol == "FTP":

                    raw, parsed = receive_ftp(
                        client
                    )

                else:

                    request = smb_request()

                    client.settimeout(TIMEOUT)
                    client.sendall(request)

                    result[
                        "client_application_bytes"
                    ] = len(request)

                    result["request_sha256"] = (
                        ssh.digest(request)
                    )

                    raw, parsed = receive_smb(
                        client
                    )

                result["received_hex"] = raw.hex()

                result["received_sha256"] = (
                    ssh.digest(raw)
                )

                result["parsed_response"] = parsed

                result["status"] = (
                    "FTP_GREETING_OBSERVED"
                    if protocol == "FTP"
                    else "SMB2_NEGOTIATION_OBSERVED"
                )

            finally:

                if client is not None:
                    client.close()
                    client = None

                if peer is not None:
                    peer.close()
                    peer = None

                if process is not None:

                    result[
                        "process_cleanup_verified"
                    ] = ssh.stop_process(process)

                    result["process_returncode"] = (
                        process.returncode
                    )

                    process = None

                diagnostics.seek(0)

                result["diagnostics"] = (
                    diagnostics.read(2048)
                    .decode(
                        "utf-8",
                        errors="replace",
                    )
                )

    except (
        OSError,
        ValueError,
        subprocess.SubprocessError,
    ) as exc:

        result["status"] = "INCOMPLETE"

        result["error_type"] = (
            type(exc).__name__
        )

        result["error_code"] = str(exc)[:160]

    finally:

        if client is not None:
            client.close()

        if peer is not None:
            peer.close()

        if process is not None:

            result["process_cleanup_verified"] = (
                ssh.stop_process(process)
            )

        if tmp is not None:

            tmp.cleanup()

            result["workspace_removed"] = (
                not folder.exists()
            )

        if not (
            result["process_cleanup_verified"]
            and result["workspace_removed"]
        ):

            result["status"] = (
                "CLEANUP_UNVERIFIED"
            )

        result["completed_at_utc"] = ssh.utc()

        result["sha256"] = ssh.digest(
            ssh.canonical(result)
        )

    return result


def run(confirmation):

    need(
        confirmation == CONFIRM,
        "EXPLICIT_CONSENT_REQUIRED",
    )

    need(
        os.geteuid() != 0,
        "ROOT_EXECUTION_FORBIDDEN",
    )

    results = []

    for protocol in ("FTP", "SMB"):

        record = evaluate(protocol)

        results.append(record)

        if record["status"] == "CLEANUP_UNVERIFIED":
            break

    report = {
        "schema": SCHEMA,
        "scope": "LOCAL_EPHEMERAL_TRANSPORT",
        "human_operators": 1,
        "results": results,
        "real_transport_observations": sum(
            record["status"] in (
                "FTP_GREETING_OBSERVED",
                "SMB2_NEGOTIATION_OBSERVED",
            )
            for record in results
        ),
        "historical_contracts_changed": False,
        "physical_a5_admitted": False,
        "a6": "ND",
        "confirmed_rf": None,
        "operational_a9_published": False,
        "experimental_observations_admitted": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    }

    report["sha256"] = ssh.digest(
        ssh.canonical(report)
    )

    return report


def main(argv=None):

    parser = argparse.ArgumentParser(
        description=__doc__
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

    print(
        ssh.canonical(report).decode("ascii")
    )

    if any(
        record["status"] == "CLEANUP_UNVERIFIED"
        for record in report["results"]
    ):

        return 4

    if report["real_transport_observations"] == 2:

        return 0

    return 3


if __name__ == "__main__":
    raise SystemExit(main())
