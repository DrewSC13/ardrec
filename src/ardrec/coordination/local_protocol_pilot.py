"""R194: bounded local FTP and SMB transport observations.

Not a vulnerability scanner or historical operational executor.
No login, file transfer or experimental admission.
"""
from __future__ import annotations

import argparse
import io
import tarfile
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
PYTHON = Path("/usr/bin/python3")

FTP_SOURCE_SHA256 = (
    "4ba0642078792df63dd3b2e9c8f838f2a"
    "3ecf428c7518d5921c0530d53512acf"
)
FTP_SOURCE_VERSION = "2.2.0"
FTP_SOURCE_MAX_BYTES = 250000
FTP_EXTRACT_MAX_BYTES = 4000000

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

    uid = os.getuid()
    gid = os.getgid()

    need(
        uid not in (0, 65534),
        "UNSUPPORTED_LOCAL_OPERATOR_UID",
    )

    etc = folder / "sandbox-etc"
    etc.mkdir(mode=0o700)

    passwd = (
        "root:x:0:0:root:/work:/usr/sbin/nologin\n"
        f"operator:x:{uid}:{gid}:operator:/work:/usr/sbin/nologin\n"
        "nobody:x:65534:65534:nobody:/work:/usr/sbin/nologin\n"
    )

    groups = {
        0: "root",
        65534: "nogroup",
    }

    if gid not in groups:

        groups[gid] = "operator"

    group = "".join(
        f"{name}:x:{number}:\n"
        for number, name in sorted(groups.items())
    )

    files = {
        "passwd": passwd,
        "group": group,
        "nsswitch.conf":
            "passwd: files\ngroup: files\nhosts: files\n",
        "hosts":
            "127.0.0.1 localhost ardrecpilot\n",
        "hostname":
            "ardrecpilot\n",
    }

    for name, content in files.items():

        path = etc / name

        with path.open("x", encoding="ascii") as handle:
            handle.write(content)

        path.chmod(0o600)

    args = [
        str(BWRAP),
        "--unshare-all",
        "--die-with-parent",
        "--cap-drop", "ALL",
        "--clearenv",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/sbin", "/sbin",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/run",
        "--tmpfs", "/tmp",
        "--tmpfs", "/var",
        "--dir", "/etc",
        "--dir", "/run/samba",
        "--dir", "/var/lib/samba",
        "--dir", "/var/cache/samba",
    ]

    for name in files:

        args.extend([
            "--ro-bind",
            str(etc / name),
            f"/etc/{name}",
        ])

    args.extend([
        "--bind", str(folder), "/work",
        "--chdir", "/work",
        "--setenv", "HOME", "/work",
        "--setenv", "PATH", "/usr/bin:/usr/sbin",
        "--setenv", "LANG", "C",
        "--setenv", "LC_ALL", "C",
        "--",
        *command,
    ])

    return info, args


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



def prepare_ftp_source(archive, folder):

    with Path(archive).open("rb") as handle:

        raw = handle.read(
            FTP_SOURCE_MAX_BYTES + 1
        )

    need(
        0 < len(raw) <= FTP_SOURCE_MAX_BYTES,
        "FTP_SOURCE_SIZE_INVALID",
    )

    need(
        ssh.digest(raw) == FTP_SOURCE_SHA256,
        "FTP_SOURCE_SHA256_INVALID",
    )

    vendor = folder / "vendor"
    vendor.mkdir(mode=0o700)

    extracted = 0
    files = 0

    with tarfile.open(
        fileobj=io.BytesIO(raw),
        mode="r:gz",
    ) as archive_file:

        for member in archive_file:

            parts = Path(member.name).parts

            need(
                bool(parts)
                and not Path(member.name).is_absolute()
                and ".." not in parts,
                "FTP_ARCHIVE_PATH_INVALID",
            )

            if (
                len(parts) < 3
                or parts[0] != "pyftpdlib-2.2.0"
                or parts[1] != "pyftpdlib"
                or not member.name.endswith(".py")
            ):

                continue

            need(
                member.isfile()
                and 0 <= member.size <= 1000000,
                "FTP_ARCHIVE_MEMBER_INVALID",
            )

            extracted += member.size
            files += 1

            need(
                extracted <= FTP_EXTRACT_MAX_BYTES
                and files <= 200,
                "FTP_ARCHIVE_EXTRACTION_LIMIT",
            )

            destination = vendor.joinpath(*parts[1:])

            destination.parent.mkdir(
                mode=0o700,
                parents=True,
                exist_ok=True,
            )

            source = archive_file.extractfile(member)

            need(
                source is not None,
                "FTP_ARCHIVE_MEMBER_UNREADABLE",
            )

            with source:

                content = source.read(
                    member.size + 1
                )

            need(
                len(content) == member.size,
                "FTP_ARCHIVE_MEMBER_SIZE_MISMATCH",
            )

            with destination.open("xb") as output:

                output.write(content)

    need(
        (vendor / "pyftpdlib/__init__.py").is_file(),
        "FTP_PACKAGE_ENTRY_MISSING",
    )

    return {
        "version": FTP_SOURCE_VERSION,
        "archive_sha256": FTP_SOURCE_SHA256,
        "source_files": files,
        "source_bytes": extracted,
        "installation_performed": False,
    }


FTP_RUNNER = """\
import os
import socket
import sys
import time

sys.path.insert(0, "/work/vendor")

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

FTPHandler.authorizer = DummyAuthorizer()
FTPHandler.timeout = 5
FTPHandler.max_login_attempts = 1

# No users and no application commands are admitted.
FTPHandler.proto_cmds = {}

peer = socket.socket(fileno=os.dup(0))

# This listener exists only within the isolated namespace.
server = FTPServer(("127.0.0.1", 0), FTPHandler)
server.max_cons = 2
server.max_cons_per_ip = 1

try:
    handler = server.handle_accepted(
        peer, peer.getpeername()
    )

    if handler is None:
        raise RuntimeError("FTP_HANDLER_NOT_STARTED")

    deadline = time.monotonic() + 5.0

    while handler.connected and time.monotonic() < deadline:
        server.serve_forever(
            timeout=0.1,
            blocking=False,
            handle_exit=False,
        )

finally:
    server.close_all()
    peer.close()
"""


def evaluate(protocol, ftp_source=None):

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

            if binary is None and ftp_source is not None:

                implementation = "PYFTPDLIB_PINNED_SOURCE"
                binary = PYTHON

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

        elif implementation == "PYFTPDLIB_PINNED_SOURCE":

            result["ftp_dependency"] = prepare_ftp_source(
                ftp_source,
                folder,
            )

            runner = folder / "ftp_runner.py"

            with runner.open(
                "x", encoding="ascii"
            ) as handle:

                handle.write(FTP_RUNNER)

            result["runner_sha256"] = ssh.digest(
                runner.read_bytes()
            )

            result["sandbox_requested"] = True

            info, command = sandbox(
                folder,
                [
                    str(binary),
                    "-I",
                    "-B",
                    "/work/ftp_runner.py",
                ],
            )

            result["sandbox_binary"] = info

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

                if protocol == "SMB":

                    log = folder / "log.smbd"

                    if (
                        log.is_file()
                        and not log.is_symlink()
                    ):

                        with log.open("rb") as handle:

                            result["samba_log_excerpt"] = (
                                handle.read(4096).decode(
                                    "utf-8",
                                    errors="replace",
                                )
                            )

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


def run(confirmation, ftp_source=None):

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

        record = evaluate(
            protocol,
            ftp_source=ftp_source
            if protocol == "FTP"
            else None,
        )

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

    parser.add_argument(
        "--ftp-source",
        type=Path,
        default=None,
        help="Pinned pyftpdlib source archive for local FTP fallback",
    )

    args = parser.parse_args(argv)

    report = run(
        args.confirm,
        ftp_source=args.ftp_source,
    )

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
