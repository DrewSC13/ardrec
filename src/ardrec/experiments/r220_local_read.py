"""R220: lectura SSH/SFTP y SMB en fixtures locales aislados.

Bounded local read verification over synthetic resources.

No historical authorization, arbitrary targets, shell execution,
operational evidence admission or experimental admission.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile

from pathlib import Path

from ardrec.coordination import local_ssh_pilot as ssh
from ardrec.coordination import local_protocol_pilot as transport
from ardrec.coordination import prospective_local_pilot as durable
from ardrec.experiments import functional_local_fixtures as previous


SCHEMA = "ARDREC-R220-LOCAL-READ-v1"

CASES = (
    ("PILOT-SSH-01", "SSH", "CONTROL"),
    ("PILOT-SSH-02", "SSH", "CONTRAST"),
    ("PILOT-SMB-01", "SMB", "CONTROL"),
    ("PILOT-SMB-02", "SMB", "CONTRAST"),
)

ALLOWED = b"ARDREC-R220-SYNTHETIC-ALLOWED\n"
RESTRICTED = b"ARDREC-R220-SYNTHETIC-RESTRICTED\n"

LIMIT = 1024

PREFIX = previous.RUNNER.split(
    "def ssh_fixture():", 1
)[0]

RUNNER = PREFIX + r'''

import errno
import stat

ALLOWED = b"ARDREC-R220-SYNTHETIC-ALLOWED\n"
RESTRICTED = b"ARDREC-R220-SYNTHETIC-RESTRICTED\n"
LIMIT = 1024

RESOURCE_NAMES = ("allowed.txt", "restricted.txt")


def bounded_read(handle):

    result = handle.read(LIMIT + 1)

    need(
        len(result) <= LIMIT,
        "READ_LIMIT_EXCEEDED",
    )

    return result


def read_record(status, content):

    return {
        "status": status,
        "bytes": len(content),
        "sha256": digest(content),
    }


def ssh_read():

    import paramiko

    versions = {
        "paramiko":
            importlib.metadata.version("paramiko"),
        "cryptography":
            importlib.metadata.version("cryptography"),
    }

    need(
        versions == {
            "paramiko": "5.0.0",
            "cryptography": "49.0.0",
        },
        "SSH_DEPENDENCY_VERSION_INVALID",
    )

    host_key = paramiko.RSAKey.generate(2048)
    client_key = paramiko.RSAKey.generate(2048)

    username = "ardrec_fixture"

    completed = threading.Event()
    errors = []

    class Server(paramiko.ServerInterface):

        def get_allowed_auths(self, user):

            return "publickey"

        def check_auth_publickey(self, user, key):

            if (
                user == username
                and key.asbytes() == client_key.asbytes()
            ):

                return paramiko.AUTH_SUCCESSFUL

            return paramiko.AUTH_FAILED

        def check_channel_request(self, kind, channel_id):

            if kind == "session":

                return paramiko.OPEN_SUCCEEDED

            return (
                paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            )

    class ReadOnlySFTP(paramiko.SFTPServerInterface):

        def open(self, path, flags, attr):

            if path not in RESOURCE_NAMES:

                return paramiko.SFTP_PERMISSION_DENIED

            if flags != os.O_RDONLY:

                return paramiko.SFTP_PERMISSION_DENIED

            try:

                source = Path("/work/data") / path

                handle = paramiko.SFTPHandle(flags)
                handle.readfile = source.open("rb")

                return handle

            except OSError as exc:

                return paramiko.SFTPServer.convert_errno(
                    exc.errno
                )

    listener = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    listener.settimeout(8)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    port = listener.getsockname()[1]

    def serve():

        server_transport = None
        peer = None

        try:

            peer, address = listener.accept()

            need(
                address[0] == "127.0.0.1",
                "SSH_PEER_INVALID",
            )

            server_transport = paramiko.Transport(peer)

            server_transport.add_server_key(host_key)

            server_transport.set_subsystem_handler(
                "sftp",
                paramiko.SFTPServer,
                ReadOnlySFTP,
            )

            server_transport.start_server(
                server=Server()
            )

            need(
                completed.wait(20),
                "SSH_CLIENT_TIMEOUT",
            )

        except Exception as exc:

            errors.append(type(exc).__name__)

        finally:

            if server_transport is not None:
                server_transport.close()

            if peer is not None:
                peer.close()

    worker = threading.Thread(
        target=serve,
        daemon=True,
    )

    worker.start()

    client = None
    session = None

    try:

        connection = socket.create_connection(
            ("127.0.0.1", port),
            timeout=5,
        )

        client = paramiko.Transport(connection)

        client.connect(
            hostkey=host_key,
            username=username,
            pkey=client_key,
        )

        need(
            client.is_authenticated(),
            "SSH_AUTHENTICATION_FAILED",
        )

        need(
            client.get_remote_server_key().asbytes()
            == host_key.asbytes(),
            "SSH_HOST_IDENTITY_INVALID",
        )

        session = paramiko.SFTPClient.from_transport(
            client
        )

        session.get_channel().settimeout(5)

        records = {}

        for name in RESOURCE_NAMES:

            try:

                with session.open(name, "rb") as handle:

                    content = bounded_read(handle)

                records[name] = read_record(
                    "READ_OK",
                    content,
                )

            except PermissionError:

                records[name] = read_record(
                    "ACCESS_DENIED",
                    b"",
                )

        return {
            "backend": "PARAMIKO_SFTP_USERSPACE",
            "versions": versions,
            "authenticated": True,
            "server_identity_verified": True,
            "operation": "FIXED_SYNTHETIC_SFTP_READ",
            "resources": records,
            "arbitrary_commands_requested": 0,
            "write_operations_requested": 0,
        }

    finally:

        try:

            if session is not None:
                session.close()

        finally:

            completed.set()

            if client is not None:
                client.close()

            listener.close()
            worker.join(timeout=5)

        need(
            not worker.is_alive() and not errors,
            "SSH_CLEANUP_INVALID",
        )


def smb_read():

    from impacket import smbserver
    from impacket import nt_errors

    from impacket.ntlm import (
        compute_lmhash,
        compute_nthash,
    )

    from impacket.smbconnection import (
        SMBConnection,
        SessionError,
    )

    from impacket.smb3structs import SMB2_DIALECT_002

    versions = {
        "impacket":
            importlib.metadata.version("impacket")
    }

    need(
        versions == {"impacket": "0.13.1"},
        "SMB_DEPENDENCY_VERSION_INVALID",
    )

    username = "ardrec_fixture"
    password = secrets.token_urlsafe(24)

    server = smbserver.SimpleSMBServer(
        listenAddress="127.0.0.1",
        listenPort=0,
    )

    server.setSMB2Support(True)
    server.setKerberosSupport(False)
    server.setNTLMSupport(True)
    server.setSMBChallenge(secrets.token_hex(8))

    server.addShare(
        "ARDRECDATA",
        "/work/data",
        "Synthetic read-only fixture",
        readOnly="yes",
    )

    server.addCredential(
        username,
        1,
        compute_lmhash(password),
        compute_nthash(password),
    )

    core = server.getServer()

    need(
        core.server_address[0] == "127.0.0.1",
        "SMB_LISTENER_INVALID",
    )

    worker = threading.Thread(
        target=core.serve_forever,
        kwargs={"poll_interval": 0.1},
        daemon=True,
    )

    worker.start()

    client = None

    try:

        client = SMBConnection(
            remoteName="127.0.0.1",
            remoteHost="127.0.0.1",
            sess_port=core.server_address[1],
            timeout=5,
            preferredDialect=SMB2_DIALECT_002,
        )

        client.login(username, password)

        need(
            not client.isGuestSession(),
            "SMB_GUEST_SESSION_REJECTED",
        )

        need(
            client.getDialect() == SMB2_DIALECT_002,
            "SMB_DIALECT_INVALID",
        )

        records = {}

        for name in RESOURCE_NAMES:

            received = bytearray()

            def consume(chunk):

                need(
                    len(received) + len(chunk) <= LIMIT,
                    "SMB_READ_LIMIT_EXCEEDED",
                )

                received.extend(chunk)

            try:

                client.getFile(
                    "ARDRECDATA",
                    name,
                    consume,
                )

                records[name] = read_record(
                    "READ_OK",
                    bytes(received),
                )

            except SessionError as exc:

                need(
                    exc.getErrorCode()
                    == nt_errors.STATUS_ACCESS_DENIED,
                    "SMB_UNCLASSIFIED_RESPONSE",
                )

                need(
                    not received,
                    "SMB_PARTIAL_TRANSFER_ON_DENIAL",
                )

                records[name] = read_record(
                    "ACCESS_DENIED",
                    b"",
                )

        client.logoff()

        return {
            "backend": "IMPACKET_USERSPACE",
            "versions": versions,
            "authenticated": True,
            "guest_session": False,
            "dialect": "0x202",
            "share_read_only_configured": True,
            "operation": "FIXED_SYNTHETIC_SMB_READ",
            "resources": records,
            "arbitrary_commands_requested": 0,
            "write_operations_requested": 0,
        }

    finally:

        try:

            if client is not None:
                client.close()

        finally:

            core.shutdown()
            core.server_close()
            worker.join(timeout=5)

        need(
            not worker.is_alive(),
            "SMB_CLEANUP_INVALID",
        )


def main():

    logging.disable(logging.CRITICAL)

    protocol, profile, host = sys.argv[1:]

    need(
        protocol in ("SSH", "SMB"),
        "PROTOCOL_INVALID",
    )

    need(
        profile in ("CONTROL", "CONTRAST"),
        "PROFILE_INVALID",
    )

    isolated = isolation(host)

    folder = Path("/work/data")

    allowed = folder / "allowed.txt"
    restricted = folder / "restricted.txt"

    need(
        sorted(p.name for p in folder.iterdir())
        == sorted(RESOURCE_NAMES),
        "FIXTURE_DIRECTORY_INVALID",
    )

    need(
        allowed.read_bytes() == ALLOWED
        and restricted.read_bytes() == RESTRICTED,
        "FIXTURE_CONTENT_INVALID",
    )

    expected_mode = (
        0o000 if profile == "CONTROL" else 0o400
    )

    try:

        restricted.chmod(expected_mode)

        effective_mode = stat.S_IMODE(
            restricted.stat().st_mode
        )

        need(
            effective_mode == expected_mode,
            "EFFECTIVE_POLICY_INVALID",
        )

        if protocol == "SSH":

            result = ssh_read()

        else:

            result = smb_read()

    finally:

        restricted.chmod(0o400)

    need(
        allowed.read_bytes() == ALLOWED
        and restricted.read_bytes() == RESTRICTED,
        "FIXTURE_CONTENT_CHANGED",
    )

    need(
        sorted(p.name for p in folder.iterdir())
        == sorted(RESOURCE_NAMES),
        "FIXTURE_DIRECTORY_CHANGED",
    )

    need(
        isolation(host) == isolated,
        "FINAL_ISOLATION_CHANGED",
    )

    result.update({
        "protocol": protocol,
        "profile": profile,
        "effective_restricted_mode": effective_mode,
        "source_unchanged": True,
        "server_cleanup_verified": True,
        "operations_requested": 2,
        "authentication_requests_planned": 1,
        "isolation": isolated,
    })

    print(json.dumps(
        result,
        sort_keys=True,
        separators=(",", ":"),
    ))


main()
'''


def digest(value):

    return hashlib.sha256(value).hexdigest()


def need(condition, reason):

    if not condition:

        raise ValueError(reason)


def verify_observation(protocol, profile, result, host):

    need(
        protocol in ("SSH", "SMB")
        and profile in ("CONTROL", "CONTRAST"),
        "CASE_INVALID",
    )

    isolated = result["isolation"]

    need(
        isolated["host_namespace"] == host
        and isolated["child_namespace"] != host
        and isolated["interfaces"] == ["lo"]
        and isolated["endpoint"] == "127.0.0.1"
        and isolated["effective_uid"] > 0
        and int(
            isolated["effective_capabilities"], 16
        ) == 0,
        "ISOLATION_INVALID",
    )

    need(
        result["protocol"] == protocol
        and result["profile"] == profile
        and result["authenticated"] is True
        and result["source_unchanged"] is True
        and result["server_cleanup_verified"] is True
        and result["operations_requested"] == 2
        and result["authentication_requests_planned"] == 1
        and result["write_operations_requested"] == 0
        and result["arbitrary_commands_requested"] == 0,
        "OPERATION_INVALID",
    )

    resources = result["resources"]

    need(
        set(resources)
        == {"allowed.txt", "restricted.txt"},
        "RESOURCE_SET_INVALID",
    )

    need(
        resources["allowed.txt"] == {
            "status": "READ_OK",
            "bytes": len(ALLOWED),
            "sha256": digest(ALLOWED),
        },
        "AUTHORIZED_RESOURCE_INVALID",
    )

    if profile == "CONTROL":

        need(
            result["effective_restricted_mode"] == 0
            and resources["restricted.txt"] == {
                "status": "ACCESS_DENIED",
                "bytes": 0,
                "sha256": digest(b""),
            },
            "CONTROL_RESULT_INVALID",
        )

    else:

        need(
            result["effective_restricted_mode"] == 0o400
            and resources["restricted.txt"] == {
                "status": "READ_OK",
                "bytes": len(RESTRICTED),
                "sha256": digest(RESTRICTED),
            },
            "CONTRAST_RESULT_INVALID",
        )

    if protocol == "SSH":

        need(
            result["backend"]
                == "PARAMIKO_SFTP_USERSPACE"
            and result["server_identity_verified"] is True
            and result["operation"]
                == "FIXED_SYNTHETIC_SFTP_READ"
            and result["versions"]
                == previous.VERSIONS["SSH"],
            "SSH_CONTRACT_INVALID",
        )

    else:

        need(
            result["backend"]
                == "IMPACKET_USERSPACE"
            and result["guest_session"] is False
            and result["dialect"] == "0x202"
            and result["share_read_only_configured"] is True
            and result["operation"]
                == "FIXED_SYNTHETIC_SMB_READ"
            and result["versions"]
                == previous.VERSIONS["SMB"],
            "SMB_CONTRACT_INVALID",
        )

    return True


def run_fixture(folder, protocol, profile):

    """Internal fixture runner; not an operational dispatcher."""

    need(os.geteuid() != 0, "ROOT_FORBIDDEN")

    need(
        protocol in ("SSH", "SMB")
        and profile in ("CONTROL", "CONTRAST"),
        "CASE_INVALID",
    )

    folder = Path(folder)
    folder.mkdir(mode=0o700, exist_ok=False)

    host = os.readlink("/proc/self/ns/net")

    with tempfile.TemporaryDirectory(
        prefix="ardrec-r220-"
    ) as temporary:

        work = Path(temporary)

        runner = work / "runner.py"

        runner.write_text(
            RUNNER,
            encoding="ascii",
        )

        runner.chmod(0o400)

        data = work / "data"
        data.mkdir(mode=0o700)

        for name, payload in (
            ("allowed.txt", ALLOWED),
            ("restricted.txt", RESTRICTED),
        ):

            path = data / name

            path.write_bytes(payload)
            path.chmod(0o400)

        python_info = ssh.trusted_binary(
            transport.PYTHON
        )

        sandbox_info, command = transport.sandbox(
            work,
            [
                str(transport.PYTHON),
                "-I",
                "-B",
                "/work/runner.py",
                protocol,
                profile,
                host,
            ],
        )

        durable.write_once(
            folder / "fixture-context.json",
            durable.seal({
                "schema": SCHEMA + "-fixture-context",
                "protocol": protocol,
                "profile": profile,
                "runner_sha256": digest(
                    RUNNER.encode("ascii")
                ),
                "allowed_sha256": digest(ALLOWED),
                "restricted_sha256": digest(RESTRICTED),
                "python_binary": python_info,
                "sandbox_binary": sandbox_info,
                "host_namespace": host,
                "started_at_utc": ssh.utc(),
                "experimental_admission": False,
            }),
        )

        try:

            process = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=45,
                check=False,
            )

            (folder / "stdout.bin").write_bytes(
                process.stdout
            )

            (folder / "stderr.bin").write_bytes(
                process.stderr
            )

            need(
                process.returncode == 0,
                "FIXTURE_PROCESS_FAILED",
            )

            need(
                0 < len(process.stdout) <= 16384,
                "FIXTURE_OUTPUT_INVALID",
            )

            observation = json.loads(process.stdout)

            verify_observation(
                protocol,
                profile,
                observation,
                host,
            )

            need(
                (data / "allowed.txt").read_bytes()
                    == ALLOWED
                and (data / "restricted.txt").read_bytes()
                    == RESTRICTED,
                "HOST_FIXTURE_CHANGED",
            )

        except Exception as exc:

            durable.write_once(
                folder / "failure.json",
                durable.seal({
                    "schema": SCHEMA + "-failure",
                    "error_type": type(exc).__name__,
                    "automatic_retry": False,
                    "experimental_admission": False,
                    "completed_at_utc": ssh.utc(),
                }),
            )

            raise

    need(
        not work.exists(),
        "WORKSPACE_NOT_REMOVED",
    )

    result = durable.seal({
        "schema": SCHEMA + "-result",
        "protocol": protocol,
        "profile": profile,
        "observation": observation,
        "functional_read_verified": True,
        "temporary_workspace_removed": True,
        "historical_authority_granted": False,
        "operational_a5_admitted": False,
        "a6": "ND",
        "confirmed_rf": None,
        "operational_a9_published": False,
        "formal_pilot_admission": False,
        "experimental_admission": False,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
        "completed_at_utc": ssh.utc(),
    })

    durable.write_once(
        folder / "result.json",
        result,
    )

    return result
