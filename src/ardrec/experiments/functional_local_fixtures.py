"""R204: bounded local SSH and SMB functional software fixtures.

No arbitrary commands, external targets, historical authorization,
operational evidence admission or experimental observations.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile

from pathlib import Path

from ardrec.coordination import local_ssh_pilot as ssh
from ardrec.coordination import local_protocol_pilot as transport
from ardrec.coordination import local_evidence_bridge as evidence
from ardrec.coordination import prospective_local_pilot as durable


SCHEMA = "ARDREC-R204-FUNCTIONAL-FIXTURES-v1"

CONFIRM = "AUTORIZO_R204_SSH_SMB_LOCAL"

PROTOCOLS = ("SSH", "SMB")

VERSIONS = {
    "SSH": {
        "paramiko": "5.0.0",
        "cryptography": "49.0.0",
    },
    "SMB": {
        "impacket": "0.13.1",
    },
}

PAYLOAD = {
    "SSH": b"ARDREC-R204-SSH-STATUS-OK\n",
    "SMB": b"ARDREC-R204-SMB-SYNTHETIC-FIXTURE\n",
}

RUNNER = r'''
import hashlib
import importlib.metadata
import json
import logging
import os
import secrets
import socket
import sys
import threading

from pathlib import Path


def need(value, reason):

    if not value:
        raise RuntimeError(reason)


def digest(value):

    return hashlib.sha256(value).hexdigest()


def isolation(host):

    child = os.readlink("/proc/self/ns/net")

    interfaces = sorted(
        name for _, name in socket.if_nameindex()
    )

    status = {}

    with open("/proc/self/status", encoding="ascii") as f:

        for line in f:

            if ":" in line:

                key, value = line.split(":", 1)
                status[key] = value.strip()

    need(
        child != host
        and interfaces == ["lo"]
        and os.geteuid() != 0
        and int(status["CapEff"], 16) == 0,
        "ISOLATION_INVALID",
    )

    return {
        "host_namespace": host,
        "child_namespace": child,
        "interfaces": interfaces,
        "effective_uid": os.geteuid(),
        "effective_capabilities": status["CapEff"],
        "endpoint": "127.0.0.1",
    }


def ssh_fixture():

    import paramiko

    versions = {
        "paramiko": importlib.metadata.version("paramiko"),
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

    payload = b"ARDREC-R204-SSH-STATUS-OK\n"

    host_key = paramiko.RSAKey.generate(2048)
    client_key = paramiko.RSAKey.generate(2048)

    username = "ardrec_fixture"

    requested = threading.Event()
    finished = threading.Event()

    errors = []

    class FixtureServer(paramiko.ServerInterface):

        def get_allowed_auths(self, username):
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

        def check_channel_subsystem_request(
            self, channel, name
        ):

            if name != "ardrec-fixture-status":

                return False

            requested.set()

            return True

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

            peer, origin = listener.accept()

            need(
                origin[0] == "127.0.0.1",
                "SSH_PEER_INVALID",
            )

            server_transport = paramiko.Transport(peer)

            server_transport.add_server_key(host_key)

            server_transport.start_server(
                server=FixtureServer()
            )

            channel = server_transport.accept(8)

            need(
                channel is not None,
                "SSH_CHANNEL_UNAVAILABLE",
            )

            need(
                requested.wait(8),
                "SSH_SUBSYSTEM_NOT_REQUESTED",
            )

            channel.settimeout(5)
            channel.sendall(payload)
            channel.send_exit_status(0)
            channel.shutdown_write()

            need(
                finished.wait(8),
                "SSH_CLIENT_NOT_FINISHED",
            )

            channel.close()

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
    received = bytearray()

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

        authenticated = client.is_authenticated()

        pinned_identity = (
            client.get_remote_server_key().asbytes()
            == host_key.asbytes()
        )

        need(
            authenticated and pinned_identity,
            "SSH_AUTHENTICATION_OR_IDENTITY_INVALID",
        )

        channel = client.open_session(timeout=5)
        channel.settimeout(5)

        channel.invoke_subsystem(
            "ardrec-fixture-status"
        )

        while True:

            chunk = channel.recv(128)

            if not chunk:
                break

            need(
                len(received) + len(chunk) <= 1024,
                "SSH_RESPONSE_LIMIT_EXCEEDED",
            )

            received.extend(chunk)

        exit_status = channel.recv_exit_status()

        need(
            bytes(received) == payload
            and exit_status == 0,
            "SSH_RESPONSE_INVALID",
        )

        channel.close()

    finally:

        finished.set()

        if client is not None:
            client.close()

        listener.close()

        worker.join(timeout=3)

    need(
        not worker.is_alive()
        and not errors,
        "SSH_SERVER_CLEANUP_INVALID",
    )

    return {
        "protocol": "SSH",
        "backend": "PARAMIKO_USERSPACE",
        "versions": versions,
        "authenticated": authenticated,
        "server_identity_verified": pinned_identity,
        "authentication_method": "PUBLIC_KEY",
        "operation": "FIXED_DIAGNOSTIC_SUBSYSTEM",
        "operations_requested": 1,
        "authentication_requests_planned": 1,
        "arbitrary_commands_requested": 0,
        "write_operations_requested": 0,
        "bytes_received": len(received),
        "expected_sha256": digest(payload),
        "received_sha256": digest(received),
        "exit_status": exit_status,
        "server_thread_stopped": True,
    }


def smb_fixture():

    from impacket import smbserver
    from impacket.ntlm import compute_lmhash, compute_nthash
    from impacket.smbconnection import SMBConnection
    from impacket.smb3structs import SMB2_DIALECT_002

    versions = {
        "impacket": importlib.metadata.version("impacket")
    }

    need(
        versions == {"impacket": "0.13.1"},
        "SMB_DEPENDENCY_VERSION_INVALID",
    )

    fixture = Path("/work/data/fixture.txt")
    before = fixture.read_bytes()

    need(
        before == b"ARDREC-R204-SMB-SYNTHETIC-FIXTURE\n",
        "SMB_FIXTURE_INVALID",
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

    server.setSMBChallenge(
        secrets.token_hex(8)
    )

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

    port = core.server_address[1]

    worker = threading.Thread(
        target=core.serve_forever,
        kwargs={"poll_interval": 0.1},
        daemon=True,
    )

    worker.start()

    client = None
    received = bytearray()

    def consume(chunk):

        need(
            len(received) + len(chunk) <= 1024,
            "SMB_TRANSFER_LIMIT_EXCEEDED",
        )

        received.extend(chunk)

    try:

        client = SMBConnection(
            remoteName="127.0.0.1",
            remoteHost="127.0.0.1",
            sess_port=port,
            timeout=5,
            preferredDialect=SMB2_DIALECT_002,
        )

        client.login(username, password)

        guest_session = bool(client.isGuestSession())

        need(
            not guest_session,
            "SMB_GUEST_SESSION_REJECTED",
        )

        dialect = client.getDialect()

        need(
            dialect == SMB2_DIALECT_002,
            "SMB_DIALECT_INVALID",
        )

        client.getFile(
            "ARDRECDATA",
            "fixture.txt",
            consume,
        )

        client.logoff()

    finally:

        try:

            if client is not None:
                client.close()

        finally:

            core.shutdown()
            core.server_close()
            worker.join(timeout=3)

    need(
        not worker.is_alive(),
        "SMB_SERVER_CLEANUP_INVALID",
    )

    after = fixture.read_bytes()

    need(
        before == bytes(received) == after,
        "SMB_TRANSFER_INTEGRITY_INVALID",
    )

    need(
        sorted(p.name for p in fixture.parent.iterdir())
        == ["fixture.txt"],
        "SMB_DIRECTORY_CHANGED",
    )

    return {
        "protocol": "SMB",
        "backend": "IMPACKET_USERSPACE",
        "versions": versions,
        "authenticated": True,
        "guest_session": guest_session,
        "dialect": hex(dialect),
        "operation": "AUTHORIZED_READ_ONLY_FILE",
        "operations_requested": 1,
        "authentication_requests_planned": 1,
        "arbitrary_commands_requested": 0,
        "write_operations_requested": 0,
        "bytes_received": len(received),
        "expected_sha256": digest(before),
        "received_sha256": digest(received),
        "final_source_sha256": digest(after),
        "source_unchanged": before == after,
        "share_read_only_configured": True,
        "server_thread_stopped": True,
    }


logging.disable(logging.CRITICAL)

protocol, host = sys.argv[1:]

stage = "ISOLATION"

try:

    result = isolation(host)

    stage = "FUNCTIONAL_OPERATION"

    if protocol == "SSH":

        result.update(ssh_fixture())

    elif protocol == "SMB":

        result.update(smb_fixture())

    else:

        raise ValueError("PROTOCOL_INVALID")

    stage = "FINAL_ISOLATION"

    final = isolation(host)

    need(
        final == {
            key: result[key]
            for key in final
        },
        "FINAL_ISOLATION_CHANGED",
    )

    print(json.dumps(
        result,
        sort_keys=True,
        separators=(",", ":"),
    ))

except Exception as exc:

    print(json.dumps({
        "status": "FAILED",
        "stage": stage,
        "error_type": type(exc).__name__,
    }, sort_keys=True))

    raise SystemExit(2)
'''


def need(value, reason):

    if not value:
        raise ValueError(reason)


def verify_observation(protocol, document, host):

    need(
        protocol in PROTOCOLS
        and type(document) is dict,
        "PROTOCOL_OR_DOCUMENT_INVALID",
    )

    expected_digest = ssh.digest(
        PAYLOAD[protocol]
    )

    need(
        document["protocol"] == protocol
        and document["host_namespace"] == host
        and type(document["child_namespace"]) is str
        and re.fullmatch(
            r"net:\[\d+\]",
            document["child_namespace"],
        )
        and document["child_namespace"] != host
        and document["interfaces"] == ["lo"]
        and document["endpoint"] == "127.0.0.1"
        and type(document["effective_uid"]) is int
        and document["effective_uid"] > 0
        and int(document["effective_capabilities"], 16) == 0,
        "ISOLATION_OBSERVATION_INVALID",
    )

    need(
        document["versions"] == VERSIONS[protocol]
        and document["authenticated"] is True
        and document["operations_requested"] == 1
        and document["authentication_requests_planned"] == 1
        and document["arbitrary_commands_requested"] == 0
        and document["write_operations_requested"] == 0
        and document["bytes_received"] == len(PAYLOAD[protocol])
        and document["expected_sha256"] == expected_digest
        and document["received_sha256"] == expected_digest
        and document["server_thread_stopped"] is True,
        "FUNCTIONAL_OBSERVATION_INVALID",
    )

    if protocol == "SSH":

        need(
            document["backend"] == "PARAMIKO_USERSPACE"
            and document["server_identity_verified"] is True
            and document["authentication_method"] == "PUBLIC_KEY"
            and document["operation"] ==
                "FIXED_DIAGNOSTIC_SUBSYSTEM"
            and document["exit_status"] == 0,
            "SSH_FUNCTIONAL_OBSERVATION_INVALID",
        )

    else:

        need(
            document["backend"] == "IMPACKET_USERSPACE"
            and document["guest_session"] is False
            and document["dialect"] == "0x202"
            and document["operation"] ==
                "AUTHORIZED_READ_ONLY_FILE"
            and document["final_source_sha256"] ==
                expected_digest
            and document["source_unchanged"] is True
            and document["share_read_only_configured"] is True,
            "SMB_FUNCTIONAL_OBSERVATION_INVALID",
        )

    return True


def run_case(folder, protocol, head, source_pin, consent):

    need(
        protocol in PROTOCOLS
        and consent == CONFIRM
        and os.geteuid() != 0,
        "EXECUTION_BOUNDARY_INVALID",
    )

    need(
        re.fullmatch(r"[a-f0-9]{40}", head)
        and re.fullmatch(r"[a-f0-9]{64}", source_pin),
        "SOURCE_IDENTITY_INVALID",
    )

    folder = Path(folder)
    folder.mkdir(mode=0o700, exist_ok=False)

    host = os.readlink("/proc/self/ns/net")

    plan = durable.seal({
        "schema": SCHEMA + "-plan",
        "protocol": protocol,
        "code_head": head,
        "capabilities_sha256": source_pin,
        "runner_sha256": ssh.digest(
            RUNNER.encode("ascii")
        ),
        "fixture_sha256": ssh.digest(
            PAYLOAD[protocol]
        ),
        "host_namespace": host,
        "created_at_utc": ssh.utc(),
        "operator_uid": os.geteuid(),
        "maximum_attempts": 1,
        "scope": "ISOLATED_LOCAL_FUNCTIONAL_FIXTURE",
        "historical_authority_granted": False,
        "experimental_unit": False,
        "p8": "NO-GO",
    })

    durable.write_once(folder / "plan.json", plan)

    with tempfile.TemporaryDirectory(
        prefix="ardrec-r204-"
    ) as temporary:

        work = Path(temporary)

        runner = work / "runner.py"

        runner.write_text(
            RUNNER,
            encoding="ascii",
        )

        runner.chmod(0o400)

        if protocol == "SMB":

            data = work / "data"
            data.mkdir(mode=0o700)

            fixture = data / "fixture.txt"
            fixture.write_bytes(PAYLOAD[protocol])
            fixture.chmod(0o400)

        python_info = ssh.trusted_binary(
            transport.PYTHON
        )

        sandbox_info, command = transport.sandbox(
            work,
            [
                str(transport.PYTHON),
                "-I", "-B",
                "/work/runner.py",
                protocol,
                host,
            ],
        )

        intent = durable.seal({
            "schema": SCHEMA + "-intent",
            "plan_sha256": plan["sha256"],
            "attempt": 1,
            "consent": CONFIRM,
            "reserved_at_utc": ssh.utc(),
            "python_binary": python_info,
            "sandbox_binary": sandbox_info,
        })

        durable.write_once(
            folder / "intent.json",
            intent,
        )

        try:

            process = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=35,
                check=False,
            )

            need(
                0 < len(process.stdout) <= 16384,
                "RUNNER_OUTPUT_INVALID",
            )

            observation = json.loads(process.stdout)

            if process.returncode != 0:

                durable.write_once(
                    folder / "runner-failure.json",
                    durable.seal({
                        "status": "FAILED",
                        "returncode": process.returncode,
                        "stage": observation.get("stage"),
                        "error_type":
                            observation.get("error_type"),
                        "stderr_sha256":
                            ssh.digest(process.stderr),
                        "automatic_retry": False,
                    }),
                )

                raise ValueError(
                    "FUNCTIONAL_RUNNER_FAILED"
                )

            verify_observation(
                protocol,
                observation,
                host,
            )

            if protocol == "SMB":

                need(
                    fixture.read_bytes() ==
                        PAYLOAD[protocol],
                    "HOST_FIXTURE_CHANGED",
                )

        except Exception as exc:

            durable.write_once(
                folder / "failure.json",
                durable.seal({
                    "schema": SCHEMA + "-failure",
                    "protocol": protocol,
                    "plan_sha256": plan["sha256"],
                    "intent_sha256": intent["sha256"],
                    "error_type": type(exc).__name__,
                    "automatic_retry": False,
                    "completed_at_utc": ssh.utc(),
                }),
            )

            raise

    need(
        not work.exists(),
        "WORKSPACE_NOT_REMOVED",
    )

    report = durable.seal({
        "schema": SCHEMA + "-result",
        "protocol": protocol,
        "plan_sha256": plan["sha256"],
        "intent_sha256": intent["sha256"],
        "completed_at_utc": ssh.utc(),
        "status": "FUNCTIONAL_OPERATION_VERIFIED",
        "observation": observation,
        "temporary_workspace_removed": True,
        "historical_authority_granted": False,
        "operational_a5_admitted": False,
        "a6": "ND",
        "confirmed_rf": None,
        "operational_a9_published": False,
        "experimental_admission": False,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })

    durable.write_once(
        folder / "result.json",
        report,
    )

    return report


def replay(folder, head, source_pin):

    folder = Path(folder)

    plan = durable.load(folder / "plan.json")
    intent = durable.load(folder / "intent.json")
    report = durable.load(folder / "result.json")

    for document in (plan, intent, report):

        need(
            evidence.verify_digest(document),
            "RECEIPT_INTEGRITY_INVALID",
        )

    protocol = plan["protocol"]

    need(
        plan["schema"] == SCHEMA + "-plan"
        and intent["schema"] == SCHEMA + "-intent"
        and report["schema"] == SCHEMA + "-result"
        and plan["code_head"] == head
        and plan["capabilities_sha256"] == source_pin
        and plan["runner_sha256"] ==
            ssh.digest(RUNNER.encode("ascii"))
        and plan["fixture_sha256"] ==
            ssh.digest(PAYLOAD[protocol])
        and plan["maximum_attempts"] == 1
        and intent["attempt"] == 1
        and intent["consent"] == CONFIRM
        and intent["plan_sha256"] == plan["sha256"]
        and report["plan_sha256"] == plan["sha256"]
        and report["intent_sha256"] == intent["sha256"]
        and report["protocol"] == protocol
        and plan["created_at_utc"]
            <= intent["reserved_at_utc"]
            <= report["completed_at_utc"],
        "RECEIPT_BINDING_INVALID",
    )

    need(
        report["status"] ==
            "FUNCTIONAL_OPERATION_VERIFIED"
        and report["temporary_workspace_removed"] is True
        and report["historical_authority_granted"] is False
        and report["operational_a5_admitted"] is False
        and report["a6"] == "ND"
        and report["confirmed_rf"] is None
        and report["operational_a9_published"] is False
        and report["experimental_admission"] is False
        and report["p8"] == "NO-GO",
        "AUTHORITY_BOUNDARY_INVALID",
    )

    verify_observation(
        protocol,
        report["observation"],
        plan["host_namespace"],
    )

    return report
