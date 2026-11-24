"""R202: isolated, authorized FTP read-only functional fixture.

No vulnerability probing, historical authority or experimental admission.
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


SCHEMA = "ARDREC-R202-FUNCTIONAL-FTP-v1"

CONFIRM = "AUTORIZO_R202_FTP_FUNCIONAL_LOCAL"

PAYLOAD = b"ARDREC-R202-SYNTHETIC-READ-ONLY-FIXTURE\n"

RUNNER = """\
import ftplib
import hashlib
import json
import logging
import os
import secrets
import socket
import sys
import threading

from pathlib import Path

sys.path[:0] = [
    "/work/vendor",
    "/work/vendor/pyasyncore-1.0.5-py3-none-any.whl",
    "/work/vendor/pyasynchat-1.0.5-py3-none-any.whl",
]

import asyncore
import asynchat
import pyftpdlib

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)

need(
    str(asyncore.__file__).startswith(
        "/work/vendor/pyasyncore-1.0.5-py3-none-any.whl/"
    ),
    "ASYNCORE_ORIGIN_INVALID",
)

need(
    str(asynchat.__file__).startswith(
        "/work/vendor/pyasynchat-1.0.5-py3-none-any.whl/"
    ),
    "ASYNCHAT_ORIGIN_INVALID",
)

need(
    str(pyftpdlib.__file__).startswith(
        "/work/vendor/pyftpdlib/"
    ),
    "FTP_PACKAGE_ORIGIN_INVALID",
)

host_namespace = sys.argv[1]
child_namespace = os.readlink("/proc/self/ns/net")

interfaces = sorted(
    name for _, name in socket.if_nameindex()
)

need(
    child_namespace != host_namespace,
    "NETWORK_NAMESPACE_NOT_SEPARATE",
)

need(
    interfaces == ["lo"],
    "UNEXPECTED_NETWORK_INTERFACES",
)

need(
    os.geteuid() != 0,
    "ROOT_EXECUTION_FORBIDDEN",
)

logging.disable(logging.CRITICAL)

fixture = Path("/work/data/fixture.txt")

before = fixture.read_bytes()

need(
    0 < len(before) <= 1024,
    "FIXTURE_SIZE_INVALID",
)

password = secrets.token_urlsafe(24)

authorizer = DummyAuthorizer()

authorizer.add_user(
    "ardrec_fixture",
    password,
    "/work/data",
    perm="er",
)

class Handler(FTPHandler):
    pass

Handler.authorizer = authorizer
Handler.timeout = 5
Handler.max_login_attempts = 1
Handler.permit_foreign_addresses = False
Handler.permit_privileged_ports = False

server = FTPServer(
    ("127.0.0.1", 0),
    Handler,
)

server.max_cons = 4
server.max_cons_per_ip = 3

port = server.socket.getsockname()[1]

worker = threading.Thread(
    target=server.serve_forever,
    kwargs={
        "timeout": 0.1,
        "blocking": True,
        "handle_exit": False,
    },
    daemon=True,
)

received = bytearray()

def consume(chunk):

    need(
        len(received) + len(chunk) <= 1024,
        "TRANSFER_LIMIT_EXCEEDED",
    )

    received.extend(chunk)

try:

    worker.start()

    with ftplib.FTP(timeout=5) as client:

        greeting = client.connect(
            "127.0.0.1",
            port,
        )

        login = client.login(
            "ardrec_fixture",
            password,
        )

        client.set_pasv(True)

        transfer = client.retrbinary(
            "RETR fixture.txt",
            consume,
            blocksize=128,
        )

        goodbye = client.quit()

finally:

    server.close_all()
    worker.join(timeout=2)

need(
    not worker.is_alive(),
    "SERVER_THREAD_NOT_STOPPED",
)

after = fixture.read_bytes()

need(
    bytes(received) == before == after,
    "TRANSFER_CONTENT_MISMATCH",
)

need(
    sorted(p.name for p in fixture.parent.iterdir())
        == ["fixture.txt"],
    "FIXTURE_DIRECTORY_CHANGED",
)

report = {
    "host_namespace": host_namespace,
    "child_namespace": child_namespace,
    "interfaces": interfaces,
    "endpoint": "127.0.0.1",
    "greeting_code": greeting[:3],
    "login_code": login[:3],
    "transfer_code": transfer[:3],
    "goodbye_code": goodbye[:3],
    "bytes_received": len(received),
    "source_sha256": hashlib.sha256(before).hexdigest(),
    "received_sha256": hashlib.sha256(received).hexdigest(),
    "final_source_sha256": hashlib.sha256(after).hexdigest(),
    "source_unchanged": before == after,
    "server_thread_stopped": not worker.is_alive(),
    "fixture_permissions": "er",
    "authentication_attempts": 1,
    "authorized_read_transfers": 1,
    "write_operations_requested": 0,
}

print(
    json.dumps(
        report,
        sort_keys=True,
        separators=(",", ":"),
    )
)
"""


def need(condition, reason):

    if not condition:
        raise ValueError(reason)


def verify_observation(document, host_namespace):

    need(
        type(document) is dict,
        "OBSERVATION_INVALID",
    )

    need(
        set(document) == {
            "host_namespace",
            "child_namespace",
            "interfaces",
            "endpoint",
            "greeting_code",
            "login_code",
            "transfer_code",
            "goodbye_code",
            "bytes_received",
            "source_sha256",
            "received_sha256",
            "final_source_sha256",
            "source_unchanged",
            "server_thread_stopped",
            "fixture_permissions",
            "authentication_attempts",
            "authorized_read_transfers",
            "write_operations_requested",
        },
        "OBSERVATION_SCHEMA_INVALID",
    )

    expected_hash = ssh.digest(PAYLOAD)

    need(
        document["host_namespace"] == host_namespace
        and re.fullmatch(
            r"net:\[\d+\]",
            host_namespace,
        ) is not None
        and type(document["child_namespace"]) is str
        and re.fullmatch(
            r"net:\[\d+\]",
            document["child_namespace"],
        ) is not None
        and document["child_namespace"] != host_namespace
        and document["interfaces"] == ["lo"]
        and document["endpoint"] == "127.0.0.1",
        "ISOLATION_OBSERVATION_INVALID",
    )

    need(
        document["greeting_code"] == "220"
        and document["login_code"] == "230"
        and document["transfer_code"] == "226"
        and document["goodbye_code"] == "221",
        "FTP_FUNCTIONAL_CODES_INVALID",
    )

    need(
        type(document["bytes_received"]) is int
        and document["bytes_received"] == len(PAYLOAD)
        and document["source_sha256"] == expected_hash
        and document["received_sha256"] == expected_hash
        and document["final_source_sha256"] == expected_hash
        and document["source_unchanged"] is True
        and document["server_thread_stopped"] is True,
        "TRANSFER_INTEGRITY_INVALID",
    )

    need(
        document["fixture_permissions"] == "er"
        and type(document["authentication_attempts"]) is int
        and document["authentication_attempts"] == 1
        and type(document["authorized_read_transfers"]) is int
        and document["authorized_read_transfers"] == 1
        and type(document["write_operations_requested"]) is int
        and document["write_operations_requested"] == 0,
        "FUNCTIONAL_SCOPE_INVALID",
    )

    return True


def run(folder, archive, code_head, consolidation, consent):

    need(
        consent == CONFIRM,
        "EXPLICIT_CONSENT_REQUIRED",
    )

    need(
        os.geteuid() != 0,
        "ROOT_EXECUTION_FORBIDDEN",
    )

    evidence.verify_digest(consolidation)

    need(
        consolidation["assessments_reproduced"] == 3
        and consolidation["static_estimates_closed"] == 0
        and consolidation["experimental_observations_admitted"] == 0,
        "PRIOR_ASSESSMENT_BOUNDARY_INVALID",
    )

    need(
        type(code_head) is str
        and re.fullmatch(
            r"[a-f0-9]{40}",
            code_head,
        ) is not None,
        "CODE_HEAD_INVALID",
    )

    folder = Path(folder)

    folder.mkdir(mode=0o700, exist_ok=False)

    host_namespace = os.readlink(
        "/proc/self/ns/net"
    )

    plan = durable.seal({
        "schema": SCHEMA + "-plan",
        "code_head": code_head,
        "prior_consolidation_sha256":
            consolidation["sha256"],
        "created_at_utc": ssh.utc(),
        "operator_uid": os.geteuid(),
        "purpose": "FUNCTIONAL_SOFTWARE_FIXTURE",
        "protocol": "FTP",
        "scope": "ISOLATED_LOCAL_ONLY",
        "fixture_sha256": ssh.digest(PAYLOAD),
        "runner_sha256": ssh.digest(
            RUNNER.encode("ascii")
        ),
        "ftp_source_sha256":
            transport.FTP_SOURCE_SHA256,
        "host_namespace": host_namespace,
        "maximum_attempts": 1,
        "historical_authority_granted": False,
        "previous_ratings_reused_as_closed_baseline": False,
        "experimental_unit": False,
        "p8": "NO-GO",
    })

    durable.write_once(
        folder / "plan.json",
        plan,
    )

    with tempfile.TemporaryDirectory(
        prefix="ardrec-r202-"
    ) as temp:

        work = Path(temp)

        python_info = ssh.trusted_binary(
            transport.PYTHON
        )

        dependency_info = transport.prepare_ftp_source(
            Path(archive),
            work,
        )

        data = work / "data"
        data.mkdir(mode=0o700)

        fixture = data / "fixture.txt"

        fixture.write_bytes(PAYLOAD)
        fixture.chmod(0o400)

        runner = work / "fixture_runner.py"

        runner.write_text(
            RUNNER,
            encoding="ascii",
        )

        runner.chmod(0o400)

        sandbox_info, command = transport.sandbox(
            work,
            [
                str(transport.PYTHON),
                "-I",
                "-B",
                "/work/fixture_runner.py",
                host_namespace,
            ],
        )

        intent = durable.seal({
            "schema": SCHEMA + "-intent",
            "plan_sha256": plan["sha256"],
            "attempt": 1,
            "reserved_at_utc": ssh.utc(),
            "consent": CONFIRM,
            "python_binary": python_info,
            "sandbox_binary": sandbox_info,
            "dependencies": dependency_info,
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
                timeout=20,
                check=False,
            )

        except (
            OSError,
            subprocess.TimeoutExpired,
        ) as exc:

            durable.write_once(
                folder / "failure.json",
                durable.seal({
                    "schema": SCHEMA + "-failure",
                    "plan_sha256": plan["sha256"],
                    "intent_sha256": intent["sha256"],
                    "error_type": type(exc).__name__,
                    "automatic_retry": False,
                    "completed_at_utc": ssh.utc(),
                }),
            )

            raise

        if process.returncode != 0:

            durable.write_once(
                folder / "failure.json",
                durable.seal({
                    "schema": SCHEMA + "-failure",
                    "plan_sha256": plan["sha256"],
                    "intent_sha256": intent["sha256"],
                    "returncode": process.returncode,
                    "stdout_sha256": ssh.digest(
                        process.stdout
                    ),
                    "stderr_sha256": ssh.digest(
                        process.stderr
                    ),
                    "automatic_retry": False,
                    "completed_at_utc": ssh.utc(),
                }),
            )

            raise ValueError(
                "ISOLATED_FUNCTIONAL_EXECUTION_FAILED"
            )

        need(
            0 < len(process.stdout) <= 16384,
            "FUNCTIONAL_REPORT_SIZE_INVALID",
        )

        observation = json.loads(process.stdout)

        verify_observation(
            observation,
            host_namespace,
        )

        need(
            fixture.read_bytes() == PAYLOAD,
            "HOST_FIXTURE_CONTENT_CHANGED",
        )

    need(
        not work.exists(),
        "TEMPORARY_WORKSPACE_NOT_REMOVED",
    )

    report = durable.seal({
        "schema": SCHEMA + "-result",
        "plan_sha256": plan["sha256"],
        "intent_sha256": intent["sha256"],
        "completed_at_utc": ssh.utc(),
        "status": "AUTHORIZED_READ_TRANSFER_VERIFIED",
        "observation": observation,
        "temporary_workspace_removed": True,
        "isolation_independently_attested": False,
        "restoration_of_historical_vm_verified": False,
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
