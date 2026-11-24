"""R199: initial ordinal assessment and private pilot preparation.

Pure exact arithmetic and preparation of configuration artifacts.
No deployment, network execution or experimental admission.
"""
from __future__ import annotations

import os
import re

from fractions import Fraction
from pathlib import Path

from ardrec.coordination import local_ssh_pilot as ssh
from ardrec.coordination import local_protocol_pilot as transport
from ardrec.coordination import local_evidence_bridge as evidence
from ardrec.coordination import prospective_local_pilot as durable


SCHEMA = "ARDREC-R199-INITIAL-ASSESSMENT-v1"

TRANSITION_PIN = (
    "c84118ec9227f6c63553f3a8d72d26ed2"
    "dc6dec93f632e917342ca2a187384e8"
)

PROTOCOLS = ("SSH", "FTP", "SMB")

DIMENSIONS = (
    "exposure",
    "probability",
    "impact",
    "operational_importance",
    "data_sensitivity",
    "dependencies",
)

EXPOSURE_LEVELS = {
    1: "LOCAL",
    2: "INTERNAL_SEGMENTED",
    3: "INTERNAL_GENERAL",
    4: "EXTERNAL_FILTERED",
    5: "EXTERNAL_DIRECT_SIMULATED",
}

CONFIG_NAMES = {
    "SSH": "sshd_config",
    "FTP": "ftp_runner.py",
    "SMB": "smb.conf",
}


def need(condition, reason):

    if not condition:
        raise ValueError(reason)


def ordinal(value):

    need(
        type(value) is int
        and 1 <= value <= 5,
        "ORDINAL_OUT_OF_DOMAIN",
    )

    return value


def compute(exposure, probability, impact, context):

    x = ordinal(exposure)
    p = ordinal(probability)
    i = ordinal(impact)

    need(
        type(context) in (tuple, list)
        and len(context) == 3,
        "CRITICALITY_COMPONENTS_INVALID",
    )

    c = sorted(
        ordinal(value)
        for value in context
    )

    initial = Fraction(
        x + p + i - 3,
        12,
    )

    criticality = max(
        c[1],
        c[2] - 1,
    )

    normalized = Fraction(
        criticality - 1,
        4,
    )

    return {
        "initial_risk": str(initial),
        "criticality_ordinal": criticality,
        "normalized_criticality":
            str(normalized),
    }


def config_bytes(protocol):

    need(
        protocol in PROTOCOLS,
        "PROTOCOL_INVALID",
    )

    if protocol == "SSH":

        return ssh.ssh_config(
            Path("/work")
        ).encode("ascii")

    if protocol == "FTP":

        return transport.FTP_RUNNER.encode(
            "ascii"
        )

    return transport.smb_config().encode(
        "ascii"
    )


def valid_sha(value):

    return (
        type(value) is str
        and re.fullmatch(
            r"[a-f0-9]{64}",
            value,
        ) is not None
    )


def make_manifest(
    protocol,
    code_head,
    config,
    inventory,
):

    need(
        protocol in PROTOCOLS,
        "PROTOCOL_INVALID",
    )

    need(
        type(code_head) is str
        and re.fullmatch(
            r"[a-f0-9]{40}",
            code_head,
        ) is not None,
        "CODE_HEAD_INVALID",
    )

    need(
        type(config) is bytes
        and config == config_bytes(protocol),
        "CONFIGURATION_SOURCE_MISMATCH",
    )

    need(
        type(inventory) is dict
        and bool(inventory),
        "INVENTORY_INVALID",
    )

    return durable.seal({
        "schema": SCHEMA + "-scenario",
        "candidate_id":
            "PILOT-MET-" + protocol + "-001",
        "protocol": protocol,
        "candidate_family": protocol + "-T01",
        "reserved_network":
            "ardrec-pilot-" + protocol.lower(),
        "purpose": "METHODOLOGICAL_PILOT_CANDIDATE",
        "code_head": code_head,
        "configuration_file": CONFIG_NAMES[protocol],
        "configuration_sha256": ssh.digest(config),
        "inventory_sha256":
            evidence.digest(inventory),
        "planned_scope": "LOCAL_ONLY",
        "planned_exposure_ordinal": 1,
        "physical_scope_verified": False,
        "service_instance_id": None,
        "actual_initial_state_verified": False,
        "restoration_verified": False,
        "deployment_performed": False,
        "baseline_closed": False,
        "execution_authorized": False,
        "experimental_unit": False,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def verify_manifest(manifest, config, inventory):

    evidence.verify_digest(manifest)

    expected = make_manifest(
        manifest["protocol"],
        manifest["code_head"],
        config,
        inventory,
    )

    need(
        manifest == expected,
        "SCENARIO_MANIFEST_MISMATCH",
    )

    return True


def draft_assessment(
    manifest,
    config,
    inventory,
    ratings,
    supports,
):

    verify_manifest(
        manifest, config, inventory
    )

    need(
        type(ratings) is dict
        and set(ratings) == set(DIMENSIONS),
        "ASSESSMENT_DIMENSIONS_INVALID",
    )

    need(
        type(supports) is dict,
        "SUPPORTS_INVALID",
    )

    values = {}

    for name in DIMENSIONS:

        record = ratings[name]

        need(
            type(record) is dict
            and set(record) == {
                "ordinal",
                "support_sha256",
                "justification",
            },
            "RATING_SCHEMA_INVALID",
        )

        value = ordinal(record["ordinal"])

        support = record["support_sha256"]

        need(
            valid_sha(support)
            and support in supports,
            "RATING_SUPPORT_MISSING",
        )

        raw = supports[support]

        need(
            type(raw) is bytes
            and 0 < len(raw) <= 1048576
            and ssh.digest(raw) == support,
            "RATING_SUPPORT_INTEGRITY_INVALID",
        )

        reason = record["justification"]

        need(
            type(reason) is str
            and 10 <= len(reason.strip()) <= 2000,
            "RATING_JUSTIFICATION_INVALID",
        )

        values[name] = value

    need(
        values["exposure"] ==
            manifest["planned_exposure_ordinal"],
        "EXPOSURE_SCOPE_MISMATCH",
    )

    calculated = compute(
        values["exposure"],
        values["probability"],
        values["impact"],
        [
            values["operational_importance"],
            values["data_sensitivity"],
            values["dependencies"],
        ],
    )

    return durable.seal({
        "schema": SCHEMA + "-draft",
        "scenario_manifest_sha256":
            manifest["sha256"],
        "candidate_id":
            manifest["candidate_id"],
        "ratings": ratings,
        "calculated": calculated,
        "support_integrity_verified": True,
        "support_semantics_verified": False,
        "ordinal_assignments_validated": False,
        "baseline_closed": False,
        "physical_initial_state_verified": False,
        "experimental_admission": False,
        "status": "DRAFT_REQUIRES_TECHNICAL_REVIEW",
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def write_bytes_once(path, raw):

    fd = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW,
        0o600,
    )

    with os.fdopen(fd, "wb") as handle:

        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())

    directory = os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY,
    )

    try:
        os.fsync(directory)

    finally:
        os.close(directory)


def materialize_case(
    folder,
    protocol,
    code_head,
    inventory,
):

    folder = Path(folder)

    folder.mkdir(
        mode=0o700,
        exist_ok=False,
    )

    config = config_bytes(protocol)

    manifest = make_manifest(
        protocol,
        code_head,
        config,
        inventory,
    )

    write_bytes_once(
        folder / CONFIG_NAMES[protocol],
        config,
    )

    durable.write_once(
        folder / "inventory.json",
        inventory,
    )

    durable.write_once(
        folder / "scenario.json",
        manifest,
    )

    durable.write_once(
        folder / "assessment-template.json",
        {
            "schema":
                SCHEMA + "-assessment-template",
            "candidate_id":
                manifest["candidate_id"],
            "scenario_manifest_sha256":
                manifest["sha256"],
            "ratings": {
                name: {
                    "ordinal": None,
                    "support_sha256": None,
                    "justification": None,
                }
                for name in DIMENSIONS
            },
            "initial_risk": None,
            "normalized_criticality": None,
            "baseline_closed": False,
            "execution_authorized": False,
            "experimental_unit": False,
        },
    )

    return verify_case(folder)


def verify_case(folder):

    folder = Path(folder)

    manifest = durable.load(
        folder / "scenario.json"
    )

    inventory = durable.load(
        folder / "inventory.json"
    )

    protocol = manifest["protocol"]

    need(
        protocol in PROTOCOLS,
        "PROTOCOL_INVALID",
    )

    config = (
        folder / CONFIG_NAMES[protocol]
    ).read_bytes()

    verify_manifest(
        manifest,
        config,
        inventory,
    )

    template = durable.load(
        folder / "assessment-template.json"
    )

    need(
        template["scenario_manifest_sha256"]
            == manifest["sha256"]
        and template["candidate_id"]
            == manifest["candidate_id"]
        and template["baseline_closed"] is False
        and template["execution_authorized"] is False
        and template["experimental_unit"] is False
        and template["initial_risk"] is None
        and template["normalized_criticality"] is None
        and template["ratings"] == {
            name: {
                "ordinal": None,
                "support_sha256": None,
                "justification": None,
            }
            for name in DIMENSIONS
        },
        "ASSESSMENT_TEMPLATE_INVALID",
    )

    return manifest


def dependency_inventory(protocol, ftp_source):

    need(
        protocol in PROTOCOLS,
        "PROTOCOL_INVALID",
    )

    if protocol == "SSH":

        return {
            "implementation": "OPENSSH",
            "sshd": ssh.trusted_binary(ssh.SSHD),
            "keygen": ssh.trusted_binary(ssh.KEYGEN),
            "host_key_created": False,
        }

    if protocol == "SMB":

        return {
            "implementation": "SAMBA_SMBD",
            "smbd": ssh.trusted_binary(
                transport.SMBD
            ),
            "bubblewrap": ssh.trusted_binary(
                transport.BWRAP
            ),
        }

    ftp_source = Path(ftp_source)

    expected = [
        (
            "pyftpdlib-2.2.0.tar.gz",
            transport.FTP_SOURCE_SHA256,
        ),
        *[
            (filename, digest)
            for filename, digest, _ in
                transport.FTP_COMPAT_WHEELS
        ],
    ]

    verified = []

    for filename, digest in expected:

        path = ftp_source / filename

        need(
            path.is_file()
            and not path.is_symlink(),
            "FTP_DEPENDENCY_MISSING",
        )

        with path.open("rb") as handle:

            raw = handle.read(250001)

        need(
            0 < len(raw) <= 250000
            and ssh.digest(raw) == digest,
            "FTP_DEPENDENCY_INVALID",
        )

        verified.append({
            "filename": filename,
            "sha256": digest,
            "bytes": len(raw),
        })

    return {
        "implementation": "PYFTPDLIB_PINNED_SOURCE",
        "python": ssh.trusted_binary(
            transport.PYTHON
        ),
        "bubblewrap": ssh.trusted_binary(
            transport.BWRAP
        ),
        "dependencies": verified,
        "installation_performed": False,
    }


def prepare(root, transition, code_head, ftp_source):

    need(
        os.geteuid() != 0,
        "ROOT_EXECUTION_FORBIDDEN",
    )

    evidence.verify_digest(transition)

    need(
        transition["sha256"] == TRANSITION_PIN
        and transition["actual_pilot_scenarios_assigned"] == 0
        and transition["static_estimates_closed"] == 0
        and transition["historical_authority_granted"] is False
        and transition["experimental_observations_admitted"] == 0,
        "TRANSITION_INVALID",
    )

    candidates = transition["pilot_candidates"]

    need(
        [item["protocol"] for item in candidates]
            == list(PROTOCOLS)
        and all(
            item["candidate_id"] ==
                "PILOT-MET-" + item["protocol"] + "-001"
            and item["execution_authorized"] is False
            and item["experimental_unit"] is False
            for item in candidates
        ),
        "PILOT_CANDIDATES_INVALID",
    )

    inventories = {
        protocol: dependency_inventory(
            protocol, ftp_source
        )
        for protocol in PROTOCOLS
    }

    root = Path(root)

    root.mkdir(mode=0o700, exist_ok=False)

    manifests = []

    for protocol in PROTOCOLS:

        manifest = materialize_case(
            root / protocol.lower(),
            protocol,
            code_head,
            inventories[protocol],
        )

        manifests.append(manifest)

    report = durable.seal({
        "schema": SCHEMA + "-preparation",
        "code_head": code_head,
        "transition_sha256": transition["sha256"],
        "configuration_packages": manifests,
        "packages_materialized": len(manifests),
        "runtime_dependencies_verified": True,
        "services_deployed": 0,
        "physical_scenarios_verified": 0,
        "static_estimates_closed": 0,
        "new_network_executions": 0,
        "historical_authority_granted": False,
        "experimental_observations_admitted": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })

    durable.write_once(
        root / "preparation.json",
        report,
    )

    return report
