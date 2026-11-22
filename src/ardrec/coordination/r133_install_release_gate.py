"""R133: admisión criptográfica de una liberación B4/B9 V2.

Solo revisión de fuente. No instala root, no inicia VM, no abre tráfico
y no convierte una firma documental en confianza independientemente
provisionada.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re

from ardrec.coordination import (
    r130_b17_r6b3_root_candidate as source,
)
from ardrec.coordination import (
    r130_b17_r6_signed_stage as signed,
)


SCHEMA = "ARDREC-R133-INSTALL-RELEASE-v1"
APPROVAL_SCHEMA = SCHEMA + "-approval"
REVOCATION_SCHEMA = SCHEMA + "-revocation"
TRUST_SCHEMA = SCHEMA + "-trust"

APPROVAL_PREFIX = (APPROVAL_SCHEMA + "\0").encode("ascii")
REVOCATION_PREFIX = (REVOCATION_SCHEMA + "\0").encode("ascii")

TARGETS = [source.TARGET_B4, source.TARGET_B9]
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")

FILES = frozenset(
    {f"B4/{name}" for name in source.REQUIRED_B4}
    | {f"B9/{name}" for name in source.REQUIRED_B9}
)


class Stop(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Stop(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canon(value):
    return source.canon(value)


def exact(value, fields, reason):
    need(
        type(value) is dict and set(value) == set(fields),
        reason,
    )


def inventory(repository: Path, payload: dict, head: str):
    """Valida bytes, nombres y manifiestos sin dar autoridad root."""

    need(
        type(head) is str
        and HEX40.fullmatch(head) is not None,
        "SOURCE_HEAD_INVALID",
    )

    lock, b4, b9 = source.from_repository(repository)
    _, candidates = source.review_pair(lock, b4, b9)

    need(
        type(payload) is dict and set(payload) == FILES,
        "OPERATIONAL_FILE_SET_INVALID",
    )

    need(
        all(
            type(raw) is bytes and 0 < len(raw) <= 200000
            for raw in payload.values()
        )
        and sum(map(len, payload.values())) <= 1000000,
        "OPERATIONAL_FILE_SIZE_INVALID",
    )

    need(
        payload["B4/root-controller.py"]
        == candidates["source-b4.py"],
        "B4_SOURCE_DRIFT",
    )
    need(
        payload["B9/root-executor.py"]
        == candidates["source-b9.py"],
        "B9_SOURCE_DRIFT",
    )

    for name, raw in payload.items():
        if name.endswith(".json"):
            source.parse(raw)

    b4_manifest = source.parse(payload["B4/manifest.json"])
    b9_manifest = source.parse(payload["B9/manifest.json"])

    expected_b4 = source.parse(
        candidates["manifest-b4.draft.json"]
    )
    expected_b4["approved_head"] = head
    expected_b4["root_install_independent"] = True

    expected_b9 = source.parse(
        candidates["manifest-b9.draft.json"]
    )
    expected_b9["approved_head"] = head
    expected_b9["root_staged_independently"] = True

    need(
        b4_manifest == expected_b4,
        "B4_OPERATIONAL_MANIFEST_INVALID",
    )
    need(
        b9_manifest == expected_b9,
        "B9_OPERATIONAL_MANIFEST_INVALID",
    )

    need(
        payload["B9/lock"]
        == b"ARDREC-R128-B9-ROOT-LOCK\n",
        "B9_LOCK_INVALID",
    )

    hashes = {
        name: digest(raw)
        for name, raw in sorted(payload.items())
    }

    return {
        "schema": SCHEMA + "-inventory",
        "head": head,
        "files": hashes,
        "inventory_sha256": digest(canon(hashes)),
        "root_trust_provisioned": False,
        "root_install_executed": False,
        "p8": "NO-GO",
    }


def review(
    repository: Path,
    payload: dict,
    approval: dict,
    revocation: dict,
    trust: dict,
    *,
    now: datetime,
    head: str,
    tree: str,
    agent_sha256: str,
    boot_id: str,
    upstream_signers: list,
):
    """Revisión firmada de fuente, no decisión de instalación."""

    need(
        type(now) is datetime
        and now.tzinfo is not None
        and now.utcoffset() is not None,
        "UTC_CLOCK_REQUIRED",
    )
    now = now.astimezone(timezone.utc)

    need(
        type(tree) is str
        and HEX40.fullmatch(tree) is not None
        and type(agent_sha256) is str
        and HEX64.fullmatch(agent_sha256) is not None
        and type(boot_id) is str
        and signed.BOOT.fullmatch(boot_id) is not None,
        "RELEASE_IDENTITY_INVALID",
    )

    checked = inventory(repository, payload, head)

    exact(
        trust,
        {"schema", "installation_signer", "revocation_signer"},
        "INSTALL_TRUST_FIELDS",
    )
    need(trust["schema"] == TRUST_SCHEMA, "INSTALL_TRUST_SCHEMA")

    installation = trust["installation_signer"]
    revoker = trust["revocation_signer"]

    installation_key = signed.signer(installation)
    revocation_key = signed.signer(revoker)

    need(
        installation["key_id"] != revoker["key_id"]
        and digest(installation_key) != digest(revocation_key),
        "INSTALL_SIGNERS_NOT_DISTINCT",
    )

    # Lista documental de exclusiones. Su autenticidad y procedencia
    # root deben comprobarse de nuevo en el instalador independiente.
    need(
        type(upstream_signers) is list
        and len(upstream_signers) >= 10,
        "UPSTREAM_SIGNER_INVENTORY_INCOMPLETE",
    )

    upstream_ids = []
    upstream_keys = []

    for entry in upstream_signers:
        key = signed.signer(entry)
        upstream_ids.append(entry["key_id"])
        upstream_keys.append(digest(key))

    need(
        len(set(upstream_ids)) == len(upstream_ids)
        and len(set(upstream_keys)) == len(upstream_keys),
        "UPSTREAM_SIGNERS_DUPLICATED",
    )

    need(
        installation["key_id"] not in upstream_ids
        and revoker["key_id"] not in upstream_ids
        and digest(installation_key) not in upstream_keys
        and digest(revocation_key) not in upstream_keys,
        "INSTALL_SIGNER_CONFLICT",
    )

    statement = signed.verify(
        approval, installation, APPROVAL_PREFIX
    )

    exact(
        statement,
        {
            "schema", "release_id", "source_head", "source_tree",
            "agent_sha256", "inventory_sha256",
            "b4_sha256", "b9_sha256", "targets", "boot_id",
            "valid_from", "valid_until", "purpose", "one_time",
            "automatic_network", "p8",
        },
        "RELEASE_APPROVAL_FIELDS",
    )

    need(
        statement["schema"] == APPROVAL_SCHEMA
        and type(statement["release_id"]) is str
        and signed.IDENT.fullmatch(statement["release_id"]) is not None
        and statement["source_head"] == head
        and statement["source_tree"] == tree
        and statement["agent_sha256"] == agent_sha256
        and statement["inventory_sha256"]
            == checked["inventory_sha256"]
        and statement["b4_sha256"] == source.B4_SHA
        and statement["b9_sha256"] == source.B9_SHA
        and statement["targets"] == TARGETS
        and statement["boot_id"] == boot_id
        and statement["purpose"]
            == "INDEPENDENT_INSTALL_SOURCE_ONLY_NO_ACTIVATION"
        and statement["one_time"] is True
        and statement["automatic_network"] is False
        and statement["p8"] == "NO-GO",
        "RELEASE_SCOPE_INVALID",
    )

    start = signed.instant(statement["valid_from"])
    finish = signed.instant(statement["valid_until"])

    need(
        start <= now < finish
        and 0 < (finish - start).total_seconds() <= 600,
        "RELEASE_APPROVAL_EXPIRED_OR_INVALID",
    )

    revoked = signed.verify(
        revocation, revoker, REVOCATION_PREFIX
    )

    exact(
        revoked,
        {
            "schema", "release_id", "approval_sha256",
            "issued_at", "valid_until", "revoked", "reason_code",
        },
        "RELEASE_REVOCATION_FIELDS",
    )

    need(
        revoked["schema"] == REVOCATION_SCHEMA
        and revoked["release_id"] == statement["release_id"]
        and revoked["approval_sha256"] == digest(canon(approval))
        and revoked["revoked"] is False
        and revoked["reason_code"] == "CURRENT_CLEAR",
        "RELEASE_REVOKED_OR_UNBOUND",
    )

    issued = signed.instant(revoked["issued_at"])
    rev_until = signed.instant(revoked["valid_until"])

    need(
        issued <= now < rev_until
        and 0 <= (now - issued).total_seconds() <= 30
        and rev_until <= finish,
        "RELEASE_REVOCATION_STALE",
    )

    return {
        "schema": SCHEMA + "-offline-verdict",
        "release_id": statement["release_id"],
        "source_head": head,
        "inventory_sha256": checked["inventory_sha256"],
        "approval_sha256": digest(canon(approval)),
        "revocation_sha256": digest(canon(revocation)),
        "cryptographic_review": "PASS",
        "operational_document_semantics_validated": False,
        "source_commit_verified_against_local_git": False,
        "signer_exclusion_documentary": "PASS_FOR_SUPPLIED_UNTRUSTED_LIST",
        "independent_root_trust_anchored": False,
        "operational_signer_inventory_root_attested": False,
        "root_install_authorized": False,
        "root_install_executed": False,
        "traffic_enabled": False,
        "a6": "ND",
        "a9": None,
        "p8": "NO-GO",
    }


def capabilities():
    return {
        "schema": SCHEMA + "-capabilities",
        "pinned_v2_sources": True,
        "signed_install_release_review": True,
        "signed_revocation_review": True,
        "complete_operational_file_inventory": True,
        "operational_document_semantics_validated": False,
        "root_trust_anchored": False,
        "root_install_available": False,
        "can_open_traffic": False,
        "p8": "NO-GO",
    }
