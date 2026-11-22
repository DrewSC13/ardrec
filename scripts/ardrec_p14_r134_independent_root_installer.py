"""ARDREC R134: núcleo autónomo de verificación de instalación.

Este archivo es una fuente candidata, NO un agente instalado.

La ejecución root requiere instalación independiente en la ruta fija,
confianza Ed25519 provisionada externamente y materiales root actuales.

No importa módulos desde el checkout, no instala controladores,
no habilita tráfico, no inicia máquinas virtuales y no concede P8.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


SCHEMA = "ARDREC-R133-INSTALL-RELEASE-v1"
APPROVAL_SCHEMA = SCHEMA + "-approval"
REVOCATION_SCHEMA = SCHEMA + "-revocation"
TRUST_SCHEMA = SCHEMA + "-trust"

APPROVAL_PREFIX = (APPROVAL_SCHEMA + "\0").encode("ascii")
REVOCATION_PREFIX = (REVOCATION_SCHEMA + "\0").encode("ascii")

AGENT = Path("/opt/ardrec/r134-installer-v1/installer.py")
DROP = Path("/var/lib/ardrec/r134-source-drop-v1")

TRUST = Path("/etc/ardrec/r134-install-trust-v1.json")
REVOCATION = Path("/etc/ardrec/r134-install-revocation-v1.json")

TARGET_B4 = Path("/var/lib/ardrec/r126-ftp-session-guard-v1")
TARGET_B9 = Path("/var/lib/ardrec/r128-one-session-v2")

B4_SHA = "f64ce5f8c31cd80f98d07f47eb99728e15e406a66b697044e3d5eefd6a3f73e8"
B9_SHA = "c3c840f66476f3f0bbd87e48f657fdc6270e09b57b130eaf9c5b3cb68980cbd3"

R116_GUARD_SHA = "c8bb29e434fcc3895ec3584e37cfd10354d2071056166d70e23526ba102e1ce7"
R116_F3_SHA = "37dae3750a26857f63487239e790a6a5a69b6ba4199592dd968ef97629d8ba3c"

R116_GUARD = Path(
    "/var/lib/ardrec/r116-f1-five-one-deny-v1/root-guard.py"
)
R116_F3 = Path(
    "/var/lib/ardrec/r116-f3-ftp-pilot-root-v1/root-pilot.py"
)

FILES_B4 = frozenset({
    "manifest.json",
    "root-controller.py",
    "grant.json",
    "contract.json",
    "scope-authorization.json",
    "pilot-permit.json",
    "traffic-window.json",
})

FILES_B9 = frozenset({
    "root-executor.py",
    "manifest.json",
    "release.json",
    "traffic-grant.json",
    "f13-handoff.json",
    "lock",
})

TARGETS = [str(TARGET_B4), str(TARGET_B9)]

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9_.:-]{3,80}\Z")
BOOT = re.compile(
    r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z"
)


class Stop(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Stop(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canon(value):
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ) + "\n"
    ).encode("ascii")


def unique_pairs(pairs):
    result = {}
    for name, value in pairs:
        need(name not in result, "DUPLICATE_JSON_KEY")
        result[name] = value
    return result


def parse(raw):
    need(
        type(raw) is bytes and 0 < len(raw) <= 200000,
        "DOCUMENT_SIZE",
    )

    try:
        doc = json.loads(
            raw,
            object_pairs_hook=unique_pairs,
            parse_constant=lambda _: need(
                False, "NONFINITE_JSON"
            ),
        )
    except Stop:
        raise
    except (ValueError, UnicodeError, TypeError) as exc:
        raise Stop("DOCUMENT_JSON_INVALID") from exc

    need(
        type(doc) is dict and canon(doc) == raw,
        "DOCUMENT_NONCANONICAL",
    )
    return doc


def exact(doc, names, reason):
    need(
        type(doc) is dict and set(doc) == set(names),
        reason,
    )
    return doc


def timestamp(value):
    need(
        type(value) is str
        and re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            value,
        ),
        "TIMESTAMP_FORMAT",
    )

    try:
        result = datetime.strptime(
            value, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise Stop("TIMESTAMP_INVALID") from exc

    need(
        result.strftime("%Y-%m-%dT%H:%M:%SZ") == value,
        "TIMESTAMP_NONCANONICAL",
    )

    return result


def check_directory(path, *, private=False):
    """Comprueba cada componente desde la raíz del sistema."""

    need(
        isinstance(path, Path) and path.is_absolute(),
        "DIRECTORY_PATH_INVALID",
    )

    chain = [path]
    chain.extend(path.parents)

    for current in reversed(chain):
        st = current.lstat()
        need(
            stat.S_ISDIR(st.st_mode)
            and st.st_uid == 0
            and not st.st_mode & 0o022
            and not current.is_symlink(),
            "ROOT_DIRECTORY_UNTRUSTED",
        )

    if private:
        st = path.lstat()
        need(
            stat.S_IMODE(st.st_mode) == 0o700,
            "PRIVATE_DIRECTORY_REQUIRED",
        )


def root_read(path, *, limit=200000):
    """Lectura de un archivo root sin seguir enlaces simbólicos."""

    need(
        isinstance(path, Path)
        and path.is_absolute()
        and not path.is_symlink(),
        "ROOT_INPUT_PATH_INVALID",
    )

    check_directory(path.parent)

    st = path.lstat()

    need(
        stat.S_ISREG(st.st_mode)
        and st.st_uid == 0
        and st.st_nlink == 1
        and stat.S_IMODE(st.st_mode) == 0o600
        and 0 < st.st_size <= limit,
        "ROOT_INPUT_METADATA_INVALID",
    )

    fd = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )

    try:
        before = os.fstat(fd)

        need(
            (
                before.st_dev, before.st_ino,
                before.st_uid, before.st_mode,
                before.st_nlink, before.st_size,
            ) == (
                st.st_dev, st.st_ino, st.st_uid,
                st.st_mode, st.st_nlink, st.st_size,
            ),
            "ROOT_INPUT_REPLACED",
        )

        raw = os.read(fd, limit + 1)
        after = os.fstat(fd)

        need(
            len(raw) == st.st_size
            and (
                before.st_dev, before.st_ino,
                before.st_size, before.st_mtime_ns,
                before.st_ctime_ns, before.st_mode,
            ) == (
                after.st_dev, after.st_ino,
                after.st_size, after.st_mtime_ns,
                after.st_ctime_ns, after.st_mode,
            ),
            "ROOT_INPUT_CHANGED",
        )

        return raw

    finally:
        os.close(fd)


def signer(entry):
    exact(
        entry,
        {"key_id", "public_key_pem"},
        "SIGNER_FIELDS",
    )

    need(
        type(entry["key_id"]) is str
        and IDENT.fullmatch(entry["key_id"]) is not None,
        "SIGNER_ID_INVALID",
    )

    pem = entry["public_key_pem"]

    need(type(pem) is str, "SIGNER_KEY_INVALID")

    try:
        raw = pem.encode("ascii")
        lines = raw.splitlines()
        need(
            len(lines) == 3
            and lines[0] == b"-----BEGIN PUBLIC KEY-----"
            and lines[-1] == b"-----END PUBLIC KEY-----",
            "SIGNER_PEM_INVALID",
        )

        der = base64.b64decode(lines[1], validate=True)

    except (UnicodeError, binascii.Error, ValueError) as exc:
        raise Stop("SIGNER_PEM_INVALID") from exc

    need(
        len(der) == 44
        and der[:12]
        == bytes.fromhex("302a300506032b6570032100"),
        "SIGNER_NOT_ED25519",
    )

    return raw


def verify_signature(envelope, authority, prefix):
    exact(
        envelope,
        {"statement", "signer_key_id", "signature_b64"},
        "SIGNED_ENVELOPE_FIELDS",
    )

    need(
        envelope["signer_key_id"] == authority["key_id"],
        "SIGNER_NOT_TRUSTED",
    )

    statement = envelope["statement"]
    need(type(statement) is dict, "SIGNED_STATEMENT_INVALID")

    encoded = envelope["signature_b64"]

    need(type(encoded) is str, "SIGNATURE_TYPE_INVALID")

    try:
        signature = base64.b64decode(
            encoded, validate=True
        )
    except (binascii.Error, ValueError) as exc:
        raise Stop("SIGNATURE_BASE64_INVALID") from exc

    need(
        len(signature) == 64
        and base64.b64encode(signature).decode() == encoded,
        "SIGNATURE_NONCANONICAL",
    )

    key = signer(authority)
    message = prefix + canon(statement)

    with tempfile.TemporaryDirectory(
        prefix="ardrec-r134-verify-", dir=("/run" if os.geteuid() == 0 else None)
    ) as temp:
        folder = Path(temp)

        def write(name, raw):
            path = folder / name
            fd = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            with os.fdopen(fd, "wb") as out:
                out.write(raw)
                out.flush()
                os.fsync(out.fileno())
            return path

        public_path = write("public.pem", key)
        message_path = write("message.bin", message)
        signature_path = write("signature.bin", signature)

        try:
            result = subprocess.run(
                [
                    "/usr/bin/openssl", "pkeyutl",
                    "-verify", "-pubin",
                    "-inkey", str(public_path),
                    "-rawin",
                    "-in", str(message_path),
                    "-sigfile", str(signature_path),
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=5,
                check=False,
                env={
                    "PATH": "/usr/bin:/bin",
                    "LC_ALL": "C",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Stop("CRYPTO_VERIFIER_UNAVAILABLE") from exc

        need(
            result.returncode == 0,
            "ED25519_SIGNATURE_INVALID",
        )

    return statement


def read_bundle():
    """Lee solamente la fuente root previamente depositada."""

    check_directory(DROP, private=True)
    check_directory(DROP / "B4", private=True)
    check_directory(DROP / "B9", private=True)

    need(
        {p.name for p in DROP.iterdir()}
        == {"B4", "B9", "approval.json"},
        "SOURCE_DROP_FILE_SCOPE",
    )

    result = {}

    for label, names in (
        ("B4", FILES_B4),
        ("B9", FILES_B9),
    ):
        folder = DROP / label

        need(
            {p.name for p in folder.iterdir()} == names,
            "ROOT_BUNDLE_FILE_SCOPE",
        )

        for name in sorted(names):
            result[f"{label}/{name}"] = root_read(
                folder / name
            )

    need(
        sha(result["B4/root-controller.py"]) == B4_SHA,
        "B4_PIN_CHANGED",
    )

    need(
        sha(result["B9/root-executor.py"]) == B9_SHA,
        "B9_PIN_CHANGED",
    )

    need(
        result["B9/lock"]
        == b"ARDREC-R128-B9-ROOT-LOCK\n",
        "B9_LOCK_INVALID",
    )

    for name, raw in result.items():
        if name.endswith(".json"):
            parse(raw)

    return result


def validate_manifests(payload, head):
    """Exige los contratos estructurales exactos B4 y B9."""

    need(
        type(head) is str
        and HEX40.fullmatch(head) is not None,
        "APPROVED_HEAD_INVALID",
    )

    b4 = parse(payload["B4/manifest.json"])
    b9 = parse(payload["B9/manifest.json"])

    expected_b4 = {
        "schema": "ARDREC-R126-B4-ROOT-DENY-SESSION-v1-root-bundle",
        "script_sha256": B4_SHA,
        "guard_sha256": R116_GUARD_SHA,
        "approved_head": head,
        "deny_only": True,
        "root_install_independent": True,
    }

    expected_b9 = {
        "schema": "ARDREC-R128-B9-ROOT-ONE-SESSION-FTP-T01-v1-root-bundle",
        "approved_head": head,
        "script_sha256": B9_SHA,
        "r126_deny_controller_sha256": B4_SHA,
        "legacy_f3_sha256": R116_F3_SHA,
        "guard_sha256": R116_GUARD_SHA,
        "root_staged_independently": True,
        "automatic_network": False,
        "p8": "NO-GO",
    }

    need(b4 == expected_b4, "B4_MANIFEST_INVALID")
    need(b9 == expected_b9, "B9_MANIFEST_INVALID")


def current_boot():
    path = Path("/proc/sys/kernel/random/boot_id")
    need(
        path.is_file() and not path.is_symlink(),
        "BOOT_SOURCE_INVALID",
    )

    value = path.read_text(encoding="ascii").strip()

    need(
        BOOT.fullmatch(value) is not None,
        "BOOT_ID_INVALID",
    )

    return value


def validate_runtime_identity():
    """La revisión privilegiada no puede proceder del checkout."""

    need(os.geteuid() == 0, "ROOT_REQUIRED")

    actual = Path(__file__).absolute()

    need(
        actual == AGENT
        and not actual.is_symlink(),
        "INDEPENDENT_AGENT_PATH_REQUIRED",
    )

    check_directory(AGENT.parent, private=True)

    agent_bytes = root_read(AGENT, limit=200000)

    return sha(agent_bytes)



UPSTREAM_TRUST = (
    (
        "/etc/ardrec/r126-root-session-trust-v1.json",
        "ARDREC-R126-B4-ROOT-DENY-SESSION-v1-trust",
        ("grant_signer", "revocation_signer"),
    ),
    (
        "/etc/ardrec/r126-ftp-t01-scope-trust-v2.json",
        "ARDREC-R115-F3-EXTERNAL-TRUST-PINS-v1",
        ("scope_signer", "revocation_signer"),
    ),
    (
        "/etc/ardrec/r115-p7-pilot-trust-v1.json",
        "ARDREC-R115-F15-P7-EXTERNAL-TRUST-v1",
        ("pilot_signer", "revocation_signer"),
    ),
    (
        "/etc/ardrec/r115-p8-trust-v1.json",
        "ARDREC-R115-F11-P8-EXTERNAL-TRUST-v1",
        ("window_signer", "revocation_signer"),
    ),
    (
        "/etc/ardrec/r128-root-traffic-trust-v1.json",
        "ARDREC-R128-B9-ROOT-ONE-SESSION-FTP-T01-v1-trust",
        ("traffic_signer", "revocation_signer"),
    ),
)


def read_upstream_trust():
    '''Lee diez autoridades desde ubicaciones root fijas.'''

    entries = []

    for location, schema, roles in UPSTREAM_TRUST:
        doc = parse(root_read(Path(location), limit=12000))
        exact(doc, {"schema", *roles}, "UPSTREAM_TRUST_FIELDS")
        need(doc["schema"] == schema, "UPSTREAM_TRUST_SCHEMA")

        for role in roles:
            signer(doc[role])
            entries.append(doc[role])

    return entries


def review_signed_bundle(
    *,
    payload,
    approval,
    revocation,
    trust,
    expected_head,
    expected_tree,
    expected_agent_sha,
    expected_boot,
    upstream,
    now,
):
    '''Auditoría documental independiente del checkout.'''

    need(
        isinstance(now, datetime)
        and now.tzinfo is not None
        and now.utcoffset() is not None,
        "UTC_CLOCK_REQUIRED",
    )

    now = now.astimezone(timezone.utc)

    required = {
        *(f"B4/{name}" for name in FILES_B4),
        *(f"B9/{name}" for name in FILES_B9),
    }

    need(
        type(payload) is dict
        and set(payload) == required
        and all(
            type(raw) is bytes and 0 < len(raw) <= 200000
            for raw in payload.values()
        ),
        "BUNDLE_INVENTORY_INVALID",
    )

    need(
        sha(payload["B4/root-controller.py"]) == B4_SHA,
        "B4_SOURCE_PIN_INVALID",
    )
    need(
        sha(payload["B9/root-executor.py"]) == B9_SHA,
        "B9_SOURCE_PIN_INVALID",
    )
    need(
        payload["B9/lock"] == b"ARDREC-R128-B9-ROOT-LOCK" + bytes([10]),
        "B9_LOCK_INVALID",
    )

    for name, raw in payload.items():
        if name.endswith(".json"):
            parse(raw)

    validate_manifests(payload, expected_head)

    inventory = {
        name: sha(raw)
        for name, raw in sorted(payload.items())
    }
    inventory_sha = sha(canon(inventory))

    exact(
        trust,
        {"schema", "installation_signer", "revocation_signer"},
        "INSTALL_TRUST_FIELDS",
    )
    need(trust["schema"] == TRUST_SCHEMA, "INSTALL_TRUST_SCHEMA")

    installation = trust["installation_signer"]
    revoker = trust["revocation_signer"]

    need(
        type(upstream) is list and len(upstream) == 10,
        "UPSTREAM_TRUST_INCOMPLETE",
    )

    identities = [*upstream, installation, revoker]
    identifiers = []
    fingerprints = []

    for entry in identities:
        key = signer(entry)
        identifiers.append(entry["key_id"])
        fingerprints.append(sha(key))

    need(
        len(set(identifiers)) == 12
        and len(set(fingerprints)) == 12,
        "SIGNERS_NOT_DISTINCT",
    )

    statement = verify_signature(
        approval,
        installation,
        APPROVAL_PREFIX,
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
        "APPROVAL_FIELDS",
    )

    need(
        statement["schema"] == APPROVAL_SCHEMA
        and type(statement["release_id"]) is str
        and IDENT.fullmatch(statement["release_id"]) is not None
        and type(expected_head) is str
        and HEX40.fullmatch(expected_head) is not None
        and type(expected_tree) is str
        and HEX40.fullmatch(expected_tree) is not None
        and type(expected_agent_sha) is str
        and HEX64.fullmatch(expected_agent_sha) is not None
        and statement["source_head"] == expected_head
        and statement["source_tree"] == expected_tree
        and statement["agent_sha256"] == expected_agent_sha
        and statement["inventory_sha256"] == inventory_sha
        and statement["b4_sha256"] == B4_SHA
        and statement["b9_sha256"] == B9_SHA
        and statement["targets"] == TARGETS
        and statement["boot_id"] == expected_boot
        and statement["purpose"]
            == "INDEPENDENT_INSTALL_SOURCE_ONLY_NO_ACTIVATION"
        and statement["one_time"] is True
        and statement["automatic_network"] is False
        and statement["p8"] == "NO-GO",
        "APPROVAL_SCOPE_INVALID",
    )

    begin = timestamp(statement["valid_from"])
    end = timestamp(statement["valid_until"])

    need(
        begin <= now < end
        and 0 < (end - begin).total_seconds() <= 600,
        "APPROVAL_NOT_CURRENT",
    )

    rev = verify_signature(
        revocation,
        revoker,
        REVOCATION_PREFIX,
    )

    exact(
        rev,
        {
            "schema", "release_id", "approval_sha256",
            "issued_at", "valid_until", "revoked", "reason_code",
        },
        "REVOCATION_FIELDS",
    )

    need(
        rev["schema"] == REVOCATION_SCHEMA
        and rev["release_id"] == statement["release_id"]
        and rev["approval_sha256"] == sha(canon(approval))
        and rev["revoked"] is False
        and rev["reason_code"] == "CURRENT_CLEAR",
        "RELEASE_REVOKED_OR_UNBOUND",
    )

    issued = timestamp(rev["issued_at"])
    rev_until = timestamp(rev["valid_until"])

    need(
        issued <= now < rev_until
        and 0 <= (now - issued).total_seconds() <= 30
        and rev_until <= end,
        "REVOCATION_NOT_CURRENT",
    )

    return {
        "schema": SCHEMA + "-root-readonly-review",
        "release_id": statement["release_id"],
        "inventory_sha256": inventory_sha,
        "approval_sha256": sha(canon(approval)),
        "revocation_sha256": sha(canon(revocation)),
        "cryptographic_review": "PASS",
        "root_trust_independence_confirmed": False,
        "git_commit_signature_independently_verified": False,
        "operational_document_semantics_complete": False,
        "root_install_authorized": False,
        "root_install_executed": False,
        "traffic_enabled": False,
        "a6": "ND",
        "a9": None,
        "p8": "NO-GO",
    }


def audit_root_readonly():
    '''Solo lectura; exige agente y documentos root reales.'''

    agent_sha = validate_runtime_identity()
    payload = read_bundle()

    need(
        sha(root_read(R116_GUARD)) == R116_GUARD_SHA
        and sha(root_read(R116_F3)) == R116_F3_SHA,
        "R116_SOURCE_DRIFT",
    )

    trust = parse(root_read(TRUST, limit=12000))
    approval = parse(root_read(DROP / "approval.json", limit=12000))
    revocation = parse(root_read(REVOCATION, limit=12000))

    exact(
        approval,
        {"statement", "signer_key_id", "signature_b64"},
        "APPROVAL_ENVELOPE_FIELDS",
    )

    statement = approval["statement"]
    need(type(statement) is dict, "APPROVAL_STATEMENT_INVALID")

    upstream = read_upstream_trust()

    return review_signed_bundle(
        payload=payload,
        approval=approval,
        revocation=revocation,
        trust=trust,
        expected_head=statement.get("source_head"),
        expected_tree=statement.get("source_tree"),
        expected_agent_sha=agent_sha,
        expected_boot=current_boot(),
        upstream=upstream,
        now=datetime.now(timezone.utc),
    )


def capabilities():
    return {
        "schema": "ARDREC-R134-INDEPENDENT-ROOT-INSTALL-CAPABILITIES-v1",
        "source_only_candidate": True,
        "fixed_independent_agent_path": str(AGENT),
        "ed25519_review": True,
        "signed_revocation_review": True,
        "root_owned_inputs_required": True,
        "operational_file_set_required": True,
        "root_readonly_audit_available": True,
        "root_install_implemented": False,
        "root_install_executed": False,
        "network_activation": False,
        "vm_boot": False,
        "a6": "ND",
        "a9": None,
        "p8": "NO-GO",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--capabilities", action="store_true")
    group.add_argument("--audit-root", action="store_true")

    options = parser.parse_args(argv)

    if options.capabilities:
        print(canon(capabilities()).decode().strip())
        return 0

    try:
        result = audit_root_readonly()
        print(canon(result).decode().strip())
        return 0
    except Exception as exc:
        print(
            canon({
                "status": "DENY_NO_OPERATION",
                "reason": type(exc).__name__ + ":"
                    + str(exc)[:140],
                "root_install": False,
                "traffic": False,
                "p8": "NO-GO",
            }).decode().strip(),
            file=sys.stderr,
        )
        return 23


if __name__ == "__main__":
    raise SystemExit(main())
