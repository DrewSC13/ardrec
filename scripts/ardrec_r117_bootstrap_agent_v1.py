"""R117 root-agent bootstrap primitives.

Self-contained: no repository imports, Git, shell, VM operations,
network access, or executable payload loading.

Host authority requires a separately trusted root entrypoint,
pinned public key, and an authenticated signed contract.
"""
from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import fcntl
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import zipfile

HEAD = "ba7a184406a08cd545d1d795b0d97101a8c112a1"
CANDIDATE_SHA = (
    "574eca7c66da8b6067adfc08bf89b7bbfa7ad238eb1b805004b9016705310f9d"
)
AGENT_SHA = (
    "6e570b0eaeb0657b6be18a06de3fea34afb2f3b3294ddcbe6b882e9b2f92c2ee"
)
PINS = {
    "bootstrap":
        "94d2038a17fd27efab4a4fc2bdb77dafff9eb3ebb1f659a516273080394e59aa",
    "approval":
        "9c6753b9a439de6eb4a17ae87fe5a09b95816461f93a76a100b4e7b2c4843389",
    "revocation":
        "db3ac74dc6121d894b63cac0c55fec8405f281147df03c34d148d71c030dc828",
}
AGENT_FILES = {
    "installer.py",
    "candidate.py",
    "ardrec_r117_release_core_v1.py",
    "ardrec_r117_recovery_v1.py",
    "source-manifest.json",
}
CONTRACT_SCHEMA = "ARDREC-R117-AGENT-BOOTSTRAP-v1"
CONTRACT_PREFIX = b"ARDREC-R117-AGENT-BOOTSTRAP-v1\x00"
CONTRACT_FIELDS = {
    "schema", "head", "candidate_sha256", "agent_sha256",
    "bootstrap_public_sha256", "approval_public_sha256",
    "revocation_public_sha256", "valid_from", "valid_until",
    "purpose", "boot_authorized", "network_authorized", "p8",
}
MANIFEST_FIELDS = {
    "schema", "head", "source_sha256", "candidate_sha256",
    "purpose", "boot_authorized", "network_authorized", "p8",
}
DESTINATION = "r117-f5b-root-agent-v1"
SPKI = bytes.fromhex("302a300506032b6570032100")


class Stop(RuntimeError):
    pass


def need(condition, reason):
    if not condition:
        raise Stop(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True, allow_nan=False) + "\n"
    ).encode("ascii")


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def document(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 8192,
         "DOCUMENT_SIZE")
    try:
        doc = json.loads(
            raw, object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(
                Stop("NONFINITE_JSON")
            ),
        )
        need(type(doc) is dict and canonical(doc) == raw,
             "DOCUMENT_NOT_CANONICAL")
        return doc
    except (ValueError, TypeError, UnicodeError) as error:
        raise Stop("INVALID_DOCUMENT") from error


def utc(value):
    need(
        type(value) is str and
        re.fullmatch(
            r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value
        ) is not None,
        "UTC_FORMAT",
    )
    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError as error:
        raise Stop("UTC_DATE") from error


def archive(raw, *, names=None):
    need(type(raw) is bytes and 0 < len(raw) <= 2_000_000,
         "ARCHIVE_SIZE")
    try:
        with zipfile.ZipFile(BytesIO(raw)) as container:
            entries = container.infolist()
            filenames = [entry.filename for entry in entries]

            need(
                len(entries) == len(set(filenames))
                and filenames == sorted(filenames),
                "ARCHIVE_NAMES_OR_ORDER",
            )

            if names is not None:
                need(set(filenames) == names,
                     "ARCHIVE_FILE_SET")

            result = {}
            for entry in entries:
                name = entry.filename

                need(
                    re.fullmatch(r"[A-Za-z0-9_./-]+", name)
                    and not name.startswith("/")
                    and "." not in name.split("/")
                    and ".." not in name.split("/")
                    and not entry.is_dir()
                    and entry.create_system == 3
                    and entry.date_time ==
                        (1980, 1, 1, 0, 0, 0)
                    and (entry.external_attr >> 16) ==
                        0o100600
                    and entry.compress_type == zipfile.ZIP_STORED
                    and not (entry.flag_bits & 1)
                    and 0 < entry.file_size <= 200000,
                    "UNTRUSTED_ARCHIVE_ENTRY",
                )

                result[name] = container.read(entry)
            return result

    except (
        zipfile.BadZipFile, OSError,
        EOFError, UnicodeError, ValueError
    ) as error:
        if isinstance(error, Stop):
            raise
        raise Stop("ARCHIVE_READ_REJECTED") from error


def bundles(agent_raw, candidate_raw):
    """Verify immutable source archives without executing their contents."""
    need(sha(agent_raw) == AGENT_SHA,
         "AGENT_SHA256_MISMATCH")
    need(sha(candidate_raw) == CANDIDATE_SHA,
         "CANDIDATE_SHA256_MISMATCH")

    agent = archive(agent_raw, names=AGENT_FILES)
    manifest = document(agent["source-manifest.json"])

    need(set(manifest) == MANIFEST_FIELDS,
         "AGENT_MANIFEST_FIELDS")
    need(
        manifest["schema"] ==
            "ARDREC-R117-F5B-ROOT-AGENT-SOURCE-v1"
        and manifest["head"] == HEAD
        and manifest["candidate_sha256"] == CANDIDATE_SHA
        and manifest["purpose"] == "SOURCE_STAGE_ONLY"
        and manifest["boot_authorized"] is False
        and manifest["network_authorized"] is False
        and manifest["p8"] == "NO-GO",
        "AGENT_MANIFEST_SCOPE",
    )

    hashes = manifest["source_sha256"]
    need(
        type(hashes) is dict
        and set(hashes) == AGENT_FILES -
            {"source-manifest.json"},
        "AGENT_SOURCE_INVENTORY",
    )

    for name, expected in hashes.items():
        need(
            type(expected) is str
            and re.fullmatch(r"[0-9a-f]{64}", expected)
            and sha(agent[name]) == expected,
            "AGENT_SOURCE_CHANGED_" + name,
        )

    candidate = archive(candidate_raw)
    need(len(candidate) == 39,
         "CANDIDATE_FILE_COUNT")
    need(
        {"manifest.json", "catalog.json", "lock"} <=
            set(candidate),
        "CANDIDATE_REQUIRED_FILES",
    )

    doc = document(candidate["manifest.json"])
    sources = doc.get("source_sha256")
    need(
        doc.get("head") == HEAD
        and doc.get("schema") ==
            "ARDREC-R117-F4-ROOT-FTP-PILOT-v1-root-bundle"
        and doc.get("p8") == "NO-GO"
        and doc.get("a6") == "ND"
        and doc.get("network_automatic") is False
        and type(sources) is dict
        and len(sources) == 36
        and set(candidate) == set(sources) |
            {"manifest.json", "catalog.json", "lock"},
        "CANDIDATE_MANIFEST_SCOPE",
    )

    for name, expected in sources.items():
        need(
            type(expected) is str
            and re.fullmatch(r"[0-9a-f]{64}", expected)
            and sha(candidate[name]) == expected,
            "CANDIDATE_SOURCE_CHANGED_" + name,
        )

    need(
        sha(candidate["catalog.json"]) ==
            doc.get("catalog_sha256"),
        "CANDIDATE_CATALOG_CHANGED",
    )
    need(
        candidate["lock"] == b"R117_F4_ROOT_LOCK_V1\n",
        "CANDIDATE_LOCK_CHANGED",
    )

    return agent


def verify_signature(public, signature, statement):
    need(
        hasattr(os, "memfd_create")
        and type(public) is bytes
        and sha(public) == PINS["bootstrap"]
        and type(signature) is bytes
        and len(signature) == 64
        and type(statement) is bytes
        and 0 < len(statement) <= 8192,
        "CRYPTO_INPUT_OR_TRUST_PIN",
    )

    descriptors = []
    try:
        for name, raw in (
            ("key", public),
            ("sig", signature),
            ("statement", statement),
        ):
            fd = os.memfd_create(
                "ardrec-bootstrap-" + name,
                os.MFD_CLOEXEC,
            )
            descriptors.append(fd)
            need(os.write(fd, raw) == len(raw),
                 "MEMFD_SHORT_WRITE")
            os.lseek(fd, 0, os.SEEK_SET)

        paths = [
            "/proc/self/fd/" + str(fd)
            for fd in descriptors
        ]

        def run(args):
            result = subprocess.run(
                ["/usr/bin/openssl", *args],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                pass_fds=tuple(descriptors),
                timeout=10,
                check=False,
                env={
                    "PATH": "/usr/bin:/bin",
                    "LC_ALL": "C",
                },
            )
            need(result.returncode == 0,
                 "ED25519_VERIFICATION_FAILED")
            return result.stdout

        der = run([
            "pkey", "-pubin",
            "-in", paths[0], "-outform", "DER",
        ])
        need(
            len(der) == 44 and der.startswith(SPKI),
            "BOOTSTRAP_KEY_NOT_ED25519",
        )

        run([
            "pkeyutl", "-verify", "-rawin",
            "-pubin", "-inkey", paths[0],
            "-sigfile", paths[1], "-in", paths[2],
        ])
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Stop("CRYPTO_SUBPROCESS_FAILED") from error
    finally:
        for fd in descriptors:
            os.close(fd)


def verify_contract(raw, signature, public, agent_raw,
                    candidate_raw, *, now):
    agent = bundles(agent_raw, candidate_raw)
    doc = document(raw)

    need(set(doc) == CONTRACT_FIELDS,
         "CONTRACT_FIELDS")
    need(
        doc["schema"] == CONTRACT_SCHEMA
        and doc["head"] == HEAD
        and doc["candidate_sha256"] == CANDIDATE_SHA
        and doc["agent_sha256"] == AGENT_SHA
        and doc["bootstrap_public_sha256"] == PINS["bootstrap"]
        and doc["approval_public_sha256"] == PINS["approval"]
        and doc["revocation_public_sha256"] == PINS["revocation"]
        and doc["purpose"] == "STAGE_ROOT_AGENT_ONLY"
        and doc["boot_authorized"] is False
        and doc["network_authorized"] is False
        and doc["p8"] == "NO-GO",
        "CONTRACT_SCOPE_CHANGED",
    )

    need(
        isinstance(now, datetime)
        and now.tzinfo is not None
        and now.utcoffset().total_seconds() == 0,
        "VERIFICATION_TIME_INVALID",
    )

    start, end = utc(doc["valid_from"]), utc(doc["valid_until"])
    need(
        start <= now < end
        and 0 < (end - start).total_seconds() <= 600,
        "BOOTSTRAP_CONTRACT_EXPIRED",
    )

    verify_signature(public, signature, CONTRACT_PREFIX + raw)

    return agent


def sync(folder):
    fd = os.open(
        folder, os.O_RDONLY | os.O_DIRECTORY |
        os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def check_directory(folder):
    info = folder.lstat()
    need(
        stat.S_ISDIR(info.st_mode)
        and not folder.is_symlink()
        and info.st_uid == os.geteuid()
        and not (info.st_mode & 0o022),
        "UNTRUSTED_STAGING_DIRECTORY",
    )


def write_once(path, raw):
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL |
        os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def rename_noreplace(root, old_name, new_name):
    """Linux atomic rename that fails if destination already exists."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    need(rename is not None, "RENAMEAT2_UNAVAILABLE")
    rename.argtypes = [
        ctypes.c_int, ctypes.c_char_p,
        ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int

    fd = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY |
        os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        result = rename(
            fd, old_name.encode("ascii"),
            fd, new_name.encode("ascii"), 1,
        )
        if result != 0:
            raise Stop(
                "ATOMIC_PUBLICATION_REJECTED_" +
                str(ctypes.get_errno())
            )
        os.fsync(fd)
    finally:
        os.close(fd)


def audit_agent(root, files):
    destination = root / DESTINATION
    check_directory(destination)
    need(
        stat.S_IMODE(destination.lstat().st_mode) == 0o700,
        "AGENT_DIRECTORY_MODE",
    )
    need(
        {entry.name for entry in destination.iterdir()} ==
            set(files),
        "INSTALLED_AGENT_FILE_SET",
    )

    for name, expected in files.items():
        path = destination / name
        fd = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            info = os.fstat(fd)
            need(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.geteuid()
                and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600,
                "INSTALLED_AGENT_METADATA_" + name,
            )
            raw = os.read(fd, 200001)
            need(raw == expected,
                 "INSTALLED_AGENT_CHANGED_" + name)
        finally:
            os.close(fd)

    return True


def stage_agent(root, files, *, checkpoint=None):
    """Atomic data-only staging. Never loads or executes staged sources.

    The future trusted root entrypoint must call verify_contract first.
    """
    need(
        isinstance(root, Path) and root.is_absolute(),
        "ROOT_PATH_INVALID",
    )
    check_directory(root)
    need(set(files) == AGENT_FILES,
         "AGENT_FILE_SCOPE_INVALID")
    for name, raw in files.items():
        need(
            type(raw) is bytes
            and 0 < len(raw) <= 200000
            and "/" not in name
            and name not in (".", ".."),
            "STAGING_ENTRY_INVALID",
        )

    lock = root / ".r117-agent-bootstrap.lock"
    fd = os.open(
        lock,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
        os.O_CLOEXEC,
        0o600,
    )

    try:
        info = os.fstat(fd)
        need(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o600,
            "BOOTSTRAP_LOCK_UNTRUSTED",
        )

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        destination = root / DESTINATION
        need(
            not destination.exists()
            and not destination.is_symlink(),
            "AGENT_ALREADY_PRESENT",
        )
        need(
            not any(root.glob(".r117-agent-stage-*")),
            "UNRESOLVED_AGENT_STAGING",
        )
        need(
            not any(root.glob(".r117-f5b-transaction-*")),
            "UNRESOLVED_RELEASE_TRANSACTION",
        )

        name = ".r117-agent-stage-" + secrets.token_hex(12)
        staging = root / name
        staging.mkdir(mode=0o700)
        sync(root)

        for filename, raw in sorted(files.items()):
            write_once(staging / filename, raw)

        sync(staging)

        if checkpoint is not None:
            checkpoint("STAGED")

        rename_noreplace(root, name, DESTINATION)
        audit_agent(root, files)

        if checkpoint is not None:
            checkpoint("PUBLISHED")

        return {
            "agent_installed": True,
            "file_count": len(files),
            "head": HEAD,
            "boot_authorized": False,
            "network_authorized": False,
            "p8": "NO-GO",
        }
    finally:
        os.close(fd)



ROOT_HOST = Path("/var/lib/ardrec")
ROOT_EXECUTOR = ROOT_HOST / "r117-agent-bootstrap-executor-v1.py"
ROOT_TRUST = Path(
    "/etc/ardrec/r117-authorities-v2/bootstrap-public.pem"
)
DENY_GUARD = (
    ROOT_HOST / "r116-f1-five-one-deny-v1" / "root-guard.py"
)


def _root_directory(path):
    info = path.lstat()
    need(
        stat.S_ISDIR(info.st_mode)
        and not path.is_symlink()
        and info.st_uid == 0
        and not (info.st_mode & 0o022),
        "ROOT_DIRECTORY_UNTRUSTED",
    )


def _root_file(path, maximum=200000):
    for parent in reversed(path.parents):
        _root_directory(parent)

    fd = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        info = os.fstat(fd)
        need(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and 0 < info.st_size <= maximum,
            "ROOT_FILE_UNTRUSTED",
        )
        data = os.read(fd, maximum + 1)
        need(len(data) == info.st_size,
             "ROOT_FILE_CHANGED")
        return data
    finally:
        os.close(fd)


def _root_context():
    """Require an independently installed root-owned executable.

    The operator must separately authenticate the bootstrap source
    before provisioning ROOT_EXECUTOR. This check alone does not
    establish independent code provenance.
    """
    need(os.geteuid() == 0, "ROOT_REQUIRED")
    need(
        Path(__file__).absolute() == ROOT_EXECUTOR,
        "EXECUTOR_NOT_ROOT_STAGED",
    )

    _root_file(ROOT_EXECUTOR)

    public = _root_file(ROOT_TRUST, 4096)
    need(
        sha(public) == PINS["bootstrap"],
        "ROOT_BOOTSTRAP_TRUST_PIN_MISMATCH",
    )

    _root_directory(ROOT_HOST)

    return ROOT_HOST, public


def _guard_host():
    """Read-only R116 deny check; no VM or network operations."""
    _root_file(DENY_GUARD)

    result = subprocess.run(
        [
            "/usr/bin/python3", "-I", "-B",
            str(DENY_GUARD), "--check",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=35,
        env={
            "PATH": "/usr/sbin:/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )

    need(
        result.returncode == 0
        and len(result.stdout) <= 65536,
        "R116_DENY_GUARD_FAILED",
    )

    status = json.loads(result.stdout)
    policy = status.get("policy", {})

    need(
        status.get("deny") == "MATCH"
        and status.get("host_writes") == 0
        and status.get("p8") == "NO-GO"
        and status.get("states") == {
            "ssh": "OFF",
            "runner": "OFF",
            "ftp": "OFF",
            "smb": "OFF",
        }
        and policy.get("active_count") == 0
        and policy.get("absent_count") == 6
        and policy.get("allow_traffic") is False,
        "PHYSICAL_DENY_NOT_0_6",
    )


def _input_bytes(path, maximum=2000000):
    fd = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        info = os.fstat(fd)
        need(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and not (info.st_mode & 0o022)
            and 0 < info.st_size <= maximum,
            "UNTRUSTED_INPUT_FILE",
        )
        raw = os.read(fd, maximum + 1)
        need(len(raw) == info.st_size,
             "INPUT_FILE_CHANGED")
        return raw
    finally:
        os.close(fd)


def root_stage(agent_path, candidate_path,
               contract_path, signature_path):
    """Root installation, gated by trusted root source and Ed25519.

    Install source only. Never launch the installed agent.
    """
    root, public = _root_context()

    _guard_host()

    agent_raw = _input_bytes(agent_path)
    candidate_raw = _input_bytes(candidate_path)
    contract_raw = _input_bytes(contract_path, 8192)
    signature_raw = _input_bytes(signature_path, 64)

    files = verify_contract(
        contract_raw,
        signature_raw,
        public,
        agent_raw,
        candidate_raw,
        now=datetime.now(timezone.utc),
    )

    # No root publication occurs before signature verification.
    result = stage_agent(root, files)

    need(audit_agent(root, files),
         "ROOT_AGENT_FINAL_AUDIT_FAILED")

    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)

    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--offline", action="store_true")
    modes.add_argument("--root-stage", action="store_true")

    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--contract", type=Path)
    parser.add_argument("--signature", type=Path)

    args = parser.parse_args()

    try:
        if args.offline:
            need(os.geteuid() != 0, "OFFLINE_ROOT_FORBIDDEN")
            need(
                args.contract is None and
                args.signature is None,
                "OFFLINE_UNEXPECTED_AUTHORIZATION",
            )

            files = bundles(
                _input_bytes(args.agent),
                _input_bytes(args.candidate),
            )

            print("R117_BOOTSTRAP_ARCHIVES=PASS")
            print("R117_BOOTSTRAP_AGENT_FILES=" + str(len(files)))
            print("R117_BOOTSTRAP_CANDIDATE_FILES=39")
            print("R117_BOOTSTRAP_ROOT_INSTALL=NOT_EXECUTED")

        else:
            need(
                args.contract is not None
                and args.signature is not None,
                "SIGNED_CONTRACT_REQUIRED",
            )

            report = root_stage(
                args.agent,
                args.candidate,
                args.contract,
                args.signature,
            )

            print(
                "R117_ROOT_AGENT_REPORT=" +
                json.dumps(report, sort_keys=True)
            )
            print("R117_ROOT_AGENT=INSTALLED_SOURCE_ONLY")
            print("R117_ROOT_AGENT_FINAL_AUDIT=PASS")

        print("R117_VM_STARTS=0")
        print("R117_NETWORK_ACTIONS=0")
        print("R117_P8=NO-GO")
        return 0

    except (
        Stop, OSError, ValueError, TypeError,
        KeyError, subprocess.TimeoutExpired
    ) as error:
        print(
            "R117_BOOTSTRAP_STOP=" +
            type(error).__name__ + ":" + str(error)[:150]
        )
        print("R117_P8=NO-GO")
        return 23


if __name__ == "__main__":
    raise SystemExit(main())
