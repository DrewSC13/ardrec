#!/usr/bin/env python3
"""ARDREC R163 V3: externally staged root-owned SOURCE-CANDIDATE agent.

This agent is deliberately NOT a live B4/B9 operational installer.
It does not start VMs, open traffic, invoke FTP, or grant P8.
A mutable checkout cannot invoke its privileged actions.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

SCHEMA = "ARDREC-R163-V3-ROOT-SOURCE-BUNDLE-v1"
ROOT_DIR = Path("/opt/ardrec/r163-installer-v1")
SELF = ROOT_DIR / "installer.py"
RUNTIME = ROOT_DIR / "runtime"
STATE = Path("/var/lib/ardrec/r163-stage-state-v1")
PARENT = Path("/var/lib/ardrec")
TRUST = Path("/etc/ardrec/r163-stage-trust-v1.json")
AUTH = Path("/etc/ardrec/r163-stage-authorization-v1.json")
REV = Path("/etc/ardrec/r163-stage-revocation-v1.json")
MANIFEST = ROOT_DIR / "manifest.json"

B4_SHA = "f64ce5f8c31cd80f98d07f47eb99728e15e406a66b697044e3d5eefd6a3f73e8"
B9_SHA = "c3c840f66476f3f0bbd87e48f657fdc6270e09b57b130eaf9c5b3cb68980cbd3"

RUNTIME_NAMES = (
    "r146_independent_install",
    "r163_single_operator_install_policy",
    "r163_install_phase_gate",
    "r163_single_operator_stage",
)
FILES = (
    "installer.py",
    *(f"runtime/{n}.py" for n in RUNTIME_NAMES),
    "source/B4/source.py",
    "source/B9/source.py",
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
PERSON = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")


class Refusal(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Refusal(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(doc):
    return (
        json.dumps(doc, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True, allow_nan=False) + "\n"
    ).encode("ascii")


def parse(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 20000,
         "MANIFEST_BYTES_INVALID")

    def pairs(values):
        out = {}
        for key, value in values:
            need(key not in out, "DUPLICATE_JSON_KEY")
            out[key] = value
        return out

    try:
        data = json.loads(
            raw, object_pairs_hook=pairs,
            parse_constant=lambda x: need(False, "NONFINITE_JSON")
        )
    except Refusal:
        raise
    except (ValueError, UnicodeError, TypeError) as exc:
        raise Refusal("INVALID_JSON") from exc

    need(type(data) is dict and canonical(data) == raw,
         "NONCANONICAL_MANIFEST")
    return data


def bundle_manifest(files, *, head, tree, operator_uid, operator_id):
    """Construct exact reproducible manifest from immutable source bytes."""
    need(type(files) is dict and set(files) == set(FILES),
         "BUNDLE_FILE_SCOPE_INVALID")
    need(type(head) is str and HEX40.fullmatch(head),
         "BUNDLE_HEAD_INVALID")
    need(type(tree) is str and HEX40.fullmatch(tree),
         "BUNDLE_TREE_INVALID")
    need(type(operator_uid) is int and operator_uid > 0,
         "BUNDLE_UID_INVALID")
    need(type(operator_id) is str and PERSON.fullmatch(operator_id),
         "BUNDLE_OPERATOR_INVALID")
    need(all(type(raw) is bytes and 0 < len(raw) <= 500000
             for raw in files.values()),
         "BUNDLE_SOURCE_BYTES_INVALID")
    need(sum(map(len, files.values())) <= 2000000,
         "BUNDLE_TOTAL_SIZE_INVALID")
    need(digest(files["source/B4/source.py"]) == B4_SHA,
         "BUNDLE_B4_PIN_INVALID")
    need(digest(files["source/B9/source.py"]) == B9_SHA,
         "BUNDLE_B9_PIN_INVALID")

    inventory = canonical({
        "B4/source.py": B4_SHA,
        "B9/source.py": B9_SHA,
    })

    return canonical({
        "schema": SCHEMA,
        "approved_head": head,
        "approved_tree": tree,
        "operator_uid": operator_uid,
        "operator_id": operator_id,
        "files": {
            name: digest(raw)
            for name, raw in sorted(files.items())
        },
        "inventory_sha256": digest(inventory),
        "custody_mode": "SINGLE_HUMAN_OPERATOR",
        "independent_authority": False,
        "operational_activation": False,
        "candidate_only": True,
        "network_traffic_authorized": False,
        "p8": "NO-GO",
    })


def verify_bundle(manifest_raw, files):
    """Reject manifest forgery, scope drift and modified B4/B9 sources."""
    doc = parse(manifest_raw)
    need(set(doc) == {
        "schema", "approved_head", "approved_tree",
        "operator_uid", "operator_id", "files",
        "inventory_sha256", "custody_mode",
        "independent_authority", "operational_activation",
        "candidate_only", "network_traffic_authorized", "p8"
    }, "MANIFEST_FIELDS_INVALID")
    expected = bundle_manifest(
        files,
        head=doc["approved_head"],
        tree=doc["approved_tree"],
        operator_uid=doc["operator_uid"],
        operator_id=doc["operator_id"],
    )
    need(manifest_raw == expected, "BUNDLE_IDENTITY_MISMATCH")
    return doc


def secure_parent(path, private=False):
    info = path.lstat()
    need(
        stat.S_ISDIR(info.st_mode)
        and not path.is_symlink()
        and info.st_uid == 0
        and not (info.st_mode & 0o022),
        "UNSAFE_ROOT_PARENT:" + str(path)
    )
    if private:
        need(stat.S_IMODE(info.st_mode) == 0o700,
             "ROOT_PRIVATE_DIRECTORY_REQUIRED")
    return True


def secure_read(path, limit=500000):
    need(isinstance(path, Path) and path.is_absolute()
         and not path.is_symlink(), "ROOT_FILE_PATH_INVALID")
    for parent in reversed(path.parents):
        secure_parent(parent)
    descriptor = os.open(
        path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        info = os.fstat(descriptor)
        need(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and 0 < info.st_size <= limit,
            "ROOT_FILE_METADATA_INVALID"
        )
        data = bytearray()
        while len(data) < info.st_size:
            chunk = os.read(descriptor, info.st_size - len(data))
            need(bool(chunk), "ROOT_FILE_SHORT_READ")
            data.extend(chunk)
        after = os.fstat(descriptor)
        need(
            (info.st_dev, info.st_ino, info.st_size,
             info.st_mtime_ns, info.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size,
             after.st_mtime_ns, after.st_ctime_ns),
            "ROOT_FILE_CHANGED_DURING_READ"
        )
        return bytes(data)
    finally:
        os.close(descriptor)


def root_entry():
    need(os.geteuid() == 0, "ROOT_REQUIRED")
    need(sys.flags.isolated == 1 and sys.dont_write_bytecode,
         "ISOLATED_PYTHON_REQUIRED")
    need(Path(__file__).absolute() == SELF
         and not Path(__file__).is_symlink(),
         "EXTERNALLY_INSTALLED_AGENT_REQUIRED")
    for path in (
        ROOT_DIR, RUNTIME, ROOT_DIR / "source",
        ROOT_DIR / "source/B4", ROOT_DIR / "source/B9",
        STATE
    ):
        secure_parent(path, private=True)
    secure_parent(PARENT)
    need(STATE.stat().st_dev == PARENT.stat().st_dev,
         "ROOT_FILESYSTEM_MISMATCH")


def load_bundle():
    root_entry()
    raw = secure_read(MANIFEST, 20000)
    files = {
        name: secure_read(ROOT_DIR / name)
        for name in FILES
    }
    doc = verify_bundle(raw, files)
    return raw, doc, files


def load_runtime():
    """Only root-owned pinned installed modules enter the import graph."""
    package = types.ModuleType("ardrec")
    package.__path__ = [str(RUNTIME)]
    subpackage = types.ModuleType("ardrec.coordination")
    subpackage.__path__ = [str(RUNTIME)]
    sys.modules["ardrec"] = package
    sys.modules["ardrec.coordination"] = subpackage

    modules = {}
    for name in RUNTIME_NAMES:
        fullname = "ardrec.coordination." + name
        path = RUNTIME / (name + ".py")
        spec = importlib.util.spec_from_file_location(fullname, path)
        need(spec is not None and spec.loader is not None,
             "INSTALLED_MODULE_LOAD_INVALID")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[fullname] = mod
        spec.loader.exec_module(mod)
        modules[name] = mod

    return modules


def build_gate(manifest_raw, doc, files, modules):
    phase = modules["r163_install_phase_gate"]
    engine = modules["r146_independent_install"]

    trusted = secure_read(TRUST, 8192)
    authorization = secure_read(AUTH, 16384)
    original_boot = Path(
        "/proc/sys/kernel/random/boot_id"
    ).read_text(encoding="ascii").strip()

    def fresh_revocation(_phase):
        # Root-owned authorization and installed code must remain pinned.
        need(secure_read(MANIFEST, 20000) == manifest_raw,
             "LIVE_AGENT_MANIFEST_CHANGED")
        need(secure_read(TRUST, 8192) == trusted,
             "LIVE_TRUST_ANCHOR_CHANGED")
        need(secure_read(AUTH, 16384) == authorization,
             "LIVE_AUTHORIZATION_CHANGED")
        need(
            Path("/proc/sys/kernel/random/boot_id")
            .read_text(encoding="ascii").strip() == original_boot,
            "LIVE_BOOT_ID_CHANGED"
        )
        for name in FILES:
            need(secure_read(ROOT_DIR / name) == files[name],
                 "LIVE_INSTALLED_SOURCE_CHANGED:" + name)
        return secure_read(REV, 16384)

    plan = {
        "schema": phase.PLAN_SCHEMA,
        "session": engine.parse(
            authorization, 16384
        )["statement"]["session"],
        "head": doc["approved_head"],
        "tree": doc["approved_tree"],
        "boot_id": original_boot,
        "operator_uid": doc["operator_uid"],
        "operator_id": doc["operator_id"],
        "inventory_sha256": doc["inventory_sha256"],
        "agent_bundle_sha256": digest(manifest_raw),
        "source_b4_sha256": B4_SHA,
        "source_b9_sha256": B9_SHA,
        "destinations": list(engine.DESTINATIONS),
        "custody_mode": "SINGLE_HUMAN_OPERATOR",
        "independent_authority": False,
        "root_install_authorized": False,
        "network_traffic_authorized": False,
        "vm_start_authorized": False,
        "action": "INSTALL_B4_B9_ONLY",
        "p8": "NO-GO",
    }
    return phase.PhaseGate(
        plan=plan,
        trust_raw=trusted,
        authorization_raw=authorization,
        read_live_revocation=fresh_revocation,
        now_provider=lambda: datetime.now(timezone.utc),
    )


def run_preflight():
    raw, doc, files = load_bundle()
    modules = load_runtime()
    gate = build_gate(raw, doc, files, modules)
    result = gate.review("before_journal")
    need(result["root_install_authorized"] is False,
         "ROOT_AUTHORITY_FORGERY")
    print("R163_V3_PREFLIGHT=PASS_SIGNED_SOURCE_ONLY")
    print("R163_V3_ROOT_INSTALL=NO")
    print("R163_V3_P8=NO-GO")


def run_stage():
    raw, doc, files = load_bundle()
    modules = load_runtime()
    gate = build_gate(raw, doc, files, modules)
    result = modules["r163_single_operator_stage"].stage(
        root_parent=PARENT,
        state_dir=STATE,
        gate=gate,
        b4=files["source/B4/source.py"],
        b9=files["source/B9/source.py"],
    )
    need(result["candidate_only"] is True
         and result["root_install_authorized"] is False
         and result["runtime_activated"] is False,
         "STAGING_AUTHORITY_INVALID")
    print("R163_V3_STAGING=" + result["status"])
    print("R163_V3_RECEIPT_SHA256=" + result["receipt_sha256"])
    print("R163_V3_RUNTIME_ACTIVATION=NO")
    print("R163_V3_TRAFFIC=0")
    print("R163_V3_P8=NO-GO")


def main():
    parser = argparse.ArgumentParser()
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--capabilities", action="store_true")
    actions.add_argument("--preflight", action="store_true")
    actions.add_argument("--stage", action="store_true")
    args = parser.parse_args()

    if args.capabilities:
        print("R163_V3_AGENT=SOURCE_CANDIDATE")
        print("R163_V3_EXTERNAL_ROOT_BOOTSTRAP_REQUIRED=YES")
        print("R163_V3_RUNTIME_ACTIVATION=NO")
        print("R163_V3_P8=NO-GO")
        return 0

    try:
        if args.preflight:
            run_preflight()
        else:
            run_stage()
        return 0
    except (Refusal, ValueError, OSError, ImportError,
            RuntimeError, KeyError, TypeError) as exc:
        print(
            "R163_V3_STOP=" + type(exc).__name__
            + ":" + str(exc)[:200]
        )
        print("R163_V3_P8=NO-GO")
        return 23


if __name__ == "__main__":
    raise SystemExit(main())
