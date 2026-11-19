#!/usr/bin/env python3
"""R106: durable R103/R104/R105 provenance bridge; local-fixture only, DENY.

The R105 socket contacts only 127.0.0.1. The F11 review is read-only;
its R103-F3 FAIL is never promoted to independent lifecycle accreditation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from threading import Thread

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO / "src"), str(REPO / "scripts")]

from ardrec.coordination import r59d_a5_result_intake as a5
from ardrec.coordination import r101_ssh_authority as r101
from ardrec.coordination import r106_ssh_case_provenance as bridge
import ardrec_p14_r104_prototype as r104
import ardrec_p14_r105_loopback_demo as r105

ROOT = Path("/home/cicada/ardrec-lab/r106-ssh-case-provenance-v1")
R104_ROOT = Path("/home/cicada/ardrec-lab/r104-functional-offline-v1")
F11_ROOT = Path("/home/cicada/ardrec-lab/r103-f5-independent-adjudication-v1")
MANIFEST_SCHEMA = "ardrec-r106-private-provenance-manifest-v1"
FILES = frozenset({"observation.json", "bridge.json", "manifest.json"})


def need(value: bool, reason: str) -> None:
    bridge.need(value, reason)


def source_proofs(r104_session: Path, f11_file: Path):
    need(r104_session.is_absolute() and r104_session.parent == R104_ROOT
         and r104_session.name.startswith("run-") and not r104_session.is_symlink(),
         "R104_OUTSIDE_EXPECTED_PRIVATE_ROOT")
    need(f11_file.is_absolute() and f11_file.name == "review.json"
         and f11_file.parent.parent == F11_ROOT
         and f11_file.parent.name.startswith("run-")
         and not f11_file.is_symlink(),
         "F11_OUTSIDE_EXPECTED_PRIVATE_ROOT")
    manifest = r104.verify(r104_session)
    report = r104._doc(r104_session, "report.json")
    need(report.get("sha256") == bridge.R104_REPORT_PIN
         and manifest.get("sha256") == bridge.R104_MANIFEST_PIN,
         "R104_EXPECTED_VERIFIED_SESSION_DRIFT")
    a5._private_root(f11_file.parent)
    review = r101.parse_private(a5._read_private(f11_file, a5.MAX_SUPPORT))
    bridge.verify_f11(review)
    need(a5.sha((REPO / "crates/ardrec-executor/src/"
                 "r105_ssh_kexinit_loopback.rs").read_bytes())
         == bridge.R105_SOURCE_PIN, "R105_RUST_SOURCE_DRIFT")
    return report, manifest, review


def observe_local() -> dict:
    """Run exactly one Rust SSHv2 fixture observation, without VM access."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
    except BaseException:
        listener.close()
        raise
    port = listener.getsockname()[1]
    errors: list[str] = []
    accepted: list[bytes] = []

    def serve() -> None:
        try:
            with listener:
                conn, address = listener.accept()
                with conn:
                    conn.settimeout(5)
                    need(address[0] == "127.0.0.1", "FIXTURE_NOT_LOOPBACK")
                    data = bytearray()
                    while not data.endswith(b"\n") and len(data) < 255:
                        byte = conn.recv(1)
                        need(bool(byte), "CLIENT_EARLY_EOF")
                        data.extend(byte)
                    accepted.append(bytes(data))
                    need(accepted == [r105.CLIENT], "UNEXPECTED_RUST_CLIENT")
                    conn.sendall(r105.SERVER + r105.packet())
        except Exception as exc:
            errors.append(type(exc).__name__ + ":" + str(exc)[:100])

    worker = Thread(target=serve, daemon=True)
    worker.start()
    try:
        cp = subprocess.run([
            "cargo", "run", "--quiet", "--locked", "--offline",
            "--example", "r105_ssh_kexinit_loopback", "--", str(port),
        ], cwd=REPO, stdin=subprocess.DEVNULL,
           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90,
           check=False, env={**os.environ, "CARGO_TERM_COLOR": "never"})
    finally:
        worker.join(timeout=6)
        listener.close()
    need(cp.returncode == 0 and not worker.is_alive() and not errors
         and accepted == [r105.CLIENT]
         and len(cp.stdout) < 8192 and len(cp.stderr) < 8192,
         "R105_FIXTURE_PROCESS_OR_IO_FAILED")
    def no_duplicate(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "RUST_JSON_DUPLICATE")
            result[key] = value
        return result
    observation = json.loads(cp.stdout, object_pairs_hook=no_duplicate)
    bridge.verify_r105(observation)
    return observation


def document(root: Path, name: str) -> dict:
    return r101.parse_private(a5._read_private(root / name, a5.MAX_SUPPORT))


def manifest_for(link: dict, observation: dict) -> dict:
    result = {
        "schema": MANIFEST_SCHEMA,
        "mode": "DURABLE_MIXED_PROVENANCE_NO_CASE_ATTESTATION",
        "link_sha256": link["sha256"],
        "observation_sha256": a5.digest(observation),
        "r104_report_sha256": link["r104_synthetic_report_sha256"],
        "r103_f11_review_sha256": link["r103_f11_forensic_review_sha256"],
        "r105_rust_source_sha256": bridge.R105_SOURCE_PIN,
        "boot_test_repeated": False,
        "vm_starts": 0,
        "ssh_authentication": False,
        "a5_operational_starts": 0,
        "a6_classification": "ND",
        "a7_confirmed_rf": None,
        "a8_transition_applied": None,
        "dispatch_allowed": False,
        "p8_operational": "NO-GO",
    }
    result["sha256"] = a5.digest(result)
    return result


def verify(session: Path, report: dict, source_manifest: dict,
           f11_review: dict) -> dict:
    a5._private_root(session)
    need({p.name for p in session.iterdir()} == FILES, "R106_SESSION_INVENTORY")
    observation = document(session, "observation.json")
    link = document(session, "bridge.json")
    manifest = document(session, "manifest.json")
    bridge.verify_link(link, report, source_manifest, observation, f11_review)
    need(manifest == manifest_for(link, observation), "R106_MANIFEST_TAMPERED")
    return manifest


def persist(report: dict, source_manifest: dict,
            observation: dict, f11_review: dict, base: Path) -> tuple[Path, dict]:
    need(isinstance(base, Path) and base.is_absolute(), "R106_ROOT_NOT_ABSOLUTE")
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    a5._private_root(base)
    link = bridge.build(report, source_manifest, observation, f11_review)
    manifest = manifest_for(link, observation)
    session = Path(tempfile.mkdtemp(prefix="run-", dir=base))
    a5._private_root(session)
    for name, doc in (("observation.json", observation),
                      ("bridge.json", link), ("manifest.json", manifest)):
        a5._store_once(session / name, a5.canonical(doc) + b"\n",
                       a5.MAX_SUPPORT)
    fd = os.open(session, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    need(verify(session, report, source_manifest, f11_review) == manifest,
         "R106_PRIVATE_READBACK_FAILED")
    return session, manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline-local-fixture", action="store_true")
    parser.add_argument("--r104-session", type=Path, required=True)
    parser.add_argument("--f11-review", type=Path, required=True)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if Path.cwd().resolve() != REPO or (args.verify is None) != args.offline_local_fixture:
        print("R106_STOP=REPO_OR_EXPLICIT_MODE_REQUIRED")
        return 23
    try:
        report, source_manifest, f11_review = source_proofs(
            args.r104_session, args.f11_review,
        )
        if args.verify is not None:
            need(args.verify.is_absolute() and args.verify.parent == ROOT
                 and args.verify.name.startswith("run-") and not args.verify.is_symlink(),
                 "VERIFY_SESSION_OUTSIDE_PRIVATE_ROOT")
            session = args.verify
            manifest = verify(session, report, source_manifest, f11_review)
        else:
            observation = observe_local()
            session, manifest = persist(report, source_manifest, observation,
                                        f11_review, ROOT)
        print("R106_R104_CASES=54")
        print("R106_R103_F11=DENIAL_OBSERVED_ORIGINAL_FAIL_PRESERVED")
        print("R106_R105_LOOPBACK=PASS_FIXTURE_ONLY")
        print("R106_CASE=SSH-T01-S01-01")
        print("R106_CASE_BINDING=SYNTHETIC_PROVENANCE_ONLY")
        print("R106_BRIDGE_SHA256=" + manifest["link_sha256"])
        print("R106_MANIFEST_SHA256=" + manifest["sha256"])
        print("R106_SESSION=" + str(session))
        print("R106_A5=NO_OPERATIONAL_START")
        print("R106_A6=ND")
        print("R106_P8=NO-GO")
        print("R106_RESULT=DURABLE_PROVENANCE_REPLAY_VERIFIED")
        return 0
    except (OSError, ValueError, KeyError, TypeError, TimeoutError,
            subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print("R106_STOP=" + type(exc).__name__ + ":" + str(exc)[:160])
        print("R106_P8=NO-GO")
        return 23


if __name__ == "__main__":
    raise SystemExit(main())
