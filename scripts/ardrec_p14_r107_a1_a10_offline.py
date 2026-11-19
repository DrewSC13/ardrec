#!/usr/bin/env python3
"""R107: unified offline A1-A10 status ledger for 54 R104 synthetic windows.

Loads *verified* R104 and R106 private receipts; never starts a VM or
runs an SSH/FTP/SMB client. The 10 stages are conservative audit statuses,
not a claim of complete operational A1-A10 algorithm implementation.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO / "src"), str(REPO / "scripts")]

from ardrec.coordination import r59d_a5_result_intake as a5
from ardrec.coordination import r101_ssh_authority as r101
from ardrec.coordination import r107_offline_a1_a10_orchestrator as engine
import ardrec_p14_r104_prototype as r104
import ardrec_p14_r106_ssh_case_bridge as r106_cli

ROOT = Path("/home/cicada/ardrec-lab/r107-offline-a1-a10-v1")
MANIFEST_SCHEMA = "ardrec-r107-private-replay-manifest-v1"
FILES = frozenset({"trace.json", "manifest.json"})


def need(ok: bool, code: str) -> None:
    engine.need(ok, code)


def source_documents(r104_session: Path, r106_session: Path,
                     f11_file: Path) -> tuple[dict, dict, dict, dict]:
    """Reopen provenances; verify R106 against original R104/F11/R105 pins."""
    report, manifest104, review = r106_cli.source_proofs(
        r104_session, f11_file)
    need(r106_session.is_absolute() and r106_session.parent == r106_cli.ROOT
         and r106_session.name.startswith("run-")
         and not r106_session.is_symlink(), "R106_SESSION_PATH_INVALID")
    manifest106 = r106_cli.verify(
        r106_session, report, manifest104, review)
    link = r106_cli.document(r106_session, "bridge.json")
    engine.verify_sources(report, manifest104, link, manifest106)
    return report, manifest104, link, manifest106


def _doc(directory: Path, name: str) -> dict:
    return r101.parse_private(
        a5._read_private(directory / name, a5.MAX_SUPPORT))


def manifest_for(trace: dict) -> dict:
    need(trace.get("schema") == engine.SCHEMA
         and trace.get("a5_operational_starts") == 0
         and trace.get("a6_classification") == "ND"
         and trace.get("p8_operational") == "NO-GO", "TRACE_NOT_CONSERVATIVE")
    result = {
        "schema": MANIFEST_SCHEMA,
        "mode": "OFFLINE_READ_ONLY_STATUS_TRACE",
        "trace_sha256": trace["sha256"],
        "trace_bytes_sha256": a5.sha(a5.canonical(trace) + b"\n"),
        "r104_manifest_sha256": trace["r104_manifest_sha256"],
        "r106_manifest_sha256": trace["r106_manifest_sha256"],
        "case_window_count": 54,
        "stage_status_count": 540,
        "r106_linked_identity_count": 1,
        "independent_physical_case_attestation": False,
        "a1_a10_operational_implementation_complete": False,
        "a5_operational_starts": 0,
        "a6_classification": "ND",
        "a7_confirmed_rf": None,
        "a9_published_generations": 0,
        "operational_dispatch": False,
        "vm_starts": 0,
        "p8_operational": "NO-GO",
    }
    result["sha256"] = a5.digest(result)
    return result


def verify(root: Path, report: dict, manifest104: dict,
           link106: dict, manifest106: dict) -> tuple[dict, dict]:
    a5._private_root(root)
    need({p.name for p in root.iterdir()} == FILES,
         "R107_SESSION_INVENTORY")
    trace = _doc(root, "trace.json")
    manifest = _doc(root, "manifest.json")
    engine.verify_trace(trace, report, manifest104, link106, manifest106)
    need(manifest == manifest_for(trace), "R107_MANIFEST_REPLAY_FAILED")
    return trace, manifest


def persist(report: dict, manifest104: dict, link106: dict,
            manifest106: dict, base: Path) -> tuple[Path, dict, dict]:
    need(isinstance(base, Path) and base.is_absolute(), "PRIVATE_ROOT_ABSOLUTE")
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    a5._private_root(base)
    trace = engine.build(report, manifest104, link106, manifest106)
    manifest = manifest_for(trace)
    session = Path(tempfile.mkdtemp(prefix="run-", dir=base))
    a5._private_root(session)
    for name, item in (("trace.json", trace), ("manifest.json", manifest)):
        a5._store_once(session / name, a5.canonical(item) + b"\n",
                       a5.MAX_SUPPORT)
    descriptor = os.open(session, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    need(verify(session, report, manifest104, link106, manifest106)
         == (trace, manifest), "R107_READBACK_REPLAY_FAILED")
    return session, trace, manifest


def display(session: Path, trace: dict, manifest: dict, *, table: bool = False,
            case_id: str | None = None) -> None:
    print("R107_CASES=" + str(trace["case_window_count"]))
    print("R107_FAMILIES=" + str(trace["family_count"]))
    print("R107_SERVICES=" + json.dumps(trace["count_by_service"], sort_keys=True))
    print("R107_ALGORITHMS=" + ",".join(trace["algorithm_ids"]))
    print("R107_STAGE_STATUS_EVENTS=" + str(trace["stage_status_count"]))
    print("R107_R106_LINKED_CASES=" + str(trace["r106_linked_identity_count"]))
    print("R107_A1_A10_IMPLEMENTATION_COMPLETE=FALSE")
    print("R107_A5=NO_OPERATIONAL_START")
    print("R107_A6=ND")
    print("R107_A7_RF=NOT_CONFIRMED")
    print("R107_A8=PAUSE_RECOMMENDED_NOT_APPLIED")
    print("R107_A9=PUBLISHED_0")
    print("R107_REPORT_SHA256=" + trace["sha256"])
    print("R107_MANIFEST_SHA256=" + manifest["sha256"])
    print("R107_SESSION=" + str(session))
    print("R107_VM_STARTS=0")
    print("R107_P8=NO-GO")
    if table:
        print("R107_TABLE_HEADER=SERVICE|SESSION|CASE|FAMILY|A6|A7_LOWER|A7_UPPER|R106_LINK")
        for item in trace["cases"]:
            print("R107_TABLE_ROW=" + "|".join((
                item["service_id"], item["session_id"], item["derived_case_id"],
                item["family_id"], item["a6_classification"],
                item["a7_interval_lower"], item["a7_interval_upper"],
                "ASSOCIATION_ONLY" if item["r106_provenance_association_only"]
                else "NONE")))
    if case_id is not None:
        found = [item for item in trace["cases"]
                 if item["case_id_a7"] == case_id]
        need(len(found) == 1, "CASE_ID_NOT_UNIQUE_OR_UNKNOWN")
        print("R107_CASE_DETAIL=" + json.dumps(found[0], sort_keys=True))
    print("R107_RESULT=DURABLE_A1_A10_OFFLINE_TRACE_REPLAY_VERIFIED")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline-synthetic", action="store_true")
    parser.add_argument("--r104-session", type=Path, required=True)
    parser.add_argument("--r106-session", type=Path, required=True)
    parser.add_argument("--f11-review", type=Path, required=True)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--table", action="store_true")
    parser.add_argument("--case-id")
    args = parser.parse_args()
    if Path.cwd().resolve() != REPO or (args.verify is None) != args.offline_synthetic:
        print("R107_STOP=REPOSITORY_OR_OFFLINE_MODE_REQUIRED")
        return 23
    try:
        report, manifest104, link106, manifest106 = source_documents(
            args.r104_session, args.r106_session, args.f11_review)
        if args.verify is None:
            session, trace, manifest = persist(
                report, manifest104, link106, manifest106, ROOT)
        else:
            need(args.verify.is_absolute() and args.verify.parent == ROOT
                 and args.verify.name.startswith("run-")
                 and not args.verify.is_symlink(), "R107_VERIFY_PATH_INVALID")
            session = args.verify
            trace, manifest = verify(
                session, report, manifest104, link106, manifest106)
        display(session, trace, manifest, table=args.table, case_id=args.case_id)
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        print("R107_STOP=" + type(exc).__name__ + ":" + str(exc)[:180])
        print("R107_P8=NO-GO")
        return 23


if __name__ == "__main__":
    raise SystemExit(main())
