"""Native batch I2–A7–A8 for the existing private research matrix.

Calculates only documentary candidates from complete, hash-checked inputs.
No operational baseline, evidence admission, dispatch, or A9 publication.
"""
from __future__ import annotations

import argparse
import csv
import io
import os
import stat
import sys
from pathlib import Path

from ardrec.experiments import (
    baseline_preparation as i2,
    paired_reconciliation as i8,
    prospective_risk_integration as risk,
    r148_paired_register as r148,
    r149_scenario_design as r149,
)

SCHEMA = "ARDREC-R336-MATRIX-BATCH-v1"
FIELDS = r149.FIELDS + ("configuration_sha256",) + tuple(
    f"{dimension}_{kind}" for dimension in i2.DIMENSIONS
    for kind in ("ordinal", "support_sha256", "justification")
)
EDITABLE = FIELDS[3:]
SUPPORTS = tuple(k for k in EDITABLE if k.endswith("_sha256"))
MAX_MATRIX = 4_000_000


def need(ok, code):
    if not ok:
        raise ValueError(code)


def parse_matrix(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_MATRIX,
         "MATRIX_SIZE_INVALID")
    text = raw.decode("utf-8", "strict")
    need("\r" not in text and "\x00" not in text, "MATRIX_CONTROL_INVALID")
    records = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    need(len(records) == 55 and tuple(records[0]) == FIELDS
         and all(len(x) == len(FIELDS) for x in records[1:]),
         "MATRIX_SHAPE_INVALID")
    rows = [dict(zip(FIELDS, record)) for record in records[1:]]
    for row in rows:
        need(all(len(v) <= 2000 and all(ord(c) >= 32 for c in v)
                 and not v.startswith(("=", "+", "-", "@"))
                 for v in row.values()), "MATRIX_VALUE_INVALID")
        need(not any(row[k].upper().startswith("PILOT-") for k in
                     ("case_id", "scenario_id", "service_instance_id")),
             "PILOT_IDENTITY_REUSE_FORBIDDEN")
        for dimension in i2.DIMENSIONS:
            ordinal = row[dimension + "_ordinal"]
            reason = row[dimension + "_justification"]
            need(not ordinal or ordinal in ("1", "2", "3", "4", "5"),
                 "MATRIX_ORDINAL_INVALID")
            need(not reason or len(reason.strip()) >= 10,
                 "MATRIX_JUSTIFICATION_INVALID")
        need(all(not row[k] or i2.valid_sha(row[k]) for k in SUPPORTS),
             "MATRIX_SUPPORT_PIN_INVALID")
    return rows


def build(catalog, protocol, registry, plan, checklist, proposal, matrix_raw,
          read_support, *, expected_matrix_sha256):
    need(i2.valid_sha(expected_matrix_sha256)
         and i2.sha(matrix_raw) == expected_matrix_sha256,
         "MATRIX_PIN_INVALID")
    rows = parse_matrix(matrix_raw)
    selection = r149.csv_bytes([{key: row[key] for key in r149.FIELDS}
                               for row in rows])
    audit, selected = i8.reconcile_selection(protocol, registry, catalog,
                                            plan, checklist, selection, proposal)
    need(all(x["status"] == "PLANNED_UNASSIGNED" for x in registry["slots"]),
         "PROSPECTIVE_REGISTER_NOT_EMPTY")
    results = []
    for row, sel in zip(rows, selected, strict=True):
        slot = row["slot_id"]
        missing = [k for k in EDITABLE if not row[k]]
        refs = {row[k] for k in SUPPORTS if row[k]}
        objects = {}
        absent = []
        for ref in sorted(refs):
            try:
                raw = read_support(ref)
            except FileNotFoundError:
                absent.append(ref)
                continue
            need(type(raw) is bytes and 0 < len(raw) <= i2.MAX_SUPPORT_BYTES
                 and i2.sha(raw) == ref, "MATRIX_SUPPORT_INTEGRITY_INVALID:" + slot)
            objects[ref] = raw
        result = {"slot_id": slot, "protocol": row["protocol"],
                  "missing_fields": missing, "missing_supports": absent,
                  "verified_supports": sorted(objects), "decision": None,
                  "i2_candidate_sha256": None, "risk_report_sha256": None}
        if missing or absent:
            result["status"] = "PENDING_FIELDS" if missing else "PENDING_SUPPORTS"
        else:
            entry = {"slot_id": slot, "selection_sha256": i2.sha(selection),
                     "configuration_sha256": row["configuration_sha256"],
                     "ratings": {d: {"ordinal": int(row[d+"_ordinal"]),
                                     "support_sha256": row[d+"_support_sha256"],
                                     "justification": row[d+"_justification"]}
                                 for d in i2.DIMENSIONS}}
            source = i2.build(catalog, protocol, registry, plan, checklist,
                              selection, entry, objects)
            report = risk.build(source)
            need(risk.verify(report, source) and report["candidate_decision"] is not None,
                 "NATIVE_RISK_REPLAY_INVALID")
            result.update(status="DOCUMENTARY_CANDIDATE_UNVERIFIED",
                          decision=report["candidate_decision"],
                          i2_candidate_sha256=source["candidate"]["sha256"],
                          risk_report_sha256=report["sha256"])
        results.append(result)
    counts = {s: sum(r["status"] == s for r in results) for s in
              ("PENDING_FIELDS", "PENDING_SUPPORTS", "DOCUMENTARY_CANDIDATE_UNVERIFIED")}
    return r148._seal({"schema": SCHEMA, "matrix_sha256": expected_matrix_sha256,
                       "selection_sha256": audit["working_sha256"],
                       "protocol_sha256": protocol["sha256"],
                       "registry_sha256": registry["sha256"],
                       "catalog_sha256": r148.digest(catalog),
                       "planned_slots": 54, "counts": counts, "records": results,
                       "baseline_closed": 0, "confirmed_rf": None,
                       "a6": "ND", "a9": "NOT_PUBLISHED", "new_protocol_attempts": 0,
                       "experimental_admitted": 0, "p7": "DRAFT_NOT_FROZEN", "p8": "NO-GO"})


def private_dir(path):
    need(path.is_absolute() and path.resolve(strict=True) == path,
         "PRIVATE_DIRECTORY_PATH_INVALID")
    st = path.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()
         and stat.S_IMODE(st.st_mode) == 0o700, "PRIVATE_DIRECTORY_INVALID")


def read_sources(registry_folder, selection_folder):
    private_dir(registry_folder)
    private_dir(selection_folder)
    protocol, registry = (r148.decode(i2.read_private(registry_folder / name, r148.MAX_BYTES))
                          for name in ("protocol.json", "observations.json"))
    plan, checklist = (r149.decode(i2.read_private(selection_folder / name, r149.MAX_JSON))
                       for name in ("plan.json", "family-checklist.json"))
    original, proposal = (i2.read_private(selection_folder / name, r149.MAX_CSV)
                          for name in ("selection-working.csv", "family-proposal.csv"))
    return protocol, registry, plan, checklist, original, proposal


def evaluate(registry_folder, selection_folder, matrix_path, support_dir,
             catalog_path, expected_matrix_sha256):
    need(os.geteuid() != 0, "ROOT_FORBIDDEN")
    private_dir(matrix_path.parent)
    private_dir(support_dir)
    need(catalog_path.is_file() and not catalog_path.is_symlink(), "CATALOG_UNSAFE")
    catalog = catalog_path.read_bytes()
    sources = read_sources(registry_folder, selection_folder)
    protocol, registry, plan, checklist, original, proposal = sources
    i8.reconcile_selection(protocol, registry, catalog, plan, checklist, original, proposal)
    matrix = i2.read_private(matrix_path, MAX_MATRIX)
    report = build(catalog, protocol, registry, plan, checklist, proposal, matrix,
                   lambda ref: i2.read_private(support_dir / (ref + ".bin"), i2.MAX_SUPPORT_BYTES),
                   expected_matrix_sha256=expected_matrix_sha256)
    need(i2.read_private(matrix_path, MAX_MATRIX) == matrix
         and read_sources(registry_folder, selection_folder) == sources
         and catalog_path.read_bytes() == catalog, "BATCH_SOURCE_CHANGED")
    return report


def render_text(report):
    lines = ["ARDREC / R336 / I2-A7-A8 LOTE DOCUMENTAL", "MATRIX_SHA256=" + report["matrix_sha256"]]
    for row in report["records"]:
        decision = row["decision"]
        if decision is None:
            detail = f"FIELDS_MISSING={len(row['missing_fields'])} SUPPORTS_MISSING={len(row['missing_supports'])}"
        else:
            detail = (f"R0={decision['candidate_initial_risk']} CN={decision['candidate_normalized_criticality']} "
                      f"RF_CANDIDATE=[{decision['hypothetical_rf_lower']},{decision['hypothetical_rf_upper']}] A6=ND")
        lines.append(f"{row['slot_id']} {row['status']} {detail}")
    lines.extend(f"{key}={value}" for key, value in report["counts"].items())
    lines += ["BASELINES_CLOSED=0", "EXPERIMENTAL_ADMITTED=0", "P8=NO-GO",
              "REPORT_SHA256=" + report["sha256"], "PASS_R336_NATIVE_BATCH"]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Calculo documental I2-A7-A8 por lote")
    for name in ("registro", "seleccion", "matriz", "soportes"):
        parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--texto", action="store_true")
    output.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = evaluate(args.registro, args.seleccion, args.matriz, args.soportes,
                          Path("lab/operational-catalog-v1/catalog.json"), args.sha256)
        if args.json:
            sys.stdout.buffer.write(r148.canonical(report))
        else:
            sys.stdout.write(render_text(report))
        return 0
    except (ValueError, OSError, TypeError, KeyError, csv.Error, RecursionError) as exc:
        print("R336_STOP=" + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
