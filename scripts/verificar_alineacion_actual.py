"""Auditar el alcance documentado sin atribuir conformidad a brechas conocidas."""

import argparse
import copy
from dataclasses import fields
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from ardrec.contracts import ND, dump_magnitude, parse_magnitude
from ardrec.messages import correlate, encode_message
from ardrec.persistence.codec import StorageError, pack, unpack
from ardrec.state import AttemptState, ConfirmedState, Report, ServiceState

CURRENT = "6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72"
BASE = "526276d382798cf5d0cda1d1966b9e0c49ad4d24"
REVIEW = "docs/traceability/alignment-current-v1.json"
COVERAGE = "docs/acceptance/current-coverage-v1.json"


def need(condition, message):
    if not condition:
        raise ValueError(message)


def read(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def bilingual(value):
    need(type(value) is dict and set(value) == {"es", "en"}, "Texto bilingüe incompleto")
    need(all(type(s) is str and s.strip() for s in value.values()), "Texto vacío")


def documents(review, coverage):
    """Comprobar cobertura y afirmaciones antes de ejecutar las sondas."""
    need(review["source"] == {"label": "TESIS ARDREC", "sha256": CURRENT}, "Fuente distinta")
    need(review["baseline_commit"] == coverage["baseline_commit"] == BASE, "Base distinta")
    need(coverage["source"] == review["source"], "Procedencia incoherente")
    need(review["review_status"] == "COMPLETE_WITH_OPEN_FINDINGS_FOR_LISTED_SCOPE", "Estado de revisión incorrecto")
    for field, expected in {
        "full_specification_alignment": "PENDING", "system_functional_acceptance": "PENDING",
        "experimental_validation": "NOT_RUN", "algorithm_implementation": "NOT_STARTED",
        "operational_prototype": "NOT_STARTED",
    }.items():
        need(review[field] == expected, f"Afirmación no acreditada: {field}")
    need(coverage["status"] == "COMPONENT_COVERAGE_NOT_SYSTEM_ACCEPTANCE", "Confusión de cobertura y aceptación")
    need(coverage["review"] == REVIEW and coverage["historical_matrix"] == "docs/acceptance/system-v1.json", "Referencia incorrecta")
    scope = review["scope"]
    need(scope["known_files"] == len(scope["source_hashes"]) == 118, "Inventario incompleto")
    need(scope["kind"] == "RECONSTRUCTED_SOURCES_WITH_LOCAL_HASH_PREFLIGHT", "Alcance incorrecto")
    bilingual(scope["exclusions"])
    bilingual(scope["inventory_rule"])
    for name, expected in scope["source_hashes"].items():
        relative = Path(name)
        need(not relative.is_absolute() and ".." not in relative.parts, "Ruta fuera del alcance")
        path = ROOT / relative
        need(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), f"Archivo ausente o enlace: {name}")
        need(hashlib.sha256(path.read_bytes()).hexdigest() == expected, f"Revisión obsoleta: {name}")
    matrix = read(coverage["historical_matrix"])
    need(coverage["historical_matrix_sha256"] == scope["source_hashes"][coverage["historical_matrix"]], "Matriz histórica distinta")
    ids = {c["id"] for c in matrix["criteria"]}
    need(len(matrix["criteria"]) == len(ids) == 27 and len(matrix["invariants"]) == 15, "Matriz incompleta")
    need(len(coverage["criteria"]) == 27 and {c["id"] for c in coverage["criteria"]} == ids, "Criterios ausentes o duplicados")
    for c in coverage["criteria"]:
        need(c["implementation"] in {"PARTIAL", "NOT_IMPLEMENTED"}, "Implementación no acreditada")
        need(c["acceptance_status"] == c["system_functional_verification"] == "PENDING", "Aceptación no acreditada")
        need(c["experimental_validation"] == ("NOT_RUN" if int(c["id"][3:]) >= 25 else "NOT_APPLICABLE"), "Experimentación no acreditada")
        bilingual(c["remaining_work"])
        for name in c["component_support_files"]:
            need(name in scope["source_hashes"], f"Soporte fuera del contexto: {name}")
    findings = review["findings"]
    need(len(findings) == 9 and {f["id"] for f in findings} == {f"AL-{n:02}" for n in range(1,10)}, "Hallazgos incompletos")
    expected_open = {"AL-04", "AL-05", "AL-06", "AL-07", "AL-09"}
    need({f["id"] for f in findings if f["status"] == "OPEN"} == expected_open, "Se cerró una brecha sin nueva revisión")
    for f in findings:
        need(f["source_sections"] and f["gate"], "Falta fuente o condición de cierre")
        for key in ("decision", "observation", "closure_evidence_required"):
            bilingual(f[key])
    domains = review["domains"]
    need(len(domains) == 5 and {d["id"] for d in domains} == {
        "CONTRACTS", "STATES", "PERSISTENCE", "ACCEPTANCE", "REFERENCE_CASES",
    }, "Ámbitos incompletos")
    for domain in domains:
        need(domain["source_sections"] and set(domain["findings"]) <= {f["id"] for f in findings}, "Enlace de hallazgo inválido")
        bilingual(domain["assessment"])
    methods = review["methodological_requirements"]
    need(len(methods) == 17 and {m["id"] for m in methods} == {f"MET-{n:02}" for n in range(1,18)}, "Metodología incompleta")
    for m in methods:
        need(m["source_section"] in {"1.9.3", "1.9.4", "1.9.5"}, "Sección metodológica incorrecta")
        need(m["acceptance_criteria"] and set(m["acceptance_criteria"]) <= ids, "Enlace de criterio inválido")
        need(m["experimental_verification"] == "NOT_RUN", "Evidencia experimental no acreditada")
        bilingual(m["requirement"])
        bilingual(m["required_evidence"])
    catalog = read("tests/fixtures/model-reference-v1.json")
    need(len(catalog["cases"]) == len({c["id"] for c in catalog["cases"]}) == 51, "Catálogo incompleto")
    need(catalog["model_verification"] == "NOT_RUN", "Oráculos confundidos con pruebas del motor")
    for c in catalog["cases"]:
        need(c["production_test_status"] == "NOT_RUN", "Verificación de algoritmo no acreditada")
        need(set(c["acceptance_criteria"]) <= ids, "Criterio de referencia ausente")
    return sorted(expected_open)


def storage_observation(value):
    try:
        encoded = pack(value)
        restored = unpack(encoded)
        need(restored == value, "El codec perdió el valor")
        return "ACCEPTED"
    except StorageError as error:
        return error.code


def probe(rust_probe=None):
    """Observar brechas actuales; esta función no pretende corregirlas."""
    fixture = read("tests/fixtures/messages-v2.json")
    request = copy.deepcopy(fixture["request"])
    result = copy.deepcopy(fixture["result_completed"])
    result["payload"]["outcome"]["started_at"] = "2026-10-18T12:00:00Z"
    result["payload"]["outcome"]["ended_at"] = "2026-10-18T12:00:01Z"
    before = json.dumps([request, result], sort_keys=True)
    correlate(request, result)
    AttemptState(encode_message(request), (Report(encode_message(result)),))
    need(json.dumps([request, result], sort_keys=True) == before, "La sonda modificó la entrada")
    rust_result = "NOT_RUN"
    if rust_probe is not None:
        call = {"op": "correlate", "args": [request, result]}
        response = subprocess.run([str(rust_probe.resolve())], input=json.dumps(call),
                                  text=True, capture_output=True, timeout=10, check=True)
        need(json.loads(response.stdout) == {"ok": True, "value": {}}, "La observación Rust cambió; revisar el hallazgo")
        rust_result = "ACCEPTED"
    large = Fraction(1, 2**100+1)
    encoded = dump_magnitude(large)
    need(parse_magnitude(encoded) == large, "El contrato numérico no conservó el racional")
    numeric = {
        "fraction_direct": storage_observation(Fraction(1,3)),
        "nd_direct": storage_observation(ND("SOPORTE_INSUFICIENTE")),
        "small_encoded_magnitude": storage_observation(dump_magnitude(Fraction(1,3))),
        "large_encoded_magnitude": storage_observation(encoded),
    }
    need(numeric == {
        "fraction_direct": "type_unsupported", "nd_direct": "type_unsupported",
        "small_encoded_magnitude": "ACCEPTED", "large_encoded_magnitude": "integer_range",
    }, "La observación de persistencia cambió; actualizar la revisión")
    return {
        "temporal": {"request_created_at": request["created_at"],
                     "outcome_started_at": result["payload"]["outcome"]["started_at"],
                     "python_correlation": "ACCEPTED", "python_attempt": "ACCEPTED",
                     "rust_correlation": rust_result, "meaning": "OPEN_FINDING_NOT_CONFORMANCE"},
        "numeric_storage": numeric,
        "state_fields_observed": {
            "ServiceState": [f.name for f in fields(ServiceState)],
            "ConfirmedState": [f.name for f in fields(ConfirmedState)],
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Auditar alineación / Audit alignment")
    parser.add_argument("--rust-probe", type=Path)
    parser.add_argument("--require-conformance", action="store_true")
    args = parser.parse_args()
    need(platform.python_version() == "3.14.7", "Usar Python 3.14.7")
    review, coverage = read(REVIEW), read(COVERAGE)
    open_findings = documents(review, coverage)
    observations = probe(args.rust_probe)
    report = {"review_id": review["review_id"], "baseline_commit": BASE,
              "source": review["source"], "audit_execution": "COMPLETE",
              "reviewed_files": 118, "domains": 5, "criteria": 27,
              "methodological_requirements": 17, "open_findings": open_findings,
              "observations": observations, "full_specification_alignment": "PENDING",
              "system_functional_acceptance": "PENDING", "experimental_validation": "NOT_RUN"}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("ARDREC_ALIGNMENT_REVIEW=COMPLETE_WITH_OPEN_FINDINGS")
    print("ARDREC_FULL_SPECIFICATION_ALIGNMENT=PENDING")
    print("ARDREC_ALGORITHM_IMPLEMENTATION=NOT_STARTED")
    print("ARDREC_OPERATIONAL_PROTOTYPE=NOT_STARTED")
    return 2 if args.require_conformance and open_findings else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"ARDREC_ALIGNMENT_AUDIT=FAIL: {error}", file=sys.stderr)
        sys.exit(1)
