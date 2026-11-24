"""Interfaz de estudio experimental: lectura y analisis no autoritativo."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from ardrec.experiments import (
    r148_paired_register as r148,
    r149_scenario_design as r149,
)

CATALOG = Path("lab/operational-catalog-v1/catalog.json")


def need(ok, code):
    if not ok:
        raise ValueError(code)


def evaluate(registry_folder, selection_folder=None, analysis=False):
    need(os.geteuid() != 0, "ROOT_FORBIDDEN")
    need(
        CATALOG.is_file() and not CATALOG.is_symlink(),
        "CATALOG_UNSAFE",
    )

    catalog = CATALOG.read_bytes()

    protocol, registry = r148.read(
        registry_folder, catalog
    )

    audit = r148.validate(
        protocol, registry, catalog
    )

    selection = None

    if selection_folder is not None:
        selection = r149.read(
            selection_folder,
            catalog,
            protocol,
            registry,
        )

    statistics = (
        r148.analyze(protocol, registry, catalog)
        if analysis else None
    )

    need(
        audit["confirmed_physical_observations"] == 0
        and audit["a9"] == "NOT_PUBLISHED"
        and audit["p8"] == "NO-GO",
        "REGISTRY_AUTHORITY_INVALID",
    )

    if selection is not None:
        need(
            selection["physical_observations"] == 0
            and selection["p7"] == "DRAFT_NOT_FROZEN"
            and selection["p8"] == "NO-GO",
            "SELECTION_AUTHORITY_INVALID",
        )

    if statistics is not None:
        need(
            statistics["claim"]
            == "EXPLORATORY_UNVERIFIED_NOT_THESIS_RESULT"
            and statistics["physical_evidence_verified"] is False
            and statistics["independent_rubric_verified"] is False
            and statistics["p7_frozen_verified"] is False,
            "STATISTICAL_AUTHORITY_INVALID",
        )

    report = {
        "schema": "ARDREC-R179-STUDY-CLI-v1",
        "scope": "READONLY_UNVERIFIED_STUDY_INPUTS",
        "source_head": protocol["head"],
        "catalog_sha256": r148.digest(catalog),
        "protocol_sha256": protocol["sha256"],
        "registry_sha256": registry["sha256"],
        "registry": audit,
        "selection": selection,
        "statistics": statistics,
        "confirmed_physical_observations": 0,
        "confirmatory_analysis_authorized": False,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
        "a6": "ND",
        "a9": "NOT_PUBLISHED",
    }

    report["sha256"] = r148.digest(
        r148.canonical(report)
    )

    return report


def render_text(report):
    audit = report["registry"]

    lines = [
        "ARDREC / ESTUDIO EXPERIMENTAL",
        f"ALCANCE={report['scope']}",
        f"ORIGEN_HEAD={report['source_head']}",
        f"REGISTRO_SHA256={report['registry_sha256']}",
        f"POSICIONES={audit['planned']}",
    ]

    for protocol, count in sorted(
        audit["by_protocol"].items()
    ):
        lines.append(f"POSICIONES_{protocol}={count}")

    for status, count in sorted(
        audit["statuses"].items()
    ):
        lines.append(f"{status}={count}")

    selection = report["selection"]

    if selection is not None:
        lines.extend([
            f"SELECCION={selection['readiness']}",
            f"SELECCION_COMPLETA={selection['statuses']['COMPLETE']}",
            f"SELECCION_PARCIAL={selection['statuses']['PARTIAL']}",
            f"SELECCION_VACIA={selection['statuses']['EMPTY']}",
            f"SELECCION_SHA256={selection['working_sha256']}",
        ])

    statistics = report["statistics"]

    if statistics is not None:
        test = statistics["primary_comparison"]
        lines.extend([
            f"ANALISIS={statistics['claim']}",
            f"PARES_NO_VERIFICADOS={test['n_pairs']}",
            f"PARES_NO_NULOS={test['n_nonzero']}",
            f"PARES_CERO={test['n_zero']}",
            "WILCOXON_P=" + (
                test["p_one_sided_exact"]
                if test["p_one_sided_exact"] is not None
                else "ND"
            ),
            f"WILCOXON_DECISION={test['decision']}",
        ])

    lines.extend([
        "OBSERVACIONES_FISICAS_ADMITIDAS=0",
        "ANALISIS_CONFIRMATORIO=NO_AUTORIZADO",
        f"P7={report['p7']}",
        f"P8={report['p8']}",
        f"RECIBO_SHA256={report['sha256']}",
    ])

    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m ardrec estudio",
        description="Consulta experimental privada, sin admision de evidencia.",
    )

    parser.add_argument(
        "--registro", type=Path, required=True
    )

    parser.add_argument(
        "--seleccion", type=Path
    )

    parser.add_argument(
        "--analisis-exploratorio",
        action="store_true",
    )

    output = parser.add_mutually_exclusive_group(
        required=True
    )

    output.add_argument("--texto", action="store_true")
    output.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)

    try:
        report = evaluate(
            args.registro,
            args.seleccion,
            args.analisis_exploratorio,
        )

        if args.json:
            sys.stdout.buffer.write(
                r148.canonical(report)
            )
        else:
            sys.stdout.write(render_text(report))

        return 0

    except (
        OSError, ValueError, KeyError,
        TypeError, RecursionError,
    ) as exc:
        print(
            "ESTUDIO_STOP=" + type(exc).__name__,
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
