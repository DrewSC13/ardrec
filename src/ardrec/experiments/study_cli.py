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


def evaluate(registry_folder, selection_folder=None, analysis=False, paired_summary=False):
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
        from ardrec.experiments import paired_reconciliation

        selection, _ = paired_reconciliation.read_selection(
            selection_folder,
            catalog,
            protocol,
            registry,
        )

    summary = None

    if paired_summary:
        need(analysis, "EXPLORATORY_FLAG_REQUIRED")
        from ardrec.experiments import paired_summary as paired
        statistics, summary = paired.analyze(
            protocol, registry, catalog
        )
    else:
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

    if summary is not None:
        report["schema"] = "ARDREC-R184-STUDY-CLI-v2"
        report["paired_summary"] = summary

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

    summary = report.get("paired_summary")

    if summary is not None:
        for key in (
            "mae_static", "mae_ardrec",
            "mean_difference", "median_difference",
            "rank_biserial", "favor_ardrec",
            "favor_static", "equal_errors",
        ):
            value = summary[key]
            lines.append(
                key.upper() + "=" +
                ("ND" if value is None else str(value))
            )

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

    sources = parser.add_mutually_exclusive_group(
        required=True
    )

    sources.add_argument(
        "--registro", type=Path
    )

    sources.add_argument(
        "--consolidacion-local", type=Path,
        help="Consulta de evidencia local consolidada",
    )

    parser.add_argument(
        "--sha256",
        help="Identificador esperado de la consolidacion",
    )

    parser.add_argument(
        "--seleccion", type=Path
    )

    parser.add_argument(
        "--analisis-exploratorio",
        action="store_true",
    )

    parser.add_argument(
        "--resumen-pareado",
        action="store_true",
        help="MAE global y efecto exploratorio en escala 0-1",
    )

    output = parser.add_mutually_exclusive_group(
        required=True
    )

    output.add_argument("--texto", action="store_true")
    output.add_argument("--json", action="store_true")
    output.add_argument("--csv", action="store_true")
    parser.add_argument("--informe-i8", action="store_true")

    parser.add_argument("--preparar-i2", action="store_true")
    parser.add_argument("--revisar-riesgo", action="store_true")
    parser.add_argument("--entrada-i2", type=Path)
    parser.add_argument("--soportes-i2", type=Path)

    args = parser.parse_args(argv)

    if args.csv and not args.informe_i8:
        parser.error("--csv requiere --informe-i8")

    if args.informe_i8:

        if (
            args.registro is None
            or args.seleccion is None
            or args.consolidacion_local is not None
            or args.sha256 is not None
            or args.preparar_i2
            or args.revisar_riesgo
            or args.entrada_i2 is not None
            or args.soportes_i2 is not None
            or args.analisis_exploratorio
            or args.resumen_pareado
        ):
            parser.error("I8 requiere registro y seleccion")

        from ardrec.experiments import paired_reconciliation as i8

        try:

            report = i8.evaluate(
                args.registro,
                args.seleccion,
                CATALOG,
            )

            if args.csv:
                sys.stdout.buffer.write(i8.export_csv(report))
            elif args.json:
                sys.stdout.buffer.write(r148.canonical(report))
            else:
                sys.stdout.write(i8.render_text(report))

            return 0

        except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
            print("I8_STOP=" + type(exc).__name__, file=sys.stderr)
            return 2

    if args.revisar_riesgo and not args.preparar_i2:
        parser.error("--revisar-riesgo requiere --preparar-i2")

    if args.preparar_i2:

        if (
            args.registro is None
            or args.seleccion is None
            or args.consolidacion_local is not None
            or args.sha256 is not None
            or args.analisis_exploratorio
            or args.resumen_pareado
        ):
            parser.error("I2 requiere registro y seleccion sin analisis")

        if (args.entrada_i2 is None) != (args.soportes_i2 is None):
            parser.error("I2 requiere entrada y soportes conjuntamente")

        from ardrec.experiments import baseline_preparation
        from ardrec.experiments import prospective_risk_integration

        engine = (
            prospective_risk_integration
            if args.revisar_riesgo
            else baseline_preparation
        )

        try:

            report = engine.evaluate(
                args.registro,
                args.seleccion,
                CATALOG,
                args.entrada_i2,
                args.soportes_i2,
            )

            if args.json:
                sys.stdout.buffer.write(r148.canonical(report))
            else:
                sys.stdout.write(engine.render_text(report))

            return 0

        except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:

            print(
                "I2_STOP=" + type(exc).__name__,
                file=sys.stderr,
            )

            return 2

    if args.entrada_i2 is not None or args.soportes_i2 is not None:
        parser.error("entrada y soportes requieren --preparar-i2")

    if args.consolidacion_local is not None:

        if not args.sha256:
            parser.error("--consolidacion-local requiere --sha256")

        if (
            args.seleccion is not None
            or args.analisis_exploratorio
            or args.resumen_pareado
        ):
            parser.error("opciones incompatibles con consolidacion local")

        from ardrec.experiments import local_consolidation

        try:

            report = local_consolidation.evaluate(
                args.consolidacion_local,
                args.sha256,
                CATALOG,
            )

            if args.json:

                sys.stdout.buffer.write(
                    r148.canonical(report)
                )

            else:

                sys.stdout.write(
                    local_consolidation.render_text(report)
                )

            return 0

        except (
            OSError, ValueError, KeyError,
            TypeError, RecursionError,
        ) as exc:

            print(
                "CONSOLIDACION_STOP=" + type(exc).__name__,
                file=sys.stderr,
            )

            return 2

    if args.sha256 is not None:
        parser.error("--sha256 requiere --consolidacion-local")

    if args.resumen_pareado and not args.analisis_exploratorio:
        parser.error("--resumen-pareado requiere --analisis-exploratorio")

    try:
        report = evaluate(
            args.registro,
            args.seleccion,
            args.analisis_exploratorio,
            args.resumen_pareado,
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
