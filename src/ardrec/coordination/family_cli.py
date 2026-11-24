"""CLI unificada de familias DEV; sin autoridad operacional."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

from ardrec.coordination import r58k_unified_family_bridge as engine

MAX_INPUT = 1_048_576


def require(condition, code):
    if not condition:
        raise ValueError(code)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("NONFINITE_JSON_VALUE")


def read_json(path: Path):
    fd = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW |
        os.O_NONBLOCK | os.O_CLOEXEC,
    )

    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())

        require(
            stat.S_ISREG(before.st_mode)
            and 0 < before.st_size <= MAX_INPUT,
            "INPUT_FILE_INVALID",
        )

        raw = handle.read(MAX_INPUT + 1)
        after = os.fstat(handle.fileno())

        require(
            len(raw) == before.st_size
            and before.st_size == after.st_size
            and before.st_mtime_ns == after.st_mtime_ns,
            "INPUT_FILE_CHANGED",
        )

    return json.loads(
        raw.decode("utf-8", "strict"),
        object_pairs_hook=unique_pairs,
        parse_constant=reject_constant,
    )


def verify_boundary(report):
    require(
        engine.verify_unified_preview(report) is True,
        "FAMILY_REPLAY_FAILED",
    )

    require(
        report["source_kind"]
        == "OFFLINE_SYNTHETIC_NO_INDEPENDENT_ATTESTATION"
        and report["a6_classification"] == "ND"
        and report["technical_truth_accredited"] is False
        and report["confirmed_final_risk"] is None
        and report["published_generation"] is None
        and report["applied_state_transition"] is None
        and report["operational_dispatch"] is False
        and report["vm_checks_executed"] is False
        and report["host_mutations"] == 0
        and report["p8_operational"] == "NO-GO",
        "OPERATIONAL_BOUNDARY_VIOLATED",
    )

    return report


def render_text(report):
    lines = [
        "ARDREC / EVALUACION UNIFICADA DE FAMILIAS DEV",
        f"ORIGEN={report['source_kind']}",
        f"CATALOGO_SHA256={report['source_catalog_sha256']}",
        f"CASOS_MODELO={report['unit_count']}",
        f"FAMILIAS_SOPORTADAS={report['supported_family_count']}",
        f"FAMILIAS_EVALUADAS={report['covered_family_count_in_batch']}",
    ]

    for service, count in sorted(
        report["count_by_service"].items()
    ):
        lines.append(f"CASOS_{service}={count}")

    lines.append(
        "FAMILIA|VARIANTE|CLASE_HIPOTETICA|"
        "A6|RF_INFERIOR|RF_SUPERIOR|A8_PROPUESTA"
    )

    for row in sorted(
        report["decisions"],
        key=lambda d: (
            d["family_id"],
            d.get("variant") or "",
            d["case_id_a7"],
        ),
    ):
        lines.append("|".join((
            row["family_id"],
            row.get("variant") or "BASE",
            row["hypothetical_result_class"],
            row["a6_classification"],
            row["a7_rf_lower"],
            row["a7_rf_upper"],
            row["a8_recommendation"],
        )))

    lines.extend([
        "A6_FISICA=ND",
        "RF_CONFIRMADO=ND",
        "A8_OPERACIONAL=NO_APLICADA",
        "A9_OPERACIONAL=NO_PUBLICADA",
        "OBSERVACIONES_EXPERIMENTALES_ADMITIDAS=0",
        f"P8={report['p8_operational']}",
        f"RECIBO_SHA256={report['sha256']}",
    ])

    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m ardrec familias",
        description="Evaluacion offline de familias DEV; no ejecuta servicios.",
    )

    parser.add_argument(
        "--dev", action="store_true", required=True,
        help="Reconocer explicitamente el alcance sintetico",
    )

    actions = parser.add_mutually_exclusive_group(
        required=True
    )

    actions.add_argument("--entrada", type=Path)
    actions.add_argument("--reproducir", type=Path)

    output = parser.add_mutually_exclusive_group(
        required=True
    )

    output.add_argument("--texto", action="store_true")
    output.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)

    try:
        require(os.geteuid() != 0, "ROOT_EXECUTION_FORBIDDEN")

        if args.entrada is not None:
            units = read_json(args.entrada)
            report = engine.build_unified_preview(units)
        else:
            report = read_json(args.reproducir)

        report = verify_boundary(report)

        if args.json:
            print(json.dumps(
                report,
                sort_keys=True,
                ensure_ascii=True,
                separators=(",", ":"),
                allow_nan=False,
            ))
        else:
            sys.stdout.write(render_text(report))

        return 0

    except (
        OSError, ValueError, TypeError,
        KeyError, UnicodeError, RecursionError,
    ) as exc:
        print(
            "FAMILIAS_STOP=" + type(exc).__name__,
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
