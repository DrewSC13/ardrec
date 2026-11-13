#!/usr/bin/env python3
"""A1-R16: demostración sintética de reglas sin despacho ni permisos P8."""
from __future__ import annotations

from fractions import Fraction
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from ardrec.state import Truth
from ardrec.rules import decide, evaluate, guard_allows


def main() -> int:
    schema = {"permiso_sintetico": "LOGICO", "listo": "LOGICO", "riesgo": "RACIONAL"}
    expr = {"op": "Y", "args": [
        {"op": "CAMPO", "nombre": "permiso_sintetico"},
        {"op": "CAMPO", "nombre": "listo"},
        {"op": "COMPARAR", "relacion": "MAYOR", "izq": {"op": "CAMPO", "nombre": "riesgo"},
         "der": {"op": "CONSTANTE", "tipo": "RACIONAL", "valor": "1/2"}},
    ]}
    scenarios = [
        ("desconocido", {"listo": Truth.VERDADERO, "riesgo": Fraction(3, 4)}, Truth.ND),
        ("denegado", {"permiso_sintetico": Truth.FALSO, "listo": Truth.VERDADERO,
                      "riesgo": Fraction(3, 4)}, Truth.FALSO),
        ("satisfecho", {"permiso_sintetico": Truth.VERDADERO, "listo": Truth.VERDADERO,
                         "riesgo": Fraction(3, 4)}, Truth.VERDADERO),
    ]
    values = []
    for ident, environment, expected in scenarios:
        result = evaluate(expr, schema, environment)
        assert result is expected, (ident, result)
        values.append({"case": ident, "guard": result.value,
                       "guard_satisfied": guard_allows(result),
                       "p8_authorization": False})

    rows = [
        {"id": "espera", "condicion": {"op": "CONSTANTE", "tipo": "LOGICO", "valor": "FALSO"}},
        {"id": "regla_unica", "condicion": expr},
    ]
    decision = decide(rows, schema, scenarios[2][1])
    assert decision.authorized and decision.selected == "regla_unica"
    print(json.dumps({"schema": "ardrec-p14-r16-a1-kernel-demo-v1",
                      "mode": "PURE_SYNTHETIC_NO_EXECUTOR",
                      "truth_model": "THREE_VALUED_EXPLICIT_ND",
                      "cases": values,
                      "decision": {"status": decision.status.value,
                                   "selected": decision.selected,
                                   "evaluations": [[key, val.value] for key, val in decision.evaluations]},
                      "a1_complete": False,
                      "operational_dispatch": False,
                      "p8_operational": "NO-GO"},
                     sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
