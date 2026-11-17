# ARDREC P14-R61 — A1: contrato de DECIDIR y propagación declarativa

**ES.** Fuente de autoridad: tesis ARDREC del 17 de noviembre de 2026,
SHA-256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`,
figura 3.4, página impresa 105 (página PDF 120). Base remota verificada:
`32c6f22d9578930f692dad6e69a1aa3ddbb1fd13`.

## Contrato preciso y oráculo independiente

- `EVALUAR(FALSE)` sigue produciendo `Truth.FALSO` (expresión individual).
- `DECIDIR([FALSO, FALSO, ...])` devuelve `status=ND`, `selected=None`,
  `output=None` y todas las evaluaciones individuales con su FALSO intacto.
- `DECIDIR([VERDADERO, FALSO])` devuelve `VERDADERO`, la identidad de la fila
  ganadora y su `salida` declarativa, cuando esté presente.
- `DECIDIR([VERDADERO, ND])` devuelve `ND`, sin salida ni selección.
- Dos filas verdaderas son ambigüedad explícita, no prioridad por orden.
- Ordenar las filas de manera distinta no cambia el resultado.
- Las filas heredadas sin `salida` mantienen contrato por identidad y exponen
  `output=None` explícitamente. Se permite un valor declarativo de texto no
  vacío, máximo 128 caracteres; otros tipos son rechazados.
- El consumidor R17 conserva la salida en `PreviewDecision.selected_output`.
  El consumidor diagnóstico R22 la expone como `UnitGuardDiagnostic.table_output`
  y la incluye en el recibo canónico únicamente si fue declarada. Para filas
  heredadas los bytes del recibo R22 no cambian por esta clave nueva.
- Ninguna salida se evalúa como código, comando o permiso operacional P8.

## Superficie de regresión y límites

Se actualizan expectativas antiguas en R16, R17, R18 y R22 que confundían
FALSO de condición con FALSO de la tabla. `guard_preview` sigue conservando el
FALSO del control individual y bloquea `TABLA_NO_ACREDITADA` si la tabla es ND.

Pruebas: `lab/tests/test_p14_r61_a1_decision_contract.py` (oráculo independiente),
R16, R17, R18 y R22; ejecutar además la suite P14 y los gates Rust y P8.

Este incremento no acredita por sí solo A1 100 %, ni A1–A10 de extremo a extremo,
ni los servicios físicos SSH/FTP/SMB, ni pilotaje/54 observaciones de hipótesis.
La salida de fila no se usa para ejecutar perfiles ni publicar generación A9.

**EN.** Aligns A1 decision-table semantics with thesis Figure 3.4. No match
returns ND without changing the individual FALSE evaluations. Adds an optional,
bounded declarative winner output and verifies its propagation through R17 and
R22 consumers. No operational dispatch, risk confirmation or experiment is
claimed.
