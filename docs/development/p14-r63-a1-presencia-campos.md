# ARDREC P14-R63 — Presencia obligatoria y opcional en A1

**Base:** `4aef1a0dfee0a24e7d280f5e0b4e0122f1026490` (PR #160).

**Fuente:** tesis ARDREC 17/11/2026, sección 3.6.1, figura 3.5, página impresa 106 (página PDF 121), SHA-256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`.

La rama CAMPO de la figura comprueba `existe O expresion.opcional`: si no existe el valor y el campo está declarado obligatorio, corresponde un error explícito. Si es opcional, la ausencia produce ND.

## Representación elegida

- `{"op":"CAMPO","nombre":"FACT"}`: **heredado**, equivalente a campo opcional. No altera configuraciones existentes.
- `{"op":"CAMPO","nombre":"FACT","opcional":true}`: explícitamente opcional; ausente -> ND.
- `{"op":"CAMPO","nombre":"FACT","opcional":false}`: obligatorio; ausente -> `A1Error("campo_obligatorio_ausente")`.
- Un campo **presente** con `Truth.ND` permanece ND, porque presencia de dato y certeza de su valor son cuestiones distintas.
- El booleano debe ser Python `bool` real, no 0/1, texto ni ninguna otra clase. No existe coerción ni ejecución de comandos.

Esta es una **decisión de codificación de la implementación**, ya que el diagrama nombra `expresion.opcional` sin fijar formato JSON.

El consumidor de diagnóstico R22 transforma el error como `GuardPreviewError("a1_campo_obligatorio_ausente")`, conservando la política fail-closed. P8: **NO-GO**.

## Aceptación

`lab/tests/test_p14_r63_a1_field_presence.py` establece 22 pruebas independientes: compatibilidad heredada; campo obligatorio ausente; presente pero ND; racionales, texto, conjuntos; errores de esquema y metadatos; expresión lógica compuesta; tabla DECIDIR; congelamiento R17; propagación de rechazo R22.

**Límites:** este incremento no confirma por sí solo A1 100%, la aceptación sistémica A1–A10, servicios físicos o las 54 observaciones experimentales. No introduce autoridad P8.

**EN.** Adds strict required/optional field-presence semantics to A1 Figure 3.5 without changing legacy optional-field behavior. Tests deterministic fail-closed propagation through R17 and R22. No live execution.
