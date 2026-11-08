# ARDREC — P8-R9 / Núcleo de reglas A1 de efecto nulo (8-XI-2026)

**Base exacta:** `9bb8e06c5d007cac82a102a97a87ab909bb35d7b` (PR #40, P8-R8 integrado y comprobado). Este documento es un **nuevo corte propuesto**, no una revisión retrospectiva de informes históricos.

**Fuente:** TESIS ARDREC, SHA-256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`, apartado **3.3.2**, páginas impresas **90, 105 y 106**, figuras 3.4–3.5 (Algoritmo 1). La tesis establece expresiones tipadas, campos autorizados, lógica trivalente y decisión por tabla de coincidencias. Los límites 24 niveles, 256 nodos, 64 filas, 64 campos, texto 128 caracteres y entero exacto de 63 bits son **decisiones de este incremento**, no valores prescritos por la tesis.

## Alcance implementado — parcial y aislado

- `src/ardrec/rules/core.py`: expresiones `CONST`, `FIELD`, `NO`, `Y`, `O`, `IGUAL`, `MENOR`, `MENOR_IGUAL`, `MAYOR`, `MAYOR_IGUAL`, `PERTENECE` y `SUBCONJUNTO`.
- Tipos: booleano, entero exacto, texto y conjunto finito de textos. Esquema explícito por campo: tipos estrictos, campos opcionales declarados, ausencia opcional → `ND`, ausencia obligatoria → error. Nunca se evalúan objetos Python mediante reflexión o `eval`.
- Lógica trivalente de Kleene: `NO ND = ND`, `FALSO Y ND = FALSO`, `VERDADERO O ND = VERDADERO`; no se acepta coerción implícita de `ND` a booleano.
- Validación completa de todas las filas **antes** de seleccionar: referencia y tipo, operadores, forma, complejidad, ID duplicados y ciclos. `DECIDIR`: múltiples coincidencias verdaderas → `RULES_AMBIGUOUS`; una coincidencia con otras condiciones `ND` → resultado `ND`; ninguna coincidencia → `ND`; una sola coincidencia y ninguna indeterminación → elección estructural `DETERMINADO`.
- Salida `RuleDecision` inmutable, con referencias al registro, servicio, caso, generación y configuración, ID de regla y procedencia declarada. Estos campos son **atribuciones del llamador no autenticadas**.
- `authorized=false` y `dispatch_allowed=false` en **todos** los resultados: la selección de una tabla no es habilitación operacional.

**No acredita:** implementación integral de A1, validación y congelamiento de reglas mediante A2, relaciones de tablas contra el catálogo de 25 familias, verificación externa de procedencia, resolución de parámetros y presupuesto, generación de decisiones operacionales, cálculo de riesgo o ejecución de casos. Los componentes existentes de A2–A10 continúan sin implementar integralmente.

**Estado de P8:** abierto. Los 29 perfiles permanecen `BLOCKED_UNBOUND_NO_EXECUTION`; cero casos reales, cero despachos, cero resultados de laboratorio. **AL-06 y AL-07**, así como las **siete obligaciones residuales**, siguen abiertos. La evaluación de software no reemplaza la validación experimental con las 54 unidades planificadas.

## Reproducción

`PYTHONPATH=src python3 -m unittest discover -s tests/unit -p test_rules_core.py -v`

`python3 scripts/verificar_a1_rules_core.py`

`python3 scripts/verificar_trazabilidad_actual.py`

**EN:** R9 proposes an isolated, type-checked deterministic rule evaluator and finite decision tables. Structural selection is not authority; no user-supplied source, field, clock, artifact or permission is trusted. Partial A1 groundwork only; full A1–A10 acceptance and experimentation remain pending.
