# Cierre de revisión del punto 1 / Point 1 review closure

## Español

**Punto 1: revisión completada del código existente, con obligaciones de desarrollo conservadas.**
Este cierre corresponde a revisar contratos, estados, persistencia, criterios de aceptación y casos de referencia.
No declara la implementación completa de la tesis, ni cierra AL-06 o AL-07.
La revisión previa ya situaba sus condiciones antes de los algoritmos y antes del ejecutor real;
no se eliminan ni se rebajan esas condiciones para pasar a trazabilidad.

Fuente SHA256: `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`. Commit revisado: `b455bf5a6fc6310ba30319d29a488291ded8e3a0`. Base integrada: `26f8506521f876d1b31b5908771de4297c81a213`.

Inventario: 182 archivos revisados y cinco auxiliares históricos adicionales fijados por SHA-256, tamaño y commit de origen. Estos cinco auxiliares se conservan; no se presentan como nueva evidencia de componentes ni del experimento. Las huellas completas y evidencias se conservan en [el registro](point-1-closure-v1.json).

### CONTRACTS

Contratos versionados, racionales exactos, ND, mensajes y tiempos revisados; los límites de formato son decisiones de implementación. No acreditan causalidad física ni autorización operacional.

### STATES

Ocho estados operacionales, terminalidad, incertidumbre y separación de candidato/confirmado; la proyección conserva campos y restricciones acotadas de la tesis. GuardFact sigue siendo entrada declarada y no cálculo A1/A3/A8/A9.

### PERSISTENCE

HEAD único vincula generación, diario, recibos e instantánea; referencias por hash, recuperación histórica y rechazo de descenso de validación. Solo contadores tienen semántica contrastada con recibos. No acredita las otras seis cargas ni custodia externa de frescura o corte eléctrico.

### ACCEPTANCE

Se conservan 27 criterios, 15 invariantes y 17 obligaciones metodológicas. La vista v2 corrige información de componentes obsoleta, manteniendo pendiente la aceptación integral.

### REFERENCE_CASES

Se conservan 51 oráculos, incluidos 16 cálculos numéricos independientes, 35 casos semánticos y ocho entradas inválidas separadas. La procedencia histórica se enlaza con la revisión de la tesis vigente; no se reetiqueta ni se presenta como ejecución de A1-A10.

### Cambios de esta revisión

Se añade una vista actual v2 para los 27 criterios y se corrigen afirmaciones obsoletas sobre magnitudes, tiempo, identidad, anclaje y contadores.
Ningún criterio se promueve a aceptación integral. La matriz histórica, las sondas históricas y los resultados anteriores conservan sus bytes.
`scripts/verificar_alineacion_actual.py` sigue siendo una sonda fijada a su base histórica: no debe presentarse como verificador de la base nueva.
Los enlaces de entrada apuntan a esta revisión; las notas ADR conservan la cronología de preparación.

### Obligaciones antes de etapas posteriores

| ID | Pasos del plan | Condición conservada |
| --- | --- | --- |
| AL-06 | 13, 14, 15, 16, 19, 20, 21, 22, 23, 24, 25 | Completar contratos y semántica de caracterización, evidencia/revisiones, objetivos, historia, ventana y controles; integrar fuentes de guardas y verificación analítica. El contrato requerido debe existir antes de implementar el algoritmo consumidor; no publicar resultados analíticos completos hasta cerrar sus invariantes. |
| AL-07 | 3, 5, 7, 8, 9, 10, 11, 12, 27 | Proveer política confiable de identidad; controlar ciclo de vida, descriptores, permisos, namespaces, artefactos y perfiles congelados. Rechazar referencias ajenas, ausentes o alteradas antes de cualquier despacho real. |
| FRESHNESS-CUSTODY | 5, 12, 13, 22, 27, 29 | Definir y verificar custodia externa de expected_head; un archivo íntegro restaurado no demuestra frescura por sí solo. |
| FILESYSTEM-POWER-LOSS | 3, 5, 12, 27, 29 | Validar durabilidad del sistema de archivos del laboratorio y pérdida de energía; SIGKILL solo acredita muerte de proceso. |
| AL04-R01 | 9, 10, 11, 12 | Vincular temporizador con inicio y final efectivos del ejecutor. |
| AL04-R02 | 3, 4, 5, 9 | Excluir o tratar suspensión del host y validar en laboratorio. |
| AL04-R03 | 10, 11, 12 | Conservar informes rechazados y conciliar ante ajustes UTC. |

### Evidencia y paso al punto 2

PR #25: CI `41355700883` e integración `26f8506521f876d1b31b5908771de4297c81a213`; CI de main `41358064180`.
El integrador exige 405 pruebas Python, 73 Rust, las 31 pruebas de contadores y todos los verificadores del flujo.
La revisión local adicional comprobó 56 pruebas de referencias, alineación de referencias, proyección y resolución estructural.
La CI de este cierre documental se comprobará antes y después de integrarlo; hasta entonces el cierre no está integrado.
El punto 2 completa y actualiza la trazabilidad ya existente. La evidencia de componentes no acepta el sistema ni valida la hipótesis.

## English

**Point 1: existing-code review complete, with development obligations retained.**
This closes review of contracts, states, persistence, acceptance criteria and reference cases.
It does not establish full thesis implementation or close AL-06/AL-07. Their original gates before algorithms
and before real execution remain in force. Historical records and acceptance are preserved.

- **CONTRACTS**: Versioned contracts, exact rationals, ND, messages and timing reviewed; format limits are implementation decisions. They do not establish physical causality or operational authorization.
- **STATES**: Eight operational states, terminality, uncertainty and candidate/confirmed separation; projections preserve thesis fields and scoped constraints. GuardFact remains supplied input, not A1/A3/A8/A9 computation.
- **PERSISTENCE**: One HEAD binds generation, journal, receipts and snapshot; hash references, historical recovery and validation-downgrade rejection. Only counter semantics are checked against receipts. Other six payloads, external freshness custody and power-loss behavior remain unverified.
- **ACCEPTANCE**: Preserves 27 criteria, 15 invariants and 17 methodological obligations. The v2 view updates stale component information while retaining pending system acceptance.
- **REFERENCE_CASES**: Preserves 51 oracles, including 16 independent numerical calculations, 35 semantic cases and eight separate invalid inputs. Historical provenance links to current-thesis review; it is neither relabeled nor presented as A1-A10 execution.

The v2 coverage view updates stale component statements without promoting system acceptance.
The historical alignment probe remains pinned to its historical baseline.
The JSON record lists all pending obligations and roadmap destinations in both languages.
Point 2 updates the existing 44-requirement traceability; full analytical state, operational execution,
algorithms, laboratory validation, system acceptance and experimental validation remain pending.
The closure must pass PR and main CI before the handoff is announced.
