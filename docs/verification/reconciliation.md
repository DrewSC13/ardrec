# Verificación de conciliación / Reconciliation verification

## Español

Fuente del comportamiento: TESIS ARDREC. Decisión de implementación:
`docs/adr/0006-conciliacion-durable.md`. La matriz de aceptación permanece en
`docs/acceptance/system-v1.json`; sus estados no se modifican automáticamente.

### Implementación

Se implementa el registro durable de consultas, su presupuesto, el cierre atómico
con respuestas y resultados y la reconstrucción del índice al recuperar. Se usa
el almacén existente, con dos nuevas operaciones versionadas. No se introduce
un ejecutor, un servicio de red ni un bucle de coordinación.

### Verificación funcional del componente

`scripts/verificar_conciliacion.py` ejecuta 35 métodos. Entre ellos, un método
comprueba 28 interrupciones reales mediante SIGKILL: 14 al registrar la consulta
y 14 al publicar su respuesta con el resultado. Cada almacén interrumpido se abre
dos veces para comprobar la recuperación repetida. Estos 28 casos son subcasos,
no 28 métodos adicionales.

| Propiedad | Comprobación | Resultado exigido |
| --- | --- | --- |
| Intención conservada | Timeout, desconexión, rechazo y abandono | Reserva intacta; cero incorporaciones nuevas. |
| Consulta previa al envío | Retorno normal y reinicio | Turno y consulta recuperables desde HEAD. |
| Presupuesto durable | Reinicios, cambios de límite e identificadores | No se reinicia ni se aumenta. |
| Publicación indivisible | SIGKILL en diario, HEAD y acuse | Consulta abierta o cierre completo; nunca medio resultado. |
| Resultado completo | Estado terminal sin resultado y recuperación posterior | Incertidumbre hasta recibir el resultado correlacionado. |
| Exactitud | Duración igual a 2^53 + 1 | Conservación exacta tras persistir y recuperar. |
| Idempotencia | Cierres repetidos y duplicados antiguos | Sin nuevas escrituras ni pérdida de incertidumbre posterior. |
| Identidad | Campos cruzados, reutilización y contenido contradictorio | Rechazo antes de escribir. |
| Estados | Aceptado, en curso, incierto, interrumpido y no iniciado | Sin inventar inicio, éxito o ausencia. |
| Separación de capas | Intercepción de sockets y procesos | Ninguna operación de red ni lanzamiento de herramienta. |

Los puntos de interrupción son creación, escritura parcial, escritura completa,
sincronización, instalación y durabilidad del objeto de diario; creación,
escritura parcial, escritura completa y sincronización del HEAD temporal;
antes y después de sustituir HEAD; sincronización del directorio y acuse.

Se mantienen además las 84 pruebas previas de estado y persistencia. La suite
completa del repositorio debe pasar de 156 a 191 métodos sin omisiones. El
instalador comprueba ese total en el entorno real y verifica el empaquetado antes
de crear el commit. CI debe comprobarse sobre el SHA publicado antes de integrar.

Los casos se ejecutan con mensajes sintéticos y archivos temporales. No demuestran
que un ejecutor real cumpla sus declaraciones ni certifican pérdida física de
energía. READY_FOR_VALIDATION significa consistencia estructural del componente,
no aceptación funcional del sistema ni evidencia analítica validada.

### Validación experimental

No se ejecutan experimentos ni se calculan métricas del modelo. La validación
experimental, la conciliación con el diario técnico Rust y la verificación externa
de soportes permanecen pendientes. A1 y el prototipo operacional no se inician.

## English

Behavioral source: TESIS ARDREC. Implementation decision:
`docs/adr/0006-conciliacion-durable.md`. The acceptance matrix remains in
`docs/acceptance/system-v1.json`; its statuses are not automatically advanced.

### Implementation

The component implements durable query slots and budgets, atomic replies with
outcomes, and query-index reconstruction on recovery. It extends the existing
store with two versioned operations. It adds no executor, network service or
coordination loop.

### Component functional verification

`scripts/verificar_conciliacion.py` runs 35 methods. One method includes 28 actual
SIGKILL cases: 14 during query registration and 14 during reply/outcome publication.
Each interrupted store is reopened twice. These are subcases, not 28 additional
methods.

Checks cover preserved reservations after timeout, disconnection, rejection or
abandonment; durable slots before transmission; budgets surviving restarts; atomic
publication; missing and older outcomes; exact values above 2^53; duplicate no-ops;
conflicting identities; distinct accepted/running/uncertain/interrupted/not-started
states; and absence of network or tool execution.

Interruption points include journal creation, partial and complete writes, sync,
installation and durability; temporary HEAD creation, partial and complete writes
and sync; before and after HEAD replacement; directory sync; and acknowledgement.
Recovery must yield an open query or a complete reply/outcome, never partial acceptance.

The existing 84 state and persistence tests remain required. The full repository
suite must increase from 156 to 191 methods without skips. The installer verifies
that total in the actual environment and checks packaging before committing.
Remote CI must be checked against the published SHA before integration.

Fixtures and temporary stores establish component behavior, not real executor
truthfulness or physical power-loss durability. READY_FOR_VALIDATION means structural
consistency and is neither system acceptance nor validated analytical evidence.

### Experimental validation

No experiments or model metrics are produced. Experimental validation, reconciliation
with the Rust technical journal and external evidence verification remain pending.
A1 and the operational prototype do not start in this increment.
