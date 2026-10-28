# Cierre acotado AL-04 / Scoped AL-04 closure

## Español

AL-04 se cierra exclusivamente para la definición de `temporal-v1`, su admisión
actual en los componentes durables y la recuperación operacional comprobada.
El cierre documental se registra localmente; su publicación, revisión de CI e
integración son un incremento separado. No se declara terminado el punto 1.

La fuente conserva la identidad TESIS ARDREC, SHA256
`6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`,
secciones 3.9.2, 3.9.3 y 3.10.2. Se contrasta con AL-04 de
`alignment-current-v1.json`. La tesis exige tiempos, duración, secuencia y
recuperación sin reejecución; la separación UTC/monotónico es una decisión de
implementación documentada en ADR 0010, no una cita de la tesis.

### Base y evidencia

- PR #18: implementación `0c1ac3ce4741b65c28cc0e39d9f85eb7c690325d`.
- Merge revisado: `57fc61b0f035405092caee7ee48e73308a45b19a`.
- Base del PR: `07858cde11ccbf9881a24589184964f2f2f8c7d7`.
- CI PR: [40565245128](https://github.com/DrewSC13/ardrec/actions/runs/40565245128), intento 1.
- CI main: [40610871070](https://github.com/DrewSC13/ardrec/actions/runs/40610871070), intento 1.

El aplicador comprueba los 148 archivos conocidos, el árbol y los padres del merge,
las firmas GitHub de ambos commits, la firma SSH local de implementación, la
identidad del PR y los nueve pasos obligatorios de CI. La asociación vacía de un
run histórico solo se acepta con estos identificadores fijados; una asociación
contradictoria bloquea el cierre. No se reetiquetan registros históricos.

La revisión R2 corrige una clasificación demasiado amplia de `.github/` en el
aplicador R1. La plantilla `.github/PULL_REQUEST_TEMPLATE.md` se verifica por
separado: ruta exacta, 489 bytes y SHA256
`628618d933aaef68995ae3f3d787e757351eb4d7f29d5d36cd9d694fc0f62005`,
aportados por diagnóstico de solo lectura sobre el merge fijado. Esta comprobación
es de identidad auxiliar, no una revisión semántica de la plantilla ni evidencia
de ejecución. No se exceptúan directorios completos: cualquier otro archivo nuevo
de CI, código, pruebas, protocolo o scripts sigue bloqueando el cierre.

| Obligación AL-04 | Evidencia y límite |
| --- | --- |
| Inversión temporal | `correlate_current` Python/Rust; oráculos explícitos y rechazo durable antes de escribir. Los lectores estructurales históricos conservan su semántica. |
| Ajustes UTC | Oráculos de retroceso/avance y consulta posterior al resultado. Un rechazo conserva incertidumbre; no autoriza un nuevo despacho. No hay detector general de ajustes del reloj. |
| Duración | Temporizadores monotónicos locales, truncamiento entero, rechazo de regresión y origen de otro PID. Las fechas UTC no se restan para obtener duración. La duración declarada aún no acredita medición física. |
| Reinicio de proceso | Cuatro escenarios Python, cada uno con un escritor y dos lectores independientes. El escritor termina mediante `os._exit(0)` después de confirmar escritura; los lectores preservan cabeza y bytes. No es SIGKILL durante escritura ni reinicio del host. |
| Lectura histórica | Python conserva el diario y bloquea promoción; Rust reconstruye un diario de formato previo, verifica lectura y rechazo sin modificar bytes. |
| No reejecución | Recuperación indica consulta pendiente, validación o revisión temporal; `new_execution_authorized` permanece falso. No se invoca una herramienta física en estos ensayos. |

El JSON adjunto conserva el manifiesto revisado, el código y huella de la prueba
suplementaria y sus resultados. Escenarios: reserva sin resultado, resultado
durable completo, diario histórico con inversión y respuesta inválida a consulta.
Las dos reaperturas deben producir resultados idénticos. Se verifica además que
un temporizador nuevo no serializa su origen; no se recupera un intervalo antiguo.
Las pruebas de Rust y el fork Python proceden del incremento integrado y de su CI.
No se atribuyen al suplemento pruebas de reinicio Rust ni fallos físicos.

### Obligaciones que permanecen abiertas

El gate original `BEFORE_REAL_EXECUTOR` sigue bloqueado por estas obligaciones:

- AL04-R01: enlazar medición con inicio y final efectivos en el supervisor; roadmap 9–12.
- AL04-R02: excluir o tratar suspensión del host y verificarlo en el laboratorio; roadmap 3–5 y 9.
- AL04-R03: conservar informes rechazados fuera del estado confirmado y conciliar ante ajustes UTC; roadmap 10–12.

El cierre acotado no satisface esas obligaciones ni habilita despacho físico.
AL-06 y AL-07 siguen abiertos; AL-05/AL-09 conservan únicamente su cierre acotado.
El estado analítico completo, alineación integral y aceptación funcional siguen
pendientes. A1–A10 y prototipo no iniciados; experimentación no ejecutada.
La matriz histórica, ADR 0010 y `temporal-policy-v1.json` conservan sus estados de
origen: este registro agrega evidencia posterior sin reescribirlos.

## English

AL-04 is closed only for the explicit temporal-v1 policy, current durable admission
and the verified operational recovery behavior. This is a local documentation
increment awaiting publication, CI review and integration. Point 1 remains in progress.
The source hash, thesis sections, PR, implementation, merge and CI identities above
are preserved. Clock design is an implementation choice, not a thesis quotation.

The installer verifies 148 known file hashes, signed commit identities and merge
parents, and all nine required CI steps. Empty historical run associations are
accepted only with pinned PR/run/merge identities; contradictory associations fail.

R2 corrects R1's overly broad classification of `.github/`. The PR template is a
separate auxiliary identity check pinned to its exact path, size and SHA256 from
the user-supplied read-only diagnostic. Its contents are not claimed as semantically
reviewed alignment evidence. No directory-wide exception is added; other unknown
CI, source, test, protocol or script files still block closure.

Python/Rust oracles cover temporal inversion, UTC adjustments and later recovery
queries. Durable writers reject invalid admissions without authorizing execution.
Legacy readers retain their semantics. Local monotonic timers are independent of
UTC and cannot restore a persisted origin. Declared durations do not establish
physical measurements.

Four supplemental Python scenarios each use one writer and two independent readers:
pending reservation, complete durable result, inconsistent historical journal and
rejected query response. The writer uses os._exit(0) after acknowledged writes.
Repeated readers preserve heads, bytes and decisions; execution authorization stays
false. This is process restart evidence, not a host reboot, power failure, mid-write
SIGKILL or Rust restart test. The JSON retains the probe source, hash and outcomes.
Existing Rust and Python fork evidence comes from the integrated increment and CI.

The original BEFORE_REAL_EXECUTOR gate remains blocked by AL04-R01 (physical timer
binding), AL04-R02 (host-suspend controls) and AL04-R03 (preservation/reconciliation
of rejected reports). Scoped closure does not permit physical dispatch. AL-06/AL-07
remain open; AL-05/AL-09 retain scoped closure. Full analytical state, specification
alignment and functional acceptance remain pending. Algorithms and prototype are not
started; experimental validation has not run. Historical records remain unchanged.
