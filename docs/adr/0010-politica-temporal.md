# ADR 0010 — Política temporal / Temporal policy

## Español

Estado: implementado como componente; revisión, publicación e integración pendientes.
Base: `07858cde11ccbf9881a24589184964f2f2f8c7d7` (PR #17).
Fuente de alineación: TESIS ARDREC, SHA256
`6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`,
secciones 3.9.2, 3.9.3 y 3.10.2. La tesis exige tiempos y secuencia causal;
las decisiones de reloj siguientes son decisiones de implementación, no citas de ella.

### Decisión

`temporal-v1` es una política de admisión explícita, independiente del formato 2.0.
Los lectores, `correlate`, el codec operacional y los reductores históricos se
conservan. `correlate_current` exige además que la fecha de respuesta, la observación
y los tiempos de proceso disponibles no precedan a la solicitud original.
Se conserva la normalización de fracciones y medianoche del calendario existente.
Las fechas iguales son admisibles; su orden físico requiere hechos adicionales.

Una respuesta de consulta debe ser posterior o igual a su consulta. La observación
del estado y el resultado original pueden preceder a la consulta de recuperación;
no se los vuelve a fechar. Ningún control UTC aislado demuestra ejecución,
terminación, autenticidad, limpieza ni autorización.

Un ajuste UTC hacia atrás puede impedir la admisión de un informe legítimo.
Se rechaza antes de escribir y se conserva la reserva/consulta pendiente; el llamador
conserva el mensaje original para diagnóstico. No se sustituyen ni corrigen sus
fechas. El diario no archiva automáticamente mensajes rechazados. El futuro adaptador
debe conservar ese diagnóstico fuera del estado confirmado y conciliar con fuentes
confiables. Un salto UTC hacia delante no se transforma en duración del proceso.
No hay detección general de ajustes UTC ni recuperación automática tras ellos.

`MonotonicTimer` en ambos lenguajes mide un intervalo local del proceso en
milisegundos enteros truncados, sin restar UTC. Rechaza regresión y desbordamiento.
El origen no se serializa; un objeto heredado tras fork rechaza el PID distinto.
Tras reinicio se recupera un resultado durable ya completo o se conserva incertidumbre;
no se recrea el origen del temporizador desde un timestamp guardado. Una nueva
instancia mide un intervalo nuevo, nunca completa el intervalo interrumpido.

No se exige igualdad entre `ended_at - started_at` y `duration_ms`. Los validadores
no prueban el origen de una duración declarada. Vincular el temporizador al inicio
y final efectivos corresponde al supervisor real, todavía no implementado.
No se comparten instantes monotónicos entre Python y Rust, procesos ni reinicios.
La suspensión del host debe excluirse en el laboratorio Linux; no se declara
medición portable de intervalos que la incluyan ni se configura aquí el host.

### Compatibilidad y admisión durable

Python audita el estado candidato y los resultados de conciliación antes de escribir.
Rust audita el modelo candidato y las respuestas antes de admitir una operación.
Las repeticiones tampoco eluden esta comprobación. La reconstrucción histórica
mantiene su semántica y conserva exactamente bytes y huellas.

Un diario antiguo temporalmente incoherente sigue siendo legible. Python lo señala
con `TEMPORAL_REVIEW_REQUIRED` y Rust ofrece `audit_temporal()`. Nuevos avances se
bloquean. Las operaciones Python de registrar incertidumbre o finalizar conservan
sus guardas originales y no promueven datos ni ejecutan herramientas.
Las APIs puras de estado y los lectores antiguos siguen siendo lectores/reductores;
no sustituyen la admisión del almacén ni son una autorización operacional.
`temporal_inversion` es un error local; no añade un código al formato de mensajes.

El corpus histórico `messages-v2.json` conserva su contenido. El nuevo
`messages-temporal-v1.json` adelanta las dos solicitudes sintéticas un segundo y
recalcula la huella de su rechazo correlacionado. Los ensayos de admisión durable
usan este conjunto; los contrastes estructurales históricos usan el anterior.
No se reetiquetan resultados antiguos ni se modifica la matriz histórica.

### Límites y cierre

Este incremento prepara evidencia de AL-04, pero no lo declara cerrado.
Faltan aplicación local, CI, revisión e integración; el supervisor físico y la
validación del laboratorio pertenecen a pasos posteriores. AL-06 y AL-07 siguen
abiertos, AL-05/AL-09 conservan su cierre acotado y el punto 1 sigue en curso.
No se implementan A1–A10 ni se inicia el experimento.

## English

`temporal-v1` adds current admission checks while preserving version 2.0 structural
readers, operational codecs and historical replay. Response, snapshot and available
process timestamps cannot precede the original request. Query responses cannot
precede their query; recovered snapshots/results may predate that query. Equality
is allowed and does not establish physical order or execution authority.

UTC rollback rejects admission without rewriting timestamps or releasing a pending
reservation. Rejected messages are not automatically archived by the journal; a
future trusted adapter must preserve diagnostics and reconcile. Forward UTC changes
are never converted into runtime duration. General clock-adjustment detection and
automatic recovery are not provided.

Process-local monotonic timers return truncated integer milliseconds, reject
regression/overflow and cannot be restored from persisted origins. Inherited timers
reject a changed PID. Restart requires a durable completed result or retained
uncertainty, never reconstruction of an interrupted interval. A fresh timer starts a
new interval. UTC differences and declared durations are not required to match.
Actual start/end binding and host-suspend exclusion remain laboratory/supervisor work.

Both durable writers audit candidates before writes. Historical journals remain
readable with unchanged bytes; temporal inconsistencies block further advancement.
Python exposes TEMPORAL_REVIEW_REQUIRED; Rust exposes audit_temporal(). Existing
uncertainty/finalization guards remain. Pure state reducers and legacy readers do
not replace current durable admission or authorize actions.

Historical fixtures and acceptance records remain unchanged. A separate current
fixture advances two synthetic request timestamps by one second and recomputes the
linked rejection hash. AL-04 remains pending review/integration; AL-06/AL-07 remain
open and point 1 remains in progress. No physical executor or algorithms are claimed.

## Referencias técnicas / Technical references

- Python: https://docs.python.org/3.14/library/time.html#time.monotonic_ns
- Rust: https://doc.rust-lang.org/std/time/struct.Instant.html

Se usa `checked_duration_since` para no confundir una regresión con cero.
La plataforma y suspensión requieren verificación independiente en el laboratorio.
