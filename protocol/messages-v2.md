# Contratos operacionales 2.0 / Operational contracts 2.0

## Español

Fuente funcional: TESIS ARDREC, secciones 3.9.1–3.9.7 y tabla 3.17.
Los nombres nuevos, la versión 2.0, los dominios concretos y los límites indicados
son decisiones de implementación; no se presentan como transcripciones de la fuente.
La especificación distingue validación de mensajes, verificación de referencias,
autorización, conciliación durable y aceptación del sistema.

### Versiones y compatibilidad

`ardrec.messages` selecciona exactamente `1.0` o `2.0`. La implementación 1.0 se
conserva en `messages_v1.py`, con sus cuatro tipos y restricciones originales.
No hay negociación automática, conversión ni degradación. Un objeto 1.0 no se
convierte en 2.0 cambiando la etiqueta. Las correlaciones entre versiones se rechazan.
El futuro flujo operacional deberá exigir 2.0 en su configuración congelada; admitir
1.0 para reproducir pruebas históricas no lo habilita para ese flujo.

### Envoltura obligatoria

Todos los objetos rechazan campos desconocidos. La envoltura contiene exactamente:
`schema_version`, `message_type`, `message_id`, `record_id`, `execution_id`,
`correlation_id`, `decision_index`, `scope`, `service_scenario_id`, `derived_case_id`,
`attempt_id`, `created_at`, `producer`, `versions`, `simulation` y `payload`.
`schema_version` es `2.0`; `simulation` es un booleano en la envoltura.
`versions` contiene `reference` y `sha256`: identifica y resume el manifiesto congelado
que el receptor deberá resolver y verificar. Una cadena SHA-256 no prueba integridad.

Los identificadores cumplen `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`. Los índices y
magnitudes enteras no admiten booleanos, cadenas ni decimales. SHA-256 usa 64 dígitos
hexadecimales minúsculos. Las fechas son UTC con `Z`, calendario válido y hasta seis
dígitos fraccionarios; no se admiten segundos intercalares ni desplazamientos horarios.

| `scope` | Identidades presentes | Identidades estructuralmente `null` |
|---|---|---|
| `attempt` | Servicio, caso derivado e intento | Ninguna |
| `discovery` | Servicio e intento técnico de descubrimiento | Caso derivado |
| `service` | Servicio | Caso derivado e intento |
| `observation` | Identidades generales de la observación | Servicio, caso derivado e intento |

Un intento de descubrimiento tiene identidad durable propia; no se transforma en un
caso derivado ni incrementa por sí solo los contadores de ejecución del modelo.
`null` solo expresa ausencia estructural en los campos enumerados; nunca equivale a ND.

### Tipos y campos de payload

En la tabla, `request_reference` identifica el mensaje original, no la consulta.
`REFS` representa cinco campos obligatorios: `host_reference`, `authorization_reference`,
`scope_reference`, `profile_reference` y `parameters_reference`.
`STATE` representa `generation`, `state_reference` y `state_sha256`.

| Tipo y productor | Ámbito | Campos exactos de `payload` |
|---|---|---|
| `execution_request`, analitico | attempt | REFS, authentication, protocol, port, limits |
| `discovery_request`, analitico | discovery | REFS, authentication, protocol, port, limits |
| `accepted_for_execution`, tecnico | attempt/discovery | request_reference, snapshot |
| `execution_result`, tecnico | attempt | request_reference, snapshot, outcome |
| `discovery_result`, tecnico | discovery | request_reference, snapshot, outcome, characterization_reference |
| `attempt_status_request`, analitico | attempt/discovery | request_reference, requested_information |
| `attempt_status_result`, tecnico | attempt/discovery | request_reference, query_reference, requested_information, snapshot |
| `supervision_event`, supervision | service/observation | action, actor_reference, authorization_reference, instruction_reference, reason_reference |
| `message_rejection`, receptor correspondiente | Todos | rejected_message_id, rejected_message_type, rejected_sha256, error_code, reason_reference |
| `closure_record`, analitico | observation | STATE, report_reference, reason_reference |
| `persisted_state`, persistencia | observation | STATE, request_reference, pointer_reference, publication_reference, status |

`protocol` es ssh/ftp/smb y `port` está entre 1 y 65535, sin imponer el puerto
predeterminado. `authentication` tiene exactamente `{mode: none}` o
`{mode: referenced, credential_reference: ID}`. La modalidad sin credenciales debe
estar autorizada por el perfil; no permite eludir controles. No se transmiten secretos,
comandos arbitrarios, direcciones sin referencia ni argumentos de shell.
`limits` contiene timeout_seconds, stdout_max_bytes, stderr_max_bytes,
artifact_max_bytes y max_supports. Son límites solicitados; el ejecutor deberá
compararlos con el perfil autorizado antes del despacho y aplicarlos al ejecutar.
`requested_information` es una lista no vacía, sin repetidos, de INICIO, TERMINACION,
RESULTADO y LIMPIEZA. La respuesta siempre incluye una instantánea coherente completa.

### Instantánea del intento

`snapshot` contiene exactamente phase, start, termination, cleanup, result, reason_code,
observed_at, journal_reference, reconciliation_required y new_execution_authorized.
Cada uno de start/termination/cleanup/result contiene exactamente status y reference.

| Hecho | Estados con referencia obligatoria | Estados con referencia `null` |
|---|---|---|
| start | VERIFICADO, NO_INICIADO | NO_ACREDITADO, NO_DETERMINADO |
| termination | VERIFICADO | EN_CURSO, NO_APLICA, NO_DETERMINADO |
| cleanup | completed, not_required, failed | pending, unknown |
| result | DISPONIBLE | PENDIENTE, NO_DISPONIBLE |

`NO_INICIADO` exige una constancia de ausencia de inicio; una desconexión no basta.
`not_required` también exige una justificación verificable de ausencia de limpieza.
Las referencias desconocidas permanecen null; el diario identifica la observación.

| phase | Restricciones | Conciliación |
|---|---|---|
| accepted | NO_ACREDITADO, terminación NO_DETERMINADO, limpieza pending, resultado PENDIENTE | Obligatoria |
| running | Inicio VERIFICADO, terminación EN_CURSO, limpieza pending, resultado PENDIENTE | Obligatoria |
| completed | Inicio y terminación VERIFICADO, resultado DISPONIBLE | Mientras limpieza no sea completed/not_required |
| interrupted | Como completed; causa TIMEOUT/INTERRUPTED/EXECUTOR_FAILURE | Mientras limpieza no sea completed/not_required |
| not_started | NO_INICIADO, terminación NO_APLICA, limpieza not_required, resultado NO_DISPONIBLE | No requerida por esta instantánea |
| uncertain | Inicio VERIFICADO/NO_DETERMINADO; terminación VERIFICADO/NO_DETERMINADO; resultado no DISPONIBLE | Obligatoria |

accepted/running/completed usan reason_code null. not_started admite REQUEST_REJECTED
/SPAWN_FAILED. uncertain admite TIMEOUT, EXECUTOR_FAILURE, CONNECTION_LOST,
STATUS_UNAVAILABLE, CLEANUP_FAILED o RESULT_UNAVAILABLE. TIMEOUT exige inicio verificado;
CLEANUP_FAILED exige limpieza failed. Si el inicio es desconocido, terminación también
lo es y limpieza solo puede ser pending/unknown. Una terminación desconocida no puede
acompañarse de limpieza completada o innecesaria.

`new_execution_authorized` siempre es false: una respuesta no autoriza otro despacho,
ni siquiera si la conciliación terminó. Estas fases describen el intento técnico y no
sustituyen Q del servicio ni confirman una generación global. Un resultado disponible
es un registro técnico, no una evidencia admitida. La aceptación no acredita inicio.

### Resultado original

`outcome` contiene started_at, ended_at, exit_code, signal, timed_out, duration_ms,
stdout_reference, stderr_reference, stdout_truncated, stderr_truncated,
effective_parameters_reference y supports. Todos son obligatorios; los campos no
acreditados admiten null bajo las restricciones siguientes.

Inicio verificado exige started_at y parámetros efectivos. Sin inicio verificado no
hay tiempos de inicio/duración, salidas, parámetros efectivos, soportes ni timed_out.
Terminación verificada exige ended_at >= started_at; sin ella no hay ended_at, exit_code
ni signal. Los tiempos acreditados no exceden observed_at, que no excede created_at.
La duración se mide monotónicamente y no se exige igualdad con la diferencia UTC.
completed/interrupted requieren duración y exactamente uno de exit_code/signal.
completed exige exit_code, timed_out false y referencias stdout/stderr; código distinto
de cero sigue siendo un resultado terminado. interrupted distingue señal de código
normal y TIMEOUT requiere timed_out true. El perfil Linux admite señales 1–64;
exit_code no negativo hasta 2^31−1. Una señal no se codifica como exit_code negativo.

La truncación exige referencia a la salida parcial. supports es una lista de referencias
únicas, nunca contenido embebido. uncertain/not_started no transportan soportes como
resultado utilizable; las salidas parciales de un inicio acreditado pueden conservarse
como diagnóstico. En completed/interrupted, snapshot.result.reference coincide con el
message_id original. Un resultado de descubrimiento completed requiere
characterization_reference; en las otras fases es null. El perfil no afirma que una
caracterización esté completa ni permite convertir salida parcial en evidencia positiva.

### Correlación, rechazos y otras responsabilidades

`correlate` valida ambos mensajes y exige las mismas identidades, ámbito, índice,
versión del manifiesto y simulation. `correlate_status(original, query, response)`
comprueba además query_reference y la información solicitada. Una respuesta de consulta
referencia el resultado original; no lo renombra ni lo reproduce como un intento nuevo.
Los soportes declarados no pueden superar max_supports de la solicitud correlacionada.

Los ocho códigos de rechazo son schema_invalid, version_incompatible,
identifier_mismatch, duplicate_conflict, out_of_scope, catalog_mismatch,
message_too_large e integrity_failure. `message_rejection` no demuestra que el intento
no comenzó y no autoriza reenvío. No se responde a otro rechazo.
Para mensajes válidos, rejected_sha256 resume la serialización determinista de
encode_message; correlate comprueba huella, identidad, tipo y receptor correcto.
Para bytes inválidos, el adaptador podrá conservar la huella de los bytes recibidos y
rejected_message_type null/desconocido, únicamente si existe contexto confiable externo;
no podrá usar correlate sobre el objeto inválido ni inventar identidades. Sin contexto
confiable se registra un error local y se descarta el mensaje. Los límites de lectura se
aplican antes de cargar el cuerpo completo. No se incluyen secretos en errores.

`compare_delivery` devuelve REPLAY para el mismo message_id y contenido canónico
idéntico; cambios generan duplicate_conflict. También rechaza reutilizar attempt_id
entre dos solicitudes de ejecución/descubrimiento con message_id diferente. NEW solo
significa que ese par no presenta conflicto. La unicidad global, respuesta durable,
reserva y bloqueo de reejecución necesitan el diario, aún pendiente de implementar.

supervision_event solicita record_control/request_pause/request_stop/request_resume;
no cambia directamente estados. El receptor verificará actor, autorización, regla y
estado, y no reabrirá estados terminales por una solicitud de reanudación.
closure_record identifica la generación, estado y reporte que se solicita registrar.
persisted_state responde a esa solicitud con status PUBLISHED y constancias de puntero
/publicación; generation coincide con decision_index y con el cierre correlacionado.
El consumidor deberá verificar la publicación durable real. Validar JSON no equivale
a fsync, bloqueo de escritor, publicación atómica ni recuperación.

### Restricciones revisadas y verificación

Se mantiene el máximo de trama de 1 MiB; el límite de 4096 bytes y 256 bits del contrato
numérico independiente permanece separado y provisional hasta verificar los algoritmos.
Se mantienen identificadores de 128 caracteres, índices/duraciones/límites de bytes
hasta 2^63−1, timeout de 1–86400 segundos y hasta 1024 soportes. Son cotas de
representación, no presupuestos de ejecución seguros: el perfil congelado podrá exigir
límites menores. Los artefactos se referencian fuera de la trama. No se relajan estos
límites automáticamente ni se redondean racionales al agotarlos.

Se eliminan las restricciones del perfil inicial que exigían credencial para todo
caso y permitían únicamente resultados terminados y limpiados. Los campos exactos,
nulls estructurales, estados y causas anteriores definen el nuevo dominio cerrado.
Las 19 muestras de tests/fixtures/messages-v2.json son sintéticas. Las pruebas cubren
los once tipos, campos obligatorios/desconocidos, versiones, límites, contradicciones,
correlación, duplicados, rechazo y persistencia declarada. No prueban autenticación del
canal, existencia de artefactos, ejecución, conciliación durable ni aceptación A1–A10.
El transporte Rust sigue validando tramas; la equivalencia semántica Rust será otro
incremento. Los estados de aceptación y validación experimental no se modifican.

## English

Functional source: TESIS ARDREC, sections 3.9.1–3.9.7 and Table 3.17. Version 2.0,
new names, exact domains and limits are implementation decisions, not quotations.
Message validation, reference verification, authorization, durable reconciliation and
system acceptance are separate responsibilities.

### Versions and envelope

ardrec.messages dispatches exactly 1.0 or 2.0. messages_v1.py preserves the original
four types and restrictions. There is no implicit conversion, negotiation or downgrade;
cross-version correlation is rejected. The future operational flow must require 2.0
through its frozen configuration; legacy replay does not authorize operational use.

Every object rejects unknown fields. The mandatory envelope fields are schema_version,
message_type, message_id, record_id, execution_id, correlation_id, decision_index,
scope, service_scenario_id, derived_case_id, attempt_id, created_at, producer, versions,
simulation and payload. schema_version is 2.0. simulation is an exact boolean.
versions contains reference and sha256 for the frozen manifest; its referenced content
must still be resolved and verified. Identifiers follow
[A-Za-z0-9][A-Za-z0-9._:-]{0,127}; hashes are 64 lowercase hexadecimal digits.
Integers reject booleans, strings and decimals. UTC timestamps require Z, a valid
calendar and at most six fractional digits; offsets and leap seconds are unsupported.

| scope | Required contextual identities | Structurally null identities |
|---|---|---|
| attempt | Service, derived case and attempt | None |
| discovery | Service and discovery attempt | Derived case |
| service | Service | Derived case and attempt |
| observation | General observation identities | Service, derived case and attempt |

Discovery has its own durable attempt identity and does not implicitly increment model
execution counters. null denotes only declared structural absence, never numerical ND.

### Payload contracts

REFS means host_reference, authorization_reference, scope_reference, profile_reference
and parameters_reference. STATE means generation, state_reference and state_sha256.
request_reference always points to the original request, not the status query.

| Type / producer | Scope | Exact payload fields |
|---|---|---|
| execution_request / analitico | attempt | REFS, authentication, protocol, port, limits |
| discovery_request / analitico | discovery | REFS, authentication, protocol, port, limits |
| accepted_for_execution / tecnico | attempt/discovery | request_reference, snapshot |
| execution_result / tecnico | attempt | request_reference, snapshot, outcome |
| discovery_result / tecnico | discovery | request_reference, snapshot, outcome, characterization_reference |
| attempt_status_request / analitico | attempt/discovery | request_reference, requested_information |
| attempt_status_result / tecnico | attempt/discovery | request_reference, query_reference, requested_information, snapshot |
| supervision_event / supervision | service/observation | action, actor_reference, authorization_reference, instruction_reference, reason_reference |
| message_rejection / corresponding receiver | All | rejected_message_id, rejected_message_type, rejected_sha256, error_code, reason_reference |
| closure_record / analitico | observation | STATE, report_reference, reason_reference |
| persisted_state / persistencia | observation | STATE, request_reference, pointer_reference, publication_reference, status |

protocol is ssh/ftp/smb; port is 1–65535 without assuming a default. authentication is
exactly {mode: none} or {mode: referenced, credential_reference: ID}. The none variant
requires profile authorization. Messages carry references, not credentials or shell
commands. limits contains timeout_seconds, stdout_max_bytes, stderr_max_bytes,
artifact_max_bytes and max_supports; the executor must authorize and enforce them.
requested_information is a nonempty unique subset of INICIO, TERMINACION, RESULTADO,
LIMPIEZA. Status responses always include a complete coherent snapshot.

### Snapshots and outcomes

snapshot has phase, start, termination, cleanup, result, reason_code, observed_at,
journal_reference, reconciliation_required and new_execution_authorized. Each fact
(start, termination, cleanup, result) has exactly status and reference.

| Fact | States requiring an ID reference | States requiring a null reference |
|---|---|---|
| start | VERIFICADO, NO_INICIADO | NO_ACREDITADO, NO_DETERMINADO |
| termination | VERIFICADO | EN_CURSO, NO_APLICA, NO_DETERMINADO |
| cleanup | completed, not_required, failed | pending, unknown |
| result | DISPONIBLE | PENDIENTE, NO_DISPONIBLE |

NO_INICIADO requires proof of non-start; disconnection is insufficient. not_required
requires a documented cleanup exemption. Unknown references remain null.

| phase | Constraints | Reconciliation |
|---|---|---|
| accepted | NO_ACREDITADO, termination NO_DETERMINADO, cleanup pending, result PENDIENTE | Required |
| running | Start VERIFICADO, termination EN_CURSO, cleanup pending, result PENDIENTE | Required |
| completed | Start and termination VERIFICADO, result DISPONIBLE | Required until cleanup completed/not_required |
| interrupted | Same as completed; TIMEOUT/INTERRUPTED/EXECUTOR_FAILURE reason | Required until cleanup completed/not_required |
| not_started | NO_INICIADO, termination NO_APLICA, cleanup not_required, result NO_DISPONIBLE | Not required by this snapshot |
| uncertain | Start and termination VERIFICADO/NO_DETERMINADO; result not DISPONIBLE | Required |

accepted/running/completed require a null reason. not_started allows REQUEST_REJECTED
or SPAWN_FAILED. uncertain allows TIMEOUT, EXECUTOR_FAILURE, CONNECTION_LOST,
STATUS_UNAVAILABLE, CLEANUP_FAILED or RESULT_UNAVAILABLE. TIMEOUT requires verified
start; CLEANUP_FAILED requires failed cleanup. Unknown start requires unknown
termination and pending/unknown cleanup. Unknown termination cannot claim completed
or unnecessary cleanup. new_execution_authorized is always false. These are technical
attempt phases, not service states or confirmed global generations. Acceptance is not
start; an available technical record is not admitted evidence.

outcome has started_at, ended_at, exit_code, signal, timed_out, duration_ms,
stdout_reference, stderr_reference, stdout_truncated, stderr_truncated,
effective_parameters_reference and supports. All fields are required. Unattested
fields are null only under these rules: verified start requires started_at and effective
parameters; unverified start forbids these, duration, outputs, supports and timed_out.
Verified termination requires ended_at >= started_at; otherwise ended_at, exit_code
and signal are null. Attested times cannot exceed observed_at <= created_at.
Duration uses a monotonic clock, independently of UTC differences.
completed/interrupted require duration and exactly one of exit_code/signal. completed
requires exit_code, no timeout, and both output references. Nonzero exit is still a
completed result. interrupted distinguishes a signal from normal exit; TIMEOUT requires
timed_out true. Linux signals are 1–64; exit_code is 0–2^31−1, never a negative signal.
Truncation requires a partial output reference. supports are unique IDs, not embedded
artifacts. uncertain/not_started have no usable supports; partial outputs after verified
start may remain diagnostic. completed/interrupted result references equal the original
message_id. A completed discovery result requires characterization_reference; other
phases require null. This does not certify complete characterization or positive evidence.

### Correlation, rejection and boundaries

correlate enforces identity, scope, index, manifest and simulation equality.
correlate_status(original, query, response) also verifies query_reference and requested
information. Responses reference the original result and cannot create a new attempt.
Correlated results cannot exceed the request's max_supports.

Rejection codes are schema_invalid, version_incompatible, identifier_mismatch,
duplicate_conflict, out_of_scope, catalog_mismatch, message_too_large and
integrity_failure. Rejection proves neither non-start nor permission to resend.
Rejecting a rejection is prohibited. For valid messages, rejected_sha256 hashes the
deterministic encode_message representation; correlation verifies digest, IDs, type
and intended receiver. Invalid input may be hashed as received, with a null/unknown
rejected_message_type, only when trustworthy external context exists. correlate cannot
validate that invalid object. Without trustworthy context, record a local error and
discard the input; never fabricate identities. Apply frame limits before reading the
whole body. Do not expose secrets through errors.

compare_delivery returns REPLAY for identical canonical content under the same ID;
changed content raises duplicate_conflict. A different execution/discovery request ID
cannot reuse an attempt ID. NEW only describes this comparison. Global uniqueness,
durable replies, reservations and reexecution prevention still need the journal.

Supervision actions are record_control/request_pause/request_stop/request_resume;
recipients must verify actor, authorization, rule and state. They cannot reopen terminal
states automatically. closure_record identifies the generation/state/report to record.
persisted_state acknowledges it with PUBLISHED and pointer/publication references;
generation equals decision_index and the correlated closure generation. Consumers must
verify actual durability: schema validation is not fsync, locking or atomic publication.

### Reviewed limits and verification scope

The 1 MiB frame limit remains. The independent numerical contract's 4096-byte and
256-bit limits remain provisional and separate pending algorithm verification. IDs are
at most 128 characters; indices, durations and byte limits at most 2^63−1; timeouts
1–86400 seconds; supports at most 1024. These are representation bounds, not safe
execution budgets. Frozen profiles must impose suitable stricter limits. Artifacts
remain external references; limits are not automatically relaxed and rationals are
never rounded on overflow.

Version 2.0 removes the legacy requirement for credentials in every request and for
results to be completed and cleaned. Exact fields, structural nulls and variants define
the expanded closed domain. The 19 fixture messages are synthetic. Tests exercise all
eleven types, fields, versions, bounds, contradictions, correlation, duplicate handling,
rejection and declared publication. They do not certify channel authentication,
artifact existence, execution, durable reconciliation or A1–A10 acceptance. Rust still
validates transport frames; equivalent semantic validation is a subsequent increment.
System acceptance and experimental validation statuses remain unchanged.
