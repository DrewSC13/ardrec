# ADR 0008 — Consultas durables por transporte local / Durable queries over local transport

## Español

Estado: decisión implementada en el componente F10. Fuente del modelo: **TESIS ARDREC**.
Base: `76423ff636e476feff67871dc9597c387584f7ae`.

### Problema y alcance

Python conserva la intención de consultar y Rust conserva las respuestas del diario
técnico. Falta unir ambos registros sin interpretar una respuesta perdida como ausencia
de ejecución ni confirmar un resultado parcial. Este incremento conecta exclusivamente
consultas de estado. No despacha solicitudes de ejecución, no inicia herramientas y no
implementa A1–A10 ni el prototipo operativo.

### Decisión

`begin_query` continúa siendo la operación explícita que registra una consulta y consume
una unidad del presupuesto durable. `exchange_query` recibe un almacén abierto y un
socket `AF_UNIX/SOCK_STREAM` conectado, exclusivo y proporcionado por el llamador.
Solo acepta una consulta en estado `QUERY_INCOMPLETE`; utiliza sus bytes originales.
No crea consultas, no aumenta el presupuesto y no ejecuta reintentos automáticos.

Rust recibe el socket por valor mediante `serve_query`, con un diario abierto y bloqueado,
un identificador de respuesta y una fecha suministrados por el llamador. Acepta solamente
`attempt_status_request` canónico, versión 2.0. `TechnicalJournal.answer` comprueba las
identidades y registra la respuesta y el resultado disponible antes de emitir bytes.
Repetir la misma consulta recupera la respuesta histórica exacta, aunque existan hechos
posteriores. Una identidad repetida con contenido distinto sigue siendo un conflicto.

### Perfil de conexión

1. Python envía una trama de consulta y hace `shutdown(SHUT_WR)`.
2. Rust exige EOF inmediatamente después de esa trama, antes de registrar la respuesta.
3. Rust envía una trama `attempt_status_result`; si el snapshot declara
   `result.status == DISPONIBLE`, envía una segunda trama con el resultado completo.
4. Rust cierra su dirección de escritura. Python exige EOF después de las tramas previstas.
5. Python llama a `complete_query` una sola vez, con la respuesta y el resultado completos.
   La correlación y la publicación durable siguen bajo el control del componente F9A.

Cada trama conserva el límite existente de 1 048 576 bytes, encabezado de longitud de
cuatro bytes en orden de red y UTF-8. JSON debe ser canónico. No se introduce otra versión
de mensajes ni un sobre JSON adicional. Una conexión contiene una sola consulta;
no admite multiplexación, bytes sobrantes ni reutilización después de un error.
Los dos extremos consumen y cierran el socket. El llamador no debe conservar duplicados
ni compartirlo con otros lectores o escritores.

Los errores de entrada, conflictos o intentos desconocidos cierran el canal. Este perfil
no convierte esos errores en `message_rejection` ni los interpreta como no inicio.
La compatibilidad general con mensajes 1.0 se conserva, pero este canal solo acepta 2.0.

Los códigos Python de `ExchangeError` distinguen `unix_stream_required`,
`invalid_timeout`, `open_query_required`, `noncanonical_or_version`,
`status_response_required`, `trailing_bytes`, `timeout`, `connection_incomplete`
e `invalid_response`. Se conserva la excepción causal. Los errores del almacén y del
modelo de estado se propagan; requieren revisión o recuperación, no una afirmación de
éxito. Rust devuelve `io::Error`, conservando como causa los errores del protocolo o diario.

### Tiempo, incertidumbre y recuperación

El plazo positivo, de hasta 60 segundos, se mide con reloj monotónico y se comparte
entre todas las operaciones de lectura y escritura del intercambio. Se actualiza el
restante antes de cada operación; un emisor que gotea bytes no renueva el presupuesto.
No incluye el establecimiento de conexión, responsabilidad del llamador. No es un plazo
de tiempo real: no puede interrumpir validación, planificación del sistema operativo o
un `fsync` en curso. No se cancelan escrituras durables a mitad de una operación.

Un fallo de transporte o una respuesta inválida anterior a `complete_query` conserva
la consulta abierta, su identidad y el presupuesto. La repetición requiere una llamada
explícita con un socket nuevo. No se llama automáticamente a `fail_query`: abandonar una
consulta y consumir otra decisión sigue siendo responsabilidad de la capa superior.
Una respuesta completa incierta puede cerrar la consulta sin resolver el intento;
`new_execution_authorized` permanece falso. Un resultado completo tampoco aplica efectos
analíticos, incrementa contadores ni publica una nueva generación confirmada.

Si falla la persistencia al completar, o muere el proceso, el llamador debe cerrar y
recuperar el almacén antes de decidir. El puntero durable determina si la consulta está
abierta o confirmada: una excepción no demuestra que la escritura no ocurrió.
El retorno exitoso de Rust solo acredita escritura al canal, no recepción ni persistencia
en Python. No hay transacción distribuida entre los diarios: la recuperación converge
mediante identidades, respuestas históricas y commits locales indivisibles.

### Confianza y trazabilidad

Este componente asume un par confiable y un diario ya bloqueado. La autenticación del par,
la selección del endpoint y el despacho de herramientas quedan en el futuro adaptador.
Las pruebas usan sockets Unix anónimos entre procesos con mensajes sintéticos; no exponen
un servicio de red ni acreditan soportes externos.

| Matriz existente | Apoyo de F10 | Límite |
| --- | --- | --- |
| AC-10; INV-09, INV-10 | Consulta durable antes del envío; sin nueva ejecución | No implementa despacho ni incorporación analítica |
| AC-11; INV-09, INV-10 | Desconexión, incertidumbre y repetición de identidad | No completa el ejecutor real ni A5 |
| AC-20; INV-13 | Confirmación local íntegra de la pareja recibida | Conserva garantías y límites de F8/F9 |
| AC-21; INV-09, INV-10, INV-13 | Reinicio de ambos extremos y respuesta histórica | No acredita aceptación funcional de todo el sistema |

Los identificadores proceden de `docs/acceptance/system-v1.json`. Este documento no
reinterpreta ni sustituye **TESIS ARDREC**. La matriz de aceptación no cambia de estado.

## English

Status: implemented component decision F10. Model source: **TESIS ARDREC**.
Baseline: `76423ff636e476feff67871dc9597c387584f7ae`.

### Problem and scope

Python retains the durable query intention; Rust retains technical journal answers.
F10 connects these records without interpreting lost replies as proof of no execution
or accepting partial results. It handles status queries only. It starts no tools,
implements no A1–A10 algorithms and does not start the operational prototype.

### Decision and connection profile

`begin_query` explicitly records a query and consumes its durable budget unit.
`exchange_query` takes an open store and an exclusive, connected, trusted Unix stream.
It requires `QUERY_INCOMPLETE` and sends the original query bytes. It neither creates
queries nor retries automatically. Rust `serve_query` owns the connected stream and
uses an already locked journal. Its caller supplies the response identifier and time.
Only canonical 2.0 `attempt_status_request` messages are accepted.

Python sends one framed query and shuts down its writing direction. Rust requires EOF
before changing the journal. `TechnicalJournal.answer` persists the answer and available
full result before transmission. Rust sends one `attempt_status_result` frame, followed
by exactly one full result frame if its snapshot declares `DISPONIBLE`, then shuts down
writing. Python requires EOF and calls `complete_query` once with the entire pair.
Correlation and atomic local publication remain the responsibility of F9A.

Existing framing is unchanged: a four-byte network-order length, UTF-8, and at most
1,048,576 payload bytes per frame. JSON must be canonical. There is no new message
version or envelope. Each connection carries one query; trailing bytes, multiplexing
and reuse are forbidden. Both functions consume and close the socket. Callers must
not retain duplicate descriptors or share readers and writers.

Malformed input, unknown attempts and conflicts close the stream. This profile does
not translate them into rejection messages or proof of no start. General 1.0 message
compatibility remains available elsewhere; this channel requires 2.0.

Python `ExchangeError` codes distinguish invalid channel/deadline, missing open query,
noncanonical or incompatible input, wrong response type, trailing bytes, timeout,
incomplete connection and invalid response. Causal exceptions are retained. Storage
and state-model errors propagate for inspection/recovery, never as success. Rust uses
`io::Error`, retaining protocol/journal errors as causes.

### Deadlines and recovery

A positive timeout of at most 60 seconds uses one monotonic deadline for all socket
reads and writes. The remaining time is recalculated before every operation, preventing
a slow sender from renewing the budget. Connection establishment belongs to the caller.
This is not a real-time bound: validation, scheduling and an ongoing fsync cannot be
interrupted. Durable writes are not cancelled halfway through publication.

Transport failure or invalid input before `complete_query` leaves the original query
open and its budget unchanged. Retrying requires an explicit call with a new socket.
The component never automatically calls `fail_query`; abandoning a query is a separate
higher-layer decision. A complete uncertain reply can close the query while the attempt
remains unresolved. `new_execution_authorized` stays false. Even a complete result does
not apply analytical effects, increment execution counters or publish a new generation.

After a storage failure or process death, close and reopen the store before deciding.
The verified durable pointer determines whether the query is open or confirmed; an
exception does not prove that a write never happened. Rust success means bytes were
written to the channel, not received or persisted by Python. No distributed transaction
is claimed: identities, historical replies and indivisible local commits enable recovery.
Identical query replay returns the exact historical answer, even after later observations;
a conflicting duplicate remains rejected.

### Trust and traceability

The caller provides a trusted peer and locked journal. Peer authentication, endpoint
selection and tool dispatch belong to the future adapter. Tests use anonymous Unix
socket pairs between processes and synthetic messages. They expose no network service
and verify no external evidence artifacts.

F10 supports existing AC-10/INV-09/INV-10 (durable intent without new execution),
AC-11/INV-09/INV-10 (uncertainty and identity replay), AC-20/INV-13 (atomic local
confirmation), and AC-21/INV-09/INV-10/INV-13 (restart recovery). It does not complete
real execution, A5, analytical incorporation or whole-system acceptance. Existing F8/F9
storage limits remain. Identifiers come from `docs/acceptance/system-v1.json`; this ADR
does not replace **TESIS ARDREC** or change acceptance statuses.
