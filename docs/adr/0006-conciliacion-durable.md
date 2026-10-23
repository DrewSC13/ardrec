# ADR 0006 — Consultas durables de conciliación / Durable reconciliation queries

## Español

Estado: implementado como componente Python; pendiente de integración con un ejecutor real.
Fuente normativa del modelo: TESIS ARDREC, apartados 3.5.5, 3.9.6 y 3.10.

### Problema

Una reserva persistida no demuestra que la herramienta haya comenzado. Un timeout
no acredita ausencia de inicio ni detención. Reiniciar el proceso tampoco debe
restablecer el presupuesto de consultas ni liberar la reserva. Una respuesta de
estado que menciona un resultado no contiene necesariamente ese resultado.

### Decisión

Se añade `ardrec.reconciliation` sobre el almacén operacional existente. La API
realiza una consulta por paso y persiste dos operaciones versionadas:

| Operación | Contenido durable | Efecto |
| --- | --- | --- |
| `reconcile_query_v1` | Consulta canónica y límite de consultas | Consume un turno y conserva incertidumbre antes de devolver los bytes. |
| `reconcile_reply_v1` | Consulta, respuesta, resultado opcional o fallo explícito | Cierra el turno mediante una única publicación de HEAD. |

El índice de consultas se reconstruye exclusivamente desde el diario alcanzable
por HEAD. No existe un contador auxiliar con autoridad independiente. Se aplica
el mismo bloqueo exclusivo, comprobación de integridad y frontera durable que
en la persistencia de estados. La consulta no cambia la generación confirmada.

`begin_query` devuelve únicamente `attempt_status_request`, con identidad,
correlación, versión y solicitud original conservadas. Solicita INICIO,
TERMINACION, RESULTADO y LIMPIEZA. No envía mensajes ni ejecuta herramientas.
El futuro adaptador deberá enviar esos bytes una sola vez por turno, imponer
sus plazos de transporte y suministrar la respuesta a `complete_query`.

El límite entero está entre 1 y 1000; el valor por defecto es 3. Es una decisión
de implementación, no un parámetro atribuido a TESIS ARDREC. Debe provenir de la
política autorizada del coordinador. El primer turno lo congela para ese intento;
los reinicios y nuevos identificadores no lo aumentan. Estos turnos limitan las
consultas registradas mediante esta API, no las llamadas arbitrarias de un cliente
externo. No existe un bucle de sondeo ni un planificador en este componente.

Solo puede existir una consulta abierta. Mientras esté abierta se bloquean nuevas
reservas, transiciones y publicaciones. Se admite conservar una incertidumbre o
detener la invocación. Tras un reinicio, `QUERY_INCOMPLETE` exige recibir una
respuesta correlacionada o cerrar explícitamente el turno como `ABANDONED`;
no se reenvía automáticamente. Un turno puede consumirse aunque el proceso haya
muerto antes del envío, decisión conservadora para mantener el límite.

### Respuestas y resultados

Se comprueba la correlación solicitud–consulta–respuesta y la continuidad de los
hechos del intento. Una aceptación conserva el inicio no acreditado. Una respuesta
`running` conserva el inicio acreditado y la terminación pendiente. Los fallos
TIMEOUT, CONNECTION_LOST, ABANDONED e INVALID_RESPONSE preservan la reserva y
los hechos anteriores. Un rechazo de consulta se registra como rechazo de esa
consulta; nunca se transforma en `not_started` del intento.

Para `completed` o `interrupted` se requiere el resultado completo antes de
devolver `READY_FOR_VALIDATION`. Se comprueban identidad, tipo, referencia,
fase, causa, diario, inicio, terminación y orden temporal. Un resultado anterior
a la respuesta de consulta es admisible. Su limpieza pendiente puede haber sido
resuelta por una consulta posterior, pero los hechos ya determinados no pueden
contradecirse. La misma identidad de resultado nunca puede cambiar de contenido.
Se conservan los bytes canónicos completos dentro del registro de conciliación,
sin alterar el mensaje original para hacerlo parecer más reciente.

La respuesta y el resultado se publican juntos. Sin el resultado se conserva una
incertidumbre durable (`RESULT_REQUIRED` mientras quede presupuesto). El resultado
completo queda disponible en `inspect_recovery(store).result`; no se inserta como
una observación posterior artificial en el historial temporal de estados. El
consumidor analítico futuro deberá leer este resultado además de los reportes
directos. Las referencias externas de inicio, ausencia, limpieza y soportes no
se verifican físicamente en este incremento.

### Decisiones de recuperación

| Decisión | Significado | Obligación del consumidor |
| --- | --- | --- |
| `QUERY_REQUIRED` | Hace falta una consulta y queda presupuesto. | Registrar un nuevo turno antes de transmitir. |
| `QUERY_INCOMPLETE` | Un turno durable no tiene cierre. | Completarlo o abandonarlo explícitamente. |
| `RESULT_REQUIRED` | Hay un estado terminal declarado sin resultado completo. | Obtener el resultado referenciado mediante el futuro adaptador. |
| `READY_FOR_VALIDATION` | Hay consistencia estructural y resolución técnica declarada. | Verificar referencias y procesar efectos antes de publicar. |
| `BUDGET_EXHAUSTED` | No se permiten nuevas consultas registradas. | El coordinador deberá detener la invocación y conservar la incertidumbre. |
| `INVOCATION_ENDED` | La invocación ya terminó. | Conservar reservas y diagnóstico. |

Cuando no hay intento pendiente se conserva la decisión del almacén (`NONE` o
`PUBLISH_CANDIDATE`). Todas las decisiones declaran `new_execution_authorized=False`.
Ni completar una consulta ni agotar el presupuesto inicia otra ejecución, cambia
los contadores incorporados, publica una generación o determina evidencia analítica.

La repetición exacta de un cierre es una operación sin cambios, incluso después
de reiniciar. Un cierre diferente para la misma consulta se rechaza. Un duplicado
antiguo tampoco elimina una incertidumbre más reciente. Las entradas malformadas
o contradictorias no cierran el turno ni modifican HEAD: el llamador debe conservar
el diagnóstico y, si corresponde, registrar INVALID_RESPONSE.

### Compatibilidad y alcance

El contenedor sigue siendo `ardrec-store-1` y el protocolo de mensajes sigue en
2.0. Las operaciones del diario llevan su propio sufijo `v1`. El lector nuevo
recupera diarios previos; el lector antiguo rechazará una operación nueva como
desconocida. No debe revertirse el lector después de escribir estos registros.
La lectura no migra ni reescribe objetos históricos.

Se mantienen las condiciones del almacén: Linux, un escritor, sistema de archivos
local y durabilidad condicionada a fsync y sustitución atómica. SHA-256 comprueba
consistencia y no autentica frente al propietario que reescribe todos los objetos.
Se conservan los límites de tamaño y longitud del diario del ADR 0005.

Este componente prepara la conciliación del coordinador. Quedan pendientes el
diario técnico Rust, su servicio de consulta, el transporte operativo acotado, la
resolución física de referencias, la política de plazos, la integración completa
de A5 y el prototipo operacional. A1–A10 no se declaran implementados por este
incremento. La aceptación funcional del sistema y la validación experimental
permanecen pendientes.

## English

Status: implemented as a Python component; integration with a real executor is pending.
Model source: TESIS ARDREC, sections 3.5.5, 3.9.6 and 3.10.

### Problem and decision

A durable reservation does not prove a tool started. A timeout proves neither
absence of start nor termination. Restarting must not reset a query budget or
release a reservation. A status response referencing an outcome need not contain
that outcome.

`ardrec.reconciliation` extends the existing operational store with two versioned
operations. `reconcile_query_v1` durably consumes a query slot before returning
canonical request bytes. `reconcile_reply_v1` atomically publishes the query,
response, optional full outcome or explicit failure through the same HEAD boundary.
The query index is rebuilt solely from the reachable journal; no separate counter
has authority. Locking and integrity checks remain those of the existing store.
Confirmed generations are unchanged by queries.

`begin_query` returns only `attempt_status_request`, preserving the original
identity, correlation and version and requesting start, termination, result and
cleanup. It performs no networking or tool execution. A future adapter must send
these bytes once per slot, enforce transport deadlines and provide the response.

The integer budget ranges from 1 to 1000, defaulting to 3. This is an implementation
choice, not a constant attributed to TESIS ARDREC. The authorized coordinator policy
must supply it. The first slot freezes the budget for the attempt; restarts and new
message identifiers cannot increase it. The budget covers queries registered through
this API, not arbitrary external client traffic. No polling loop or scheduler is added.

Only one query may remain open. It blocks new reservations, transitions and
publications while allowing uncertainty recording or invocation termination.
After a restart an incomplete query must receive its correlated reply or be
explicitly abandoned. It is never automatically resent. A slot can be consumed
even if the process died before transmission, conservatively preserving the limit.

### Validation and recovery

Request–query–reply correlation and established facts are checked. Acceptance is
not a verified start; running is not termination. TIMEOUT, CONNECTION_LOST,
ABANDONED and INVALID_RESPONSE retain the reservation and previous facts. A query
rejection never becomes a not-started outcome for the original attempt.

Completed and interrupted statuses require the full referenced outcome before
`READY_FOR_VALIDATION`. Checks cover identity, type, reference, phase, cause,
journal, start, termination and chronology. An outcome older than the status reply
is accepted. A later query may resolve pending cleanup but cannot contradict fixed
facts. The same outcome identifier cannot acquire different contents.

Canonical outcome bytes are stored unchanged in the reconciliation record together
with the response. They are exposed through `inspect_recovery(store).result`, rather
than inserted as an artificially newer observation in the state history. Future
analytical consumers must inspect these outcomes as well as direct reports.
Missing outcomes retain durable uncertainty. External references for start,
absence, cleanup and supporting evidence are not physically verified here.

The decisions are QUERY_REQUIRED, QUERY_INCOMPLETE, RESULT_REQUIRED,
READY_FOR_VALIDATION, BUDGET_EXHAUSTED and INVOCATION_ENDED. Without a pending
attempt, the store's NONE or PUBLISH_CANDIDATE decision is preserved. All decisions
set `new_execution_authorized=False`. Readiness requires subsequent external
verification and effect processing. Budget exhaustion requires the future
coordinator to stop the invocation while retaining uncertainty. No decision itself
launches execution, increments incorporated counts or publishes analytical state.

An identical completion is a no-op, including after restart. A conflicting
completion is rejected. An old duplicate cannot clear newer uncertainty. Invalid
input leaves the query open and HEAD unchanged; the caller retains its diagnostic
and may explicitly record INVALID_RESPONSE.

### Compatibility and limits

The container remains `ardrec-store-1`; the message protocol remains 2.0. Journal
operations use their own `v1` suffix. New readers recover older journals. Old readers
reject new operations as unknown and must not be restored after these records are
written. Reading does not migrate or rewrite historical objects.

Existing storage assumptions remain: Linux, one writer, a local filesystem and
durability conditional on fsync and atomic replacement. SHA-256 checks consistency,
not authenticity against an owner rewriting all objects. ADR 0005 size and journal
length limits remain in force.

This component prepares coordinator reconciliation. The Rust technical journal,
query service, bounded operational transport, physical reference resolution,
deadline policy, complete A5 integration and operational prototype remain pending.
This increment does not declare A1–A10 implemented. Whole-system functional
acceptance and experimental validation remain pending.
