# ADR 0004 — Modelos de estado / State models

## Español

### Problema y fuente

TESIS ARDREC distingue el estado operacional del servicio, los hechos técnicos del
intento y el desenlace de la invocación. Confundirlos permitiría contar una aceptación
como ejecución, presentar incertidumbre como pausa o confirmar una fase local sin
publicación durable. Las fuentes de este contrato son 3.2.1, 3.5.1–3.5.7, 3.8.1–3.8.3,
3.9.1–3.9.3, 3.9.6, 3.9.10–3.9.11 y 3.10.1–3.10.2 de TESIS ARDREC, en particular
las tablas 3.4, 3.5, 3.6, 3.13 y 3.18.

### Decisión

`src/ardrec/state.py` contiene modelos operacionales en memoria y operaciones puras.
La propiedad del estado analítico corresponde a Python. Los contratos Rust del
protocolo permanecen como frontera estructural de intercambio. Este incremento no
reimplementa los estados analíticos en el ejecutor técnico.

| Modelo | Responsabilidad | Límite |
|---|---|---|
| `ServiceState` | Fase operacional, causa, espera y traza candidata | No calcula riesgo ni evidencia |
| `AttemptState` | Solicitud, respuestas correlacionadas, incertidumbre e incorporación declarada | No ejecuta ni escribe un diario |
| `ConfirmedState` | Identidad y referencia de la generación recibida del almacenamiento | No verifica físicamente la durabilidad |
| `GlobalState` | Estado confirmado, servicios candidatos, intentos e invocación | No publica candidatos |
| `GuardFact` | Resultado explícito VERDADERO, FALSO o ND con referencia | No evalúa expresiones de A1 |

Las estructuras usan dataclasses congeladas, tuplas y bytes canónicos. Las propiedades
que exponen mensajes devuelven objetos reconstruidos, evitando compartir diccionarios
mutables. Esta inmutabilidad es un contrato de programación, no una barrera frente a
código hostil ejecutado dentro del mismo intérprete.

### Estados y transiciones del servicio

Se conservan PREPARADO, PENDIENTE, ACTIVO, VALIDACION, ACTUALIZADO, PAUSADO,
CERRADO y DETENIDO. Los dos últimos son terminales para la misma observación.

| Ruta | Condición necesaria | Resultado local |
|---|---|---|
| T1: PREPARADO → PENDIENTE | Preparación autorizada y precondiciones válidas | Candidato preparado |
| T2: PENDIENTE → ACTIVO | Inicio acreditado del intento reservado; referencia coincidente | Fase activa |
| T3: ACTIVO → VALIDACION | Terminación, limpieza y resultado determinado acreditados | Fase de validación |
| T4: VALIDACION → ACTUALIZADO | Desenlace procesable y efectos calculados por sus módulos | Fase actualizada |
| T5: PENDIENTE → ACTUALIZADO | Control autorizado o no inicio documentado | Efectos sin ejecución ficticia |
| T6: ACTUALIZADO → PENDIENTE | Trabajo admisible y precedencia resuelta | Candidato para continuar |
| T7: PENDIENTE o ACTUALIZADO → CERRADO | Criterio ordinario verdadero y precedencia resuelta | Cierre candidato |
| T8: PENDIENTE o ACTUALIZADO → PAUSADO | Espera externa identificada, autorización y precedencia | Pausa candidata |
| T9: PAUSADO → PENDIENTE | Nueva autorización, espera resuelta y precondiciones | Reanudación candidata |
| T10: No terminal → DETENIDO | Causa respaldada y efecto procesable | Detención candidata |

T5 se representa con dos variantes explícitas: control y no inicio. T0 requiere una
generación inicial publicada; no se fabrica una inicialización A2 mediante un cambio
de enum. El constructor de `ConfirmedState` representa datos ya cargados, sin ejecutar
T0. Las guardas de este módulo exigen exactamente los hechos previstos para cada ruta,
sin coerción de booleanos ni conversión implícita de ND.

La traza guarda origen, destino, evento, generación y referencias de las guardas.
Cada operación devuelve un objeto nuevo y conserva `confirmed`. ACTIVO, VALIDACION
y ACTUALIZADO se mantienen como fases locales; no pueden cargarse como estados
publicables en este contrato. Una traza candidata tampoco es un historial durable.

CERRADO conserva ES, SA, CV y LE, incluidas sus referencias y valores ND cuando
corresponda. El motivo principal sigue ES > SA > CV > LE entre los criterios verdaderos.
El módulo no calcula esos criterios ni ejecuta A8. La guarda `precedence_resolved`
procede de la política congelada; no se inventa un orden entre controles y pausas.
Una reanudación exige una referencia de autorización diferente de la que autorizó
la pausa, además de la referencia de la espera resuelta.

### Intento y bloqueo global

El intento tiene una reserva local previa y las seis fases del protocolo 2.0:
accepted, running, completed, interrupted, not_started y uncertain. La reserva no
acredita envío, aceptación, inicio ni durabilidad. Solo se permite una reserva pendiente
de incorporación en todo el estado global, incluidos los descubrimientos controlados.

Se reutilizan la decodificación y correlación del protocolo 2.0. Las respuestas de
consulta requieren la solicitud original y la consulta. Los registros incorporados
se mantienen como bytes canónicos. La versión 1.0 sigue disponible en el módulo de
mensajes, pero este adaptador de estados exige explícitamente 2.0: no inventa hechos
faltantes mediante una conversión silenciosa.

Las respuestas posteriores no pueden borrar hechos acreditados, cambiar su referencia,
retroceder desde un desenlace determinado ni sustituir el diario original. Una limpieza
fallida puede resolverse posteriormente con una nueva constancia; una limpieza ya
acreditada no se degrada silenciosamente. Las consultas no ejecutan herramientas.

La pérdida de comunicación conserva la solicitud, las respuestas y los hechos conocidos.
Un duplicado idéntico es idempotente y no elimina una incertidumbre posterior. Un
message_rejection no constituye por sí mismo prueba de ausencia de inicio. Los
resultados inciertos y la limpieza pendiente, fallida o desconocida bloquean validación,
pausa y cierre ordinario hasta resolver sus requisitos. Un resultado interrumpido con
inicio, terminación y limpieza acreditados puede pasar a validación, sin convertirse
por ello en evidencia admisible.

`technical_resolved` diferencia resolución técnica de incorporación confirmada. Incluso
un resultado resuelto conserva la reserva hasta que una futura capa de publicación
acredite su incorporación. `Incorporation` permite representar un recibo ya cargado,
cuya generación debe ser posterior a la decisión, no posterior a la autoridad confirmada,
y cuyo evento debe figurar entre los incorporados. Dos intentos no pueden consumir el
mismo evento. No existe una función que fabrique estos recibos o publique generaciones.

`GlobalState.incorporated_execution_count` cuenta exclusivamente los intentos
representados con incorporación confirmada e inicio VERIFICADO, una vez declarada
verificada la autoridad. No reemplaza el repositorio completo de contadores. Un no
inicio aporta cero; una aceptación, una reserva o un inicio aún no incorporado aportan
cero. La simulación se distingue explícitamente y no admite recibos de incorporación
real. Los intentos conservan su identidad original al cargar una nueva invocación.

### Invocación y autoridad

EN_CURSO es una fase interna de implementación. Los resultados de invocación de
TESIS ARDREC son FINALIZADA, PAUSADA y DETENIDA. FINALIZADA exige servicios
confirmados terminales; PAUSADA exige al menos un servicio confirmado en pausa y los
demás pausados o terminales. Ambas rechazan reservas pendientes y candidatos sin publicar.
DETENIDA puede conservar incertidumbre y autoridad no comprobada: finaliza la invocación
sin convertir automáticamente ningún servicio en DETENIDO.

Una solicitud de transición T10 requiere causa procesable y autoridad verificada.
Si no se pueden cumplir esas condiciones, debe detenerse la invocación conservando la
última generación. Incluso una detención candidata procesable conserva las reservas:
no acredita que una herramienta haya terminado ni que la limpieza sea satisfactoria.

### Frontera de confianza y alcance

`authority=VERDADERO` y los hechos de guarda son entradas del llamador que deberá
resolver y verificar sus referencias. No son certificados de autenticidad, comprobación
del sistema de archivos ni una evaluación de reglas ya implementada. Estos objetos no
deben construirse directamente a partir de mensajes externos sin dichas comprobaciones.
El módulo valida consistencia y transiciones; no garantiza la verdad física de una referencia.

Este incremento implementa contratos operacionales y sus guardas. No implementa el
estado analítico numérico completo Z, la inicialización A2, la conciliación durable A5,
los cálculos A6/A7, la decisión A8, la publicación A9 ni la coordinación A10. Las reservas
se representan en memoria; no deben utilizarse para ejecutar herramientas reales antes
de implementar el diario y las garantías de recuperación. A1 y el prototipo operacional
no se inician. La aceptación funcional completa y la validación experimental permanecen
pendientes. Véase `../verification/state-models.md` para la evidencia de verificación.

## English

### Problem and source

TESIS ARDREC distinguishes service operational states, attempt facts and invocation
outcomes. Treating them as one state would count acceptance as execution, disguise
uncertainty as a pause or confirm local processing without durable publication.
This contract follows sections 3.2.1, 3.5.1–3.5.7, 3.8.1–3.8.3, 3.9.1–3.9.3,
3.9.6, 3.9.10–3.9.11 and 3.10.1–3.10.2, particularly tables 3.4, 3.5, 3.6, 3.13 and 3.18.

### Decision and service transitions

`src/ardrec/state.py` provides in-memory operational models and pure transformations.
Python owns analytical state; Rust retains protocol boundary validation. Frozen
objects, tuples and canonical message bytes prevent ordinary mutation and dictionary
aliasing. This is a programming contract, not protection against hostile in-process code.

| Model | Responsibility | Boundary |
|---|---|---|
| `ServiceState` | Operational phase, cause, wait and candidate trace | No risk or evidence calculations |
| `AttemptState` | Request, correlated reports, uncertainty and declared incorporation | No execution or journal writes |
| `ConfirmedState` | Loaded generation identity and reference | No physical durability verification |
| `GlobalState` | Confirmed state, candidate services, attempts and invocation | No publication |
| `GuardFact` | Explicit VERDADERO, FALSO or ND with a reference | No A1 expression evaluation |

The eight service states retain their Spanish identifiers. CERRADO and DETENIDO are
terminal for the same observation. The transition contract is:

| Route | Required condition | Local result |
|---|---|---|
| T1: PREPARADO → PENDIENTE | Authorized preparation and valid preconditions | Prepared candidate |
| T2: PENDIENTE → ACTIVO | Verified physical start of the reserved attempt | Active phase |
| T3: ACTIVO → VALIDACION | Verified termination, cleanup and determined result | Validation phase |
| T4: VALIDACION → ACTUALIZADO | Processable outcome and externally calculated effects | Updated phase |
| T5: PENDIENTE → ACTUALIZADO | Authorized control or documented absence of start | No fictional execution |
| T6: ACTUALIZADO → PENDIENTE | Admissible work and resolved precedence | Continuation candidate |
| T7: PENDIENTE or ACTUALIZADO → CERRADO | True ordinary criterion and resolved precedence | Closure candidate |
| T8: PENDIENTE or ACTUALIZADO → PAUSADO | Identified external wait, authorization and precedence | Pause candidate |
| T9: PAUSADO → PENDIENTE | New authorization, resolved wait and preconditions | Resumption candidate |
| T10: Nonterminal → DETENIDO | Supported cause and processable effect | Stop candidate |

T5 has explicit control and no-start variants. T0 requires a published initial generation;
constructing a loaded `ConfirmedState` does not implement A2 or publication. Exact guard
sets require explicit VERDADERO; false and unknown facts cannot enable a transition.
All operations preserve the confirmed object and generation. ACTIVO, VALIDACION and
ACTUALIZADO remain local phases; a candidate trace is not durable history.

Closure retains all four criteria, references and unknown values. The primary true
criterion follows ES > SA > CV > LE. This module neither calculates A8 criteria nor
invents precedence among controls and pauses. Resumption requires a new authorization
reference and the original resolved wait reference.

### Attempts, uncertainty and invocation

A local reservation precedes the six protocol 2.0 phases: accepted, running, completed,
interrupted, not_started and uncertain. Reservation proves neither dispatch nor durability.
Only one attempt may await incorporation globally, including controlled discovery.
The adapter uses existing 2.0 decoding and correlation; query responses require both
the original request and query. Legacy 1.0 remains supported by the message layer but
is not implicitly converted into a richer state snapshot.

New reports preserve established facts and their references, chronological order and
journal identity. Failed cleanup can be resolved by a new record; verified cleanup is
not silently downgraded. Communication loss preserves request identity and known facts.
Identical duplicate reports are idempotent and cannot erase a later uncertainty marker.
Message rejection alone does not prove absence of execution. Uncertainty and unresolved
cleanup block validation, ordinary closure and pause. A determined interrupted result
may enter validation; it does not automatically become admissible evidence.

Technical resolution is separate from confirmed incorporation. Resolved attempts remain
reserved until a future publication layer establishes incorporation. A loaded
`Incorporation` must refer to an event present in the confirmed generation, after its
decision generation, without double consumption. No function creates durable receipts
or publishes generations. The global incorporated count only covers represented,
confirmed physical starts under verified authority; it does not replace the complete
counter repository. No-start contributes zero, and simulation cannot produce real
incorporation receipts. Prior attempts retain their original execution identity across
new invocations.

EN_CURSO is an implementation phase. FINALIZADA, PAUSADA and DETENIDA are invocation
outcomes. Finalization requires confirmed terminal services. Pausing requires at least
one confirmed paused service and all remaining services paused or terminal. Both reject
unincorporated attempts and unpublished candidates. Stopping an invocation may preserve
uncertainty or unverified authority without changing any confirmed service state.
A processable T10 stop remains a candidate and does not release outstanding reservations.

### Trust boundary and scope

The caller must resolve and verify authority and guard references. Their declared values
are not authenticity certificates, filesystem checks or implemented rule evaluation.
Untrusted messages cannot be promoted directly into trusted guard facts. This module
checks consistency and transitions, not the physical truth of external references.

This increment does not implement full numerical analytical state Z, A1–A10, durable
journaling, recovery, actual execution or operational orchestration. In-memory reservations
must not drive real tools before durable guarantees exist. Functional system acceptance
and experimental validation remain pending. Verification is described in
`../verification/state-models.md`.
