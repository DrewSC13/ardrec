# ADR 0005 — Persistencia y diario de intentos / Persistence and attempt journal

## Español

### Contexto y alcance

TESIS ARDREC, secciones 3.10.1–3.10.2 y tabla 3.18, separa decisión,
intención, resultado técnico, candidato y generación confirmada. Las secciones
3.4, 3.5 y 3.9 exigen conservar reservas, distinguir incertidumbre de ausencia y
contabilizar efectos únicamente después de su incorporación confirmada.

Este incremento implementa almacenamiento local de los modelos operacionales
existentes. No completa el estado analítico Z, los algoritmos A1–A10, el diario
interno del ejecutor Rust, la consulta remota de intentos ni el prototipo
operacional. Las referencias de autorización, soportes y efectos calculados son
hechos suministrados por el llamador y aún requieren verificación externa.
No se modifica la matriz de aceptación funcional ni la validación experimental.

### Decisión

Se adopta un almacén `ardrec-store-1`, independiente de la versión 2.0 del
protocolo. Su API pública es `ardrec.persistence.DurableStore`.

| Elemento | Función |
| --- | --- |
| `LOCK` | Inodo estable con bloqueo exclusivo no bloqueante durante toda la sesión. |
| `journal/<sha256>.json` | Registro inmutable: secuencia, predecesor, operación, argumentos, huella del estado resultante y generación. |
| `generations/<sha256>.json` | Instantánea operacional publicada con recibos de incorporación y enlace a la generación anterior. |
| `HEAD` | Única autoridad: identidad, secuencia y huellas de diario y generación, con comprobación SHA-256. |
| `.pending-*` | Escritura provisional; nunca constituye autoridad por sí misma. |

El diario registra operaciones, no un estado arbitrario aportado al abrir el
almacén. La recuperación reproduce las operaciones con los validadores de estado
existentes y compara sus resultados con las huellas almacenadas. Las generaciones
publicadas deben coincidir exactamente con esa reproducción.

### Frontera transaccional

1. Validar argumentos, identidad, fases y condiciones antes de escribir.
2. Si hay publicación, escribir la generación en un temporal, sincronizar el
   archivo, instalarla sin reemplazar objetos previos y sincronizar su directorio.
3. Escribir y sincronizar el registro encadenado del diario del mismo modo.
4. Escribir y sincronizar un `HEAD` provisional con las referencias completas.
5. Sustituir `HEAD` atómicamente y sincronizar el directorio del almacén.
6. Devolver la confirmación únicamente después de completar la sincronización.

La confirmación de un resultado técnico solo acredita su registro durable:
no acredita incorporación analítica. `publish` integra el recibo del intento,
los eventos y la generación en una sola publicación. No depende de una marca
final escrita en una segunda transacción. Un acuse perdido exige recuperar y
leer la autoridad; no autoriza repetir la acción física.

`reserve` registra conjuntamente la referencia de decisión y la intención,
antes de cualquier posible envío externo. Esta API elimina la ventana de una
decisión persistida sin intención; no representa ni ejecuta una decisión externa
anterior. Tras recuperar una intención pendiente, se exige conciliación y se
rechaza reservarla otra vez. El módulo no contiene operaciones de red ni de
lanzamiento de herramientas.

### API y restricciones

| Operación | Contrato |
| --- | --- |
| `create(path, initial)` | Crear exclusivamente un directorio nuevo con generación 0, servicios PREPARADO, sin intentos ni simulación. |
| `open(path, record_id=..., configuration_sha256=..., expected_head=None)` | Bloquear, verificar identidad/cadena/generaciones y recuperar; `expected_head` permite exigir un ancla externa exacta. |
| `reserve(request, decision_reference=...)` | Persistir intención única sobre estado confirmado habilitado; nunca enviar la solicitud. |
| `report(attempt_id, message, query=None)` | Correlacionar y registrar un resultado; duplicado exacto es una operación nula. |
| `uncertain(attempt_id, reason_reference)` | Mantener identidad, hechos acreditados y reserva. |
| `transition(service_id, transition, context)` | Registrar un candidato conforme a T1–T10, sin adelantar la generación confirmada. |
| `publish(expected_generation=..., reference=..., event=...)` | Comprobar generación esperada, referencias únicas, fases publicables, intento resuelto y efectos preparados; incorporar de forma indivisible. |
| `finish(outcome, reason_reference)` | Persistir salida de invocación, distinta del estado de servicio. |
| `state`, `head_sha256`, `recovery_action` | Consultar la sesión válida bajo su bloqueo. |
| `close()` | Cerrar descriptores y liberar el bloqueo; no borrar `LOCK`. |

La publicación ordinaria no admite intentos inciertos. Un resultado resuelto
requiere su transición de procesamiento: T4 para ejecución, T5_NO_INICIO para
ausencia acreditada o T1 para descubrimiento. T10 permite una detención con causa
y efecto procesables conforme al modelo. Las fases ACTIVO, VALIDACION y
ACTUALIZADO no se publican como generación confirmada.

Los identificadores y referencias no se reutilizan para dar una segunda
incorporación al mismo evento. Se conserva el historial completo de intentos de
esta observación, por lo que el contador representado no se reinicia al reabrir.
Un intento acreditado como no iniciado no incrementa el contador de ejecución.
Un resultado técnico completo sin publicación mantiene su reserva.

Una sesión pertenece a un proceso y un hilo. Abrir otra sesión concurrente
produce `writer_busy`; heredar la sesión mediante `fork` no habilita su uso.
Los métodos consultan que el puntero y los inodos retenidos no hayan cambiado.
Tras cualquier excepción dentro de la frontera de escritura, la sesión queda
inhabilitada, aunque el nuevo puntero pueda ser visible. Se debe cerrar y abrir
para verificar la autoridad. No se vuelve a escribir automáticamente.

### Recuperación

| Punto de interrupción | Resultado al recuperar |
| --- | --- |
| Inicialización sin `HEAD` | Almacén incompleto: error, sin promover objetos aislados. |
| Intención todavía no publicada | Sigue la autoridad anterior; esta API no ha autorizado envío alguno. |
| Intención publicada sin desenlace | `RECONCILE_ATTEMPT`; conservar reserva y consultar al ejecutor futuro. |
| Resultado técnico durable sin incorporación | `INCORPORATE_RESULT`; procesar el resultado guardado, sin repetir herramienta. |
| Candidato registrado sin publicación | Confirmado anterior y candidato separados; `PUBLISH_CANDIDATE` si no hay intento pendiente. |
| Generación escrita, puntero anterior | La generación aislada no es autoridad; conservarla como sobrante. |
| Puntero reemplazado, acuse perdido | Verificar cadena y generación visibles; sincronizar el puntero antes de devolver autoridad. |
| Incorporación ya publicada | Recibo y generación concordantes; recuperar repetidamente no duplica efectos. |
| Autoridad ausente, corrupta o incoherente | Error cerrado; no devolver una sesión utilizable. |
| Invocación terminada | `INVOCATION_ENDED`; conservar reservas y estado de servicio sin inventar una reapertura. |

La recuperación no elimina sobrantes, no selecciona la generación con mayor
número, no revierte automáticamente y no llama a herramientas. Una nueva
invocación sobre una observación detenida, el cambio de configuración y la
conciliación con el diario del ejecutor quedan para la integración del coordinador.

### Formato, integridad y límites

Se usa JSON canónico ASCII, ordenado y sin números de punto flotante. Los bytes
de mensajes se conservan exactamente mediante base64 canónico. El códec tiene
una lista cerrada de clases y enumeraciones: no usa `pickle`, importaciones
dinámicas ni evaluación de expresiones. Rechaza campos desconocidos, claves
repetidas, versiones incompatibles y tipos fuera del contrato.

Límites de este perfil: 16 MiB por objeto y 100 000 registros por observación.
Un límite agotado produce error sin confirmación nueva. La recuperación es
lineal en el diario; las instantáneas y las trazas retienen historia y pueden
crecer. No se implementan compactación, rotación, recolección de sobrantes ni
un objetivo de rendimiento. Estos límites son decisiones de implementación,
no constantes atribuidas a TESIS ARDREC.

SHA-256 detecta cambios respecto de las referencias conservadas, pero no firma
el diario ni demuestra autenticidad frente a un propietario que reescriba toda
la cadena. Una restauración coherente antigua requiere un ancla confiable
externa para detectarse; `expected_head` comprueba esa igualdad cuando se aporta.
Los commits del desarrollo sí se firman mediante la configuración Git existente.
No se anuncia el almacén como resistente a un administrador hostil.

### Garantías del entorno

Perfil local Linux, mismo sistema de archivos, propietario único y directorio
privado. Se rechazan enlaces simbólicos en la apertura, archivos no regulares,
enlaces duros inesperados y sustitución de inodos retenidos. `flock` es cooperativo:
no reemplaza permisos ni protege contra programas que lo ignoren.

La durabilidad depende de que el sistema de archivos y el dispositivo respeten
`fsync` y sustitución atómica. Se sincronizan archivos **y directorios**; un error
de E/S nunca se convierte en éxito. No se certifican NFS, SMB, almacenamiento de
objetos, sincronizadores de carpetas ni el comportamiento físico ante un corte
eléctrico. Las pruebas de procesos y fallos inyectados verifican el protocolo de
escritura, no certifican la caché del dispositivo ni un sistema de archivos concreto.

### Trazabilidad

| Fuente | Implementación | Verificación |
| --- | --- | --- |
| TESIS ARDREC §3.10.1 | `_commit`, `_install`, `publish` | Publicación indivisible, E/S fallida, generaciones inmutables. |
| TESIS ARDREC §3.10.2, tabla 3.18 | `_recover`, `recovery_action` | 68 interrupciones con SIGKILL y reapertura repetida. |
| TESIS ARDREC §3.4 y §3.9 | `reserve`, `report`, recibos | Reserva durable, ausencia acreditada y contador sin duplicación. |
| TESIS ARDREC §3.5 | `transition`, `finish` y modelos previos | Separación de candidato, confirmado y salida de invocación. |
| Futuros A5 y A9 | API de almacenamiento disponible | No implica implementación completa de esos algoritmos. |

### Referencias técnicas

- TESIS ARDREC, secciones y tabla indicadas.
- Linux man-pages: [fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html).
- Linux man-pages: [flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html).
- Python: [os](https://docs.python.org/3.14/library/os.html), `fsync`, `replace`, `open`.

## English

### Context and scope

TESIS ARDREC §§3.10.1–3.10.2 and Table 3.18 distinguish decisions, intentions,
technical outcomes, candidates and confirmed generations. Sections 3.4, 3.5 and
3.9 require retained reservations, explicit uncertainty and accounting only after
confirmed incorporation.

This increment stores the existing operational state models. It does not complete
analytical state Z, algorithms A1–A10, the Rust executor's internal journal,
remote attempt queries or the operational prototype. Authorization, support and
calculated-effect references are caller-supplied facts requiring external
verification. System acceptance and experimental validation statuses are unchanged.

### Decision

`ardrec.persistence.DurableStore` implements `ardrec-store-1`, independently of
protocol 2.0. `LOCK` holds a nonblocking exclusive session lock. Immutable
`journal/<sha256>.json` records contain sequence, predecessor, operation,
arguments, resulting-state hash and generation reference. Immutable
`generations/<sha256>.json` snapshots contain operational state, incorporation
receipts and predecessor. `HEAD` is the sole authority, binding identity,
journal position and generation through hashes. `.pending-*` files are never
authoritative on their own.

Recovery replays validated operations rather than trusting an arbitrary state
snapshot. Published generations must exactly match replayed states.

### Transaction boundary

1. Validate the complete operation before writing.
2. For publication, write a temporary generation, sync it, install without
   overwriting previous objects, and sync its directory.
3. Persist the linked journal record using the same procedure.
4. Write and sync a temporary `HEAD` containing complete references.
5. Atomically replace `HEAD` and sync the store directory.
6. Return acknowledgement only after synchronization succeeds.

A durable technical outcome is not an incorporated analytical effect. `publish`
commits the receipt, events and generation together, without an essential second
transaction for a final marker. A lost acknowledgement requires authority
recovery, never an automatic physical action retry.

`reserve` persists the decision reference and intention atomically before any
possible external dispatch. This API has no decision-only persistence window;
it neither represents nor executes an earlier external decision. A recovered
pending intention requires reconciliation and cannot be reserved again. The
module contains no network or tool-execution operations.

### API and constraints

| Operation | Contract |
| --- | --- |
| `create(path, initial)` | Exclusively create a new store at generation 0, PREPARADO services, no attempts or simulation. |
| `open(path, record_id=..., configuration_sha256=..., expected_head=None)` | Lock, validate identity/history/generations and recover; optionally require an exact external head anchor. |
| `reserve(request, decision_reference=...)` | Record one intention on eligible confirmed state, without sending it. |
| `report(attempt_id, message, query=None)` | Correlate and persist observations; exact duplicates are no-ops. |
| `uncertain(attempt_id, reason_reference)` | Preserve identity, established facts and reservation. |
| `transition(service_id, transition, context)` | Record a candidate using existing T1–T10 rules, without advancing confirmed generation. |
| `publish(expected_generation=..., reference=..., event=...)` | Validate expected generation, unique references, publishable phases, resolved attempt and staged effects; incorporate atomically. |
| `finish(outcome, reason_reference)` | Persist invocation outcome separately from service states. |
| `state`, `head_sha256`, `recovery_action` | Read a valid locked session. |
| `close()` | Close descriptors and release the lock without deleting `LOCK`. |

Publication rejects uncertain attempts. Resolved outcomes require processing
transitions: T4 for execution, T5_NO_INICIO for verified absence, or T1 for
discovery. T10 allows a supported processable stop under the state model.
ACTIVO, VALIDACION and ACTUALIZADO remain candidate phases.

Events cannot be incorporated twice. The observation retains complete attempt
history; reopening does not reset its represented execution count. Verified
absence adds no execution. A complete unincorporated outcome keeps its reservation.

Sessions belong to one process and thread. Another writer receives `writer_busy`;
a session inherited through `fork` cannot be used. Retained inodes and head bytes
are checked. Any exception inside the write boundary poisons the session even if
a new head is visible. Close and reopen to reconcile; never retry blindly.

### Recovery

| Interruption | Recovery behavior |
| --- | --- |
| Initialization without `HEAD` | Error; never promote isolated objects. |
| Intention not published | Previous authority remains; this API has not authorized dispatch. |
| Published intention without outcome | `RECONCILE_ATTEMPT`; retain reservation for future executor reconciliation. |
| Durable outcome not incorporated | `INCORPORATE_RESULT`; process stored outcome without rerunning the tool. |
| Durable candidate not published | Keep confirmed and candidate states distinct; `PUBLISH_CANDIDATE` when no attempt is pending. |
| Generation installed, previous head | Preserve the orphan; it is not authoritative. |
| Head replaced, acknowledgement lost | Verify visible authority and synchronize it before returning. |
| Incorporation published | Receipt and generation agree; repeated recovery cannot duplicate effects. |
| Missing, corrupt or inconsistent authority | Fail closed without returning a usable session. |
| Invocation ended | `INVOCATION_ENDED`; retain reservations without inventing service reopening. |

Recovery never deletes orphans, selects the highest generation automatically,
rolls back automatically or invokes tools. New invocations after termination,
configuration changes and reconciliation against the executor journal remain
coordinator integration work.

### Format, integrity and limits

Canonical ASCII JSON uses sorted keys and no floating-point numbers. Canonical
base64 preserves exact protocol bytes. A closed class/enum codec uses no pickle,
dynamic imports or expression evaluation. Unknown fields, duplicate keys,
incompatible versions and invalid types are rejected.

Profile limits are 16 MiB per object and 100,000 journal records per observation.
Capacity exhaustion fails without new acknowledgement. Recovery is linear in
history; retained snapshots/traces grow. Compaction, rotation, orphan collection
and performance targets are not implemented. These are implementation choices,
not constants attributed to TESIS ARDREC.

SHA-256 checks consistency but does not sign records or authenticate against an
owner rewriting the complete chain. Detecting coherent rollback requires a
trusted external anchor; optional `expected_head` checks exact equality. Git
commits remain signed using the existing configuration. The store is not claimed
to resist a hostile administrator.

### Environment guarantees

This profile targets local Linux, one filesystem and owner, with a private store
directory. It rejects symbolic links while opening, nonregular files, unexpected
hard links and replaced retained inodes. Cooperative `flock` does not replace
permissions or protect against programs that ignore it.

Durability depends on filesystem/device compliance with `fsync` and atomic
replacement. Both files and directories are synchronized. I/O errors never become
success. NFS, SMB, object stores, folder synchronization services and physical
power-loss behavior are not certified. Process death and injected failures test
the write protocol, not device-cache correctness or a particular filesystem.

### Traceability

| Source | Implementation | Verification |
| --- | --- | --- |
| TESIS ARDREC §3.10.1 | `_commit`, `_install`, `publish` | Atomic publication, I/O failure, immutable generations. |
| TESIS ARDREC §3.10.2, Table 3.18 | `_recover`, `recovery_action` | 68 SIGKILL interruption cases and repeated recovery. |
| TESIS ARDREC §§3.4, 3.9 | `reserve`, `report`, receipts | Durable reservation, verified absence and no double accounting. |
| TESIS ARDREC §3.5 | `transition`, `finish`, previous models | Candidate/confirmed/invocation separation. |
| Future A5 and A9 | Available storage API | Does not imply complete algorithm implementation. |

Technical references: TESIS ARDREC sections above; Linux [fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html)
and [flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html); Python
[os](https://docs.python.org/3.14/library/os.html) documentation.
