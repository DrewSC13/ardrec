# ADR 0007 — Diario técnico Rust / Rust technical journal

## Español

Estado: componente implementado; integración con herramientas reales pendiente.
Fuente del modelo: TESIS ARDREC, tratamiento de duplicados, consulta del intento y recuperación durable.

### Problema

Una respuesta perdida no permite repetir una herramienta. El componente técnico necesita
conservar solicitudes, hechos declarados, resultados originales y respuestas de consulta.
Un rechazo de mensaje no demuestra ausencia de inicio. Un estado terminal con referencia
a un resultado tampoco basta si sus bytes completos no quedaron registrados.

### Decisión

Se incorpora `ardrec_executor::journal::TechnicalJournal`, un almacén local Linux con
un escritor exclusivo. Usa las dependencias ya fijadas del validador; Cargo.lock no cambia.
El formato independiente es `ardrec-technical-journal-1`. No comparte archivos ni formato
con el almacén analítico Python. Ambos se relacionan mediante mensajes del protocolo 2.0.

| Operación | Registro durable | Regla principal |
| --- | --- | --- |
| `register` | Solicitud original canónica | Mismo mensaje idéntico: repetición; otro mensaje con el mismo intento: conflicto. |
| `record_report` | Aceptación, rechazo o resultado | Resultado y snapshot se confirman juntos. |
| `observe` | Snapshot aportado por el adaptador | Conserva hechos determinados y orden temporal. |
| `answer` | Consulta, respuesta y resultado asociado | Devuelve bytes solo después de publicar HEAD. |

Registrar no ejecuta ni autoriza una herramienta. Antes de recibir hechos, la consulta
responde `uncertain`, inicio no determinado y `STATUS_UNAVAILABLE`. Un intento desconocido
produce `attempt_unknown`; nunca se inventa `not_started`. El primer acuse o rechazo
puede recuperarse mediante `first_reply`. Un rechazo conserva la incertidumbre existente.

Un snapshot `running` recuperado describe lo registrado en `observed_at`: no prueba que
el proceso siga vivo. Siempre exige conciliación. El adaptador futuro deberá comprobar
la situación real. Todas las respuestas conservan `new_execution_authorized=false`.

`observe` no admite un resultado disponible si falta su mensaje completo. Los hechos
acreditados de inicio y terminación conservan estado y referencia. Los estados terminales
no retroceden. Una limpieza pendiente puede resolverse con una observación posterior sin
reescribir el resultado original. Los mensajes inciertos pueden conservarse como diagnóstico;
no se transforman por sí mismos en evidencia ni en un resultado terminal disponible.

Los identificadores de mensaje quedan vinculados a bytes canónicos. Una consulta repetida
recupera su respuesta histórica exacta, aunque exista un estado posterior. Para una nueva
observación se necesita otra identidad de consulta. Los parámetros de respuesta suministrados
al repetir una consulta no cambian el acuse ya durable. El presupuesto de consultas sigue
perteneciendo al componente Python; el diario Rust no reinicia ese presupuesto.

### Publicación y recuperación

Cada operación nueva produce un registro canónico con formato, secuencia, huella anterior,
operación y argumentos. Su nombre es SHA-256 del contenido. Los registros se instalan sin
sobrescribir mediante enlace y retirada del temporal; un enlace temporal huérfano no altera
la identidad del objeto. El archivo HEAD contiene formato, secuencia y huella del último registro.

El orden es: escribir registro, sincronizar archivo, instalar registro, sincronizar directorio,
escribir y sincronizar HEAD temporal, sustituir HEAD y sincronizar directorio raíz. Los acuses
se devuelven después de esa frontera. Un error durante la publicación invalida la sesión:
se debe cerrar y recuperar antes de continuar, incluso si la sustitución ya pudo realizarse.

La recuperación recorre exclusivamente la cadena alcanzable desde HEAD, comprueba huellas,
secuencias, forma canónica, operaciones, correlaciones y transiciones, y vuelve a sincronizar
la frontera visible. No retrocede a una generación anterior si encuentra corrupción. No
interpreta temporales ni registros huérfanos como confirmados. Una carpeta sin HEAD no se
considera un diario vacío y no se reinicializa automáticamente.

`LOCK` es un archivo permanente. Su bloqueo exclusivo no bloqueante se mantiene durante
toda la sesión y se libera al cerrar el descriptor o terminar el proceso. No se elimina ni
reemplaza para recuperar un bloqueo. El directorio raíz se crea con permisos 0700; los archivos,
con 0600. Se rechazan enlaces simbólicos en las rutas comprobadas.

### Alcance y límites

- Solo Linux y un sistema de archivos local con semántica adecuada de fsync, enlace y rename.
- Directorio privado y rutas administradas por el mismo usuario; no se promete protección
  frente a un atacante con capacidad de sustituir rutas entre comprobación y uso.
- SHA-256 detecta alteraciones incoherentes; no autentica al propietario ni impide reescribir
  toda la cadena o restaurar una copia antigua válida. No existe un ancla externa antirretroceso.
- Máximo 4096 operaciones, 64 MiB de historial alcanzable y 4 MiB + 4096 bytes por registro.
  Son límites de implementación, no parámetros atribuidos a TESIS ARDREC.
- No hay compactación ni recolección automática de huérfanos. Al agotar límites se rechaza
  la escritura. No debe crearse otro diario para eludir identidades o reejecutar intentos.
- La reducción mantiene índices en memoria y copia el candidato antes de publicar. La
  recuperación y el coste de actualización crecen con el historial; no se afirma coste constante.
- No se verifican físicamente referencias de autorización, inicio, ausencia, limpieza o soportes.
- No hay servidor, transporte conectado a herramientas, planificación, lanzamiento ni reintento
  automático. A1 y el prototipo operacional no comienzan en este incremento.

### Verificación

34 pruebas Rust del diario; 60 interrupciones reales SIGKILL sobre registro, observación,
resultado y respuesta; bloqueo entre procesos; intercambio durable Python–Rust con reinicio.
Las interrupciones prueban muerte de proceso, no pérdida eléctrica ni todos los sistemas de
archivos. La aceptación funcional del sistema y la validación experimental siguen pendientes.

Referencia técnica de la implementación: biblioteca estándar Rust, `File::try_lock` y
`File::sync_all`: https://doc.rust-lang.org/std/fs/struct.File.html.

## English

Status: component implemented; integration with real tools remains pending.
Model source: TESIS ARDREC, duplicate handling, attempt queries and durable recovery.

### Problem and decision

A lost response does not permit running a tool again. The technical component must retain
requests, declared facts, original outcomes and query replies. A message rejection does not
prove that execution never started, and a terminal result reference is insufficient without
the complete stored message.

`ardrec_executor::journal::TechnicalJournal` is a local Linux store with one exclusive writer.
It uses existing pinned dependencies without changing Cargo.lock. Its independent format is
`ardrec-technical-journal-1`. It exchanges protocol 2.0 messages with Python rather than sharing
Python storage files or format.

| Operation | Durable record | Main rule |
| --- | --- | --- |
| `register` | Canonical original request | Identical delivery replays; a new message cannot reuse the attempt. |
| `record_report` | Acceptance, rejection or outcome | Outcome and snapshot publish atomically. |
| `observe` | Adapter-provided snapshot | Preserves determined facts and chronological order. |
| `answer` | Query, reply and associated outcome | Returns bytes only after publishing HEAD. |

Registration neither launches nor authorizes a tool. Before facts arrive, queries return
`uncertain`, undetermined start and `STATUS_UNAVAILABLE`. Unknown attempts return
`attempt_unknown`, never fabricated non-start. `first_reply` retrieves the first acceptance
or rejection. Rejections preserve existing uncertainty.

Recovered `running` snapshots describe the observation recorded at `observed_at`; they do not
prove current process liveness. The future adapter must reconcile the actual situation.
All replies keep `new_execution_authorized=false`.

Available-result snapshots require the full stored message. Verified start and termination
facts keep their status and references; terminal phases cannot regress. Pending cleanup may
be resolved without rewriting the original outcome. Uncertain messages remain diagnostics,
not automatically evidence or available terminal outcomes.

Message identities are bound to canonical bytes. Repeated queries return their exact historical
reply despite later observations. A fresh query requires a fresh identity. Newly supplied reply
metadata cannot alter an existing receipt. Query budgeting remains owned by the Python layer.

### Publication and recovery

Each operation records format, sequence, previous digest, operation and arguments. The immutable
record name is its SHA-256 digest. A link installs it without overwriting; removing the temporary
name leaves the installed object. Orphan temporary links do not change content identity.
HEAD holds the format, sequence and latest record digest.

Publication writes and synchronizes the record, installs it and synchronizes its directory,
then writes and synchronizes a temporary HEAD, replaces HEAD and synchronizes the root.
Acknowledgements follow this boundary. Any publication error poisons the session: close and
recover before continuing, even when replacement may already have occurred.

Recovery follows only the HEAD-reachable chain, verifies hashes, sequences, canonical encoding,
operations, correlations and transitions, and synchronizes the visible boundary. Corruption
never triggers fallback to an older generation. Orphans are not confirmed. Missing HEAD does
not mean an empty store and does not permit automatic initialization.

The permanent LOCK file holds a nonblocking exclusive lock for the session. Closing the handle
or process termination releases it; the file is not deleted or replaced. Root permissions are
0700 and file permissions 0600. Checked paths reject symbolic links.

### Limits and verification

The component targets Linux local filesystems with suitable fsync, link and rename semantics.
Paths must be privately managed; hostile path substitution races are outside the guarantee.
Hashes detect inconsistent alteration but do not authenticate the owner, prevent complete
chain rewriting or detect rollback to an older valid copy without an external anchor.

Implementation limits are 4096 operations, 64 MiB of reachable history and 4 MiB + 4096 bytes
per record. These are not TESIS ARDREC model parameters. No compaction or automatic orphan
collection exists. A full store rejects writes; a new store must not bypass attempt identities.
In-memory candidate copying and replay cost grow with retained history.

External authorization, start, absence, cleanup and support references are not physically
verified. There is no tool server, dispatcher, automatic retry or operational prototype here.
A1 remains unstarted.

Verification covers 34 Rust tests, 60 actual SIGKILL interruptions across four operations,
process locking and a durable Python–Rust exchange across restart. Process crashes do not
simulate power loss or every filesystem. Whole-system acceptance and experimental validation
remain pending.

Implementation reference: Rust standard library, `File::try_lock` and `File::sync_all`:
https://doc.rust-lang.org/std/fs/struct.File.html.
