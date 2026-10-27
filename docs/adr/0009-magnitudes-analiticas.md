# ADR 0009 — Magnitudes analíticas exactas / Exact analytical magnitudes

## Español

Estado: decisión implementada en este incremento; integración y CI remotas pendientes.
Fuente conceptual: TESIS ARDREC, secciones 3.2.9, 3.9.4, 3.9.10 y 3.10.
La revisión AL-05 identifica que el contrato Python permite componentes de 256 bits,
pero el codec operacional admite enteros de 64 bits y rechaza Fraction y ND.
AL-09 distingue equivalencia operacional de equivalencia del contrato numérico.

Se incorpora `ardrec.persistence.magnitudes`, un archivo independiente de objetos
inmutables, y `ardrec_executor::magnitudes`, un lector equivalente en Rust.
El formato `ardrec-magnitude-1` contiene exactamente `format` y `magnitude`.
El objeto `magnitude` conserva las variantes existentes DETERMINADO y ND.

| Elemento | Contrato | Rechazo |
| --- | --- | --- |
| Racional | Numerador con signo; denominador positivo; MCD igual a uno | Booleanos, flotantes, cadenas numéricas, cero en denominador y fracciones sin reducir |
| Componentes | Valor absoluto del numerador y denominador hasta `2**256 - 1` | Desbordamiento; el límite procede del contrato implementado, no es una cota matemática de la tesis |
| Cero | `0/1` | `0/d` para `d != 1`; el token JSON `-0` se interpreta como cero, igual que Python |
| ND | `reason_code` que cumple `[A-Z][A-Z0-9_]{0,63}` | Ausencia, motivo inválido, sustitución implícita por cero |
| Documento | UTF-8; campos exactos; claves únicas | Versiones distintas, campos extra, claves duplicadas, JSON malformado |
| Tamaño | Magnitud aislada: 4096 bytes; registro: 8192 bytes | Se rechaza antes de validar el contenido si excede su límite |

Los lectores pueden aceptar espacios y orden diferente de campos; producen los mismos
bytes canónicos ASCII, sin redondeo. El archivo persistente exige además que los bytes
almacenados ya sean canónicos. La variante ND mantiene su motivo como parte del hash.
No se añade conversión implícita al codec operacional ni a mensajes 1.0/2.0.

Rust utiliza la característica `raw_value` de la versión ya fijada de `serde_json`.
Se conservan los tokens enteros; cuatro palabras de 64 bits permiten validar el límite
y el MCD sin pasar por coma flotante. Esta representación valida datos; no implementa
las ecuaciones ni los algoritmos A1–A10. No se agregan dependencias ni cambia Cargo.lock.

La escritura exige un directorio privado y un único escritor cooperativo mediante
`flock`. Se escribe un temporal exclusivo, se completa toda escritura corta, se
sincroniza el archivo, se publica mediante renombrado y se sincroniza el directorio.
Solo entonces se devuelve la referencia SHA256. Un objeto existente se verifica y
reutiliza; no se sobrescribe. Los temporales de fallos se preservan sin autoridad.
Una excepción de E/S invalida la sesión; la recuperación abre otra sesión y verifica
nombre, integridad, formato, canonicidad y sincronización antes de devolver el valor.

La referencia identifica una magnitud, **no una generación analítica confirmada**.
Este archivo no tiene puntero HEAD, presupuestos ni estado de ejecución. AL-06 deberá
integrarlo en el estado analítico y su publicación global; AL-07 deberá resolver las
referencias externas con su contexto y autoridad. No se cambia el criterio de autoridad
de las generaciones operacionales existentes.

Compatibilidad: se mantienen los bytes, límites y lectores operacionales anteriores.
No existen objetos analíticos de este nuevo formato que migrar. Un formato desconocido
se rechaza; una futura migración requerirá versión explícita, comparación exacta y
preservación del original. No se reinterpreta un objeto operacional como magnitud.

Alcance del almacenamiento: Linux, sistema de archivos local con `flock`, renombrado
atómico y `fsync` efectivos; directorio administrado por el mismo usuario confiable.
Se rechazan enlaces simbólicos, enlaces duros y sustituciones detectables de directorio
o bloqueo. No se promete resistencia frente a un atacante con el mismo UID, NFS,
fallos del hardware ni cortes físicos de energía. SIGKILL prueba caída del proceso.
No hay eliminación automática de huérfanos ni cuota global de objetos en este componente;
la gestión de capacidad y retención corresponde a la integración del estado completo.

La evidencia se enlaza en [magnitudes exactas](../verification/exact-magnitudes.md) y
[la ampliación de trazabilidad](../traceability/exact-magnitudes-v1.json).
La matriz histórica y las instantáneas previas no se reescriben. El cierre integral de
AL-05/AL-09 requiere verificar e integrar el incremento; la aceptación funcional global
y la validación experimental permanecen pendientes.

## English

Status: decision implemented in this increment; remote integration and CI pending.
Conceptual source: TESIS ARDREC, sections 3.2.9, 3.9.4, 3.9.10 and 3.10.
AL-05 identifies the mismatch between 256-bit numerical components and the 64-bit
operational codec. AL-09 separates operational parity from numerical-contract parity.

`ardrec.persistence.magnitudes` adds an independent immutable object archive;
`ardrec_executor::magnitudes` adds the equivalent Rust reader. A record has exactly
`format: "ardrec-magnitude-1"` and `magnitude`, preserving the DETERMINADO and ND variants.
Rationals require reduced form, a positive denominator, and component magnitudes at most
`2**256 - 1`. This engineering bound comes from the existing contract, not the thesis.
Zero is `0/1`; JSON `-0` has Python's zero meaning. ND preserves its explicit reason
matching `[A-Z][A-Z0-9_]{0,63}`. Booleans, floats, numeric strings, overflow, duplicates,
extra fields, invalid UTF-8 and unknown versions are rejected. Limits are 4096 bytes
for a standalone magnitude and 8192 bytes for a record.

Readers accept JSON whitespace and field reordering, returning identical canonical
ASCII bytes without rounding. Persistent objects must already be canonical. Rust uses
`raw_value` in the pinned serde_json version and four 64-bit words for exact range/GCD
validation. No dependency version or Cargo.lock changes; no A1–A10 equations are added.
Operational codecs and messages 1.0/2.0 retain their original domain.

A private directory and nonblocking `flock` allow one cooperating writer. An exclusive
temporary file is fully written and synchronized, renamed, then its directory is
synchronized before returning SHA256. Existing objects are verified and reused, never
replaced. Failure remnants are preserved without authority. I/O errors invalidate the
session; recovery opens another session and verifies identity, hash, format, canonical
bytes and synchronization before returning a value.

A reference identifies one magnitude, **not a committed analytical generation**.
There is no HEAD pointer, execution state or budget in this archive. AL-06 must integrate
analytical state and global publication; AL-07 must resolve external references and
authority. Existing operational generation authority is unchanged. No old analytical
objects need migration; future migrations must explicitly version the format, compare
exact values and preserve originals. Operational objects are not implicitly converted.

The scope is a local Linux filesystem with working flock, atomic rename and fsync,
managed by a trusted owner. Symlinks, hard links and detectable lock/root replacement
are rejected. Same-UID attackers, NFS, hardware faults and physical power loss are
outside the guarantee. SIGKILL exercises process death. No automatic orphan collection
or global object quota is provided; full-state integration must govern capacity and
retention. Historical snapshots remain unchanged. Component verification and integration
are required before closing the findings; system acceptance and experiments remain pending.
