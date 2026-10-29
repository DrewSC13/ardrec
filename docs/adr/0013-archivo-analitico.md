# ADR 0013 — Archivo analítico / Analytical archive

## Español

Estado: implementación preparada; aplicación local e integración pendientes.
Base: PR #21, `302db91b4a5566d399fe12a3ac708f570485d02b`.
Fuente revisada: tesis SHA256
`6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`,
secciones 3.2.1, 3.9.10 y 3.10.1–3.10.2.

### Problema y decisión

La resolución del PR #21 recibe bytes de un proveedor. No conserva por sí sola
los objetos ni las proyecciones que los designan. `AnalyticalArchive` añade un
archivo Linux de conjuntos completos, separado de `DurableStore`. Antes de escribir
valida el manifiesto contra la huella esperada y resuelve las siete referencias de
cada servicio. Captura todos los bytes y las proyecciones canónicas antes de crear
el directorio temporal; no vuelve a consultar al proveedor durante la escritura.

Cada conjunto incluye metadatos canónicos con formato `ardrec-analytical-archive-1`,
huella del manifiesto y lista ordenada de huellas de proyecciones. La huella de esos
metadatos identifica el directorio instalado. Los archivos se nombran por SHA256
con sufijo `.json`: metadatos, manifiesto, proyecciones y objetos referenciados.
Se conservan los límites de los contratos existentes y se añade un máximo de
16 MiB por conjunto. Es una restricción de esta versión, no una cifra de la tesis.
No existe un límite de tamaño acumulado del archivo ni recolección automática;
su presupuesto total deberá establecerse en la integración y el laboratorio.

### Almacenamiento y recuperación

Una sesión mantiene un bloqueo exclusivo no bloqueante en `LOCK`. Todas las rutas
se abren por descriptores sin seguir enlaces simbólicos. Se exige propietario local,
directorios privados, archivos regulares privados sin enlaces duros y uso desde el
proceso e hilo que abrió la sesión. Los archivos se sincronizan y quedan con modo
0400; se sincroniza el directorio temporal, se instala mediante renombrado y se
sincroniza la raíz antes de devolver la huella. Se comprueban escrituras cortas.

Un conjunto existente se recupera y compara antes de reutilizarlo; no se sobrescribe.
Un fallo durante el almacenamiento o la recuperación invalida la sesión. Un error
de validación del candidato anterior a las escrituras no la invalida. Los temporales
se conservan para diagnóstico. `load(snapshot_sha256)` abre exclusivamente la huella
solicitada: verifica los metadatos, proyecciones, manifiesto y todos los objetos;
vuelve a sincronizar antes de devolver el conjunto completo. No busca una generación
mayor, no promueve huérfanos y no repara objetos ausentes o corruptos.

El fallo posterior al renombrado puede dejar el conjunto instalado aunque la llamada
no haya confirmado éxito. Debe reabrirse la sesión y recuperarse mediante la huella
esperada conocida. La presencia de ese directorio no confirma una generación global.
La muerte de proceso y los errores inyectados no sustituyen una validación de pérdida
de energía ni demuestran garantías de todo sistema de archivos.

### Frontera de autoridad y pendientes

La huella de los metadatos enlaza íntegramente el conjunto, pero su procedencia
confiable todavía debe establecerla el publicador global. No hay `HEAD` del archivo,
anclaje de frescura, selección automática ni promoción de autoridad. Un llamador puede
solicitar un conjunto histórico válido. La API no distingue por sí sola si es vigente.
El valor retornado no concede guardas ni autorización y las cargas siguen siendo
opacas. La alineación operacional del PR #21 sigue siendo una comprobación separada.

El modelo admite escritores cooperativos bajo un mismo propietario local. No protege
contra un atacante con el mismo UID o privilegios que modifique archivos y directorios
durante operaciones, ni contra reemplazo del almacenamiento subyacente. Deben validarse
el aislamiento, los permisos de ancestros y las garantías del sistema de archivos en
el laboratorio. No se incorporan credenciales, ejecución de servicios ni tráfico remoto.

AL-06 continúa abierto: faltan semántica de las cargas, estado analítico global completo,
fuentes verificadas para guardas y publicación integral con `DurableStore` y su
recuperación. AL-07 permanece abierto para perfiles, autorizaciones, soportes externos
y autenticación del par. Se mantienen AL04-R01/R02/R03 y los cierres acotados anteriores.
El punto 1, A1–A10, aceptación funcional, prototipo y experimento no se declaran completos.

## English

`AnalyticalArchive` stores complete projections, a pinned manifest and all referenced
objects in a separate Linux archive. It validates and captures the full input before
writing. Canonical metadata bind the manifest hash and ordered projection hashes;
their SHA256 identifies the installed directory. Existing codec limits apply, plus
a 16 MiB snapshot limit. Aggregate archive capacity and cleanup remain integration
and laboratory obligations.

A private, owner-controlled directory and a nonblocking exclusive lock restrict
cooperative writers. File descriptors reject symlinks, nonregular files, hardlinks
and cross-thread/process use. Files and directories are synchronized before success.
Existing snapshots are verified and reused without replacement. Failed sessions
must be reopened; temporary artifacts are retained. Loading requires an explicit
snapshot hash, verifies all content and synchronizes again. It never promotes an
orphan, selects the latest generation, repairs corrupt content or dispatches tools.

The archive has no authoritative HEAD or freshness anchor. An installed snapshot
does not establish global confirmation; opaque payloads do not grant authorization.
Trusted snapshot provenance, complete analytical state, semantics, sourced guards
and integration with global publication/recovery remain pending. AL-06 and AL-07
stay open. Same-UID/privileged adversaries and arbitrary filesystem durability are
outside this component's guarantees. Process-kill tests do not establish power-loss
behavior. All experimental and full-system acceptance claims remain pending.
