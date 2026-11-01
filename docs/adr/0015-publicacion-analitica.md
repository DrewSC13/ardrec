# ADR 0015 — Anclaje de la instantánea analítica / Analytical snapshot anchoring

Estado / Status: propuesto para integración / proposed for integration.
Base revisada / Reviewed base: `a4969622b6b1eb368a18810325dd122f9dcdce3e`.

## Español

La tesis vigente, SHA-256
`6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`,
secciones 3.9.10 y 3.10.1–3.10.2, exige resolver los objetos originalmente
confirmados y publicar una generación integral mediante un único puntero.
El archivo del ADR 0013 conserva bytes, pero por sí solo no determina cuál
instantánea corresponde a la generación confirmada.

Se incorporan operaciones explícitas `initialize_analytical_v1` y
`publish_analytical_v1` al diario existente. Ambas guardan `snapshot_sha256`
en sus argumentos y `analytical_snapshot_sha256` en el objeto inmutable de
generación. El único `HEAD` existente referencia esa generación y su diario.
No se crea un segundo puntero ni una marca posterior necesaria para confirmar.
Los recibos de incorporación siguen formando parte de la misma publicación.

Orden obligatorio:

1. Almacenar la instantánea completa mediante `AnalyticalArchive.store`.
2. Cargarla por su hash exacto, resolver todos los objetos y comprobar el
   contexto, conjunto de servicios y fases contra el candidato global que
   resultaría de la publicación.
3. Comparar caracterización, riesgo inicial y criticidad congelados con la
   instantánea confirmada anterior, si existe.
4. Instalar generación y diario inmutables; sustituir y sincronizar `HEAD`.
5. Devolver confirmación solo tras la sincronización y la comprobación final.

`DurableStore.create(..., analytical_archive=archive, snapshot_sha256=sha)`
permite comenzar con una generación cero anclada. Para un almacén histórico,
`open(..., analytical_archive=archive)` seguido de `publish_analytical(...)`
incorpora el anclaje durante una publicación operacional válida. No permite una
publicación vacía para simular una migración. La primera adopción no demuestra
los valores analíticos de generaciones históricas que carecían de anclaje.

Después del primer anclaje se rechaza `publish(...)`: cada generación posterior
debe usar `publish_analytical(...)`. Las operaciones intermedias retienen la
instantánea de la generación confirmada. La recuperación reconstruye todas las
operaciones y verifica también las instantáneas históricas ancladas, sin elegir
por fecha, nombre, generación máxima ni archivos huérfanos. Falta o corrupción
bloquea la apertura. Las lecturas y mutaciones de una sesión anclada vuelven a
verificar su instantánea vigente; un fallo invalida la sesión.

El llamador conserva abierto el archivo durante la vida del almacén y cierra
primero el almacén. Las sesiones conservan los controles de propietario,
proceso, hilo, permisos, enlaces y exclusión existentes. Los hashes no protegen
contra un atacante con capacidad de reescribir el almacén completo y todos sus
anclajes. `expected_head` permite contrastar un checkpoint externo confiable;
este incremento no implementa su custodia ni un servicio independiente de
frescura. Sin él, restaurar una historia antigua íntegra sigue siendo posible.

Compatibilidad: los registros existentes no se reescriben. Un almacén sin
anclajes conserva el comportamiento histórico. Los lectores antiguos rechazan
las operaciones nuevas como desconocidas. No se autoriza eliminarlas para
volver a ejecutar una versión antigua. No cambia el protocolo ni Rust.

Límites: el vínculo durable confirma identidad e integridad estructural; los
`payload` siguen siendo opacos. No acredita evidencia vigente, semántica de
contadores, objetivos, historial, ventana, controles ni fuentes de guardas.
No implementa A1–A10, evaluación analítica integral o autorización de perfiles.
AL-06 y AL-07 permanecen abiertos; tampoco modifica los cierres acotados
AL-04/05/09, sus obligaciones residuales ni la matriz histórica de aceptación.
La validación de corte eléctrico y garantías del sistema de archivos requiere
el laboratorio; SIGKILL verifica muerte de proceso, no pérdida física de energía.

## English

Thesis sections 3.9.10 and 3.10.1–3.10.2 require original confirmed references
and a single publication boundary. The new versioned journal operations bind
an immutable archive snapshot hash to the existing generation object. The
existing HEAD remains the sole publication pointer. Incorporation receipts,
operational state and the snapshot anchor share one generation publication.

The archive must be durable first. Publication loads exact bytes, resolves all
references, checks context, service set and candidate phases, and preserves
frozen values across anchored generations. Initialization can anchor generation
zero; legacy adoption occurs only through a valid nonempty operational
publication. A first anchor cannot prove absent historical analytical values.
Once anchored, legacy publication cannot discard the anchor. Intermediate
operations retain it. Recovery validates every anchored historical snapshot;
missing/corrupt data fails closed without promoting orphan or newer files.

The archive session must outlive the store session. Existing process/thread,
filesystem identity, permissions and locking controls remain applicable.
Current snapshot bytes are checked on session use. The optional trusted
external `expected_head` checkpoint detects a complete valid history rollback;
checkpoint custody and an independent freshness authority remain unimplemented.
Legacy bytes stay unchanged, and old readers reject new operation names.

Payload semantics, guard sources, full analytical state, algorithms, real
execution and operational profile authorization remain pending. AL-06/AL-07
remain open. Process-crash tests do not establish power-loss durability.
