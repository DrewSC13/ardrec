# ADR 0016 — Contadores analíticos / Analytical counters

## Español

Estado: implementado en preparación; validación completa en el equipo objetivo e
integración pendientes. Base PR #24: `415d758d813f46f975d5c9b72ef64ad6ff40ffb7`.
Fuente revisada: TESIS ARDREC, SHA256
`6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`.
Secciones 3.3.1, 3.4.4 (página impresa 95) y 3.9.10 (165–166).

### Problema y decisión

El anclaje del PR #24 conserva la pertenencia de las referencias a una generación,
pero las cargas siguen opacas. Un contador con una huella correcta podía discrepar
de los intentos incorporados. Este incremento comprueba específicamente esa carga
contra el diario reproducido y el estado de la generación candidata.

El formato `ardrec-execution-counters-1` contiene `format` y `cases`. Cada caso
contiene `derived_case_id`, `confirmed_executions` y `receipts`. Cada recibo contiene
`attempt_id`, `event_reference`, `generation_index`, `start_status`, `request_sha256`
y `report_sha256`. Se ordenan los casos por identificador y los recibos por generación
e identificador de intento. La comparación de bytes canónicos distingue booleanos
de enteros y rechaza versiones, campos extra, omisiones, duplicados y alteraciones.
Los límites del resolutor existente siguen aplicándose; si se supera su tamaño,
la publicación se rechaza y se conserva la generación anterior.

Solo se incluyen intentos de `scope=attempt` con recibo de incorporación confirmado.
La suma aumenta únicamente para `start.status=VERIFICADO`. Un `NO_INICIADO` conserva
su recibo con contribución cero. La reserva, aceptación, recepción de un resultado y
la incertidumbre no aumentan por sí mismas el contador confirmado. El descubrimiento
no se trata como ejecución de un caso derivado. Cambiar la invocación no elimina los
recibos anteriores del registro. Los recibos no pueden ser posteriores a la generación
de origen declarada por el objeto que los contiene.

El índice representa los casos con recibos: un caso sin entrada no tiene ejecuciones
incorporadas representadas. No es el catálogo de casos habilitados, ni verifica sus
presupuestos Lij, repetición autorizada, bloqueo por no inicio o perfiles operacionales.
No sustituye A3/A5 ni autoriza una nueva ejecución. Las reservas pendientes siguen en
el diario operacional y siguen bloqueando el despacho mediante sus reglas existentes.

### Integración y compatibilidad

`DurableStore.create(..., validate_counters=True)` requiere una instantánea válida y
registra `initialize_analytical_counters_v1`. `publish_analytical_counters(...)` registra
`publish_analytical_counters_v1`. La generación incluye
`analytical_validation=execution_counters_v1`. Estado, recibo y anclaje conservan la
publicación única de HEAD. Se valida antes de escribir y durante recuperación y acceso.

La adopción desde un almacén anterior ocurre en una publicación operacional no vacía;
no reescribe archivos históricos. Una vez adoptado, `publish` y `publish_analytical`
no pueden quitar la validación de contadores. La recuperación exige esa misma regla.
Los lectores antiguos rechazan las operaciones nuevas que desconocen. El modo previo
sigue disponible para datos históricos y continúa identificado como `structural_only`;
no recibe una certificación retroactiva de semántica. `analytical_validation` expone el
alcance efectivo después de reproducir el diario, sin aceptar una opción de apertura
que permita rebajarlo. Ninguna propiedad del objeto creado por un llamador demuestra
por sí sola autenticidad: la integración utiliza el estado del almacén durable.

### Evidencia y pendientes

31 pruebas nuevas cubren cómputo por caso, no inicio, aceptación, reserva, incertidumbre,
descubrimiento, separación de servicios/casos, recibos, versiones, incompatibilidades,
adopción, acceso, recuperación y 20 puntos de SIGKILL. La muerte de procesos no simula
pérdida física de energía. El total exigido en el equipo objetivo es 405 pruebas Python,
además de las 73 Rust, empaquetado y verificadores existentes.

Solo `execution_counters` adquiere validación semántica acotada contra los recibos.
Las otras seis cargas, la evidencia vigente, objetivos, historial analítico, ventanas,
controles y fuentes de guardas siguen pendientes. La custodia externa de frescura,
identidad operacional, perfiles y obligaciones AL04-R01/R02/R03 siguen pendientes.
AL-06 y AL-07 permanecen abiertos; punto 1 en curso. No se declaran implementados
A1–A10, aceptación funcional, prototipo operacional ni validación experimental.

## English

This increment validates the execution-counter payload against incorporated attempts
in the replayed durable state. Canonical case entries carry exact counts and receipts
with attempt/event/generation identity, start status and request/report hashes. Only
incorporated derived-case attempts with verified physical start increase the count.
Verified non-start retains a zero-count receipt. Reservations, acceptance, unresolved
attempts, unincorporated reports and discovery do not count as confirmed case runs.
Changing invocation does not reset earlier receipts. Object origin cannot precede a
receipt it claims to contain. Size limits fail closed.

Two versioned initialization/publication operations persist this validation mode in
the generation. Validation runs before writes, during replay and on access. Adoption
preserves historical bytes and requires a nonempty operational publication. Once
adopted, structural-only publication cannot downgrade it; old readers reject unknown
operations. Legacy data remain structurally validated only. Counts do not establish
catalog membership, budgets, authorization, no-start blocking or external authenticity.

31 added tests include 20 process-death boundaries. Target validation requires all
405 Python tests, 73 Rust tests, packaging and existing verifiers. Remaining payloads,
sourced guards, freshness custody and operational profiles are pending. AL-06/AL-07
and point 1 remain open, with no A1–A10, system acceptance or experimental claims.
