# Verificación del canal de conciliación / Reconciliation channel verification

## Español

Fuente del modelo: **TESIS ARDREC**. Especificación del componente:
`docs/adr/0008-conciliacion-por-transporte.md`. F10 conecta F9A y F9B por un socket Unix,
conservando los contratos de mensajes 2.0 y los formatos de almacenamiento existentes.

### Implementación

- `src/ardrec/reconciliation_transport.py`: transmisión de una consulta abierta y
  confirmación durable de la respuesta completa; consume el socket recibido.
- `crates/ardrec-executor/src/reconciliation_transport.rs`: validación de consulta,
  persistencia previa a la entrega y recuperación de respuestas históricas.
- `crates/ardrec-executor/examples/reconciliation_probe.rs`: sonda sintética de una
  conexión; recibe el socket por stdin y no abre endpoints ni ejecuta herramientas.

### Verificación funcional del componente

`tests/unit/test_reconciliation_transport.py` incorpora 14 métodos: respuesta íntegra y
reinicio, fragmentación, truncamiento de cualquiera de las tramas, longitud excesiva,
UTF-8 inválido, bytes adicionales, duplicación, JSON/versiones inválidos, codificación
no canónica, correlación e identidad incorrectas, incertidumbre, requisito de consulta
abierta, timeout, goteo de bytes, plazos inválidos y rechazo de tipos de canal incorrectos.
Los casos negativos comprueban que el puntero, la consulta abierta y el presupuesto
permanecen iguales. Una respuesta completa incierta mantiene el intento sin resolver.

Las diez pruebas Rust del módulo cubren respuesta durable y repetición exacta, rechazo
de solicitudes de ejecución, bytes sobrantes, tramas inválidas, intento desconocido,
versiones y codificación, espera de EOF acotada, plazos inválidos, emisor lento y
conflictos de identidad. Se mantienen las reglas `unsafe_code=forbid` y `missing_docs=deny`.

`scripts/verificar_conciliacion_transporte.py` construye las sondas e intercambia mensajes
entre procesos Python y Rust mediante sockets Unix anónimos heredados explícitamente.
Comprueba cuatro variantes: completado, interrumpido, no inicio verificable e incierto.
Repite cada consulta después de reabrir el diario y contrasta los bytes con su respuesta
durable. Un entero sintético `9007199254740993` comprueba conservación por encima de la
precisión exacta de binary64; no constituye una medición de duración experimental.

La misma prueba aplica **29 interrupciones reales por SIGKILL**:

| Proceso | Puntos | Comprobación posterior |
| --- | ---: | --- |
| Rust | 15 | Python conserva la consulta; Rust recupera el estado anterior o la respuesta íntegra; repetir añade como máximo un registro |
| Python | 14 | La consulta queda abierta o confirmada íntegramente; recuperar una respuesta ya durable no añade otro registro Rust |

En ambos diarios se comprueba la recuperación desde disco. El contador de ejecuciones
incorporadas sigue en cero y la generación confirmada sigue en uno. La consulta usa una
unidad de presupuesto, incluso tras recuperar y repetir el mismo intercambio.
Las inyecciones viven en sondas/pruebas; no hay una variable de entorno de producción
que active caídas. Estas pruebas no simulan pérdida de energía ni fallo de hardware.

### Ejecución y evidencia

Desde la raíz, con Python 3.14.7, Rust 1.98.1 y las dependencias de Cargo.lock disponibles:

```bash
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests/unit -p 'test_*.py' -v
.venv/bin/python scripts/verificar_conciliacion_transporte.py
```

La suite Python completa incluye 205 métodos. La suite Rust completa incluye 60 métodos
al sumar las diez pruebas nuevas a las cincuenta existentes. CI conserva sus pasos previos
y añade «Verificar conciliación por socket / Verify socket reconciliation».
El instalador vuelve a verificar en la máquina del proyecto antes de publicar y registra
las huellas y los resultados en `docs/development/F10-conciliacion-transporte.json`.
Los controles de empaquetado/formato/Clippy que exigen Git limpio se ejecutan después del
commit firmado y antes del push. Su estado en el archivo de evidencia corresponde al
momento de creación del archivo; la salida posterior confirma su resultado final.

### Validación experimental y aceptación

Estas pruebas verifican el componente. No ejecutan A1–A10, herramientas SSH/FTP/SMB,
experimentos, autenticación de pares o una sesión completa del prototipo. No acreditan
los criterios completos AC-10, AC-11, AC-20 o AC-21. La aceptación funcional del sistema
sigue pendiente; la validación experimental no se ha ejecutado. La autenticación,
el despacho real y la integración del ejecutor siguen pendientes.

## English

Model source: **TESIS ARDREC**. Component specification:
`docs/adr/0008-conciliacion-por-transporte.md`. F10 connects F9A and F9B through a Unix
socket while preserving message version 2.0 and existing storage formats.

### Implementation and component verification

The Python module sends an already open durable query and atomically completes the
received pair. The Rust module validates queries and persists answers before delivery.
Both own their supplied sockets. `reconciliation_probe.rs` is a synthetic single-use
peer receiving the socket through stdin; it opens no endpoint and executes no tools.

Fourteen Python test methods cover complete replies and restart, fragmentation,
truncation, excessive length, invalid UTF-8, trailing bytes, duplicate replies, invalid
JSON/versions, noncanonical encoding, correlation and identity mismatch, uncertainty,
open-query requirements, timeout, trickling input, invalid deadlines and channel types.
Negative cases retain the same durable pointer, open query and budget. Complete uncertain
replies leave the attempt unresolved.

Ten Rust methods cover durable reply replay, rejecting execution requests, extra bytes,
malformed frames, unknown attempts, incompatible/noncanonical input, bounded EOF waits,
invalid deadlines, slow senders and conflicting duplicate identities. Workspace rules
continue to forbid unsafe code and require public API documentation.

`scripts/verificar_conciliacion_transporte.py` builds the probes and exchanges messages
between Python and Rust processes through explicitly inherited anonymous Unix sockets.
It checks completed, interrupted, verified-not-started and uncertain variants. After
reopening the journal it repeats each query and compares exact durable reply bytes.
The synthetic integer `9007199254740993` checks preservation beyond binary64 exact
integer precision; it is not an experimental duration measurement.

Twenty-nine real SIGKILL interruptions cover 15 Rust publication points and 14 Python
confirmation points. Rust recovery yields either the previous state or a complete
answer; Python keeps the query open or confirms the entire pair. Explicit replay adds
at most one Rust answer record, never another record for an already durable answer.
Recovery reads both stores from disk. Incorporated executions remain zero, the confirmed
generation remains one and the query budget remains one across retries. Fault injection
exists only in tests/probes, not a production environment switch. Power loss and hardware
failure are not simulated.

### Execution, evidence and scope

Use the commands above with Python 3.14.7, Rust 1.98.1 and Cargo.lock dependencies present.
The complete Python suite has 205 methods; the complete Rust suite has 60. CI preserves
previous steps and adds the socket reconciliation verifier. The installer reruns checks
on the project machine and records hashes and results in the F10 JSON record. Packaging,
formatting and Clippy checks requiring clean Git run after the signed commit and before
publication; the record retains creation-time statuses and subsequent output confirms
final outcomes.

Implementation, component verification and experimental validation remain distinct.
These checks run no A1–A10 algorithms, SSH/FTP/SMB tools, experiments, peer authentication
or full prototype sessions. They do not establish complete AC-10/AC-11/AC-20/AC-21
acceptance. System acceptance remains pending, experiments have not run, and real
executor dispatch, authentication and integration remain pending.
