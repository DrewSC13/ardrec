# Equivalencia del protocolo Python–Rust / Python–Rust protocol equivalence

## Español

### Objetivo y alcance

Se incorpora validación semántica en el ejecutor Rust para los perfiles 1.0 y 2.0
ya definidos a partir de TESIS ARDREC. El alcance comprende estructura, tipos,
campos obligatorios, variantes, versiones, restricciones internas, correlaciones,
repeticiones y serialización. Validar un mensaje no comprueba la existencia de
sus soportes ni autoriza ejecutar herramientas o repetir intentos.

La base de este incremento es `406b2566f7f5e560b4d90b94fcff3734c0396a71`.
Se conservan los mensajes válidos y los ejemplos aprobados. El perfil 1.0
mantiene sus restricciones históricas y no se transforma implícitamente a 2.0.
Se corrige una comprobación de fecha en Python para ambos perfiles, descrita abajo.

### Implementación

`ardrec_executor::messages` expone `validate_message`, `decode_message`,
`encode_message`, `correlate`, `correlate_status` y `compare_delivery`.
`MessageError::code()` identifica el rechazo y `Delivery` distingue `Replay`
de `New`. La comparación de entregas es local a dos documentos; no constituye
un registro durable de idempotencia.

El análisis JSON utiliza Serde con un visitante que rechaza claves repetidas
en cualquier objeto. Un control léxico previo impide decimales, exponentes,
ceros iniciales y números aproximados, y normaliza exclusivamente el entero
`-0` a `0`, como Python. Serde sigue siendo responsable de la gramática JSON.
Se rechazan UTF-8 inválido, documentos concatenados y datos posteriores.

El límite de entrada es 1.048.576 bytes, comprobado antes del análisis. Los
índices y límites numéricos operacionales conservan enteros hasta `2^63 − 1`;
los booleanos no se admiten como enteros. Las duraciones no pasan por `f64`.
El código de salida negativo de 1.0 se conserva, mientras 2.0 separa código
no negativo y señal. Las restricciones específicas de puerto, tiempo y soportes
se mantienen. Esto no amplía los mensajes con racionales ni cambia el contrato
numérico independiente de 256 bits.

La serialización válida coincide byte a byte con Python: claves ordenadas,
separadores compactos, orden original de listas e identidad exacta de enteros.
Todos los campos de texto actualmente admitidos son ASCII. Las fechas UTC se
validan por calendario gregoriano y hasta seis dígitos de fracción; la comparación
emplea componentes enteros y conserva las reglas temporales de cada perfil.
Se conserva el comportamiento de Python 3.14.7: `24:00:00Z`, con fracción cero,
representa la medianoche del día siguiente al comparar instantes. La cadena
original se conserva al serializar. Se rechazan minutos, segundos o fracciones
no nulos con hora 24 y el desbordamiento más allá del año 9999. Este caso se
verifica explícitamente porque Python 3.12 no acepta esa representación.

Durante la comparación se detectó que `datetime.fromisoformat` de Python 3.14.7
normaliza algunas fechas originales inválidas cuando la hora es 24:00, por ejemplo
`2026-01-00T24:00:00Z` y `0000-12-31T24:00:00Z`. Los perfiles Python ahora validan
el año, mes y día originales antes de esa normalización. Rust aplica el mismo orden.
Estas entradas se rechazan con `schema_invalid`; la aceptación accidental anterior
no se conserva como comportamiento contractual. Los ejemplos válidos permanecen intactos.

Se fijan tres dependencias directas: `serde =1.0.228`, `serde_json =1.0.145` y
`sha2 =0.10.9`. `Cargo.lock` fija las transitivas y sus sumas de comprobación.
Las versiones elegidas están verificadas para este incremento; no se presentan
como las últimas disponibles. Se conservan `forbid(unsafe_code)` y las reglas
de documentación del crate. La prohibición de código inseguro del crate propio
no constituye una auditoría de todas las dependencias transitivas.

### Verificación funcional del contrato

Las pruebas Rust directas comprueban ambos perfiles, bytes canónicos, enteros
exactos, límite de entrada, UTF-8, números no admitidos, claves duplicadas,
versión desconocida, repetición, reutilización de intentos, identidad y huella.

Las once pruebas nuevas en `tests/unit/test_protocol_equivalence.py` incorporan:

- Enteros alrededor de `2^53`, extremos operacionales y valores fuera de rango.
- Cero negativo entero; rechazo de decimales, exponentes, NaN e infinitos.
- Claves repetidas en cada objeto, incluidas claves equivalentes mediante escapes.
- UTF-8 inválido, BOM, truncamiento, comentarios, basura final y anidamiento excesivo.
- Fronteras de bytes, identificadores, soportes, puertos y presupuestos.
- Calendario bisiesto, años límite, fracciones y fechas no admitidas.

`scripts/verificar_protocolo.py` ejecuta también las pruebas históricas de mensajes
1.0 y 2.0. Para cada llamada ejercitada, aplica las mismas entradas a Python y
al binario Rust `protocol_probe`. Compara aceptación/rechazo, códigos de error,
clasificación de entregas y bytes canónicos, y comprueba que Python no muta las
entradas. Cada proceso de prueba tiene un tiempo máximo; una caída de Rust o una
respuesta inválida hace fallar la verificación. La sonda recibe una envoltura
acotada por stdin y no implementa un servicio de ejecución.

El corpus conserva expectativas explícitas en las pruebas; estas no se cambian
para ajustarse a lo que produzca Rust. Las comparaciones son evidencia para los
casos ejercitados, no una demostración exhaustiva de equivalencia para toda
entrada posible. Para entradas con varios errores simultáneos, no se establece
una nueva prioridad global entre errores de sintaxis y de semántica.

### Reproducción e integración continua

Desde la raíz del repositorio:

```bash
cargo fetch --locked
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests/unit -p 'test_*.py' -v
.venv/bin/python scripts/verificar_protocolo.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
```

La descarga de dependencias es explícita y utiliza el bloqueo existente. Las
compilaciones y pruebas posteriores usan `--locked --offline`. El verificador
comprueba que los archivos de bloqueo no cambien y emplea un directorio temporal
de compilación. El entorno Python sigue fijado en 3.14.7 y Rust en 1.98.1.

El trabajo Rust de CI prepara también Python con la acción ya fijada por SHA,
descarga las dependencias bloqueadas y añade el paso
`Contrastar protocolo Python-Rust / Compare Python-Rust protocol`.
Se conservan los pasos previos de compilación, Clippy y transporte.
El registro de ejecución local se encuentra en
`docs/development/F6-validacion-protocolo-rust.json`.

### Separación de estados

La implementación y la verificación del contrato pueden aprobarse sin aprobar
la aceptación funcional del sistema completo. Este incremento no ejecuta A1–A10,
no incorpora conciliación durable, no inicia el prototipo operacional y no genera
observaciones experimentales. La aceptación global permanece pendiente y la
validación experimental permanece sin ejecutar.

## English

### Objective and scope

This increment adds semantic validation to the Rust executor for existing 1.0
and 2.0 profiles derived from TESIS ARDREC. It covers structure, types, required
fields, variants, versions, internal constraints, correlations, repeated delivery
and serialization. Validating a message neither verifies external artifacts nor
authorizes tool execution or another attempt.

The baseline is `406b2566f7f5e560b4d90b94fcff3734c0396a71`. Valid messages and approved examples are preserved. Profile 1.0 keeps its historical
constraints and is never implicitly converted to 2.0. Both Python profiles receive
the calendar validation correction described below.

### Implementation

`ardrec_executor::messages` exposes `validate_message`, `decode_message`,
`encode_message`, `correlate`, `correlate_status` and `compare_delivery`.
`MessageError::code()` identifies rejection; `Delivery` distinguishes `Replay`
from `New`. Comparing two deliveries does not provide durable idempotency.

JSON decoding uses Serde with a visitor rejecting duplicate keys in every object.
A lexical check rejects decimal/exponent notation, leading zeros and approximate
numbers, normalizing only integer `-0` to `0`, as Python does. Serde remains
responsible for JSON grammar. Invalid UTF-8, concatenated documents and trailing
data are rejected.

The 1,048,576-byte input limit is checked before parsing. Operational indices
and numeric budgets preserve integers up to `2^63 − 1`; booleans are not integers
and durations never pass through `f64`. Negative exit codes remain available in
1.0; 2.0 separates a nonnegative exit code from a signal. Specific port, timeout
and support constraints are unchanged. This does not add rational values to
operational messages or modify the separate 256-bit numeric contract.

Valid serialization matches Python byte for byte: sorted keys, compact separators,
preserved array order and exact integers. All currently accepted text fields are
ASCII. UTC timestamps use Gregorian calendar validation and up to six fractional
digits. Integer component comparison preserves each profile's temporal rules.
Python 3.14.7 accepts `24:00:00Z` with a zero fraction as next-day midnight;
Rust applies the same instant comparison while retaining the original string
when serializing. Nonzero minutes, seconds or fractions with hour 24 and
rollover beyond year 9999 are rejected. This case is explicit because Python
3.12 does not accept that representation.

Differential review found that Python 3.14.7 `datetime.fromisoformat` normalizes
some invalid original dates when the hour is 24:00, including
`2026-01-00T24:00:00Z` and `0000-12-31T24:00:00Z`. Both Python profiles now validate
the original year, month and day before normalization, matching Rust's order.
Those inputs are rejected with `schema_invalid`; previous accidental acceptance
is not retained as contractual behavior. Valid examples remain unchanged.

Direct dependencies are pinned to `serde =1.0.228`, `serde_json =1.0.145` and
`sha2 =0.10.9`; `Cargo.lock` pins transitive versions and checksums. These versions
were verified for this increment and are not claimed to be the latest releases.
The crate retains `forbid(unsafe_code)` and documentation checks; this is not an
audit of unsafe code in every transitive dependency.

### Contract verification

Direct Rust tests cover both profiles, canonical bytes, exact integers, input
limits, UTF-8, rejected numbers, duplicate keys, unknown versions, replay, attempt
reuse, identity and hashes.

The eleven new tests in `tests/unit/test_protocol_equivalence.py` cover integers
around `2^53`, operational bounds, integer negative zero, floating-point rejection,
escaped duplicate keys, malformed documents, oversized input, identifier/support/
port/budget limits, leap years and timestamp precision.

`scripts/verificar_protocolo.py` also runs the historical 1.0 and 2.0 message tests.
Every exercised call is applied to Python and the Rust `protocol_probe` binary
with identical inputs. It compares acceptance, rejection codes, delivery status
and canonical bytes, checking that Python does not mutate inputs. Probe processes
have timeouts; a crash or invalid response fails verification. The probe accepts
a bounded stdin test envelope and is not an execution service.

Tests retain explicit expectations rather than changing them to match Rust output.
The comparisons are evidence for exercised cases, not an exhaustive equivalence
proof for every possible input. No new global syntax-versus-semantics error priority
is established for inputs containing multiple simultaneous faults.

### Reproduction and CI

Run the commands in the Spanish reproduction block from the repository root.
Dependency fetching is explicit and locked. Subsequent builds and tests use
`--locked --offline`; the verifier checks unchanged lock files and builds in a
temporary directory. Python remains 3.14.7 and Rust remains 1.98.1.

The Rust CI job also sets up Python using the existing SHA-pinned action, fetches
locked dependencies and adds
`Contrastar protocolo Python-Rust / Compare Python-Rust protocol`.
Existing build, Clippy and transport checks remain. Local execution evidence is
recorded in `docs/development/F6-validacion-protocolo-rust.json`.

### Separate acceptance states

Contract implementation and verification can pass while full system functional
acceptance remains pending. This increment runs none of A1–A10, implements no
durable reconciliation, starts no operational prototype and produces no
experimental observations. System acceptance stays pending and experimental
validation remains not run.
