# Perfil inicial de mensajes / Initial message profile

## Español

### Fuente y alcance

Se implementa un perfil inicial basado en las secciones 3.9.3 y 3.9.5–3.9.7
de TESIS ARDREC. Los ejemplos de solicitud, aceptación,
consulta y resultado corresponden a las páginas impresas 114–117.
La huella del documento se conserva en el ADR 0002.

El módulo `ardrec.messages` valida cuatro tipos en Python:
`execution_request`, `accepted_for_execution`, `attempt_status_request`
y `execution_result`. No representa todavía el protocolo operacional completo.
Las muestras de prueba se adaptan de los ejemplos académicos; las envolturas
de aceptación y consulta se completan con la identidad de la solicitud.

### Reglas

Se exigen los campos declarados y se rechazan campos adicionales.
La versión admitida es `1.0`. El productor debe corresponder al tipo.
Los identificadores, índices, referencias y fechas se validan antes del envío
y después de la decodificación. La representación JSON rechaza claves
duplicadas, decimales, NaN, Infinity, UTF-8 inválido y documentos concatenados.

La correlación exige coincidencia de registro, ejecución, decisión,
servicio–escenario, caso, intento y referencia de versiones.
Las aceptaciones y resultados deben referenciar la solicitud original.
El indicador de simulación del resultado debe coincidir con la solicitud.

Una aceptación conserva `start_status: NO_ACREDITADO`.
El resultado inicialmente admitido declara `technical_status: completed`,
inicio `VERIFICADO`, `timed_out: false` y limpieza `completed`.
Puede tener código de salida distinto de cero; terminar no significa
demostrar evidencia positiva.

### Decisiones iniciales de implementación

- Identificadores ASCII de 1–128 caracteres: letras, dígitos, punto,
  guion, guion bajo y dos puntos; inicio alfanumérico.
- Fechas UTC terminadas en Z, con hasta seis cifras fraccionarias.
- Índices y duraciones entre 0 y 2^63−1; código de salida con signo de 32 bits.
- Puertos entre 1 y 65535; tiempo solicitado entre 1 y 86400 segundos.
- Protocolos representados como `ssh`, `ftp` y `smb`.
- Hasta 1024 referencias de soporte, sin duplicados.
- Documento de hasta 1 MiB, conforme al límite inicial de transporte.

Estos límites y convenciones son decisiones del prototipo, no nuevas reglas
matemáticas de la tesis. El perfil de solicitud exige una referencia de
credenciales, siguiendo el ejemplo; no incorpora todavía una variante sin ella.

### Responsabilidades pendientes

Validar una referencia no comprueba que exista, sea auténtica o esté autorizada.
El módulo no incrementa contadores, inicia procesos, admite evidencia ni cambia
el riesgo. Tampoco conserva estado: detectar claves JSON duplicadas no equivale
a detectar la repetición de un mensaje o intento entre solicitudes.

Quedan pendientes los resultados inciertos o interrumpidos, la respuesta de
consulta, los demás tipos del protocolo, la conciliación durable, la gestión de
duplicados entre mensajes y la validación equivalente en Rust.

La suite se ejecuta mediante el paso existente de pruebas Python de CI.
Las pruebas de este perfil no constituyen validación experimental de A1–A10.

## English

### Source and scope

This initial profile follows sections 3.9.3 and 3.9.5–3.9.7 of
TESIS ARDREC. Request, acceptance, query and result examples
appear on printed pages 114–117. ADR 0002 records the source document hash.

The Python `ardrec.messages` module validates `execution_request`,
`accepted_for_execution`, `attempt_status_request` and `execution_result`.
It does not yet implement the full operational protocol.
Test fixtures adapt the academic examples; acceptance and query envelopes
are completed using the original request identity.

### Rules

Declared fields are required; additional fields are rejected.
The supported version is `1.0`, and the producer must match the message type.
Identifiers, indexes, references and timestamps are validated before encoding
and after decoding. JSON decoding rejects duplicate keys, decimals, NaN,
Infinity, invalid UTF-8 and concatenated documents.

Correlation requires matching record, execution, decision, service–scenario,
case, attempt and version references. Acceptances and results must reference
the original request. Result and request simulation flags must match.

Acceptance retains `start_status: NO_ACREDITADO`.
The initial result profile requires `technical_status: completed`,
a `VERIFICADO` start, `timed_out: false` and `completed` cleanup.
A nonzero exit code is allowed; completion does not establish positive evidence.

### Initial implementation decisions

- ASCII identifiers of 1–128 characters: letters, digits, dot, hyphen,
  underscore and colon, starting with an alphanumeric character.
- UTC timestamps ending in Z, with up to six fractional digits.
- Indexes and durations from 0 to 2^63−1; signed 32-bit exit codes.
- Ports from 1 to 65535; requested timeouts from 1 to 86400 seconds.
- Protocol values `ssh`, `ftp` and `smb`.
- Up to 1024 unique support references.
- Documents up to 1 MiB, matching the initial transport limit.

These are prototype decisions, not additional mathematical thesis rules.
The request profile requires a credential reference, following the example;
a credential-free variant is not yet included.

### Remaining responsibilities

Valid reference syntax does not establish existence, authenticity or authorization.
The module does not increment counters, start processes, admit evidence or change
risk. It is stateless: detecting duplicate JSON keys is not equivalent to
detecting repeated message or attempt identifiers across requests.

Uncertain or interrupted results, query responses, remaining message types,
durable reconciliation, cross-message duplicate handling and equivalent Rust
validation remain pending.

The existing Python CI test step discovers this suite automatically.
These profile tests do not establish experimental validation of A1–A10.
