# Transporte local / Local transport

## Español

### Decisión y fundamento

La sección 3.9.3 de Marco Aplicativo_v3(1).pdf establece un socket Unix
local y tramas con un prefijo de cuatro bytes en orden de red,
seguido de un documento JSON UTF-8.

Este incremento implementa la capa de encuadre en Python y Rust:
longitud en bytes, recepción completa, escrituras parciales,
rechazo de longitudes inválidas y comprobación de UTF-8.

El máximo inicial del contenido es 1 MiB. Es una decisión de implementación,
no una cifra prescrita por la tesis. Es independiente del límite de
4096 bytes del contrato de una magnitud numérica.

### Responsabilidades

Las funciones de encuadre aceptan texto UTF-8 y no validan su gramática
JSON ni su esquema de dominio. Esas verificaciones corresponden a la
capa de mensajes. Una trama recibida no acredita una solicitud aceptada,
un inicio técnico, evidencia admitida ni una transición confirmada.

El llamador configura los tiempos de espera y descarta el canal después
de cualquier error de lectura o escritura. No se reintenta el mensaje.

La sonda utiliza un directorio privado 0700, un socket 0600 y tiempos de
espera de cinco segundos por operación de E/S. Estos tiempos no constituyen
un plazo total de trama. La sonda devuelve dos mensajes y termina;
es un auxiliar de pruebas, no un ejecutor de herramientas.

### Verificación y pendientes

Se incorporan pruebas unitarias de fragmentación, UTF-8, límites,
truncamiento, tramas consecutivas y escrituras sin progreso.
La prueba de integración intercambia dos documentos JSON entre procesos
Python y Rust mediante un socket Unix real.

Siguen pendientes el esquema completo de mensajes, correlación,
duplicados, reconciliación durable, autenticación del interlocutor
y gestión de plazos totales de producción.
No se ejecutan acciones técnicas ni experimentos de A1–A10.

Los comentarios explicativos del código se redactan únicamente en español,
de forma breve, para facilitar su estudio. La documentación del proyecto
y los mensajes de commit mantienen español primero e inglés después.

## English

### Decision and rationale

Section 3.9.3 of Marco Aplicativo_v3(1).pdf specifies a local Unix socket
and frames with a four-byte network-order length prefix followed by a
UTF-8 JSON document.

This increment implements Python and Rust framing: byte lengths,
complete reads, partial writes, invalid-length rejection and UTF-8 checks.

The initial payload limit is 1 MiB. This is an implementation decision,
not a thesis-prescribed value. It is independent of the numeric
magnitude contract's 4096-byte limit.

### Responsibilities

Framing functions accept UTF-8 text without validating JSON grammar
or domain schemas. Those checks belong to the message layer.
Receiving a frame does not establish request acceptance, technical
execution, evidence admission or a confirmed state transition.

The caller configures timeouts and discards the channel after any
read or write error. Messages are not automatically retried.

The probe uses a private 0700 directory, a 0600 socket and five-second
timeouts per I/O operation. These are not total-frame deadlines.
It echoes two messages and exits; it is a test helper, not a tool executor.

### Verification and remaining work

Unit tests cover fragmentation, UTF-8, limits, truncation, consecutive
frames and writes without progress. The integration test exchanges two
JSON documents between Python and Rust processes over a real Unix socket.

Full message schemas, correlation, duplicates, durable reconciliation,
peer authentication and production total-frame deadlines remain pending.
No technical actions or A1–A10 experiments are executed.

Explanatory code comments use Spanish only and remain brief to support
study. Project documentation and commit messages retain Spanish first
and English second.
