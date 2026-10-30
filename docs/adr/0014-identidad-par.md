# ADR 0014 — Identidad del par / Peer identity

## Español

Estado: componente propuesto para revisión e integración; AL-07 permanece abierto.
Base revisada: `5306f15e0057dfa205168a23fd3b3b6196becc20`.
Tesis: SHA256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`;
secciones 3.7.5 y 3.9.2. Las obligaciones de soportes y resolución de 3.9.8–3.9.9
siguen pendientes y no se deducen de la identidad del canal.

### Problema y decisión

La conciliación anterior exigía que el llamador entregara un socket ya autenticado,
pero no comprobaba esa condición. Ahora `exchange_query` y `serve_query` verifican
las credenciales Linux del extremo conectado antes de leer mensajes, consultar el
diario dentro del intercambio o confirmar una respuesta.

La política exige PID, UID y GID exactos, proporcionados por el llamador desde una
fuente confiable ajena al mensaje y al socket. No se infiere la política de las
credenciales recibidas ni basta que ambos procesos compartan usuario. Python
rechaza la ausencia de `expected_peer`; Rust exige `PeerIdentity` como argumento.
PID cero, cuentas sin mapear, plataforma no implementada, canal no conectado,
familia/tipo incorrectos y errores del kernel no permiten continuar.

Python utiliza `SO_PEERCRED`; Rust usa la API segura de `rustix =1.1.6`, limitada a
Linux, con dependencias fijadas en `Cargo.lock`. Se mantiene `unsafe_code=forbid`
en el código del proyecto. Esto no afirma que las dependencias carezcan de código
unsafe. Las funciones auxiliares de identidad no consumen bytes; las funciones de
intercambio consumen el socket y lo cierran también ante rechazo.

El cambio altera la API de conciliación y adapta todos sus llamadores del repositorio.
No modifica formatos del protocolo, persistencia, estado analítico o matriz histórica.

### Alcance y límites

`SO_PEERCRED` conserva credenciales del establecimiento de la conexión (connect,
listen o socketpair). Un descriptor heredado o transferido no identifica a su nuevo
receptor. Las pruebas F10 con socketpair fijan la identidad del proceso creador y
solo prueban el transporte sintético. La nueva sonda conecta procesos separados por
una ruta Unix privada y exige el PID real del proceso servidor y del cliente.

Quedan por integrar la fuente confiable de identidades, el ciclo de vida del proceso,
la prevención de reutilización indebida de PID y la política de namespaces. Este
componente no prueba identidad del ejecutable, resistencia frente a procesos con
privilegios equivalentes o superiores, ni autorización operacional. El servicio real
necesitará además permisos de directorios/socket, control de descriptores, perfiles
congelados, integridad de recursos y validación semántica de referencias y soportes.
Los mismos requisitos se aplican al futuro camino de despacho, aún no implementado.

AL-06 y AL-07 siguen abiertos. Continúan AL04-R01/R02/R03 y el bloqueo previo al
ejecutor real. No se implementan A1–A10 ni se ejecuta un experimento.

### Verificación requerida

20 pruebas Python nuevas cubren credenciales, rechazos, errores, no consumo de bytes,
cierre, inmutabilidad y conservación del diario; cuatro pruebas Rust nuevas cubren
la política y el rechazo antes del diario. La suite completa exige 349 pruebas Python
y 73 Rust sin omisiones. Siete escenarios Python–Rust por ruta Unix comprueban éxito,
rechazo independiente de PID/UID/GID en cada lado y diarios intactos ante rechazo.
El paso nuevo de CI conserva todos los pasos anteriores. Véase
`docs/verification/peer-identity.md` para distinguir preparación y evidencia ejecutada.

## English

Status: component proposed for review and integration; AL-07 remains open.
The reviewed baseline and thesis hashes are listed above.

Previously reconciliation required a caller-authenticated socket without enforcing
that assumption. Both exchange APIs now compare Linux peer credentials against an
explicit, independently trusted PID/UID/GID policy before protocol reads or journal
access inside the exchange. Missing policy, invalid identifiers, unsupported platforms,
wrong socket type, disconnected sockets and kernel failures fail closed. Exchange APIs
own and close the connection; the credential helper does not consume bytes.

Python uses SO_PEERCRED and Rust uses the safe rustix 1.1.6 API with a locked dependency
graph. The project keeps its unsafe-code prohibition; this makes no claim about unsafe
code inside dependencies. All existing callers are updated. Persistence formats,
protocol formats, analytical state and historical acceptance records stay unchanged.

Credentials describe connection establishment, not a later recipient of a transferred
or inherited descriptor. Existing socketpair tests pin their creator and remain
synthetic transport tests. New pathname-socket scenarios use distinct actual process
identities. Trusted policy provisioning, process lifetime/PID reuse, namespaces,
filesystem permissions, descriptor control, executable integrity, frozen execution
profiles and semantic artifact/reference validation remain integration obligations.
This component neither authorizes operational execution nor closes AL-07 or AL-06.

Required checks: 349 Python tests (20 added), 73 Rust tests (four added), all existing
verification steps and seven new cross-language credential scenarios. Preparation-time
limitations and mandatory target-host validation are recorded in the verification note.
No A1–A10 algorithms, operational prototype or experimental validation are claimed.

## Referencias / References

- Linux unix(7), SO_PEERCRED: https://man7.org/linux/man-pages/man7/unix.7.html
- rustix socket_peercred: https://docs.rs/rustix/1.1.6/rustix/net/sockopt/fn.socket_peercred.html
- Contrato previo / Previous contract: `docs/adr/0008-conciliacion-por-transporte.md`.
