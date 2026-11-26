# R305 — Vinculación previa al despacho local / Local pre-dispatch binding

## Español

Se endurecen los puntos de entrada existentes R206 y R221, sin agregar un
controlador, operación, destino o permiso. Las transacciones de autorización,
reserva y reclamación del diario R205 aceptan la huella completa esperada del
plan. Ambos controladores la exigen. Los consumidores históricos de la API
conservan la firma anterior; la nueva opción no acredita autoridad operacional.

R221 comprueba todos los casos del lote antes de persistir el consentimiento,
verifica identidad, perfil fijo, plan, consentimiento y diario antes de reservar
y vuelve a leer los originales antes de entrar al ejecutor. Los archivos JSON
privados requieren propietario efectivo, modo 0600, tamaño acotado, forma
canónica, SHA-256 y ausencia de alias y enlaces duros. R206 contrasta el plan
registrado y el consentimiento exacto, y verifica la fuente FTP fijada antes de
reservar y otra vez antes de invocar el fixture. Esta fuente regular debe ser
propiedad del operador y no permitir escritura grupal ni de terceros.

Los rechazos previos a la reserva no consumen intentos. Un fallo posterior a
la reserva conserva el intento reservado como UNCERTAIN, sin recibo ni
reintento automático. No se presenta como una ejecución de protocolo.

Las pruebas usan SQLite y archivos locales reales, con centinelas en lugar de
los ejecutores y fuentes de cobertura y checkout de prueba. No realizan
tráfico ni acreditan una identidad de servicio físico. El límite de confianza
sigue siendo el operador monousuario; no se garantiza atomicidad entre el
último chequeo y el acceso al archivo por un proceso posterior. No se cierra
AL-06/AL-07, no se congela P7 y P8 permanece NO-GO.

## English

The existing R206 and R221 local software-fixture admission paths now bind
journal authorization, reservation and dispatch claim to the complete expected
plan digest. R221 rechecks batch, fixed case/profile, consent and private source
files before reservation and before runner entry. R206 checks the pinned FTP
source at both boundaries. No new executor, operations, destinations or
privileges are introduced. Legacy journal callers remain compatible. Tests use
real local files and SQLite with runner sentinels and test checkout/coverage
inputs; they generate no protocol traffic. Late rejection preserves UNCERTAIN
without retry or receipt. Same-UID races and physical operational admission
remain outside this proof; AL-06/AL-07 stay open, P7 unfrozen and P8 NO-GO.
