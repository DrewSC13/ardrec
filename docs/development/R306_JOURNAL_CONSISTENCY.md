# R306 — Consistencia material del diario / Journal materialization consistency

## Español

Se corrige el lector existente R294 (A5 histórico). Antes de devolver su
informe, contrasta las marcas de autorización, reserva y revocación y la
huella de reserva de la tabla `plans` con los eventos del mismo plan.
Además verifica la vigencia del plan para registro, consentimiento,
reserva y reclamación histórica de despacho, el vencimiento efectivo y
las restricciones temporales de reserva, reclamación y recibo. Los eventos
que se generan sin detalle deben conservarlo vacío.

Se utiliza exclusivamente la copia privada de los bytes SQLite ya fijados
por SHA-256. No se modifica el diario original, su esquema, ni el formato
del informe R294. Se conserva la compatibilidad con recibos R205 que no
contienen reclamación de despacho y con recibos posteriores al vencimiento
si la reserva fue válida. Los retrocesos de reloj que el escritor permite
siguen señalándose como incidencias de cronología, sin acreditar resultados.

La trazabilidad conserva la huella original R294 y exige la huella exacta
de la revisión R306, sin modificar el inventario histórico ni las aceptaciones.

Las pruebas crean diarios sintéticos reales y alteran únicamente sus copias
locales. No se invoca ningún ejecutor de protocolo. La coincidencia interna
no acredita autenticidad externa, causalidad con un caso DEV ni verdad técnica
A6. No se amplía autoridad ni se cierra AL-06 o AL-07; P8 sigue NO-GO.

## English

The existing R294 reader now reconciles the reservation digest and the
materialized authorization, reservation and revocation timestamps against
replayed events. It checks the original plan's validity interval and event
semantics. It reads only a private copy of the pinned database and leaves
both original bytes and the R294 report format unchanged. Legacy receipts
without a dispatch claim and valid late receipts remain readable. Clock
regressions permitted by the original writer remain chronology issues.
Synthetic SQLite tests exercise these checks without protocol execution.
Internal consistency is not external authenticity, causal DEV-case binding,
technical evidence admission or operational authority. P8 remains NO-GO.
