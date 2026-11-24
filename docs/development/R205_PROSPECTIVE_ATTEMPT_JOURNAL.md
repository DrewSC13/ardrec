# R205 - Control transaccional de intentos prospectivos

Controlador no privilegiado para planes de fixtures locales.

Registra planes canonicos, consentimiento explicito vinculado
al plan, identidad del codigo, vigencia y alcance fijo.

SQLite conserva una unica reserva por plan mediante
BEGIN IMMEDIATE, restricciones de unicidad y synchronous FULL.

La revocacion previa impide reservar. Si ya existe una reserva,
la revocacion conserva el intento como incierto.

El registro de un hash de recibo no implica su validacion tecnica.
Las pruebas comprueban concurrencia, persistencia, expiracion,
revocacion, identidad y ausencia de reintentos.

El controlador no despacha operaciones de red.
No concede autoridad privilegiada ni reemplaza B4/B9.
No representa una autoridad humana independiente.
No protege contra un operador malicioso con el mismo UID.

La verificacion de identidad recibida requiere un invocador
confiable. Una reserva no sustituye la comprobacion de
autorizacion inmediatamente anterior al despacho efectivo.

A6 permanece ND. Rf confirmado y A9 operacional permanecen
sin publicar. P7 es borrador y P8 permanece NO-GO.
