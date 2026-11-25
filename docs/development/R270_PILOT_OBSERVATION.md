# R270 — Observaciones funcionales del piloto

Incorpora recibos y archivos originales recuperados
sin repetir operaciones ni modificar informes historicos.

Vincula las observaciones con I1-I3, I6 e I7 y con
el controlador nativo del piloto.

El contador original de intentos es una lista de protocolos.
La cantidad se obtiene mediante validacion del conjunto
y su cardinalidad, no mediante comparacion lista-entero.

La lectura de control no acredita una comparacion de acceso
restringido. A6 permanece ND, A7 conserva las cotas y A8
emite exclusivamente una recomendacion.

No se publica una generacion A9 operacional.

## English

Read-only ingestion of recovered development observations.
Original failure history remains intact. No physical dispatch,
operational evidence admission or experimental promotion.

Private observations remain outside the public repository.
