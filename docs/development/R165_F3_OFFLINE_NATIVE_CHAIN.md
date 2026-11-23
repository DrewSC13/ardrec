# ARDREC R165-F3 — Ejecución algorítmica nativa integrada

## Alcance

Ensayo de integración A5–A10 mediante los verificadores y reductores
originales, sin iniciar infraestructura, instalar autoridad root,
modificar nftables ni enviar tráfico a los servicios del laboratorio.

## Contratos ejecutados

1. B10: reproducción del diario F13, recibo B9 y resultado QGA.
2. B11: verificación documental de firmas Ed25519 y revocación.
3. B12: comprobación de calibración firmada y cálculo exacto A7
   mediante dos oráculos matemáticos independientes.
4. Estado nativo: transición T10 a DETENIDO en memoria.
5. B13/B12: comprobación de publicación A9 mediante el reductor
   original, sin crear una generación persistida.
6. A10: seis eventos verificables, vinculados mediante SHA-256.

## Procedencia del fixture

El ensayo positivo de A6 es inyectado con las simulaciones root y R127
ya utilizadas en las pruebas unitarias R129-B11. No constituye un
testimonio físico ni una ejecución independiente en el laboratorio.

La copia A6 se vincula al caso y a las firmas documentales, pero no
se acredita físicamente. B12 produce un valor matemático candidato,
nunca un Rf confirmado.

La autoridad VERDADERO del GlobalState de prueba pertenece únicamente
al modelo construido en memoria y NO representa autorización P8.

## Alcance de A8 y A9

La transición A8 se ejecuta realmente mediante transition_service,
pero afecta solamente al GlobalState de prueba, no al estado operacional.

B13 invoca el reductor nativo A9 como preflight. Su generación
candidata no se guarda. No se llama a DurableStore.create,
DurableStore.open ni DurableStore.publish en la integración F3.

Las transacciones persistidas reales en almacenes privados de prueba
siguen cubiertas por las suites R129-B13 y R129-B15.

## Validación y límites

Veinte pruebas nuevas verifican cálculo, identidad, trazabilidad,
replay, integridad, firmas, revocaciones, bloqueo root, prohibición
de sockets y exclusión de almacenamiento nativo.

A6=ND, Rf confirmado=None, A9 operacional=None, P8=NO-GO.
No se producen observaciones reales ni resultados experimentales
admisibles para las 54 unidades del estudio.
