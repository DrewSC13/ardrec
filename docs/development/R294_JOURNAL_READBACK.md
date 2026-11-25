# R294 — Reapertura histórica de diarios / Historical journal readback

Recupera diarios locales R205 mediante una copia temporal privada,
una huella SHA-256 esperada y el lector nativo Journal.snapshot.
Contrasta cronología, estados, contadores y recibos sin reservar
intentos ni acreditar autoridad operacional.

    python -m ardrec estudio --diario-historico /ruta/diario.sqlite3 --sha256 HUELLA --texto

También admite --json. No se suman diarios históricos como si
representaran observaciones experimentales independientes.

The reader preserves original bytes and rejects inconsistent state
or counter histories. Receipts remain unverified technical inputs.
Current authority is ND. P8 remains NO-GO.

No operational execution, formal pilot admission or A9 publication.

## Compatibilidad historica R206 / Historical compatibility

DISPATCH_CLAIMED is a historical reservation-bound event.
It does not change RESERVED or increment the attempt count.
Repeated claims and inconsistent reservation digests are rejected.
A recorded claim does not establish a completed physical operation,
current authorization or technical validation of a receipt.
