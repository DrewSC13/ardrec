# R114-F7 — Cierre trazable A1–A10 a partir de FTP-T01 real (ruta NO-GO)

## Procedencia y límites

Origen: recibo privado R114-F6 `intake-39e569b8`, SHA-256 del manifiesto `db39be6b144888c978fa35fb4aa6620342f81c6458acd9687cb99204d50e4686`, y recuperación postreinicio `session-80d39f15dad2`, SHA-256 del recibo `0eb4342ece47e75d11b1d3acf2be492183b8c7bd2e8f8afb4286fda57e8c7548`.

El intento físico `FTP-T01-S01-01`/`ATT_R114_F5_FTP_T01_01` produjo una respuesta de control `220` autenticada mediante F5/F5C/F6. La cadena de evidencia no constituye prueba de vulnerabilidad. El catálogo P7 permanece `P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE`.

El reporte R114-F7 no declara ejecución operacional de A1–A10; identifica sus límites para este caso real. A5 queda acreditado como observación física de un único intento; A3 sigue con cinco precondiciones formales ND, A6 permanece ND; Rf A7, transición A8 y publicación A9 no se confirman. A10 aquí es replay privado, no disparo operativo del algoritmo A10.

## Recuperación y seguridad

El operador solo ejecuta **replays históricos existentes** (`--replay`) y verifica bytes propietarios `0600` en sesiones privadas. No usa sudo ni root, no inicia VM, no invoca QGA, no realiza conexiones y no modifica `nft`/libvirt. No reinvoca capturas F5 ni ingestas F6. El SHA-256 del controlador de arranque anterior se autentica antes de su replay; el replay lee archivos existentes sin operaciones físicas.

Un único recibo privado F7 se sella con hashes de cada fuente. Cualquier modificación de fuente, replays, estado de política, número de conexiones o semántica A6/A7/A8/A9 impide reproducir el cierre.

## Criterio para merge de alcance reducido

Este incremento puede sustentar un **merge de código de ingesta y ruta segura de NO-GO**, condicionado a los controles de revisión y CI de la rama principal. No constituye aprobación para operaciones P8 ni para declarar un prototipo de recalibración de riesgo positivo a partir de datos reales. La habilitación formal A3/P7, los soportes de negociación SSH/SMB y la primera recalibración admitida A6→A7 siguen siendo trabajo pendiente y no deben silenciarse.

## Plan de aceptación

1. **903 pruebas en Prometheus:** 859 precedentes y 44 nuevas, sin regresiones.
2. Commit GPG firmado en rama `feat/p14-r111-r114-real-lab`, historial y árbol limpios.
3. Replay de F6 y recuperación postreinicio originales, ambos sin operaciones de host.
4. Creación y segundo replay del recibo R114-F7 con los dos hashes originales intactos.
5. `A6=ND`, `P8=NO-GO`, ningún cambio de red, sin push ni merge automático.
