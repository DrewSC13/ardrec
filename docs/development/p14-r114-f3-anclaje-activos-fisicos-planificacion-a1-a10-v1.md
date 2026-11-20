# R114-F3 — Anclaje verificable de tres activos reales y planificación A1–A10

## Objetivo y límites

**Solo reutilización de evidencia física existente.** R114-F2 acreditó una matriz de 25 familias y 29 rutas con variantes, pero ninguna identidad A5 ni condición A6. R114-F3 une esa matriz al inventario **real** MAC/IP de R113-F2, preserva el recibo raíz de F10R y construye tres anclajes de activo (SSH, FTP y SMB) para que el prototipo pueda planificar actividades de verificación sin fabricar casos de laboratorio.

Fuentes requeridas, **reabiertas y verificadas** en cada generación y replay:

- R114-F2 matriz `matrix-b7f856d1`, manifiesto SHA-256 `8c8b06bd79828db5fb150ae8219ed3dd97a7f10ade0c19cbebb27c7e956fa57e`, informe `05d3f2415228386a250f7a8f38cc77d86c3bead5de0f6550226fe916d21a1c85`.
- R113-F2 identidad QGA `proof-c40akbko`, manifiesto SHA-256 `84e81025cac7180619edd530765052576a6726efe304ec3247bab68075df810b`. Su verificador vuelve a reproducir la captura F1 original. No consulta QGA.
- R114-F1 y F10R se revalidan a través de R114-F2: respuestas reales, hashes, ventana F6 cerrada, 3 conexiones TCP, SSH y FTP con identificación, SMB sin respuesta SMB2.
- Catálogo P7: 25 familias, 29 caminos de variante, SHA-256 fijado en los motores `r58h`, `r58i`, `r58j`.

## Semántica de salida

El sistema crea **tres** `asset_anchor_id`, cada uno vinculado a la VM, IP, CIDR, MAC y puente concretos del laboratorio. Los **29** `candidate_planning_id` identifican exclusivamente opciones de planificación de familias, no un `derived_case_id`, un `case_id_a7`, un intento A5, una condición A6 o una prueba ejecutada. No se generan 54 casos sintéticos. Un anclaje no prueba presencia actual del servicio fuera de la captura histórica.

El informe conserva para A1–A10 los límites de autoridad:

- A1: procedencia registrada y verificable, sin A5.
- A2: requisitos del catálogo identificados; las precondiciones no están acreditadas.
- A3 y A4: sin transición aplicada ni despacho de familias.
- A5: cero reservas e intentos iniciados; ninguna identidad A5 física acreditada.
- A6: `ND`; ningún soporte de familia admitido y ninguna vulnerabilidad afirmada.
- A7: ningún Rf confirmado ni recalculación de riesgo.
- A8 y A9: ninguna transición operacional ni generación publicada.
- A10: recibo privado reproducible; no se declara ejecución operacional de A10.

Las condiciones `HOST_KEY_MATCH`/`TRANSPORT_NEGOTIATION` (SSH-T01), `CONTROL_CHANNEL_RESPONSE` (FTP-T01) y `SMB_DIALECT`/`TRANSPORT_NEGOTIATION` (SMB-T01) permanecen pendientes hasta una comprobación A5 independiente, contextualizada y autorizada. El banner SSH, saludo FTP 220 y la conexión TCP SMB se conservan solo como hechos de servicio, no como soportes A6 automáticamente acreditados.

## Reglas operativas

1. Solo Python local. Cero `sudo`, `virsh`, `nft`, `systemctl`, TCP, nuevas ejecuciones QGA, activaciones de servicio, aperturas R34 o intentos A5.
2. Verificar rama, HEAD firmado exacto, árbol limpio y SHA-256 del ZIP antes de instalar; ejecutar las **743 pruebas** en Prometheus (707 anteriores más 36 nuevas), firmar commit, y no realizar push/merge.
3. Crear recibo privado 0700/0600 de un solo uso en `/home/cicada/ardrec-lab/r114-f3-physical-asset-anchors-v1` y replay sin red. Los datos unitarios simulados se emplean **solo en pruebas automatizadas**, jamás como evidencia física.
4. Si aparece un error después del inicio de la creación, conservar el incidente y no repetir a ciegas. El replay verifica tanto el hash como la equivalencia semántica recomputada de todas las fuentes.
5. Mantener `P8=NO-GO`, `A5=NO_START`, `A6=ND`, `Rf=NO_CONFIRMADO`, `PUSH=NO`, `MERGE=NO`.

## Paso siguiente

Elegir y autorizar una **identidad A5** para una familia y un activo, con alcance, precondiciones, configuración y soportes concretos. Preparar una verificación SMB2 independiente, acotada y con recuperación autónoma F6; no repetir F10R. Luego ejecutar los algoritmos reales de evaluación A6, recalibración A7 y transición A8 con únicamente evidencia admitida.
