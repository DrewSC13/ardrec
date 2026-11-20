# ARDREC R115-F14 — Puente reproducible A5→A6 (NO-GO)

## Propósito

La entrada F13 conserva un resultado del lector FTP-T01 F10, medido por F12 y registrado con un intento único, pero **no constituye una certificación física**. F14 reconstruye la fuente F13 y genera una matriz de los soportes de A6, sin convertir un saludo FTP `220` en una condición de vulnerabilidad o riesgo confirmado. El esquema se limita al catálogo FTP-T01 y al SHA-256 inmutable del P7 borrador.

## Contrato funcional

- Verificación exacta del catálogo de 25 familias y del perfil no ejecutable.
- Relectura canónica del diario F13: reserva, consumo, terminal, hashes y replay del transporte F10/F12.
- Vinculación de `case_id`, sesión, índice, familia, destino, intento y SHA-256 de la reserva.
- Clasificación de `TARGET_ATTESTATION`, `INTEGRITY_PROVENANCE` y `CONTROL_CHANNEL_RESPONSE`. La comprobación local de bytes es un candidato de soporte, nunca autoridad técnica de A6.
- Resultados trivalentes `ND` para los tres soportes y las cinco guardas A3; A6 `ND`, riesgo confirmado no calculado, A8 no aplicado, A9/A10 no publicados, P8 `NO-GO`.
- Persistencia privada de revisión con SHA-256 y verificación reproducible contra la fuente F13 actual; los recibos anteriores no se alteran.

## Límites y operación

No hay sockets, `connect`, comandos FTP, arranque libvirt, nftables, `sudo`, firma, autorización, mutación del catálogo, generación publicada ni operaciones de persistencia A7–A10. Los datos devueltos son **auditoría de una fuente no acreditada físicamente**, no una afirmación de que el piloto se ejecutó.

El instalador R115-F14 solo instala, prueba y firma fuentes, y consulta `--capabilities`. Para auditar un diario F13 generado en una futura sesión autorizada: `PYTHONPATH=src:scripts python3 scripts/ardrec_p14_r115_f14_a5_a6_handoff.py --review-receipt /ruta/privada/case-...`; después `--verify-report /ruta/privada/review-...`. No ejecutar estos subcomandos con directorios ajenos o sin control de integridad.

La ejecución física continúa dependiendo de autoridad y revocación independientes, arranques autorizados, vinculaciones DENY, calibración P7, ventana P8 efectiva y atestación de origen. Las firmas de código Git no sustituyen esas autorizaciones.

## Validación

Pruebas aisladas con sockets simulados, controles de hashes, manifiestos, cambios de origen, rutas no confiables, alias de intento, relectura y prohibición de promoción A6/A9. Regresión R112–R114 y R115-F1–F14, sin red en instalador.
