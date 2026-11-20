# R114-F2 — Matriz reproducible de brechas por familia y variante

## Procedencia, prohibiciones y propósito

Únicamente recibe el original F1 `intake-d4371c00`: su manifiesto debe coincidir con el SHA-256 `923d8dda4d7e94f0d9173719d43c835fef68c33d8696cb3096c042ca35df680f`. Revalida los **siete archivos fuente**, la respuesta QGA efectiva, las tres observaciones, la restauración F6 y el reporte R114-F1 con sus hashes. El catálogo de 25 familias P7 se consulta mediante **los tres motores originales** (R58-H/I/J) y el pin `5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e`.

La matriz cubre 25 familias y 29 rutas de variantes (FTP-T02, FTP-T08, SMB-T03 y SMB-T09). Conserva explícitamente sus listas de precondiciones, soportes requeridos, soportes de aceptación y exigencias de limpieza.

**No acredita automáticamente ninguna precondición ni soporte**: una respuesta SSH `SSH-2.0`, el saludo FTP `220` y la conexión TCP SMB son hechos de servicio, no resultados de un intento autorizado identificado con `case_id`, `assessment_index`, `family_id` y prueba A5 firmada. No se generan 54 identidades de caso, no se ejecuta A5, no se evalúa A6 como verdad, no se calcula Rf ni se publica A9. P8 permanece NO-GO.

### Hechos físicos admitidos como observaciones, no como vulnerabilidades

- SSH: `10.203.30.1 → 10.203.30.2:22`, conexión TCP y banner de identificación SSH.
- FTP: `10.203.31.1 → 10.203.31.2:21`, conexión TCP y saludo de control `220`.
- SMB: `10.203.32.1 → 10.203.32.2:445`, conexión TCP, sin respuesta de negociación SMB2 acreditada.
- Cierre de la ventana F10R: F6 reportó restauración DENY y acreditación de las seis interfaces.

### Próximas verificaciones legítimas

1. Correlacionar identidades exactas de casos A5 con familias P7 **mediante autoridad independiente y recibo de inicio**, no por nombres/IP inferidos.
2. Obtener por método autorizado los soportes concretos exigidos por la familia; priorizar SSH-T01, FTP-T01 y SMB-T01 como **candidatas de revisión**, no hallazgos.
3. Corregir/analizar negociación SMB2 en una nueva ventana separada, solo con autorización y watchdog, preservando F10R inmutable.
4. Únicamente después, permitir clasificación trivalente A6 de una condición completamente soportada y su trazabilidad hasta A7/A8/A9; nunca asumir un riesgo final confirmado sin todos los requisitos.

## Reproducibilidad

El recibo F2 contiene `report.json` y `manifest.json` canónicos, en un directorio privado 0700, con archivos 0600 y escritura O_EXCL. El replay valida sus hashes y **reprocesa desde los archivos fuente F1** y el catálogo original, sin root, sin QGA, sin `nft` ni red. Una edición, suplantación o cambio de catálogo falla conservadoramente.

No se toca ningún recibo histórico ni se realiza push o merge.
