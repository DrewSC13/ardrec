# P14-R69 — Sesión DEV durable A2–A1–A9 desde la entrada normal

**Fecha del incremento:** 17 de noviembre de 2026. **Base:** `58c482bc3c3b9df833d25fe95778f3473e5d6d38` (R68 integrado). **Ámbito:** exclusivamente fixture sintética de desarrollo, sin autorización operativa P8.

## Problema y cambio implementado

La vista R28 calculaba una sesión sin generación confirmada A9, mientras R68 se consumía desde pruebas y reproducción. R69 incorpora una ruta opt-in en `scripts/demo_p14_r28_a1_a10_tui.py --durable-dev-root ...` y `python -m ardrec --durable-dev-root ...`, sin modificar la semántica de `--preview` ni del ciclo R28. Reutiliza las prevalidaciones R17–R21, la codificación canónica de estado, `DurableStore.create/open` y `evaluate_complete_a1` R68. El conjunto inicial confirmado contiene SSH_DEV, FTP_DEV y SMB_DEV en PREPARADO; las reglas congeladas y la fixture forman parte de la configuración y se vinculan mediante SHA-256 con `ConfirmedState.configuration_sha256`.

Se crea la generación 0 **una sola vez** y se reabre por replay de A9. Se reproducen las tres decisiones R68, los siete campos contextuales y el recibo `a1-generation-0.json`. La entrada `--tui` presenta una vista local de lectura y retorna al cerrar con `q`; sigue siendo una TUI DEV provisional y **no** es la integración completa R38. `--json`/`--texto` exponen identidad, generación, hashes y decisiones sin fingir resultados físicos.

La ruta rechaza un cambio de fixture o configuración congelada, hash externo incorrecto, generación obsoleta, `HEAD`/diario/generación corrompidos, archivo privado adulterado, dobles escritores, rutas con symlink, directorio compartido o pérdida del almacén tras congelar una configuración. Un almacén faltante no se reconstruye automáticamente. La inicialización parcialmente creada debe revisarse con sus archivos conservados. Los pines opcionales recibidos de CLI prueban concordancia con el valor proporcionado, **no** confianza de origen por sí solos.

La vía R28 de proceso benigno mantiene su contrato de ejecución local; se ajustó de 1000 a 3000 ms su límite para el fixture `ok` ante arranque frío del intérprete. El límite de 3000 ms ya estaba admitido por la clase de fixture, y no cambia la ausencia de autorización VM ni el límite de salida de 4096 bytes. El oráculo existente R28 conserva `BENIGN_EXIT_ZERO` como resultado exigido; DEADLINE es fallo, nunca PASS.

## Resultados de aceptación reproducibles

| Grupo | Prueba independiente / evidencia | Resultado esperado |
|---|---|---|
| A2 inicialización | Escenario fijado, R17–R21 y estado PREPARADO | Regla/estado/configuración vinculados a SHA |
| A1 consumidor real | R28 y `python -m ardrec`, tres decisiones R68 | SSH=ALLOW, SMB=DENY, FTP=ND y siete campos |
| A9 inicial | `DurableStore.create`, generación 0 y HEAD durable | Apertura y replay idénticos, sin nuevo diario |
| Recuperación / no corrupción | Mutación de configuración, HEAD, diario, generación o recibo | Rechazo sin recálculo oculto |
| Concurrencia | Dos aperturas simultáneas | Segundo escritor rechazado |
| Pines | Hash válido/erróneo, generación obsoleta | Coincidencia o fallo cerrado |
| Límite de confianza | Datos sintéticos, ND, sin Rf | P8=NO-GO, sin operación, sin publicación posterior |
| Compatibilidad | Regresiones R26, R28, R67 y R68 | Las salidas históricas no se sustituyen |

**Comprobación local del paquete:** `PYTHONPATH=src python -B -m unittest discover -s lab/tests -p test_p14_r69_durable_dev.py -v`, 21 pruebas. Ejecutar también R26, R28, R67 y R68. El resultado de CI, las firmas, la aplicación en Prometheus y cualquier prueba de laboratorio son evidencias separadas que solo se acreditarán cuando ocurran.

## Pendientes explícitos — siguientes incrementos

- A1: el núcleo R68 es reproducible; su recibo interno conserva `global_configuration_r17_membership_attested=false`, `external_pin_authority_attested=false` y `a9_publication_attested=false`. R69 vincula configuración y regla para **esta ruta de fixture**, sin alterar esas afirmaciones sobre un emisor externo o publicador posterior.
- A2: validación de configuración/autoridad real de los 54 casos y dependencias completas, fuera de las tres unidades de la fixture.
- A9: publicación candidata con `publish_analytical_counters` y sus siete grupos de invariantes, recuperación ante interrupción y actualización multigeneracional; R69 solo acredita creación y reapertura de generación 0.
- A3–A8/A10: unir el ciclo real de eventos, conciliación de un intento, A6 admisible, derivados exactos A7, precedencia A8, generación A9 posterior y reporte/TUI R38 desde el mismo `HEAD`.
- Laboratorio: F11, SSH/FTP/FTPS/SMB físicos, aislamiento, restauración, aprobación y evidencias siguen pendientes de verificación específica en Prometheus.

## English summary

R69 wires the existing frozen R17–R21 DEV fixture, R68's full A1 evaluator, and `DurableStore` initialization/recovery into the normal R28 CLI and Python module entrypoint. It creates an immutable generation-0 receipt for three synthetic services, replays it without duplicating the journal, and rejects changed configuration, corrupted storage, stale pins, and concurrent writers. It **does not** certify operational dispatch, physical observations, a recalibrated final risk, or subsequent analytical A9 publication.
