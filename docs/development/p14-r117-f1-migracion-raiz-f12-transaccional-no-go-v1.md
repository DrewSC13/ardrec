# R117-F1 — Reconciliación de fuentes raíz F12 (NO-GO)

## Alcance

Actualización **explícita**, transaccional y reversible de los paquetes raíz F1 y F3 desde los bytes ya instalados de R116-F8 hacia los bytes fijados en el merge R116-F12/F13. **No es un piloto P7**, no constituye autorización, no habilita P8 ni genera evidencia A6. R113/R114, el intento `window-46ebd6a6`, su marcador y los recibos F9B/F10/F11 permanecen inmutables.

El contrato de origen corresponde al merge `fdb6efa0c297ce18b28cddb9494514f51d88bdb4`. El programa `scripts/ardrec_p14_r117_f1_redeploy_root.py` exige la rama R117, commit fuente firmado (G), ancestro base y árbol limpio. Comprueba los SHA-256 de F1/F3 y los 33 archivos de F3 contra sus manifiestos. Solo obtiene bytes desde Git comprometido y cotejado con el árbol.

## Procedimiento de operación

1. **Instalar y firmar** el parche F1 (solo fuentes y CI). No invoca comandos privilegiados.
2. Con autorización administrativa para mantenimiento de archivos privados del laboratorio, ejecutar `--inspect` usando el script **desde el nuevo commit firmado**. No se permite ejecutar a partir de contenido temporal o sin autenticar.
3. Exigir `R117_F1_RESULT=PASS_READONLY_REVIEW_READY_FOR_SEPARATE_APPLY`, 4 VM apagadas, DENY 0/6, cero temporizadores y F8 intacto. Si no se cumplen los requisitos, detenerse.
4. Solo mediante una **segunda ejecución explícita** de `--apply`, tomar bloqueo `flock`, volver a inspeccionar, archivar las instalaciones F8 mediante `rename`, instalar exclusivamente F12 en las rutas originales y revalidar hashes y F1 `--check`.
5. Conservar `capture-*` bajo `/var/lib/ardrec/r117-f1-root-f12-migration-v1/` y sus hashes privados. El expediente de R114 no se toca.

La migración usa nombres root originales porque los ejecutables F1 y F3 verifican `__file__` contra esas rutas. El manifiesto F3 nuevo asocia sus 33 fuentes con el commit R117 firmado de instalación, manteniendo `NO-GO`. No se añaden autorizaciones ni certificados; el directorio `authority/` permanece vacío.

## Recuperación y evidencias

Si el segundo montaje falla, el procedimiento mueve las instalaciones nuevas parciales al expediente y restituye las carpetas F8 originales, sin borrar bytes. Un fallo del rollback exige revisión humana; **nunca se reejecuta `--apply` a ciegas**. `--inspect` solo acepta la versión F8 de partida: tras migrar, su rechazo de una segunda ejecución es el resultado esperado.

## Garantías y limitaciones

- Prohibidos `nft -f`, `virsh start`, `systemd-run`, apertura de sockets, `--arm-deny`, `--execute-pilot`, modificación del catálogo y publicación de A9.
- R113/R114 se autentican mediante SHA-256 y replay histórico de solo lectura antes de mover F1/F3.
- Esta migración **no prueba** recuperación desde reglas permisivas, DENY 5/1, temporalidad dura inferior a 60 s ni una autorización externa.
- P7 permanece `DRAFT_NOT_CALIBRATED`, A6 `ND` y P8 `NO-GO`.
- El programa de migración se valida en tests sin privilegios con fallos y rollback; la aceptación física solo puede producirla Prometheus con evidencia del estado anfitrión.

## Evidencia de pruebas

`lab/tests/test_p14_r117_f1_root_migration.py` comprueba SHA de origen y los 33 pins, prohibición de ejecución sin modo, inspección sin aplicación, ruta de instalación explícita, escritor exclusivo, modos 0700/0600, rechazo de destino existente, bytes nulos y restauración ante fallo. CI ejecuta exactamente el patrón de test de R117-F1, sin solapamiento con futuras F10/F12/F13.
