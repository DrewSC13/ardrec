# ARDREC P14-R35.2 — Recuperación de nftables parcial / Partial nftables recovery

## 1. Base y evidencia

- Base Git: `62c59af210557a75161325f250485eed1271ed26` (PR #102).
- Incidencia: `installed_nft_table_semantics_mismatch` tras instalación de `bridge/ardrec_r34_guard` y **sin** recursos libvirt definidos.
- Prueba forense: prioridad impresa como `filter` pero JSON con `prio = -200`; tres cadenas, cuatro reglas `drop`, seis TAP exactos.
- Evidencia privada: `r35-private-Z9vpswND/recibos-instalacion-20261114T144532Z-41790` y `diagnostico-nft-CEv2Inzh`.

## 2. Cambio de motor

- Sustituir verificación textual por verificación estructural de `nft -j -a list table bridge ardrec_r34_guard`.
- Verificar familia/tabla, cadenas, prioridades numéricas, políticas, reglas, direcciones, conjuntos TAP, contadores y `drop` sin aceptar elementos o expresiones adicionales.
- Para recuperación, exigir el recibo de la primera instalación parcial con digest interno `8a082fc006c9a588c3d2063972221c953f4b264a4c6a277f14e750660e3123f1`, cadena fuente idéntica y evidencia histórica de una única creación nft satisfactoria.
- Revalidar en el anfitrión la tabla **existente** y todo el preflight R35 (colisiones, UUID, 12 QCOW2, 8 XML).
- Prohibir en recuperación el segundo `nft -f -`. Continuar con el nwfilter y las definiciones solo si la verificación JSON actual pasa.
- Mantener no-start, no-autostart, P8 NO-GO, ausencia de rollback automático, recibos privados y estado parcial en fallos.

## 3. CLI

La recuperación admite un modo de preflight de lectura independiente (`--preflight-verified-nft-partial`, sin autorización de instalación) y otro de instalación (`--resume-verified-nft-partial`, con autorización explícita). Ambos exigen el recibo anterior. Para la instalación:

```
--resume-verified-nft-partial
--prior-partial-receipts /RUTA_ABSOLUTA/recibos-instalacion-20261114T144532Z-41790
--i-authorize-r35-installation
```

Se aplican igualmente `--source-archive` y `--receipt-dir` (directorio inexistente), ambos absolutos. La instalación original `--install-deny-first-inactive` conserva el requisito de ausencia previa de tabla.

## 4. Límites y criterios de aceptación

- Este parche de Git no ejecuta acciones privilegiadas ni modifica el anfitrión.
- No usarlo para múltiples instalaciones, otras tablas, otros UUID o recuperación de un estado parcial diferente de R35.1.
- La recuperación en Prometheus está sujeta a ejecución separada, explícita y auditada.
- No inicia VM/redes, no modifica QCOW2 ni el firewall global, no instala persistencia y no habilita P8.
- Las condiciones de aceptación finales siguen siendo tres redes inactivas, cuatro VM apagadas, filtro deny-all y tabla nftables exacta; no hay validación funcional de pentesting.
