# ARDREC R112-F6 — Corrección física del ciclo de vida del hook F11

## Base y procedencia

- Rama acumulativa local: `feat/p14-r111-r114-real-lab`.
- Padre firmado: `fa965b28dcfc19172ab0fdf7fd3180bc7873efa1` (R112-F5).
- Hook instalado y verificado R112-F5: `0a9d84a45649e8a81d09298be0fd828b13c155bc372ed2c678c169d2e566a1c7`.
- Hook candidato F6: `1b35c2205a70ebdb1156d3cddd2e044a404763da3a9134df1f05dca48200269b`.
- Recibo F5 privado y plan F5 son entradas de procedencia, autenticadas antes de preparar la operación. No se publican en Git.

## Defecto corregido antes de permitir arranques

En libvirt 10.5+ el evento `release end` recibe una **causa de apagado** en el cuarto argumento; no siempre recibe `-`. El hook F5 negaba el cierre debido a la validación prematura de ese cuarto argumento. F6 procesa `stopped end` y `release end` para las VM R33 admitidas antes del control de argumentos de arranque. No borra marcas ni emite permisos en estos eventos.

En un reinicio de daemon, libvirt ejecuta `reconnect begin` sobre un QEMU activo. Rechazar la operación **puede matar QEMU**, por lo que F6 deja de rechazar indiscriminadamente las reconexiones de sesiones previamente completadas. Para autorizar `reconnect begin` exige tres marcas root-owned `0600` (`used`, `stage`, `active`) con un mismo SHA-256 bajo `/run/ardrec-f11-boot-v1` (`0700`, root). Las marcas solo nacen con `prepare begin` → `start begin` → `started begin`, en ese orden, con permiso válido de máximo 600 segundos. Una marca incompleta, alterada, ausente, symlink o con permisos débiles produce DENY. La reconexión posterior a la caducidad de un permiso se reconoce por la marca de arranque completado; **no autoriza nuevos arranques**.

## Intervención F6 (sin arranques)

1. Reproducir F5 y verificar el hook F5 instalado, todas las VM apagadas, las tres redes activas, F11 activo, `nwfilter` y nftables DENY, sin otros invitados asociados a R33 y sin permisos residuales.
2. Capturar el plan de cambio privado y verificarlo antes de modificar un archivo root.
3. Bajo autorización independiente, escribir la intención antes de cualquier operación; crear un stage root:root `0755` fuera de hooks; verificar SHA; hacer un único `mv -T` hacia el hook instalado.
4. Verificar cinco controles negativos de arranque/reconexión sin permisos y tres invocaciones directas de cierre legítimo. Comparar nuevo inventario real; solo se permite cambiar el SHA del hook.
5. Reabrir y reproducir los recibos; crear commit firmado local. **No hay push, merge, arranque de VM, red abierta, servicio FTP/SMB, ni datos experimentales A5/A6/A7/A9.**

Los tests unitarios emplean dobles de prueba para validar el código del mecanismo; **no se presentan como resultados físicos**. Solo Prometheus proporciona los recibos de instalación y lectura reales.

## Riesgos residuales que bloquean la admisión positiva

- El nuevo hook puede estar instalado sin que libvirt lo haya descubierto o ejecutado realmente; las pruebas directas no acreditan el callback del daemon. Se necesita una comprobación negativa integrada y control de invitados ajenos antes de cualquier permiso positivo.
- El funcionamiento de `reconnect` se demuestra en pruebas del hook, **no** mediante reinicio real de libvirt. No se reinicia el daemon para validar este incremento.
- Una sesión completada conserva las marcas de un solo uso; no se permite borrar ni reemplazar marcas automáticamente. La habilitación de un segundo arranque requiere una recuperación revisada con VM apagada y recibo nuevo.
- Una expiración durante el arranque puede rechazar el último evento. La autorización futura debe tener suficiente margen y supervisión independiente.
- Las barreras R34 y el `nwfilter` siguen en DROP, por lo que las conexiones reales de R113 aún no están habilitadas.
- `P8=NO-GO`; los 54 casos todavía no son mediciones físicas de SSH, FTP y SMB.

Documentación oficial: https://libvirt.org/hooks.html
