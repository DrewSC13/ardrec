# ARDREC P14–R36.2 — Monitor profesional de desarrollo con evidencia real de infraestructura

## Identidad y alcance

- Base exacta de `main`: `b9af5eb0669d19881b18cb78dee7878858fcb753` (R35.4 PR #105).
- La topología real R35 fue terminada como `DEPLOYMENT_COMPLETE_INACTIVE`: redes SSH/FTP/SMB inactivas y cuatro dominios apagados. La cadena de recibos privados ya está autenticada por R35.4.
- La captura física R36.0, realizada en Prometheus de solo lectura, es `PASS_READONLY`, con `nft_guard.json`, `nwfilter.xml`, XML de 3 redes y 4 dominios, listados activos/inactivos y `interfaces.json`.
- La sesión R36.1 `DEV_TUTOR_001` contiene A1–A10 de desarrollo, **no** resultados de pentesting. No se puede transformar evidencia sintética en resultado técnico real simplemente cambiando el visor.

## Meta inmediata

Sustituir la presentación R28 de 10 pantallas aisladas por un monitor profesional `curses` con:

1. Panel izquierdo con inventario real y autenticado: cuatro dominios apagados, tres redes inactivas, nft y nwfilter verificados, sin TAP ni bridges reservados.
2. Indicadores de **CPU y memoria física del anfitrión en vivo** leídos de `/proc` y carga de `os.getloadavg` (sin `sudo` ni comandos externos).
3. Selector de A1–A10 con panel derecho de detalle que incluye fuente, entrada derivada del reporte real de desarrollo, proceso, estado, salida y guardas. Teclas `1..9`, `0` para A10, `h/l` o flechas, `Up/Down` para desplazamiento, `q` para salir.
4. Estado visible incondicional `P8 NO-GO`, diferencia estricta `REAL_READONLY_SNAPSHOT` frente a `SYNTHETIC_PREVIEW_ONLY`, `Rf` real `ND`, ningún despacho, generación ni evidencia final.
5. Representación textual y JSON sin una sesión curses para pruebas, auditoría, tutor y captura de evidencia.

## Proveniencia de datos y seguridad

Los parámetros requeridos son tres directorios existentes, privados (`0700`), cuyo inventario y SHA256SUMS se comprueban en Python: recibos de R35, R36.0 y R36.1. Los archivos deben ser regulares, privados, sin enlaces simbólicos ni miembros adicionales. Un SHA256SUMS verifica integridad de esa carpeta; no constituye por sí solo una firma independiente ni prueba de autenticidad física. El recibo R35 se valida además con el verificador de despliegue, el snapshot R36 se vincula por el digest interno R35 y se revalidan semánticamente XML, NFT, filtros, UUID, MAC, ciclo de vida, listados e interfaces mediante los validadores de R33–R35. Los datos R36 no se reconsultan en tiempo real; son **observaciones reales en la captura previa**. Las únicas métricas actualizadas automáticamente son CPU/RAM/load del sistema operativo que presenta la interfaz.

La salida de A1–A10 se obtiene de la sesión R36.1 verificada por `verify_development_cycle`. Los campos que carecen de evidencia operacional permanecen `ND`, `NOT_EXECUTED` o `PENDING`. Ningún cambio en A1–A10 se atribuye a la observación del anfitrión.

El monitor **no** invoca `subprocess`, no abre sockets, no utiliza `virsh`, `nft`, `ip` o `sudo`, no instala paquetes y no toca las VM. Una nueva observación libvirt requiere una captura física separada y autorizada. La aplicación del parche solo añade código y documentación al repositorio, sin acciones sobre libvirt/nft/host.

## Uso en Prometheus

```
python3 -B scripts/demo_p14_r36_readonly_dashboard.py \
  --r35-receipts /home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND/recibos-completacion-r354-20261114T184737Z-76964 \
  --r36-snapshot /home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND/r36-readonly-4cw4m4ny \
  --r361-receipts /home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND/r361-tui-preview-olAtckRK \
  --tui
```

Cambiar `--tui` por `--texto` o `--json` para revisar la fuente sin interfaz interactiva. Se recomienda terminal de al menos 110 columnas × 32 filas; funciona desde 76×20 con contenido reducido. Fuera de un TTY real, `--tui` devuelve error y nunca emula un éxito.

## Pruebas y límites

- 24 pruebas unitarias locales iniciales de vistas, permisos, inventario, procedencia, casos negativos y bloqueo de ejecución. Una prueba adicional de integración sintética verificó el lector empleando exactamente los validadores R33/R34/R35 del código actual y un modelo de recibo R35; esto **no** sustituye el ensayo en Prometheus.
- Deben ejecutarse regresión P14 completa, trazabilidad y CI tras commit firmado y sobre rama/PR protegidos. Ejecutar las pruebas con `umask 022` para preservar el ensayo R33 de directorios inseguros; mantener `umask 077` en los recibos reales.
- `P8=NO-GO` se mantiene. El laboratorio está apagado y nft/nwfilter son *deny-all*. La recolección de resultados SSH/FTP/SMB **reales** requerirá una fase distinta: validación de aislamiento tras arranque autorizado, políticas acotadas de comunicación, limpieza/restauración verificable, perfiles ejecutables con permisos explícitos y evidencia de cada familia. No simular que A5–A7 están operativos por mostrar un snapshot.

## Trazabilidad

Esta fase conserva 10 etapas A1–A10 y sus estados de desarrollo; no modifica el motor académico ni los 10 algoritmos. Los hallazgos AL-06 y AL-07 continúan abiertos, la aceptación funcional de sistema queda `PENDING`, y la validación experimental `NOT_RUN`. La siguiente iteración podrá conectar **eventos técnicos realmente autorizados** con la máquina de estados, las guardas, el cálculo Rf y la vista, sin contaminar los recibos R35/R36 ya cerrados.
