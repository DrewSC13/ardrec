# ARDREC R58-B / F11: barreras de arranque y watchdog — CANDIDATAS FUENTE

Este incremento agrupa por primera vez las tres piezas necesarias para avanzar
sobre el bloqueo F11 observado en Prometheus: **dependencia exigible de systemd**,
**bloqueo del arranque de VM R33 por hook QEMU**, y **supervisión periódica
privilegiada exclusivamente DENY**. Son archivos VERSIONADOS, no instalados.

## Estado de origen

- Base: `main` merge PR #133 `a827a3935ec0bdeeff8a0fa0aabfca5f041d43a2`.
- R34 nft bridge: DENY observado, cuatro DROP, seis TAP.
- nwfilter `ardrec-r33-block-until-containment` DROP ALL.
- `ardrec-r34-boot-deny.service`: `enabled`, no ejecución registrada.
- `libvirtd.service`: `After=` sin dependencia fuerte demostrada.
- Cuatro VM apagadas; red FTP inactiva.
- `P8=NO-GO`, 0/25 familias aceptadas, pruebas experimentales pendientes.

## Componentes fuente

1. `lab/f11-runtime-v1/libvirtd-f11-guard.conf` es la propuesta de drop-in
   `/etc/systemd/system/libvirtd.service.d/90-ardrec-r34-boot.conf`.
   Añade `Requires=` y `After=` para la unidad existente, sin cambiar su código.
   Requiere analizar el impacto en otros invitados antes de instalar. No se
   debe reiniciar libvirtd durante la instalación de código.
2. `lab/f11-runtime-v1/00-ardrec-r33-deny` es el hook QEMU propuesto para
   `/etc/libvirt/hooks/qemu.d/00-ardrec-r33-deny`. En `prepare begin`, `start begin`,
   `migrate`, `restore`, `reconnect`, `attach` y otros eventos que no sean
   apagado/release devuelve error para las cuatro VM de R33. Los dominios
   ajenos al prefijo quedan inalterados. Un nombre no autorizado bajo el
   prefijo también se deniega. No consulta libvirt desde dentro del hook.
   No existe token, excepción ni ruta de autorización positiva.
3. `lab/f11-runtime-v1/ardrec-r34-deny-watchdog.service` y `.timer` son
   candidatos para un temporizador **del sistema** que invoca el bundle
   `root:root` F11 existente a intervalos. Solo verifica o crea R34 DENY
   cuando está ausente, mediante las restricciones de `boot-guard.py`.
   No es una garantía de disponibilidad continua: existen ventanas entre ticks,
   y cae si systemd/host no están operativos.
4. `scripts/ardrec_p14_r58b_runtime_design.py --verify-offline` valida el
   contrato de fuentes y emite los hash SHA256 de los cuatro candidatos.
   No comprueba ni modifica el host.
5. CI ejecuta la suite `test_p14_r58b_f11_runtime_design.py` offline.

## Restricciones decisivas

- Instalar un hook mientras libvirtd está arrancado **no implica que lo cargue**;
  libvirt requiere nueva inicialización del daemon para reconocer hooks.
- Un reinicio de libvirtd puede afectar VM **ajenas a ARDREC**. Primero se exige
  inventario y plan de continuidad o mecanismo específico equivalente.
- `qemu.d` requiere una versión de libvirt que soporte hooks por directorio;
  comprobar versión y ubicación efectiva antes de instalar.
- Nunca reemplazar hooks existentes ni desactivar redes no relacionadas.
- Las pruebas del hook en Python demuestran lógica de salida; solo una prueba
  negativa real de `virsh start` demuestra que libvirt utiliza el hook.
- `Requires=` no bloquea por sí solo API de arranque manual, y un watchdog
  periódico no da contención instantánea. Se requieren evidencias independientes
  de activación y readback del host.
- El hook está diseñado para DENEGAR todas las VM R33: **no instalarlo como si
  autorizara FTPS**. Una futura autorización temporal tendría otro cambio
  revisado y probado, con mantenimiento y restauración de DENY.
- Autoridad para aplicar configuración física: NINGUNA en este incremento.
  `P8=NO-GO`; ni tráfico, ni cambios en nft, ni libvirt, ni systemd.

## Plan de integración y habilitación futura

1. Integrar código, tests y CI en un PR único.
2. Con una autorización separada, hacer preflight efectivo del host, verificar
   versión de libvirt, ruta hooks, posibles conflictos, estado R34/bindings,
   VMs no ARDREC, integridad y permisos.
3. Preparar instalación atómica root-owned de archivos con hash y rollback
   de configuración, sin reiniciar libvirt todavía.
4. Autorizar por separado la activación y comprobar dependencias efectivas,
   ejecución inicial del guardia, carga del hook, prueba negativa de arranque
   acotada a R33, vigilancia y recuperación independiente con recibos privados.
5. Ninguna apertura de tráfico ni aplicación del XML FTP durante estas pruebas.

Fuente oficial de eventos QEMU: https://libvirt.org/hooks.html
