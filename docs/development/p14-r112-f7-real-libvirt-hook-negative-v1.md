# ARDREC P14 — R112-F7 / prueba negativa física de integración F11 con libvirt

**Origen:** commit local firmado R112-F6 `1a22f13ff585e9b3724a42680607c1d45f98469e`, rama `feat/p14-r111-r114-real-lab`.

Este incremento NO crea permisos F11, NO abre tráfico, NO modifica nftables ni XML, NO reinicia libvirt, NO hace push/merge, y conserva `P8=NO-GO`.

## Objetivo operacional verificable

Probar que **libvirt ejecuta efectivamente** el hook root-owned F11 v3 (`1b35c220…`), no solo que su CLI aislado devuelve 79. Realiza **exactamente un intento explícitamente autorizado** de `sudo -n virsh -c qemu:///system start ardrec-r33-dev-ssh` con ausencia total de directorio de permisos `/run/ardrec-f11-boot-v1`, redes SSH/FTP/SMB activas, cuatro VM apagadas y R34 invariable. El resultado aceptable es el rechazo por el propio hook **con** marcador `ARDREC_F11_QEMU_HOOK=DENY_UNATTESTED_OR_ALREADY_USED_LEASE` en el error de libvirt, cuatro VM apagadas después y DENY estructural intacto.

## Secuencia

1. `--plan` reautentica la instalación física R112-F6 y captura observaciones actuales; prueba por separado la denegación directa del hook; verifica que no haya otras VM ejecutándose y guarda un plan privado.
2. `--verify-plan` autentica el plan sin escribir en libvirt.
3. `--negative-probe ... --i-authorize-one-ssh-start-denial-test` vuelve a medir el host, crea un recibo de intención y un marcador exclusivo **antes** del intento real de arranque, ejecuta una sola llamada a `virsh start` para SSH y vuelve a medir todas las VM y redes.
4. `--verify-probe` reproduce el recibo y sus condiciones exactas.

**Advertencia de seguridad:** el comando de prueba efectivamente solicita arrancar una VM y su rechazo NO está garantizado antes de medirlo. Si el hook no está cargado por el daemon, el intento podría arrancar SSH. Ante respuesta incierta o un arranque inesperado, se conserva la evidencia y se detiene sin reintento, shutdown ni destroy automáticos. Se requiere revisión física y recuperación expresamente autorizada antes de cualquier acción posterior. No operar la prueba sin un responsable presente y capacidad efectiva de detener/aislar el invitado.

La revisión de libvirt indica que el reconocimiento de scripts hook instalados después del arranque del daemon puede exigir una nueva inicialización. Este incremento no reinicia servicios, ya que tal operación podría afectar invitados ajenos. La prueba negativa descubre el problema en vez de ocultarlo.

Ningún éxito de R112-F7 valida aislamiento contra tráfico, servicios dentro de los invitados, A5/A6/A7 o autorización operacional. Es una prueba exclusiva del control negativo F11.
