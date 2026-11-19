# P14 — R112-F8: primer arranque QEMU SSH real, admisión F11 de un solo uso

**Naturaleza:** operación física opcional y explícita sobre Prometheus, **no** una simulación ni ejecución A5. **Estado P8:** `NO-GO`.

## Procedencia

- Padre Git local firmado: `0b00f79afd8e7b62fb81c54807e099873ed726d5` (R112-F7); misma rama acumulativa `feat/p14-r111-r114-real-lab`.
- R112-F7: evidencia privada del intento `virsh start ardrec-r33-dev-ssh` **rechazado por libvirt** con el marcador del hook F11 v3, sin permiso y sin arranque.
- Hook F11 v3 físico: SHA-256 `1b35c2205a70ebdb1156d3cddd2e044a404763da3a9134df1f05dca48200269b`; propiedad root, modo 0755, única entrada en `/etc/libvirt/hooks`.
- Tres redes R33 activas pero sin forwarding, IP/DNS/DHCP; las cuatro VM apagadas; runner con tres NIC; `nwfilter` y R34 cuatro reglas DROP conservadas.

## Funciones y controles

El ejecutor `scripts/ardrec_p14_r112_f8_ssh_positive_boot.py` ofrece cuatro acciones independientes:

1. `--plan`: consulta el anfitrión, verifica los recibos F6/F7 y produce un plan privado sin mutación.
2. `--verify-plan`: reproducción documental del plan; no consulta ni modifica el estado actual.
3. `--boot-ssh <plan> --i-authorize-one-real-ssh-boot-under-r34-deny`: **única acción física autorizada** para iniciar `ardrec-r33-dev-ssh` con los filtros completos, tras nueva conciliación del anfitrión.
4. `--verify-boot <recibo> --plan-session <plan>`: verifica los archivos del recibo; no ejecuta el arranque ni declara que la VM continúe encendida.

La transacción física crea exclusivamente `/run/ardrec-f11-boot-v1` (`root:root`, 0700), el permiso específico `allow-ardrec-r33-dev-ssh.json` (0600) y un solo `sudo -n virsh -c qemu:///system start ardrec-r33-dev-ssh` bajo autorización del operador. El permiso contiene un nonce aleatorio de 256 bits, vigencia **180 segundos** (inferior al máximo de 600 del hook), identidad exacta, `R34 DENY` y `P8 NO-GO`. El hook consume el permiso una vez en `prepare`, registra `stage` en `start` y `active` en `started`. El recibo exige las tres marcas root-owned, todas correspondientes al SHA del permiso, `virsh start` exitoso, SSH `RUNNING`, otras tres VM apagadas, XML *live* SSH con interfaz exacta, redes aún activas y estructura R34/nwfilter sin alteración.

**No hay reintento.** Se almacena una marca durable `boot.once` *antes* de los primeros comandos que modifican el host. Si se pierde comunicación, hay timeout, falta una marca o se detecta drift, el ejecutor registra incidencia y no vuelve a emitir el permiso, no apaga el invitado ni intenta limpiar `/run` automáticamente. Se exige reconciliación humana posterior del host.

## Límites explícitos

- `RUNNING` demuestra el estado QEMU reportado por libvirt, **no** que Linux haya finalizado el arranque, que `sshd` esté activo o que el runner pueda conectarse.
- El arranque no autoriza tráfico, eliminación o modificación de R34, `nwfilter`, F11, watchdog, libvirt o redes.
- No se realiza `ssh`, `ftp`, `smb`, `nmap`, fuerza bruta ni prueba de explotación; A5 no ejecutado; A6 ND; Rf no confirmado; A9 cero.
- El permiso de un solo uso y sus marcas impiden arrancar de nuevo la misma VM sin un **nuevo procedimiento de restauración/admisión**, que todavía **no** implementa F8. No retirar manualmente `used-*`, `stage-*`, `active-*` ni alterar el permiso para intentar otro arranque.
- El vencimiento del permiso **no apaga** la VM. El cierre seguro y la recuperación de una VM encendida exigen una fase física separada. No reiniciar libvirt mientras una VM R33 está activa sin revisar previamente las reglas `reconnect`.
- Ante un inicio imprevisto o fallo de comprobación, preservar el recibo, verificar el estado real y aplicar el procedimiento de contingencia autorizado; no suponer que el error de la CLI significa que no hubo arranque.
- No se envían recibos privados a Git, no se hace push ni merge antes de R114.

## Criterios de aceptación

Pruebas nuevas R112-F8: 22; pruebas acumuladas R112: 171; pruebas de regresión R111: 11. Después de la operación física: un solo SSH en `RUNNING`, runner/FTP/SMB apagados, 3 redes activas y L2 DENY, `used/stage/active` con hash idéntico de la concesión, recibo privado reproducible y commit firmado. No se atribuye verificación de protocolo.

Referencia: https://libvirt.org/hooks.html — tres llamadas del hook QEMU durante arranque: `prepare begin`, `start begin`, `started begin`.

## R112-F8-R1: correccion de integracion antes del primer arranque fisico

El primer intento de F8 en Prometheus fallo con `AttributeError` antes de
`boot.once`, antes de crear la concesion root y antes del comando `virsh start`.
La causa fue pasar el modulo CLI de F6 a `f7_core.same` en lugar de su
motor puro `f6.core`, que define `snapshot_ok`. Las pruebas originales
habian sustituido `f7_core.same` con un mock; R1 elimina ese mock en las
pruebas del ejecutor y agrega verificaciones de la frontera F6/F7 real.

Este error no acredita ningun arranque SSH. Verificar en el host el estado
SHUTOFF de las cuatro VM, la ausencia del directorio de concesiones F11
y la ausencia de `boot.once` antes de crear un plan NUEVO. No reutilizar
el plan del intento fallido para iniciar un invitado.

No se modifican las politicas de host, F11, R34, `nwfilter` o las redes.
La autorizacion positiva siempre requiere una invocacion separada, voluntaria
y explicita, con recepcion de evidencias y prohibicion de reintentos.
