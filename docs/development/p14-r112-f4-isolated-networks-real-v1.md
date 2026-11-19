# ARDREC — R112-F4 / Redes libvirt físicas aisladas bajo DENY

## Fuente real y alcance

R112-F3, 2026-11-19, Prometheus: `ardrec-r33-dev-net-ssh`, `-ftp` y `-smb` están definidas, persistentes, sin autostart y **INACTIVE**; cuatro dominios R33 están SHUTOFF; F11 hook y R34 DENY permanecen activos. La lectura fue doble con `LC_ALL=C` y no introdujo cambios. Esta condición procede de una medición del host y no es un ejemplo sintético.

Base de trabajo local, **no publicada**: `1cc6db8e8b0ee19ad9f3474a062ad933430eb8f2`, rama `feat/p14-r111-r114-real-lab`. No hacer push ni merge antes de R114.

La NIC FTP y SMB del runner ya fueron definidas en R112-F1: todas las redes de esa VM deben estar activas para poder arrancarla. **Este incremento solamente activa las tres redes libvirt; no permite arrancar invitados ni establecer sesiones de protocolo.** El hook F11 sigue siendo deny-only, el filtro `ardrec-r33-block-until-containment` sigue DROP ALL y las cuatro reglas nftables R34 permanecen.

## Controles exactos

- Verificación fresca de **29** pruebas R111/R112 y tres lecturas `virsh net-info` en inglés, todas por `virsh --readonly`, para comprobar F11, R34, nwfilter, cuatro dominios apagados y tres NIC inactivas.
- Redes nominadas y UUID fijos: SSH `81661f30-4bf2-513b-a384-c5066d407548`, FTP `a301f714-46b9-5987-ba85-492edd9e65b8`, SMB `0d20eab3-1838-5c18-b182-73ae90f5fa9c`.
- XML: bridges `br33d30`, `br33d31`, `br33d32`; sin `forward`, `<ip>`, DHCP ni DNS habilitado. Autostart desactivado. La ausencia de IPv6 en el XML no se interpreta como prueba independiente de filtrado.
- Inventario adicional de dominios definidos: rechazar cualquier VM ajena con interfaz R33 en XML activo o inactivo. El inventario se conserva privado.
- Plan y recibos privados `0700`/`0600`, JSON canónico, huellas SHA-256, marcador `apply.once`, intención persistida **antes** de cada orden de libvirt.
- Mutación explícita única por rol: `sudo -n virsh -c qemu:///system net-start ardrec-r33-dev-net-{ssh,ftp,smb}`. Ningún `net-autostart`, `virsh start`, `nft -f`, redefinición XML, modificación de F11 o comando de red de protocolo.
- Después de cada operación se verifica el mismo inventario y el estado acumulativo (SSH, luego FTP, luego SMB), incluidos el hook DENY y la estructura nftables R34.
- Si hay fallo o incertidumbre, **no reintentar ni restaurar automáticamente**. Los archivos `.once`, `intent-*.json`, `result-*.json` y el último readback permiten auditar una ejecución parcial.
- La restauración es otro acto explícito, solo con cuatro invitados apagados y F11/R34 DENY: `net-destroy` de SMB, FTP y SSH en ese orden, con nueva lectura y recibo para cada paso. No invocarla mientras se desarrollan R113–R114 con invitados encendidos.

## Ejemplo de operación desde Prometheus

```sh
cd /home/cicada/Development/GitHub/ardrec
PYTHONPATH=src:scripts .venv/bin/python -B scripts/ardrec_p14_r112_f4_isolated_networks.py --plan
# Verificar el recibo del plan y repetir las comprobaciones antes de autorizar.
PYTHONPATH=src:scripts .venv/bin/python -B scripts/ardrec_p14_r112_f4_isolated_networks.py --verify-plan /home/cicada/ardrec-lab/r112-f4-real-isolated-networks-v1/plan-XXXXX
PYTHONPATH=src:scripts .venv/bin/python -B scripts/ardrec_p14_r112_f4_isolated_networks.py --apply /home/cicada/ardrec-lab/r112-f4-real-isolated-networks-v1/plan-XXXXX --i-authorize-three-deny-isolated-network-starts
```

La ruta real la imprime el CLI; no sustituir `XXXXX` por una ruta imaginada. El verificador de aplicación requiere el recibo exacto.

## Limitaciones

El control por hook F11 **sigue denegando los arranques R33**. `VM_STARTS=0`, `P8=NO-GO`, `A5=0`, `A6=ND`, `Rf` no confirmado, A9 sin publicación. Que la red esté `ACTIVE` tampoco acredita enlace, tráfico autorizado, servicio SSH/FTP/SMB configurado o seguridad del huésped. El siguiente incremento deberá definir una concesión de arranque específica y verificable, y una política acotada de comunicación entre invitados, antes de comenzar R113.

Documentación de hooks oficial: https://libvirt.org/hooks.html.
