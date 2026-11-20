# ARDREC R112-F2 — Readback real de F11 tras añadir NIC FTP/SMB

## Objetivo

Obtener una **segunda medición física** del host Prometheus antes de introducir
cualquier autorización temporal de arranque. R112-F1 ya modificó **solo** el XML
inactivo del runner, añadió las NIC FTP y SMB y verificó el readback.

Base local: `8d46223ee39fb66305c40c24cdf7e0ce0078ce88`, rama
`feat/p14-r111-r114-real-lab`. No publicar ni fusionar antes de R114.

## Fuente física vinculada

- R112 plan privado: `/home/cicada/ardrec-lab/r112-real-runner-nic-v1/plan-gavsqoqt`
- R112 aplicación física: `/home/cicada/ardrec-lab/r112-real-runner-nic-v1/apply-ah1ck__9`
- R111 original: `ec6cab5569c559d274f318d0dd0c6abd3989f416a7384f84bae35129a5a04851`
- Hook F11 fijado: `8bad829fa029d78375f28f6978669721dc934481a97ee867449f45a1662dbc38`

## Implementación

El ejecutable reutiliza **29 sondas físicas de solo lectura** R111/R112:
libvirt, XML de cuatro dominios, tres redes, `nwfilter`, reglas nftables,
propiedad/hash del hook y unidades F11. Añade cuatro consultas `systemctl show`
de la unidad `libvirtd`, el servicio R34, el watchdog y su temporizador.

Las pruebas validan el modo de lectura, la reconciliación 1→3 NIC, el estado
SHUTOFF (incluido `APAGADO`), reglas DROP y los recibos de la definición
anterior. El resultado conserva salida de fuente física, 4 estados de las VM,
3 estados de redes (`ACTIVE`, `INACTIVE`, `UNKNOWN`), estado del timer/watchdog,
propiedades `Requires/After`, SHA de snapshot y SHA de recibo.

Se crea un único directorio privado con `snapshot.json`, `units.json`,
`readiness.json` y `manifest.json`, permisos 0700/0600, hash por archivo y
recomputación completa. No se guarda dato privado en Git.

## Límites de autoridad

El hook F11 observado es **DENY-only**. La presencia de cuatro reglas DROP,
un timer activo y cuatro invitados apagados NO autoriza arrancar las VM.
Un servicio watchdog `inactive` entre ticks no demuestra fallo; un timer
activo tampoco demuestra watchdog independiente ni contención continua.

Este incremento **NO incluye** `virsh start`, `virsh net-start`, `virsh define`,
`nft add/delete`, `systemctl restart/enable`, edición de hooks, conexiones
SSH/FTP/SMB, A5 operacional ni publicación A9. La salida normal es
`BLOCKED_F11_EXPLICIT_ALLOW_NOT_IMPLEMENTED`, `P8=NO-GO`, `VM_STARTS=0`.

## Próxima fase física

Diseñar y revisar una **excepción mínima, temporal, reversible, firmada** para
un único par runner/servidor por vez, conservando las redes R33 aisladas y
verificando simultáneamente persistencia R34, recuperación F11 y no egress.
Cada intervención debe tener preflight fresco, recibo anterior, una sola
mutación autorizada, readback y restauración probada. No convertir esta
medición read-only en permiso de arranque ni levantar simultáneamente las
cuatro VM por conveniencia.

## Comandos

```shell
PYTHONPATH=src:scripts .venv/bin/python -B -m unittest discover -s lab/tests -p 'test_p14_r112_f11_live_readiness.py' -v
PYTHONPATH=src:scripts .venv/bin/python -B scripts/ardrec_p14_r112_f11_live_readiness.py --capture-readonly --r112-plan /home/cicada/ardrec-lab/r112-real-runner-nic-v1/plan-gavsqoqt --r112-apply /home/cicada/ardrec-lab/r112-real-runner-nic-v1/apply-ah1ck__9
```

## English

This increment cross-checks the actual three-NIC runner and 29 baseline host
probes with four read-only systemd inspections. It emits immutable private
receipts. It is intentionally not a boot permission or a protocol test.
