# R112-F1 — Definición real y reversible de las NIC FTP/SMB del runner

## Entrada verificable

Base acumulativa R111 firmado: `41f5e1e66aa80ecfcf530dfd1916102b6bc457f0`.
`main` remoto permanece en `4d01b095771079e7e778b9b3c3f4640296191117`.
Un único PR y merge después de R114. Los recibos reales son **privados**, fuera de Git.

R111 registró 29 lecturas reales en Prometheus. R111-F1 corrigió la traducción
`APAGADO` a `SHUTOFF`, dejando como hallazgo físico el runner de una NIC SSH
con falta de dos NIC. Las redes y las tres VM objetivo se observaron definidas.
El estado histórico no acredita el estado actual: R112 repite las 29 lecturas.

## Mutación física única permitida

`sudo -n virsh -c qemu:///system define <candidate.xml>` contra la definición
**inactiva** `ardrec-r33-dev-runner` exclusivamente. Requiere autorización
explícita de la persona operadora mediante
`--i-authorize-runner-inactive-nics-only`.

Las NIC son:

| red | MAC del runner | TAP | modelo | nwfilter |
|---|---|---|---|---|
| FTP `ardrec-r33-dev-net-ftp` | `52:54:00:ad:31:01` | `a33d31r` | virtio | `ardrec-r33-block-until-containment` |
| SMB `ardrec-r33-dev-net-smb` | `52:54:00:ad:32:01` | `a33d32r` | virtio | `ardrec-r33-block-until-containment` |

SSH existente `a33d30r` debe preservarse. Se exige además identidad exacta
MAC/TAP/filtro de las otras tres VM, cuatro VM apagadas, F11 boot unit y timer
activos, hash real F11 observado, definiciones de redes aisladas, único
nwfilter DROP INOUT y cuatro reglas nftables R34 cuya estructura no deriva.

No ejecuta `virsh start`, `net-start`, `attach-*`, `nft -f`, `systemctl start`,
`reboot`, `sudo virsh destroy`, autenticación, sondas ni cambios de credenciales.
**Agregar interfaces inactivas no habilita A5 ni permite probar el servicio.**

## Transacciones y recuperación

`--plan` crea `/home/cicada/ardrec-lab/r112-real-runner-nic-v1/plan-*` con
`snapshot.json`, `before.xml`, `candidate.xml`, `plan.json`, `manifest.json`.
Directorios 0700, archivos 0600. No escribe la definición host.
`--verify-plan` verifica hashes y semántica sin contactos de host.

`--apply` vuelve a medir estado real, valida la inmutabilidad del origen,
crea `apply-*/intent.json` y un marcador exclusivo `apply.once` **antes** de
la única llamada a `virsh define`. Guarda el resultado y el nuevo snapshot,
exige postlectura exacta y conserva el marcador aunque libvirt falle. No hay
reintento automático. Un resultado incierto exige revisión del estado físico.

`--verify-physical --plan-session ...` reproduce offline los recibos, hashes,
invariantes y cambios autorizados. `--restore` con autorización diferente
`--i-authorize-restore-runner-inactive-only` se permite en la misma rama
acumulativa incluso después del commit R112, si conserva R111 como ancestro,
y solo está permitido si la definición
actual corresponde a la candidata y las VM están apagadas. Se restaura desde
`before.xml` y se verifican de nuevo F11, R34, redes y VM; no hay rollback
implícito después de una aplicación incierta.

## Aceptación

- `R112_PLAN=READY_REAL_XML_SSH_TO_SSH_FTP_SMB` con `R112_PLAN_P8=NO-GO`.
- Solo si el operador autoriza la definición: `R112_PHYSICAL_RESULT=RUNNER_INACTIVE_NICS_DEFINED`.
- `R112_PHYSICAL_REPLAY=PASS` con un recibo físico privado comprobado.
- Ninguna VM arrancada, tráfico de servicio 0, F11/R34 preservados.
- Commit local firmado, sin push y sin merge hasta R114.

Esta evidencia se limita a **configuración real de topología**, no acreditación
experimental de SSH/FTP/SMB. La activación temporal fail-closed de F11,
servicios invitados y conectividad acotada quedan para posteriores subetapas
de R112 y R113.
