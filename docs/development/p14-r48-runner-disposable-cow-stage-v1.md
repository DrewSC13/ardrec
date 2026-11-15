# ARDREC P14-R48 — Overlay de ejecución desechable para runner SSH-only

**Base:** `60c330e627d2822257d0f60de610b46c986538aa` (merge de R47). **Estado:** solo preparación física de una nueva capa `qcow2`; P8 `NO-GO`.

## Evidencia y límites

La inspección del host muestra al runner apagado, SSH encendida, bridge SSH activo y redes FTP/SMB inactivas. El disco `runner-runtime.qcow2` de R32 tiene tres capas: R32 `runner-runtime.qcow2`, R6 `runner-runtime.qcow2`, R4 `runner-base.qcow2`; 24 GiB lógicos. Un `df` sin privilegios sobre el archivo devolvió permiso denegado y **no** indica ausencia de espacio. El preflight R48 usa `sudo -n df -P -B1 /var/lib/libvirt/images` y bloquea si hay menos de 2 GiB disponibles.

R48 verifica los recibos R45, R46 y R47 y realiza la lectura independiente del estado real mediante R47 antes y después de crear el overlay. La creación física requiere **otra autorización explícita**, por separado de `--preflight-readonly`. El destino único es `/var/lib/libvirt/images/ardrec-dev-point4-r48/runner-ssh-isolated.qcow2`, con respaldo `/var/lib/libvirt/images/ardrec-dev-point4-r32/runner-runtime.qcow2`. Se comprueba la cadena exacta de cuatro imágenes, `qcow2`, 24 GiB virtuales, propietario `libvirt-qemu`, modo 0600 y SHA-256 idéntico de la capa R32 antes/después.

La creación usa QEMU `qemu-img create -f qcow2 -F qcow2 -b` y nunca `rebase`, `commit`, copia en caliente ni `qemu-img -u`. El programa conserva un recibo privado 0700 con intento persistido **antes** de la escritura del host. Si falla una operación, NO elimina ni reintenta la creación automáticamente. Revisar el estado físico antes de cualquier recuperación.

El XML privado `runner-ssh-only-deny-r48.xml` contiene **solo la NIC SSH**, mismo UUID/MAC/TAP y disco nuevo; referencia al filtro **R33 deny-all**, no a un permiso ARP/ICMP. **No** se ejecuta `virsh define`, `virsh start`, `virsh destroy`, `nft`, `nwfilter-define`, ni se envía tráfico. No se altera el filtro R33, la tabla R34 ni las VM actuales. Los XML candidatos siguen sin instalación. Esta fase no acredita restauración ensayada ni conectividad real.

## Ejecución en Prometheus

```bash
cd /home/cicada/Development/GitHub/ardrec
BASE=/home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND
R45="$BASE/r45-ssh-candidate-20261115T023018Z-5663"
R46="$BASE/r46-ssh-audit-20261115T025021Z-5663"
R47="$BASE/r47-filter-stage-20261115T030627Z-5663"
sudo -v
python3 -B scripts/ardrec_p14_r48_runner_cow_stage.py --preflight-readonly --r45-dir "$R45" --r46-dir "$R46" --r47-dir "$R47" | more

# SOLO tras revisar preflight y autorizar crear una capa nueva del runner:
REC="$BASE/r48-runner-overlay-$(date -u +%Y%m%dT%H%M%SZ)-$$"
python3 -B scripts/ardrec_p14_r48_runner_cow_stage.py --stage-one-overlay --r45-dir "$R45" --r46-dir "$R46" --r47-dir "$R47" --receipt-dir "$REC" --i-authorize-one-new-runner-qcow2-only

# Verificación sin cambios:
python3 -B scripts/ardrec_p14_r48_runner_cow_stage.py --verify-overlay --r45-dir "$R45" --r46-dir "$R46" --r47-dir "$R47" --receipt-dir "$REC"
( cd "$REC" && sha256sum -c SHA256SUMS )
virt-xml-validate "$REC/runner-ssh-only-deny-r48.xml" domain
```

## Siguiente puerta

R49 podrá proponer, con autorización nueva y verificación exacta de la capa R48, reemplazar **solo la definición inactiva del runner apagado** y efectuar su primer arranque con R33/R34 todavía en `DROP`. Debe documentarse recuperación de XML/overlay y prueba de restauración antes de permitir tráfico. No abrir FTP/SMB. La conectividad positiva requerirá diseño de reglas nftables R34 y testigos independientes de red; `P8=NO-GO` continúa.
