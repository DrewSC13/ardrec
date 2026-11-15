# ARDREC P14-R49 — Runner SSH-only: redefinición fría, restauración y primer arranque

**Base:** `f321970709a36e1414e700af0d52e8e5e60ebb3f` (PR #123, merge R48). **P8 operacional:** `NO-GO`. R49 no configura pentesting, no envía sondas ni autoriza A5/A6. Todos los archivos de evidencia permanecen fuera del repositorio público.

## Condiciones exactas

R45 generó los XML candidatos y los filtros específicos; R47 registró dos filtros nuevos sin usarlos; R48 creó un nuevo overlay `qcow2` con respaldo R32 y el XML `runner-ssh-only-deny-r48.xml`. Al inicio de R49, `ardrec-r33-dev-ssh` está `RUNNING`, `ardrec-r33-dev-runner`, FTP y SMB están `SHUTOFF`; la red SSH está activa y las redes FTP/SMB inactivas. El filtro compartido `ardrec-r33-block-until-containment` sigue siendo `DROP INOUT ALL` y la tabla nftables `ardrec_r34_guard` mantiene cuatro reglas de descarte para los seis TAP. El bridge SSH no tiene dirección IPv4.

El preflight autentica los recibos R45, R46, R47 y R48, valida la cadena y el hash de R32, comprueba el estado *live* de SSH y el estado apagado de FTP/SMB y confronta el XML inactivo del runner con la línea base R46. R47/R48 verifican los estados históricos de tres NIC y **solo son reutilizables antes del cambio de definición**. R49 incorpora verificación propia para la transición aprobada a una NIC, sin aceptar diferencias de UUID, MAC, TAP, disco, filtro, volumen, orden de arranque ni dispositivos de salida adicionales. Tolera únicamente normalizaciones inocuas de XML por libvirt, como `memory` expresada en KiB en vez de MiB.

## Mutaciones posibles y autorizaciones independientes

El módulo ofrece modos separados; ninguno implica autorización para los demás:

- `--preflight-readonly`: lecturas solamente.
- `--define-ssh-only-runner`: **única escritura al host** `virsh define` de `runner-ssh-only-deny-r48.xml`, con el runner apagado; cambia exclusivamente la definición persistente del runner. Requiere `--i-authorize-runner-domain-definition-only`.
- `--verify-defined`: lecturas de configuración, disco y recibos, exige runner apagado.
- `--restore-original-when-shutoff`: reintroduce, mediante **otro `virsh define` autorizado**, la definición original de tres NIC y disco R32. Exige runner apagado. Requiere `--i-authorize-restore-original-runner-definition-only`. No descarta el overlay R48 ni detiene VM.
- `--verify-restored`: compara readback real con el XML original y exige filtro R33, nftables R34 y topología original intactos.
- `--start-isolated-runner`: **única escritura al host** `virsh start ardrec-r33-dev-runner` y solo después de verificar el recibo de definición; exige filtro R33 y R34 en estado deny. Requiere autorización separada `--i-authorize-runner-first-boot-under-r33-r34-deny`.
- `--verify-first-boot`: comprobación de las definiciones *live* e inactivas, una NIC SSH, disco R48, filtro R33, tabla R34, FTP/SMB apagados, SSH en RUNNING. No ejecuta QGA, `ping`, `ssh`, `nmap`, ni tráfico de prueba.

No existen acciones implícitas para hacer `destroy`, `shutdown`, `undefine`, `nwfilter-define`, `nft -f`, `flush ruleset`, cambiar credenciales o abrir puertos. Un intento incompleto crea un directorio privado con `intent` anterior a la mutación y se detiene; **no** se reintenta automáticamente, elimina archivos ni se presume que una operación fallida no cambió el host.

El primer arranque puede ocasionar paquetes generados por el sistema invitado, pero R49 no autoriza ni inicia sondas de conectividad: las capas R33/R34 siguen denegando. Los contadores nftables no son prueba positiva de aislamiento. No se acredita la IP del invitado, una conexión SSH real, una restauración del sistema invitado, ni un riesgo recalibrado. `P8=NO-GO` y Rf permanece `ND`.

## Secuencia recomendada en Prometheus

```bash
cd /home/cicada/Development/GitHub/ardrec
BASE=/home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND
R45="$BASE/r45-ssh-candidate-20261115T023018Z-5663"
R46="$BASE/r46-ssh-audit-20261115T025021Z-5663"
R47="$BASE/r47-filter-stage-20261115T030627Z-5663"
R48="$BASE/r48-runner-overlay-20261115T034518Z-5663"
sudo -v
python3 -B scripts/ardrec_p14_r49_runner_first_boot.py --preflight-readonly \
  --r45-dir "$R45" --r46-dir "$R46" --r47-dir "$R47" --r48-dir "$R48" | more
```

Solo cuando el preflight pasa, una persona autorizada puede decidir **definir** el runner (no arrancarlo), con un recibo privado nuevo:

```bash
DEFINE_REC="$BASE/r49-runner-define-$(date -u +%Y%m%dT%H%M%SZ)-$$"
python3 -B scripts/ardrec_p14_r49_runner_first_boot.py --define-ssh-only-runner \
  --r45-dir "$R45" --r46-dir "$R46" --r47-dir "$R47" --r48-dir "$R48" \
  --definition-receipt-dir "$DEFINE_REC" \
  --i-authorize-runner-domain-definition-only
python3 -B scripts/ardrec_p14_r49_runner_first_boot.py --verify-defined \
  --r45-dir "$R45" --r46-dir "$R46" --r47-dir "$R47" --r48-dir "$R48" \
  --definition-receipt-dir "$DEFINE_REC"
( cd "$DEFINE_REC" && sha256sum -c SHA256SUMS )
```

Para ensayar **restauración de definición** antes del primer arranque, estando apagado:

```bash
RESTORE_REC="$BASE/r49-runner-restore-$(date -u +%Y%m%dT%H%M%SZ)-$$"
python3 -B scripts/ardrec_p14_r49_runner_first_boot.py --restore-original-when-shutoff \
  --r45-dir "$R45" --r46-dir "$R46" --r47-dir "$R47" --r48-dir "$R48" \
  --definition-receipt-dir "$DEFINE_REC" --restore-receipt-dir "$RESTORE_REC" \
  --i-authorize-restore-original-runner-definition-only
python3 -B scripts/ardrec_p14_r49_runner_first_boot.py --verify-restored \
  --r45-dir "$R45" --r46-dir "$R46" --r47-dir "$R47" --r48-dir "$R48" \
  --definition-receipt-dir "$DEFINE_REC" --restore-receipt-dir "$RESTORE_REC"
( cd "$RESTORE_REC" && sha256sum -c SHA256SUMS )
```

Esto prueba **solo restauración de la definición inactiva** y preservación de R32; no equivale a recuperar el sistema operativo de la VM ni probar reversión de cambios en el invitado. Si luego se desea arrancar, hay que repetir `--define-ssh-only-runner` con un **nuevo** `DEFINE_REC`, verificar de nuevo y, tras autorización independiente, usar:

```bash
BOOT_REC="$BASE/r49-runner-boot-$(date -u +%Y%m%dT%H%M%SZ)-$$"
python3 -B scripts/ardrec_p14_r49_runner_first_boot.py --start-isolated-runner \
  --r45-dir "$R45" --r46-dir "$R46" --r47-dir "$R47" --r48-dir "$R48" \
  --definition-receipt-dir "$DEFINE_REC" --boot-receipt-dir "$BOOT_REC" \
  --i-authorize-runner-first-boot-under-r33-r34-deny
python3 -B scripts/ardrec_p14_r49_runner_first_boot.py --verify-first-boot \
  --r45-dir "$R45" --r46-dir "$R46" --r47-dir "$R47" --r48-dir "$R48" \
  --definition-receipt-dir "$DEFINE_REC" --boot-receipt-dir "$BOOT_REC"
( cd "$BOOT_REC" && sha256sum -c SHA256SUMS )
```

Si el runner está encendido, **no** invoques restauración: la función exige que esté apagado y no contiene órdenes para apagarlo. Cualquier detención posterior requerirá operación autorizada propia. El overlay R48 cambia legítimamente al arrancar; no volver a ejecutar el verificador histórico R48 esperando el mismo `stat` del momento del staging. R49 verifica cadena y respaldo R32 sin atribuir inmutabilidad al disco de ejecución.

## Puerta siguiente

R49 no habilita conectividad. R50 tendrá que medir la configuración de IP de ambos invitados con controles locales, preparar el cambio nftables R34 en un mantenimiento separado y registrar testigos positivos/negativos ARP/ICMP entre las dos NIC aisladas. Solo entonces podrá discutirse una concesión limitada para pruebas SSH y vinculación con A5/A6 y el TUI R38.
