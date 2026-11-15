# ARDREC P14-R47 — Definición física acotada de dos filtros nuevos sin referencias

**Base SHA:** `e659f0b76582236c0061960975027f3830cd59df` (merge R46, PR #121). **Modo:** `STAGED_NEW_UNUSED_FILTERS_ONLY_NO_GO`. No se incluye ninguna prueba de tráfico ni acceso a SSH/FTP/SMB.

## Dependencias inmóviles

- Recibo R45-F1 privado: `r45-ssh-candidate-20261115T023018Z-5663`, SHA interno `3ddca2761bd4ca2d4244afa962bec305e68985466687824fa6ddd9db93bdceb3`.
- Recibo R46 privado: `r46-ssh-audit-20261115T025021Z-5663`, SHA interno `6cbe72db1b93f6ce33b63d6337d808f583a30944fa327b1a46c9b01f18284abb`.
- `ardrec-r33-dev-ssh` **RUNNING**, con filtro R33 en la NIC real y en la definición inactiva; runner **SHUTOFF**, definido originalmente con tres NIC. Tabla `ardrec_r34_guard` permanece en `DROP` para seis TAP. Bridge `br33d30` sin dirección IPv4.

## Qué ejecuta R47

El programa tiene `--plan` (sin consultas del host), `--stage-new-unused-filters` (una sola mutación explícitamente autorizada) y `--verify-staged` (solo lectura). Relee R45/R46 y valida sus SHA internos, el estado libvirt actual y la configuración *live* del SSH antes de ejecutar cualquier escritura. Rechaza cambios de identidad, disco, MAC, TAP, estado de VM, filtros, puente y reglas nftables.

**Única operación de host permitida en el staging:** ejecutar dos veces `sudo -n -- /usr/bin/virsh -c qemu:///system nwfilter-define` con los XML R45-F1 autenticados, y leer de vuelta con `nwfilter-dumpxml`. Los nombres son nuevos, separados del filtro R33 compartido: `ardrec-r45-ssh-icmp-candidate` y `ardrec-r45-runner-icmp-candidate`. No se ejecuta `virsh define`, `start`, `destroy`, `attach-interface`, `nft -f`, QGA, `ping`, `tcpdump` ni ningún comando de pen-testing. No se modifican interfaces, dominios, filtros existentes ni el cortafuegos.

**No se habilita conectividad:** las VM siguen referenciando el filtro R33 con `DROP ALL` y la tabla nftables R34 permanece en denegación. Las reglas candidatas de R45 todavía no están ligadas a ninguna NIC. P8 queda `NO-GO`.

## Fallo parcial y restauración

Primero se crea un directorio nuevo privado 0700 y un `r47-stage-intent.json` con escritura exclusiva 0600, antes del primer `nwfilter-define`. Se registra cada definición exitosa por separado. Si una operación falla, el programa se detiene y preserva el recibo parcial; NO intenta reanudar ni anular automáticamente el cambio. Una restauración eventual debe validar primero que ningún dominio utiliza el filtro, y requerirá una orden independiente autorizada. **R47 no acredita rollback ensayado.**

Si se supera el staging, el programa comprueba que la definición activa y la inactiva de SSH sigan usando R33, que el runner permanezca apagado, que `ardrec_r34_guard` siga en deny-all, y que los dos nuevos filtros puedan releerse con reglas exactamente iguales a las R45-F1. El recibo y su `SHA256SUMS` se verifican de nuevo con `--verify-staged`. Solo registrar dos filtros no implica que se haya validado aislamiento.

## Operación en Prometheus

```bash
cd /home/cicada/Development/GitHub/ardrec
BASE=/home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND
R45="$BASE/r45-ssh-candidate-20261115T023018Z-5663"
R46="$BASE/r46-ssh-audit-20261115T025021Z-5663"

# Comprobar fuentes sin escribir ni consultar el host:
python3 -B scripts/ardrec_p14_r47_filter_stage.py --plan \
  --r45-dir "$R45" --r46-dir "$R46" | more

# Solo bajo autorización específica para añadir dos filtros que no están en uso:
REC="$BASE/r47-filter-stage-$(date -u +%Y%m%dT%H%M%SZ)-$$"
sudo -v
python3 -B scripts/ardrec_p14_r47_filter_stage.py \
  --stage-new-unused-filters --r45-dir "$R45" --r46-dir "$R46" \
  --receipt-dir "$REC" \
  --i-authorize-two-unique-unused-nwfilter-definitions-only

# Solo si staging terminó íntegramente:
python3 -B scripts/ardrec_p14_r47_filter_stage.py \
  --verify-staged --r45-dir "$R45" --r46-dir "$R46" --receipt-dir "$REC"
( cd "$REC" && sha256sum -c SHA256SUMS )
```

Ante fallo o incertidumbre NO volver a ejecutar staging con otro directorio: conservar el intento y revisar `nwfilter-list`/`nwfilter-dumpxml`. No publicar `REC` ni los XML privados en GitHub.

## Puerta R48

Solo después de comprobar filtros nuevos *sin uso* y un procedimiento independiente de restauración: transición coordinada de XML de dominio y tabla nftables **en el mismo mantenimiento**, sin tocar el filtro R33 compartido, con SSH detenida bajo autorización separada, runner SSH-only, testigos positivos y negativos, límites de paquetes y evidencia en origen/destino. Nada de esto se implementa ni se permite en R47.
