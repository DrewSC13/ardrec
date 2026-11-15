# P14-R46 — Auditoría del estado SSH y respaldo verificable, sin despliegue

**Base**: `20cb051262c0e556954e51a01e2089bab954100e` (R45-F1). **Fuentes**: modelo R33, política R34 y candidato R45 con SHA interno exacto `3ddca2761bd4ca2d4244afa962bec305e68985466687824fa6ddd9db93bdceb3`.

## Hallazgos R44/R46 que motivan el control

En Prometheus el dominio `ardrec-r33-dev-ssh` aparece **ejecutando**, con una NIC `a33d30t` y filtro R33 de denegación. `ardrec-r33-dev-runner` está **apagado**, con tres NIC (`a33d30r`, `a33d31r`, `a33d32r`); las redes FTP y SMB están inactivas. El `nwfilter` R33 instalado contiene `drop inout all` y nftables mantiene cuatro descartos sobre los TAP reservados. El bridge SSH carece de IPv4. El destino positivo SSH `10.203.30.1` no está disponible todavía. Los contadores cero no prueban aislamiento.

## Alcance real de R46

Este incremento agrega una **comprobación de solo lectura** del host y un archivo de evidencia privada e inmutable. No sustituye reglas, no ejecuta tráfico, no altera VMs, no acredita P8 ni habilita pentesting:

1. Relee el recibo R45 firmado por SHA, sin reutilizar materializaciones R45 previas fallidas.
2. Relee los XML **inactivos** de ambos dominios, estados de las VMs, definición del filtro R33, lista de filtros, tabla nftables R34 y asignaciones IPv4 del bridge.
3. Contrasta nombre, UUID, disco, NIC, MAC, TAP, red, referencia a filtro y política de reboot contra el modelo R33. Exige SSH RUNNING y runner SHUTOFF, sin filtros R45 definidos.
4. Valida que el filtro R33 tenga exclusivamente `DROP INOUT ALL`, y que la tabla R34 siga disponiendo de las cuatro reglas de `drop` sobre los seis TAP. Si la representación del host es distinta, **bloquea** y se analiza antes de ampliar el parser.
5. Guarda los XML inactivos originales y los demás testigos en un subdirectorio nuevo `0700`, archivos `0600`, comprobando hashes del contenido y un reporte determinista. Verificar el recibo no vuelve a consultar el host.
6. Describe las diferencias previstas R45 (SSH cambia referencia de filtro; runner reduce 3 NIC a 1) y mantiene explícitamente `rollback_tested=false` y `host_mutations=false`.

## Límites de la restauración

Los snapshots son la **base documental** para un plan de recuperación futuro, no un rollback ensayado. Se prohíbe aplicar automáticamente `virsh define` sobre una VM encendida; el XML `--inactive` no garantiza equivalencia con la definición **live**. Un cambio de filtro compartido R33 podría afectar a otras NIC. La transición requiere un plan separado de mantenimiento, respaldo verificable del estado vivo, revisión de reglas nftables en la tabla existente, ensayo de reversión y aprobación explícita de acciones y tráfico.

En concreto, **no cargar** `bridge-ssh-syntax-only.nft`, ni usar `virsh nwfilter-define`, `virsh define`, `virsh start`, `virsh attach-interface`, `nft -f` ni rutas de pentesting en R46.

## Comandos de Prometheus

```bash
cd /home/cicada/Development/GitHub/ardrec
BASE=/home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND
R45="$BASE/r45-ssh-candidate-20261115T023018Z-5663"
REC="$BASE/r46-ssh-audit-$(date -u +%Y%m%dT%H%M%SZ)-$$"

sudo -v
python3 -B scripts/ardrec_p14_r46_ssh_transition_audit.py \
  --inspect-readonly --r45-dir "$R45" --receipt-dir "$REC" \
  --i-authorize-readonly-inspection-and-private-receipt

python3 -B scripts/ardrec_p14_r46_ssh_transition_audit.py \
  --verify-receipt --r45-dir "$R45" --receipt-dir "$REC"

( cd "$REC" && sha256sum -c SHA256SUMS )
```

La autorización para escritura local y lecturas pasivas **no** es autorización para abrir tráfico. P8=NO-GO, Rf=ND, AL-06/AL-07 abiertos, CI obligatorio y TUI R38 intacto.
