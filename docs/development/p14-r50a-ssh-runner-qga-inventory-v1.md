# ARDREC P14-R50-A — Inventario real y limitado de red de SSH y runner

**Base exacta:** `f59d7ace03aa6ff296b3f425e14a38c005610ecc` (PR #124, R49). **Estado de P8:** `NO-GO`.

## Alcance y evidencia de origen

R49 verificó físicamente dos VM encendidas: `ardrec-r33-dev-ssh` y `ardrec-r33-dev-runner`. FTP/SMB y sus redes continúan apagados. El runner tiene una sola NIC SSH, el nuevo overlay R48 y filtro R33 `drop all`; las reglas nftables R34 de descarte no fueron alteradas. R49 no acreditó dirección IP del invitado ni pruebas positivas de conectividad. El recibo de arranque R49 original tiene SHA interno `82f6a4101802bb35043e35c741731cc2b99fd12bb6a3f7054280e5d9a0c9e303`; el recibo de definición tiene SHA interno `70f273c30b4b3a4e9c39328013cdd506a3b8d5a3780be8476c10cea3e4d15d98`.

R50-A añade una lectura física estrictamente acotada a **dos comandos internos de QEMU Guest Agent por invitado**: `guest-ping` (estado del agente, **no** ICMP) y `guest-network-get-interfaces` (interfaz/MAC/direcciones IP). No usa `guest-exec`, comandos de shell en invitado, ICMP, SSH, Nmap, escaneo, sshd, modificación de rutas o capturas PCAP. El host se valida mediante `r49.verify_boot` antes y después de las consultas; este verificador comprueba R33/R34 y el estado de las VM. Toda respuesta y el informe quedan en un recibo privado fuera de Git.

## Criterio objetivo

**Corrección R50-A-F1 (2026-11-15):** la primera versión del módulo exigía
un prefijo `/24` introducido sin sustento. R42.1 ya había observado y
fijado `PROBE_PREFIX=28` para `ens3` del SSH (2026-11-14); R42.3 reutiliza
ese valor. La versión corregida emplea `r421.PROBE_PREFIX=28` para
ambos invitados. La versión v1 del recibo ya registrado (estado REVIEW)
**no se reescribe** y puede volver a verificarse con el criterio v1.
Los nuevos informes utilizan el esquema `ardrec-p14-r50a-guest-pair-network-readonly-v2`.
Una conciliación offline separada puede demostrar la reinterpretación
con los bytes QGA originales y un recibo enlazado por SHA-256.


Se cotejan las MAC y direcciones de diseño, nunca se presume que una dirección de la definición libvirt sea una dirección activa dentro de Linux:

| VM | MAC esperada | IPv4 esperado | Prefijo |
| --- | --- | --- | --- |
| SSH | `52:54:00:ad:30:02` | `10.203.30.2` | `/28` |
| runner | `52:54:00:ad:30:01` | `10.203.30.1` | `/28` |

`GUEST_PAIR_EXPECTED_IP_MAC_OBSERVED_NO_GO` requiere ambas interfaces coincidentes sin NIC adicional con MAC ni otra IPv4 en la interfaz encontrada. `GUEST_PAIR_CONFIG_REVIEW_NO_GO` indica un hallazgo divergente, no un éxito de conectividad. Si QGA falla, falta, devuelve datos malformados o se detecta deriva del host, se conserva `r50a-intent.json`, los datos ya recibidos y `r50a-failure.json` con hashes; no hay reintento automático. No equiparar una respuesta de QGA a evidencia de aislamiento de red.

## Orden de operación

1. Aplicar el parche sobre `main` con ZIP, hash, comprobación `--check`, 30 pruebas R50-A, regresión P14, trazabilidad y firma Git.
2. Ejecutar `--preflight-readonly` con los recibos R45–R49; consulta el host pero **no** QGA.
3. Solo tras autorización explícita, ejecutar una captura `--capture-guest-pair-readonly` en un directorio `r50a-guest-pair-YYYYMMDDTHHMMSSZ-PID` bajo el directorio privado 0700.
4. Si termina, ejecutar `--verify-receipt` (verifica recibo y estado real del host; no vuelve a consultar QGA) y `sha256sum -c SHA256SUMS`.
5. Conservar toda la evidencia física fuera de GitHub y compartir solo el estado y los digests.

## Comandos

```bash
cd /home/cicada/Development/GitHub/ardrec
BASE=/home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND
R45="$BASE/r45-ssh-candidate-20261115T023018Z-5663"
R46="$BASE/r46-ssh-audit-20261115T025021Z-5663"
R47="$BASE/r47-filter-stage-20261115T030627Z-5663"
R48="$BASE/r48-runner-overlay-20261115T034518Z-5663"
DEFINE="$BASE/r49-runner-define-20261115T040920Z-5663"
BOOT="$BASE/r49-runner-boot-20261115T040936Z-5663"
sudo -v
python3 -B scripts/ardrec_p14_r50a_guest_pair_inventory.py --preflight-readonly \
  --r45-dir "$R45" --r46-dir "$R46" --r47-dir "$R47" --r48-dir "$R48" \
  --definition-receipt-dir "$DEFINE" --boot-receipt-dir "$BOOT"

# Solo después de R50A_PREFLIGHT=PASS_HOST_READONLY y autorización de lectura QGA:
REC="$BASE/r50a-guest-pair-$(date -u +%Y%m%dT%H%M%SZ)-$$"
python3 -B scripts/ardrec_p14_r50a_guest_pair_inventory.py --capture-guest-pair-readonly \
  --r45-dir "$R45" --r46-dir "$R46" --r47-dir "$R47" --r48-dir "$R48" \
  --definition-receipt-dir "$DEFINE" --boot-receipt-dir "$BOOT" \
  --receipt-dir "$REC" --i-authorize-two-qga-readonly-guest-inventories

# Solo si la captura terminó íntegramente:
python3 -B scripts/ardrec_p14_r50a_guest_pair_inventory.py --verify-receipt \
  --r45-dir "$R45" --r46-dir "$R46" --r47-dir "$R47" --r48-dir "$R48" \
  --definition-receipt-dir "$DEFINE" --boot-receipt-dir "$BOOT" \
  --receipt-dir "$REC"
( cd "$REC" && sha256sum -c SHA256SUMS )
```

**Límite metodológico:** resultado de ambas direcciones IP no implica que ARP/ICMP pase los filtros. Aún faltan testigos positivos, negativos y restauración de políticas para la apertura de conectividad. P8 permanece `NO-GO`, A5/A6 no obtienen autoridad de ejecución y Rf sigue `ND` en ausencia de evidencia de servicio válida.
