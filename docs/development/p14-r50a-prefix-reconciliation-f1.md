# ARDREC R50-A-F1 — Corrección exacta de prefijo y conciliación histórica

- Base Git: `f59d7ace03aa6ff296b3f425e14a38c005610ecc`.
- Rama de trabajo: `feat/p14-r50a-guest-pair-network-inventory-main`.
- Fuente de criterio revisada: `src/ardrec/coordination/r421_bounded_negative_probe.py`.
- Evidencia histórica R42.1: `PROBE_PREFIX = 28` (observado en SSH ens3 el 2026-11-14).
- Recibo histórico físico R50A v1: `aea38a60711471e6d08a2b3a7c9f0f78cab0c515e15863bb8724276032c7732d`.

## Distinción de versiones

El primer R50-A utilizaba `/24` y clasificó correctamente, conforme a esa regla
incorrecta, ambas VM como `GUEST_IP_OR_NIC_REVIEW_NO_GO`. La regla contradice la
observación R42.1. La revisión F1 usa `/28`, sin modificar MAC/IP, QGA, red ni
VM. El informe original sigue verificado con su esquema v1 y criterio `/24`;
los informes posteriores usan esquema v2 y criterio `/28`. No se convierte
silenciosamente un REVIEW histórico en PASS.

La conciliación offline revisa los bytes de las respuestas QGA originales,
exige que la única diferencia sea el prefijo, comprueba los SHA y el estado
host por medio de la verificación R49 ya disponible, y crea un recibo nuevo
con los dos resultados y los digests. Sin QGA nuevo, guest-exec, paquetes,
`virsh define`, reinicio ni modificación de nftables. Nunca sobrescribe los
archivos anteriores. Si algo cambia, bloquea la conciliación.

## Operación posterior al parche

```bash
cd /home/cicada/Development/GitHub/ardrec
BASE=/home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND
R45="$BASE/r45-ssh-candidate-20261115T023018Z-5663"
R46="$BASE/r46-ssh-audit-20261115T025021Z-5663"
R47="$BASE/r47-filter-stage-20261115T030627Z-5663"
R48="$BASE/r48-runner-overlay-20261115T034518Z-5663"
DEFINE="$BASE/r49-runner-define-20261115T040920Z-5663"
BOOT="$BASE/r49-runner-boot-20261115T040936Z-5663"
LEGACY="$BASE/r50a-guest-pair-20261115T042327Z-5663"
RECON="$BASE/r50a-prefix-review-$(date -u +%Y%m%dT%H%M%SZ)-$$"
sudo -v
python3 -B scripts/ardrec_p14_r50a_guest_pair_inventory.py --verify-receipt \
  --r45-dir "$R45" --r46-dir "$R46" --r47-dir "$R47" --r48-dir "$R48" \
  --definition-receipt-dir "$DEFINE" --boot-receipt-dir "$BOOT" --receipt-dir "$LEGACY"
python3 -B scripts/ardrec_p14_r50a_guest_pair_inventory.py --reconcile-prefix-offline \
  --r45-dir "$R45" --r46-dir "$R46" --r47-dir "$R47" --r48-dir "$R48" \
  --definition-receipt-dir "$DEFINE" --boot-receipt-dir "$BOOT" \
  --receipt-dir "$LEGACY" --reconciliation-dir "$RECON"
python3 -B scripts/ardrec_p14_r50a_guest_pair_inventory.py --verify-prefix-reconciliation \
  --r45-dir "$R45" --r46-dir "$R46" --r47-dir "$R47" --r48-dir "$R48" \
  --definition-receipt-dir "$DEFINE" --boot-receipt-dir "$BOOT" \
  --receipt-dir "$LEGACY" --reconciliation-dir "$RECON"
( cd "$RECON" && sha256sum -c SHA256SUMS )
```

## Límites

No se atribuye conectividad, aislamiento por paquetes, autorización de
pentesting, aceptación funcional general ni recalibración Rf. P8 permanece
`NO-GO`, Rf `ND`. No registrar recibos privados en GitHub.


## Fe de erratas F1-R2 (15/11/2026)

La versión F1-R1 se bloqueó por permisos del árbol Git: R50-A original
creaba los archivos bajo el `umask` de Prometheus (por ejemplo 0600), mientras
F1-R1 exigía exactamente 0644. F1-R2 conserva los modos seguros originales y
compara los contenidos por SHA-256 para admitir únicamente las preimágenes
exactas de R50-A.

**Separación obligatoria de evidencias:** `--verify-receipt` conserva su
preflight *live* R49/R34 y puede fallar si nftables no está accesible. El nuevo
`--verify-historical-receipt-offline`, `--reconcile-prefix-offline` y
`--verify-prefix-reconciliation` realizan únicamente controles de integridad
del recibo histórico, cuyos hashes están fijados en el código, y aplican los
criterios originales v1 (/24) y corregidos (/28) respectivamente. No consultan
libvirt ni nftables ni vuelven a contactar QGA. Un éxito offline **no** prueba
que el cortafuegos siga activo en ese instante. Ante fallo de R34, cualquier
modificación de red o envío de paquetes está bloqueada hasta diagnóstico y
restablecimiento específico y autorizado.
