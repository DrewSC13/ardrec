# ARDREC P14-R39 — Reconciliación SSH de solo lectura posterior al primer arranque

## Base, entradas y causa

Base exacta: PR #109 integrado, `main=0fed6d86ce93ddffd3dd1d7b9ff7eac703f5af0c`. El recibo autorizado R36.5 registra `FIRST_BOOT_DENY_POLICY_PRESENT_UNTESTED`, `network_started=true`, `vm_started=true`, sin aislamiento probado ni pruebas del servicio. El diagnóstico del operador del 14/11/2026 mostró **SSH apagado / red SSH activa**, puente `br33d30` sin TAP y FTP/SMB/runner apagados. El QEMU del SSH registró SIGTERM desde libvirtd y `reason=shutdown`; `guest-info`/`guest-network-get-interfaces` se consultaron antes, pero no se ha atribuido el origen de la solicitud de apagado.

R39 **no reproduce** R36.5, **no arranca** SSH, **no corrige** red/bridge ni realiza `ping`, SSH, FTP, SMB, escaneo o pentesting. Importar el estado de infraestructura no lo transforma en una comprobación técnica del servicio. Tampoco marca como acreditado el aislamiento de red.

## Qué valida

1. Verifica que los dos directorios de recibos R36.5 posean inventario exacto con SHA256SUMS, permisos privados y archivos regulares, y comprueba los SHA y campos internos con los validadores existentes.
2. Comprueba el enlace de recibos preflight → primer arranque, las dos operaciones exactas `net-start` SSH y `start` SSH declaradas, su secuencia en el registro de comandos y sus códigos de retorno; rechaza comandos inesperados en ese registro.
3. Ejecuta el validador físico `r365.current(..., phase='NETWORK_ONLY')` sobre el estado **actual**. Reusa nftables, nwfilter, XML libvirt, identidad de red, MAC, inventario de dominios y redes, autoarranque y nombres de interfaces. El único acceso privilegiado nuevo es `sudo -n -- virsh --readonly ...`; nftables ya se lee mediante la interfaz de solo lectura de R35. Se necesita `sudo -v` interactivo antes del CLI.
4. Si todos los controles pasan, guarda en un nuevo directorio privado un reporte sellado sin salida cruda de comandos. El estado exacto se llama `SSH_NETWORK_ACTIVE_DOMAIN_OFF_RECONCILED_NO_GO`.
5. Cualquier diferencia, falta de permisos o alteración de los recibos produce error **sin reintentar, arrancar, detener, limpiar o mutar** el entorno. Los métodos de activación heredados están sobrescritos para rechazarse explícitamente.

## Límites de prueba

- SHA256SUMS es integridad local; no aporta por sí solo firma independiente, identidad del huésped ni atribución causal al apagado.
- La lectura del host es secuencial y depende del instante de ejecución: no es un snapshot atómico ni una certificación de tráfico bloqueado. El campo `captured_at_utc` se genera durante la ejecución y participa en la huella. Un replay del mismo reporte es determinista; repetir la captura física puede producir un reporte diferente.
- Una VM apagada con la red activa **no** es `READY_FOR_EXPLICIT_FIRST_BOOT`; el primer arranque ya ocurrió. La siguiente reanudación necesita un contrato y autorización nuevos. No reutilizar el recibo R36.5 como autorización.
- No se revalida el SHA del overlay SSH después del arranque: su cambio puede ser legítimo y su integridad requerirá una etapa específica de análisis posterior.
- `guest_isolation_tested=false`, `real_service_testing=NOT_EXECUTED`, `technical_truth_accredited=false`, `final_risk=null`, `published_generation=null`, `P8=NO-GO` y `experimental_validation=NOT_RUN` son obligatorios. AL-06/AL-07 continúan abiertos.

## Uso exclusivo en Prometheus

El código fuente se ejecuta en `/home/cicada/Development/GitHub/ardrec`. `ardrec-patches` almacena exclusivamente parches y recibos físicos privados; no es el árbol de desarrollo.

```bash
cd /home/cicada/Development/GitHub/ardrec
sudo -v

BASE=/home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND

python3 -B scripts/ardrec_p14_r39_ssh_reconciliation.py \
  --r365-preflight "$BASE/recibos-preflight-r365-20261114T200434Z-94940" \
  --r365-first-boot "$BASE/recibos-first-boot-r365-20261114T200824Z-98270" \
  --receipt-dir "$BASE/r39-ssh-reconciliation-$(date -u +%Y%m%dT%H%M%SZ)-$$"
```

El directorio padre debe estar bajo propiedad del operador y modo `0700`, y el directorio destino no debe existir. El proceso guarda `r39_reconciliation.json` y `SHA256SUMS`, ambos `0600`, en una carpeta `0700`.

## Pruebas y cierre

```bash
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r39*.py' -v 2>&1 | more
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14*.py' -q 2>&1 | more
python3 -B scripts/verificar_trazabilidad_actual.py | more
git diff --check
```

Requiere PR firmado y CI protegida. No considerar `R39_STATUS=PASS` de forma genérica: el resultado válido es **solo** `SSH_NETWORK_ACTIVE_DOMAIN_OFF_RECONCILED_NO_GO`, que permite diseñar una reanudación posterior separada. El siguiente incremento será R40 de preflight para recuperación SSH, y R41 aislamiento de tráfico; cualquier prueba SSH real debe ir después de acreditar aislamiento y autorización del ensayo.
