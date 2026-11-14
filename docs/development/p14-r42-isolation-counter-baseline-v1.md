# ARDREC P14-R42.0 — Línea de base de contadores de aislamiento SSH

## Base y alcance

Base Git exacta `54cadf66163111842ad48a3fa13b548d18febcc5` (merge firmado del PR #112). Fuente privada R41.1 exacta: `r411_external_start.json` con SHA interno `3b08bd0b91b2041a8517a1739efd21285d42e6c17f117e6a3ef9d76c65a1571b`, vinculada semánticamente a los recibos R41, R40, R39 y R36.5. Requiere VM SSH activa, FTP/SMB/runner apagados y únicamente la red SSH de ARDREC activa. El operador invoca `sudo -v` antes de la ejecución.

R42.0 captura dos lecturas secuenciales del inventario libvirt/nftables mediante el contrato `r365.current(SSH_RUNNING)` y dos lecturas de los **cuatro** contadores de las reglas nftables `bridge/ardrec_r34_guard`. Reutiliza el validador estricto R35, exige `drop` y reglas de interfaz y prioridad correctas, y compara los `handle` y la monotonía de `packets/bytes`. En circunstancias normales, la segunda lectura podría mostrar cambios por tráfico no provocado por el ensayo; estos valores son **delta no atribuido** y no prueban eficacia de aislamiento.

## No hace ni acredita

No genera tráfico, no ejecuta comandos en huésped, no inspecciona el QCOW2 en uso, no altera ip/nftables/nwfilter, no inicia/apaga dominios, no crea puentes ni cambia interfaces. `guest_isolation_tested=false`, `counters_prove_isolation=false`, `active_test_performed=false`, `operational_dispatch=false`, `final_risk=null`, `experimental_validation=NOT_RUN`, `p8_operational=NO-GO` se preservan obligatoriamente. Las capturas sucesivas no equivalen a un snapshot atómico. SHA256SUMS demuestra integridad local, no prueba externa de procedencia o causalidad. El estado `SSH_DENY_COUNTER_BASELINE_ONLY_NO_GO` es preparatorio; no permite pentesting.

La siguiente etapa R42.1 debe aportar **origen atribuible de paquetes**, estímulo autorizado y acotado en el segmento del laboratorio, observación de entrada/salida por superficies independientes y controles positivos/negativos. Un incremento de contador por sí solo no admite `PASS_ISOLATION`.

## Operación en Prometheus (sin tráfico)

```bash
cd /home/cicada/Development/GitHub/ardrec
BASE=/home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND
sudo -v
python3 -B scripts/ardrec_p14_r42_isolation_baseline.py \
  --r411-observation "$BASE/r411-external-ssh-20261114T224307Z-5663" \
  --r41-preflight "$BASE/r41-ssh-preflight-20261114T223009Z-5663" \
  --r40-preflight "$BASE/r40-ssh-preflight-20261114T221736Z-5663" \
  --r39-reconciliation "$BASE/r39-ssh-reconciliation-20261114T215708Z-5663" \
  --r365-preflight "$BASE/recibos-preflight-r365-20261114T200434Z-94940" \
  --r365-first-boot "$BASE/recibos-first-boot-r365-20261114T200824Z-98270" \
  --receipt-dir "$BASE/r42-counter-baseline-$(date -u +%Y%m%dT%H%M%SZ)-$$"
```

Recibo `r42_counter_baseline.json` y `SHA256SUMS` bajo carpeta nueva `0700`, ficheros `0600`, sin salida cruda ni huellas sensibles en Git. Bloqueo sin mutación ante deriva, error de permisos, falta de recursos o reglas cambiadas.

## Pruebas y gobernanza

```bash
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r42*.py' -q
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14*.py' -q
python3 -B scripts/verificar_trazabilidad_actual.py
git diff --check
```

Firmar commits con SSH, abrir PR, esperar CI, fusionar mediante merge normal de rama protegida. No habilitar `--admin`, `--auto` ni publicar recibos privados.
