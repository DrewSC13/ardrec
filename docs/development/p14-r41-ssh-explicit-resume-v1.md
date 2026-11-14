# ARDREC P14-R41 — Reanudación SSH con autorización independiente

Base exacta: `80430ca74ba37018b0f1ecf95fd78a737c33d928` (PR #111). Estado confirmado en Prometheus: R39 red SSH activa/VM apagada; recibo R40 `POSTBOOT_STORAGE_CONTAINMENT_CONSISTENT_NO_GO`, SHA-256 **4666328583d16c8be5d9be15250be98779a3e6868bd7b0a2c91bca450e56bda7**.

## Contrato de operación

- Modo `--preflight-only`: SOLO lectura física y almacenamiento, más recibo local privado. Autentica recibos R36.5, R39 y el recibo R40 fijado por su SHA interno. Revalida desde el archivo fuente R32–R34 autenticado nftables, nwfilter, XML, MAC, inventarios, red SSH y puente, inactividad de las cuatro VM y de FTP/SMB, y las 12 imágenes QCOW2. Exige que ningún overlay difiera de la observación postarranque R40. Exige MemAvailable >= 2816 MiB (768 MiB SSH más 2048 MiB reserva). Ninguna autorización operacional se deriva de ese recibo.
- Modo `--resume-ssh --prior-r41-preflight <directorio> --i-authorize-r41-ssh-resume`: una autorización nueva del operador, completamente separada del primer arranque R36.5. Requiere preflight R41 autenticado y con antigüedad de **máximo 20 minutos**, repite la validación física y de almacenamiento, vuelve a leer el estado inmediatamente antes de mutar, crea un recibo **de intención antes de ejecutar** y solo permite `sudo -n -- /usr/bin/virsh -c qemu:///system start ardrec-r33-dev-ssh`. Nunca emite `net-start` ni comandos sobre FTP/SMB/runner.
- Verifica `r365.current(phase='SSH_RUNNING')` tras el intento único. Al confirmarlo registra `SSH_RESUMED_DENY_FIRST_UNTESTED`. Cualquier fallo en la mutación o lectura posterior registra `PARTIAL_NO_GO_REVIEW_REQUIRED`, sin reinicio repetido, rollback, shutdown ni recuperación automática. **En resultado parcial, la VM podría haber arrancado: no repetir la operación.**
- El recibo lleva `attempt_id` aleatorio (128 bits), enlace al preflight autorizado, observación física y un manifiesto SHA256SUMS. Los permisos son carpeta 0700 y archivos 0600, destino nuevo exclusivo. SHA local no equivale a firma independiente ni evita por sí mismo repetir una autorización deliberada; no existe mecanismo global de bloqueo de intentos duplicados fuera del host.
- Ninguna prueba del huésped, consulta del Guest Agent, ping, escaneo de puertos, SSH, FTP o SMB. Las comprobaciones positivas y negativas de aislamiento se harán después y con otro contrato, antes de admitir evidencia real A6. `P8=NO-GO`, `experimental_validation=NOT_RUN`, `final_risk=null`, `operational_dispatch=false` en ambos modos.

## Instrucciones para Prometheus

```bash
cd /home/cicada/Development/GitHub/ardrec
sudo -v
BASE=/home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND
ARCHIVE="$BASE/source-r32-r33-r34.tar.gz"
python3 -B scripts/ardrec_p14_r41_ssh_resume.py \
  --preflight-only \
  --source-archive "$ARCHIVE" \
  --r365-preflight "$BASE/recibos-preflight-r365-20261114T200434Z-94940" \
  --r365-first-boot "$BASE/recibos-first-boot-r365-20261114T200824Z-98270" \
  --r39-reconciliation "$BASE/r39-ssh-reconciliation-20261114T215708Z-5663" \
  --r40-preflight "$BASE/r40-ssh-preflight-20261114T221736Z-5663" \
  --receipt-dir "$BASE/r41-ssh-preflight-$(date -u +%Y%m%dT%H%M%SZ)-$$"
```

**Detenerse después del preflight.** La autorización del segundo modo no está implícita en haber aplicado el parche ni en que el preflight devuelva PASS. Evaluar su resultado con el operador antes de permitir el comando físico.

## Límites

La captura física es secuencial, no atómica. Las lecturas de imagen antes del arranque observan un instante; la existencia de políticas deny-first no demuestra bloqueo real de tráfico. Se mantiene sin acreditación la identidad del sistema operativo invitado y la causa histórica del apagado. La máquina puede apagarse nuevamente por sus políticas de ciclo de vida. Los controles R41 no otorgan permiso de pentesting, despacho ni riesgo final.
