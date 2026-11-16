# ARDREC R58-A / F11-P F2 — CI de auditoría de arranque

## Alcance

El incremento añade una sola etapa Python en `.github/workflows/ci.yml`, inmediatamente después del gate R58-A/FTP; incorpora una prueba del contrato de descubrimiento y preserva los cuatro archivos F11-P existentes. Ningún paso ejecuta el guardia root, invoca sudo, accede al host de Prometheus ni modifica libvirt, nftables, systemd o máquinas virtuales.

## Procedencia e invariantes

- Merge base `c238f44a7f8cb9f8c251424fa7b5d9c9e9c7e94d` (PR #132).
- Rama de integración `feat/p14-r58a-f11p-boot-readiness`.
- Ancla CI: el archivo previo debe tener SHA-256 `a49cde185a8e2881be956dddd4bc6297a224a8da0bc19910bd5be91af4d4f4ee`.
- El instalador comprueba las SHA-256 de los cuatro archivos F11-P/F1 antes de incorporar la etapa a CI.
- Las pruebas ejecutables en CI son offline: `test_p14_r58a_f11p_*.py`; no invocan el modo `--host-readonly`.

## Resultados observados en Prometheus previos a este incremento

- F11-P/F1: 43 pruebas sintéticas PASS y ejecución física de **solo lectura** (`RC=21`).
- Estado: `BLOCKED_F11_BOOT_GUARD_UNSTARTED`.
- `R34 DENY`: dos lecturas estructuralmente verificadas; `nwfilter`: DROP ALL.
- Archivos raíz `root:root`, directorio `700` con 2 enlaces, tres archivos `600` con 1 enlace cada uno.
- `libvirtd` activo con dependencia de orden pero sin dependencia obligatoria del guardia; primera ejecución no documentada.

## Restricciones

`P8=NO-GO`; ni la instalación ni las pruebas del gate acreditan F11, el arranque manual bloqueado, el watchdog independiente o autorización de FTP. La implementación efectiva de esos controles será un incremento separado, sujeto a preflight y autorización física explícita.

## EN

Adds one Python-only CI step for offline F11-P boot-readiness tests, preserves FTP checks, and attests no host operations. No first-boot, independent recovery or manual guest boot authorization is implied.
