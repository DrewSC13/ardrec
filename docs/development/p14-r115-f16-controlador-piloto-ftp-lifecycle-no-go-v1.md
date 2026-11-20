# R115-F16 — Frontera física de piloto P7 FTP-T01

**Base Git requerida:** `9a1d95a7df5da3a400489f815161b4dc00faa689` (F15 firmado). **Rama:** `feat/p14-r115-a3-p7-a6-real`.

## Integración comprobable

- Se relee el estado físico mediante el capturador F5, contrastando la huella del recuperador R113-F6, el hook F11, las definiciones y los `nwfilter-binding` actuales. No se acepta un estado de una captura antigua.
- El estado de arranque FTP previsto por F7/F8 es **SSH, runner y FTP activos; SMB apagada**. Las seis posiciones de vinculación deben presentar **cinco filtros DENY activos (runner-SSH, runner-FTP, runner-SMB, SSH, FTP) y una ausencia justificada por estado apagado (SMB)**.
- Se valida el recibo físico FTP de F8 mediante `replay()`: esta función verifica también el recibo runner y, recursivamente, el recibo SSH de F7; no se aceptan etiquetas de estado sin recibos verificables.
- El permiso F15 se evalúa con la autorización de alcance F6, claves públicas root-owned y revocación vigente; un documento firmado NO es un despacho físico.
- El ejecutor R114-F5 antiguo no puede reutilizarse como controlador R115: su ventana es de 120 s y su recuperación histórica exige **6/6 vinculaciones activas**. F15 exige una ventana independiente de hasta 60 s y el estado físico FTP diseñado tiene 5 activos + 1 apagado.

## Estado y bloqueo funcional

Este incremento verifica el estado **actual** y proporciona un contrato programático seguro para un futuro controlador raíz. No instala reglas permisivas, no ejecuta `virsh start`, no abre sockets, no emite firmas, no modifica P7 y no promueve A5 a A6. Su evaluación termina siempre con `P8=NO-GO`, aun ante documentos válidos. Esto es intencional: no hay en F16 un ayudante raíz de ventana de 60 s, con denegación autónoma para el ciclo de vida 5/1, que pueda atestarse en Prometheus. Crear esa capacidad requiere una implementación y prueba separadas; no se ejecutará la política de 120 s de R114 como sustituto.

La ruta posterior es: implementar root-owned deny-first, temporizador autónomo de restauración 60s, verificación pre/post real, permiso externo efectivo y conexión única desde runner. Cada acción requiere identidad, evidencia y autorización independiente. La familia FTP-T01 sigue en borrador `P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE`; este componente NO habilita el catálogo general.

## Uso seguro

`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts python3 scripts/ardrec_p14_r115_f16_physical_pilot_controller.py --capabilities`

`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts python3 scripts/ardrec_p14_r115_f16_physical_pilot_controller.py --inspect-current`

`--inspect-current` necesita `sudo -n` previamente autenticado en el TTY de Prometheus, pero **solo** para consultas de lectura F5. Se conservan recibos privados 0700/0600 bajo `/home/cicada/ardrec-lab/r115-f16-physical-pilot-review-v1/` y manifiesto SHA-256. Cuando existan documentos externos o recibos de arranque, deben proporcionarse únicamente a través de las opciones explícitas `--contract`, `--authorization`, `--pilot`, `--ftp-plan` y `--ftp-boot`. Las claves privadas nunca entran en ARDREC.
