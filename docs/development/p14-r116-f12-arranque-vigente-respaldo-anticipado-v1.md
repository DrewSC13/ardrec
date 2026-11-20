# R116-F12 — Arranque aislado por HEAD y respaldo anticipado DENY (fuentes, NO-GO)

## Alcance y reconciliación

F10 acreditó un disparo de systemd configurado a 60 segundos y observado a 63,252 segundos; F11 acreditó la reaplicación DENY 0/6 en 63,242 segundos observados. Ninguna de esas medidas es una garantía de restauración desde reglas permisivas antes del segundo 60.

Este cambio **no reescribe ni desautoriza** el historial R115-F7/F8. Copia su contrato de arranque con dominios de firma, rutas de recibos y raíces de confianza propios de R116-F12; requiere que `source_commit` corresponda al HEAD Git firmado y sigue utilizando el revisor Ed25519 con revocación actual R116-F2. `--plan` no arranca máquinas; `--boot` requiere permisos externos independientes de arranque y autorizaciones específicas por rol, además de intervención explícita. La ausencia de esos permisos mantiene la ejecución bloqueada. Una denegación después de consumir el marcador prohíbe el reintento.

## Respaldos temporales

El guardián F1 mantiene el límite documental **máximo de 60 segundos** pero adelanta `systemd-run --on-active` a **45 segundos**, con `AccuracySec=1s`. El recibo del guardián separa `duration_seconds=60` de `backup_delay_seconds=45`. El controlador F3 exige ambos valores; la sola existencia de un temporizador no autoriza tráfico. Se siguen verificando su estado activo, deadline monotónico, permisos/revocaciones vigentes y estado físico 5/1 antes y durante la operación.

La anticipación de 45 segundos **no es una garantía temporal dura**: systemd puede experimentar latencia de planificación o fallo del anfitrión. No acreditar seguridad de apertura estrictamente limitada a 60 segundos hasta demostrar una barrera física/kerneI de expiración y recuperación desde reglas permisivas bajo fallo. F1/F3 instalados como root permanecen en su versión F8 hasta migración separada firmada, sin sobrescribir ni perder los recibos F9/F10/F11.

## Trazabilidad de recibos

F3 deja de buscar R115-F8 como si fuera un arranque nuevo: espera planes y recibos específicos de `/home/cicada/ardrec-lab/r116-f12-runner-ftp-deny-v1` y los reproduce mediante el código R116-F12 ejecutado como usuario no privilegiado. R113/R114 y sus recibos físicos históricos permanecen inmutables y no son un permiso P7/P8.

## Criterios de cierre de este incremento

- Nuevos validadores de la cadena SSH→runner→FTP, vinculados a rama y HEAD R116.
- Separación de raíces de confianza de arranque R115/R116 y dominios de firma.
- Manifiestos root F1/F3 actualizados por hashes exactos, y suite de regresión R112–R116 en CI.
- Fuente exclusivamente, sin sudo, `virsh start`, `nft -f`, `systemd-run`, tráfico ni firma externa emitida.
- **P7=DRAFT; A5 físico nuevo=NOT_ATTESTED; A6=ND; P8=NO-GO.**

## Pendientes para aceptación física

1. Instalar las nuevas fuentes F1/F3 en una migración administrativa independiente, preservando versiones anteriores.
2. Proveer raíces de confianza y revocaciones independientes actuales de alcance, arranque y piloto; no autogenerarlas.
3. Acreditar arranques físicos 1/5 → 4/2 → 5/1 con recibos firmados R116 nuevos y SMB apagada.
4. Probar recuperación bajo fallo y límite efectivo desde reglas permisivas antes de ejecutar FTP-T01.
5. Reconciliar resultado A5 con soportes A6; no inferir vulnerabilidad del banner FTP `220`.
