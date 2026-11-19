# ARDREC — R112-F12: reanudación controlada SSH → runner después del reinicio

**Tipo:** recuperación física, con nuevas autorizaciones de un solo uso.
**Rama:** `feat/p14-r111-r114-real-lab`.
**Padre inmutable:** `f92e42c100497b09a961ca70d09b3454beb49ac8` (F11N).
**Estado:** P8 = `NO-GO`; R34 = `DENY`; observaciones A5/A6/A7/A9 = **no acreditadas**.

## Antecedentes verificables

El equipo Prometheus se reinició; el diagnóstico de 2026-11-19 confirmó cuatro VM apagadas, tres redes inactivas, unidades R34 presentes, hook F11 con SHA verificado y ausencia de leases temporales. Posteriormente, F11N reactivó exactamente las redes SSH, FTP, SMB sin arrancar VM. Su replay histórico retornó `R112_F11N_REPLAY=PASS` y fijó el recibo `9eea08bfb68a80af06b360d029c7b7912cddf659a307df7129f72740d406f427`.

Los recibos pre-reinicio F8S y F9 se **preservan como históricos**, no se presentan como prueba de ejecución actual de QEMU. Esta recuperación NO reutiliza tickets F11, leases ni planes de arranque anteriores. No modifica F10.

## Contrato de F12

1. `--plan --role ssh`: enlaza el replay F11N; exige cuatro huéspedes apagados, tres redes activas, F11 y R34 intactos, 29 sondas legibles, filtros `DENY`, y ningún lease/marker SSH previo. Genera `plan-*` privado 0700 con archivos 0600.
2. `--boot --role ssh`: autorización explícita, verifica contra una segunda captura, registra `boot.once` duradero, emite un ticket de 180 segundos específico para SSH, instala un lease root 0600, verifica su SHA, realiza **exactamente un** `virsh start ardrec-r33-dev-ssh`, comprueba estado final, las tres etapas F11, live XML y DENY. No hay reintento ni apagado automático.
3. `--replay --role ssh`: comprueba el plan y el recibo físico **sin arrancar ninguna VM**.
4. `--plan --role runner --previous-ssh-plan ... --previous-ssh-receipt ...`: primero reproduce el nuevo recibo SSH de F12; requiere SSH encendida, runner/FTP/SMB apagadas, redes y protecciones intactas. Crea un nuevo plan.
5. `--boot --role runner`: segunda autorización explícita, ticket F11 independiente, un único `virsh start` para runner y validación física completa. No altera SSH ni las demás VM.
6. `--replay --role runner`: comprueba la cadena F11N → F12 SSH → F12 runner sin cambiar el host.

**Prohibido**: abrir puertos, modificar `nftables`, `nwfilter`, XML libvirt, directorios de leases existentes, ejecutar comandos `destroy`, `shutdown`, `reboot`, habilitar autostart, repetir arranques o limpiar marcadores tras un incidente. Ante cualquier resultado incierto, se preservan el estado físico y las evidencias; `P8=NO-GO`.

## Evidencias privadas y control experimental

Directorio `/home/cicada/ardrec-lab/r112-f12-postreboot-ssh-runner-v1` con sesiones `plan-*` y `boot-*`, recibos SHA-256, capturas previas/posteriores, comandos, leases y fases del hook. No agregar estas evidencias privadas a Git. Mantener código, pruebas y documentación con commit firmado en la rama actual. No push/PR/merge hasta terminar R111–R114.

Las pruebas de regresión usan fixtures offline y **no** cuentan como observaciones SSH, FTP ni SMB reales. El arranque QEMU tampoco acredita disponibilidad del protocolo ni A5–A9. No usar `P8=GO` sin autorización operacional independiente.

## Continuidad / Next steps

**ES:** Tras dos recibos F12 válidos, preparar F10 FTP y SMB en planes nuevos, auditando la cadena F12 antes de autorizar cada arranque. Después establecer admisión temporal estricta del tráfico de laboratorio y observaciones R113 con procedencia real, seguidas de R114 (A1–A10, persistencia, TUI, trazabilidad y evaluación experimental).
**EN:** F12 restores two individually authorized, one-use QEMU boots while preserving deny-by-default networking. It does not authorize protocol tests or the thesis's operational evaluation.
