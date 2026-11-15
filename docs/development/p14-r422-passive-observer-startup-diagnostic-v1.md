# ARDREC P14-R42.2-D1 — Diagnóstico pasivo del arranque de observadores

## Motivo

Después del intento R42.2 que terminó `observer_exited_before_header_tap`, el recibo privado válido demuestra que no se obtuvo cabecera PCAP. Una autorización `sudo -l` y un filtro BPF compilable no acreditan que el proceso real haya conseguido abrir la captura. R42.2 original consume `stdout` sin conservar en el informe el `stderr` de arranque. No repetir ICMP para investigar.

## Alcance

Script independiente de diagnóstico **solo pasivo**: reutiliza la cadena de fuentes selladas R41.1/R42.0/R42.1, verifica el preflight físico actual y ejecuta para TAP/puente **exactamente** el argv de observador existente (incluido `timeout 18`), pero interrumpe cada observador al obtener la cabecera o al vencer un máximo de 3.5 segundos. Supervisa el grupo de procesos y registra el código de salida, la presencia/corrección de la cabecera PCAP y `stderr` clasificado, huella SHA256 y extracto breve. Se permite observar ARP/ICMP ya presente, pero **no se inyecta tráfico**.

No utiliza QEMU Guest Agent, `guest-exec`, `ping`, ajustes de interfaces, red/libvirt, nftables ni operaciones de VM. Sin instalación, apertura de firewall, reinicios, ni nuevos intentos activos. Requiere una **autorización independiente** para abrir capturas pasivas. Los datos resumidos se guardan en directorio privado nuevo (0700, archivos 0600, `SHA256SUMS`) ajeno al repositorio. No guarda PCAP crudo. El diagnóstico no acredita aislamiento. Siempre `P8=NO-GO`.

## Semántica

`PASSIVE_OBSERVERS_READY_NO_GO`: se obtuvo cabecera PCAP de ambos observadores, pero no se ha ensayado tráfico. `PASSIVE_OBSERVER_STARTUP_FAILURE_NO_GO`: al menos un observador no proporcionó cabecera válida; examinar `stderr_class`, `stderr_excerpt` y `exit_code` en el recibo. `BLOCKED_NO_PACKET_INJECTION`: guardas de origen, host, archivo privado o permisos bloquearon el diagnóstico. No repetir ensayo R42.2 hasta resolver la causa.

No se alteran los 4 archivos existentes R42.2, ni los recibos históricos. La prueba de 981 casos P14 se amplía con pruebas de este script, sin modificar la máquina, el huésped ni su red.

## R42.2-F2 — Conservación de sesión de terminal para sudo

El diagnóstico físico D1 (`r422_observer_diagnostic.json`, SHA interno `3820c0d4dcc9829d73600f1e8670c386f3474a0ad7a5f6b6cd0b86ac356c04b8`) confirmó que ambos observadores fallaron por `sudo: a password is required` aunque `sudo -l` aprobó los comandos. Se corrige el uso de `subprocess.Popen(start_new_session=True)` por `process_group=0`: cada proceso obtiene un grupo propio para señales `killpg`, **sin salir de la sesión/TTY del operador**, conservando la posible caché de `sudo -v` por terminal. La autorización sigue siendo `sudo -n` y **nunca se introduce `NOPASSWD`**, contraseñas en tuberías ni permisos amplios. Si el sudoers usa otro modo de caché y sigue denegando, se conserva bloqueo `NO-GO`. Primero repetir exclusivamente D1 con recibo nuevo; R42.2 activo exige una autorización nueva, sin reintento automático.
