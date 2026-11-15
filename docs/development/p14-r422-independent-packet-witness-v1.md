# ARDREC P14-R42.2 — Testigo independiente limitado TAP/bridge

## Base y motivación

Base Git firmada `728a4b07219ba9a7f4e0d16cb2e05543d14849dd` (PR #114), recibo privado original R42.1 `r421_negative_probe.json` con digest interno `c59303812eba75bd44392a585de79f678070f49f276b32b7f5fff18a804f47d9`. Se autentica el historial R42.0→R41.1→R41→R40→R39→R36.5. R42.1 observó 1 paquete transmitido según `ping`, 0 respuestas, pero 0 deltas en los cuatro contadores nftables: no es prueba de entrega de paquetes ni de bloqueo.

R42.2 instrumenta **dos observadores pasivos independientes del agente del huésped** con `tcpdump -w -`: TAP `a33d30t` y bridge `br33d30`, bajo filtro fijo `ether src 52:54:00:ad:30:02 and (arp or icmp)`. `-p` evita modo promiscuo; límites: máximo 12 paquetes/observador, snaplen 128 bytes y duración 18 s por proceso; ningún archivo temporal bruto fuera del directorio privado del intento. Los PCAP y sus hashes se almacenan allí con modos 0600; no van a Git. Se exige lectura del encabezado PCAP de **ambos** procesos antes de intentar el paquete.

El único estímulo autorizado es `guest-exec` de `/usr/bin/ping` con origen `10.203.30.2/28`, destino `10.203.30.1` (runner apagado), `-c 1 -W 1`, `-s 56` y patrón aleatorio de 8 bytes fijado en el recibo de intención. Puede generar ARP. El patrón permite identificar un ICMP Echo Request específico si llega a un observador. La observación ARP no contiene el patrón y **no acredita por sí sola causalidad**. No hay instalación de herramientas ni cambios en el huésped, nftables, libvirt, bridge o interfaces. El proceso de captura es temporal y supervisado, y el operador deberá autorizar una sola ejecución adicional, separada del preflight.

## Resultados y límites de inferencia

- `TAP_ONLY_PACKET_WITNESSED_NO_GO`: TAP observó ARP/ICMP de la MAC/IP esperadas; bridge no observó esos paquetes. Es evidencia de observación, **no** prueba de que nwfilter o nftables causaran el bloqueo.
- `BRIDGE_PACKET_WITNESSED_REVIEW_NO_GO`: bridge también vio tráfico; revisar sin inferir alcance fuera del bridge.
- `NO_GUEST_EGRESS_WITNESSED_NO_GO`: el huésped informó transmisión pero el observador no identificó ARP/ICMP; puede ser pre-filtro, pérdida de observación u otra causa.
- `INCONCLUSIVE_PACKET_WITNESS_NO_GO`, `UNEXPECTED_REPLY_REVIEW_NO_GO` o `REVIEW_REQUIRED_GUEST_ACTION_POSSIBLE`: mantener evidencia y no reintentar automáticamente.

La ausencia de paquete en bridge no demuestra inexistencia de otro camino; la mera lectura del encabezado PCAP no acredita entrega. Los contadores nftables siguen siendo deltas no atribuibles. No hay testigo positivo de destino, por lo que `isolation_proven=false`, `operational_dispatch=false`, `final_risk=null`, `p8_operational=NO-GO` en **todos** los resultados. R42.3 deberá considerar un destino controlado y una prueba positiva/negativa bajo una autorización nueva.

## Procedimiento

1. Aplicar parche con SHA256 y `--check` sobre rama `feat/p14-r422-independent-packet-witness-main` exactamente desde base `728a4b0`, sin cambios locales.
2. Ejecutar pruebas R42.2 y P14 completas y `scripts/verificar_trazabilidad_actual.py` en Prometheus.
3. Ejecutar solo `--preflight-only` para verificar historial, contención, contadores inmutables e instalación de `tcpdump` en ruta permitida, sin contacto con Guest Agent ni emisión de paquetes. Si falta tcpdump, **bloquear** y no instalarlo por efecto lateral.
4. La ejecución activa es opcional, nueva y requiere autorización explícita del operador con `--execute-observed-one-icmp --i-authorize-r422-captured-guest-agent`. Registrar intención antes de todo QGA. Si se produce fallo o salida incierta, conservar el intento y **no repetir** automáticamente.
5. Recibo y PCAP en `r35-private-.../r422-pcap-...` con 0700/0600 y SHA256SUMS. Nunca leer ni hashear overlay QCOW2 activo, cambiar firewall, iniciar FTP/SMB/runner, escanear, tocar Internet ni activar P8.

El ejecutor utiliza siempre subprocess sin `shell=True` ni `set -euo pipefail`; espera procesos de captura con terminación supervisada. Toda discrepancia física produce NO-GO conservador.

## R42.2-F2 — Conservación de sesión de terminal para sudo

El diagnóstico físico D1 (`r422_observer_diagnostic.json`, SHA interno `3820c0d4dcc9829d73600f1e8670c386f3474a0ad7a5f6b6cd0b86ac356c04b8`) confirmó que ambos observadores fallaron por `sudo: a password is required` aunque `sudo -l` aprobó los comandos. Se corrige el uso de `subprocess.Popen(start_new_session=True)` por `process_group=0`: cada proceso obtiene un grupo propio para señales `killpg`, **sin salir de la sesión/TTY del operador**, conservando la posible caché de `sudo -v` por terminal. La autorización sigue siendo `sudo -n` y **nunca se introduce `NOPASSWD`**, contraseñas en tuberías ni permisos amplios. Si el sudoers usa otro modo de caché y sigue denegando, se conserva bloqueo `NO-GO`. Primero repetir exclusivamente D1 con recibo nuevo; R42.2 activo exige una autorización nueva, sin reintento automático.
