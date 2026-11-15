# ARDREC P14-R42.3 — Diagnóstico del camino del huésped sin estímulo

## Base y evidencia

Base de código fija: `7e2936d0e9c61e42fbacae11affeee592abd4897`, PR #115. Recibo R42.2 físico fijo: SHA interno `7816e46d3fd4b24a50bce0171bffd4d3ea307167485f5111529b4b9ed10f3ae6`. Exigir inventario exacto `r422_intent.json`, `r422_packet_witness.json`, `r422-tap.pcap`, `r422-bridge.pcap`, `SHA256SUMS`, verificación semántica de PCAP y toda la cadena R42.1/R42.0/R41.1/R41/R40/R39/R36.5. R42.2 observó cero tramas TAP y puente; cero deltas nftables; el huésped declaró `ping` 1 transmitido y 0 recibidos. Esto **no** acredita aislamiento.

## Alcance

`--preflight-only`: valida la cadena, el estado SSH_RUNNING y las reglas/counters mediante el preflight de R42.2; no contacta a QEMU Guest Agent, no crea recibo y no genera tráfico.

`--i-authorize-r423-guest-readonly`: requiere autorización nueva. Crea recibo de intención antes de cualquier acción del agente. Solo permite `guest-ping`, `guest-network-get-interfaces`, `guest-exec` de `/usr/bin/cat` con un argumento que sea exactamente uno de `/proc/net/route`, `/proc/net/arp`, `/sys/class/net/ens3/statistics/tx_packets`, `/sys/class/net/ens3/statistics/rx_packets`, y `guest-exec-status` con PID válido. No interpreta comandos de shell ni invoca `ping`, `ip`, `ssh`, escaneos o herramientas de red. Guarda solo clasificaciones de ruta/ARP, valores numéricos e identidades SHA256 de las lecturas, sin copiar `/proc` crudo en recibos. Compara inventario de host antes/después. Registra el error como recibo privado si una ejecución del agente queda inconclusa; **sin reintento automático**.

La lectura de `/proc/net/route` solo informa rutas del núcleo visibles en ese momento; no sustituye un `ip route get` y puede no explicar reglas de policy routing. `/proc/net/arp` puede carecer de entrada si no existe una resolución reciente; `ABSENT` no equivale a bloqueo. Los contadores de interfaz son acumulados, no deltas atribuibles a R42.2; no reconstruyen tráfico histórico. QGA y el proceso `cat` sí se ejecutan dentro del huésped, pero no generan un estímulo de red. Ningún resultado acredita aislamiento, no ejecuta pentesting ni permite elevar `P8`.

## Pruebas, gobernanza y próximo paso

Probar suite nueva y `test_p14*.py` completa, trazabilidad, staging exclusivo de cuatro archivos y commit SSH firmado. Mantener recibos privados fuera de Git. Después del resultado físico, el próximo incremento debe incorporar un **testigo positivo de recepción del laboratorio** (con receptor y topología autorizados) antes de cualquier prueba concluyente de aislamiento. **P8=NO-GO** en R42.3.
