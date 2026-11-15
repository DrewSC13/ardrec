# ARDREC R42.5 — Restauración del monitor clásico R38 con evidencia SSH sellada

## Objetivo

La interfaz introducida en R42.4 era una lista plana con diez vistas de texto. Esta entrega la sustituye como vista por defecto del mismo CLI (`--tui`, `--texto`) por el tablero **ya implementado en R38**: tres paneles (ALGORITMOS, DETALLE, ESTADO/AUDITORÍA), selección resaltada y navegación F1–F5, teclado directo 1..0, filtros, búsqueda y TAB.

No se borran R38 ni R42.4: `--json` conserva el bundle R42.4 exacto; el código de R38 conserva el motor de navegación y los estados. El adaptador R42.5 no implementa una segunda máquina de estados, solo añade observaciones físicas al panel de auditoría de R38 y las incorpora al detalle cuando el terminal tiene menor ancho.

## Proveniencia y límites

R42.4 autentica `r422_packet_witness.json`, PCAP y `r423_guest_route_inventory.json` con verificadores existentes y hashes fijados. R42.5 verifica además que el informe de desarrollo reconstruido coincida exactamente con el hash y las diez etapas de desarrollo vinculadas por el bundle. El panel informa **SSH FÍSICO / NO EN VIVO**, ARP ABSENT, TX 0, RX 15, TAP 0, BRIDGE 0; no atribuye causalidad ni acredita aislamiento. A1–A10 son solo ejecución o previsualización de desarrollo. A5 no ejecutó pentesting real; A6 no acredita una condición técnica; Rf final ND; generación técnica no publicada.

`P8=NO-GO` se presenta siempre. No hay llamadas a `virsh`, `sudo`, red, `tcpdump`, escritura ni despacho. Todos los recibos quedan fuera del repositorio y nunca se incluyen en los commits.

## Comando único (reemplaza la vista plana)

```sh
BASE=/home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND
python3 -B scripts/ardrec_p14_r424_evidence_tui.py \
  --r422-result "$BASE/r422-pcap-20261115T004614Z-5663" \
  --r423-result "$BASE/r423-guest-path-20261115T010451Z-5663" \
  --tui
```

Reemplazar `--tui` por `--texto` para un fotograma de 120 × 32 sin curses. `--json` sigue generando el bundle original de R42.4.

## Criterios de integración

- Todas las pruebas R42.5 y regresión P14 PASS.
- Paneles R38 y teclas existentes preservados; cero tramas fabricadas.
- `P8=NO-GO` y `Rf=ND` persistentes en texto, TUI y bundle.
- PR protegido, commit SSH firmado, tres verificaciones CI; ninguna promoción de evidencias sintéticas a condiciones técnicas reales.

Siguiente trabajo funcional, separado de esta corrección visual: recepción positiva aislada y conexión autorizada de los ejecutores técnicos A5/A6 a los algoritmos A1–A10.
