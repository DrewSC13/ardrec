# P14 R42.4 — TUI de evidencia física SSH + A1–A10 de desarrollo

Base inmutable `b67550840b3b30f29361654bfed3d573a7167e59` (PR #116). Este incremento da una vista terminal única sobre dos recibos físicos privados autenticados (R42.2 y R42.3) y sobre un ciclo de desarrollo A1–A10 calculado en memoria desde el fixture fijo. **No ejecuta pentesting real ni certifica aislamiento; P8=NO-GO.**

## Distinción de fuentes

- Bloque `REAL_READONLY_SSH_SNAPSHOT`: R42.2 confirma cero tramas en TAP y puente bajo su filtro, con ping que notificó un paquete transmitido; R42.3 confirma ruta directa `ens3`, ARP ausente, TX=0 y RX=15 en lectura posterior. No son mediciones simultáneas ni prueban causalidad, bloqueo ni entrega.
- Bloque `SYNTHETIC_A1_A10_DEVELOPMENT_ONLY`: se construye a partir de `lab/p14-r26-session-v1/scenario.json` sin ejecución real de SSH, FTP o SMB. Los estados `PENDING`, `ND`, `NOT_EXECUTED` y `NO-GO` se conservan.
- Fuentes: recibo R42.2 SHA256 `7816e46d3fd4b24a50bce0171bffd4d3ea307167485f5111529b4b9ed10f3ae6`; recibo R42.3 SHA256 `5e2444b0f4c3c928f887274938eebb2bc085290f20c476d982283a07e2d44dd8`.

## Operaciones y límites

La herramienta **no** contiene llamadas a `subprocess`, `sudo`, `virsh`, `tcpdump`, sockets o escritura de archivos. Verifica inventario y huellas de recibos con validadores del repositorio. Salida `--texto`, `--json` o `--tui` interactiva (`q` salir; `j/k` o flechas para cambiar algoritmo). No almacena capturas, no materializa recibos fuera del área privada y no introduce datos privados en el commit.

## Uso

```
BASE=/home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND
python3 -B scripts/ardrec_p14_r424_evidence_tui.py \
  --r422-result "$BASE/r422-pcap-20261115T004614Z-5663" \
  --r423-result "$BASE/r423-guest-path-20261115T010451Z-5663" \
  --texto
```

Reemplazar `--texto` por `--tui` cuando se use una terminal interactiva de al menos 70 × 22. Modo JSON igualmente de solo lectura. Pruebas: test P14 R42.4, regresión P14, trazabilidad y `git diff --check` antes del commit firmado. Se preservan AL-06 y AL-07; ninguna generación A9 ni Rf técnico se acredita.
