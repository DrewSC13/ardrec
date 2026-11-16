# ARDREC · R58-Y — Registro durable y TUI de observaciones SSH verificadas

**Base fijada:** `930866989b8343d14dbe5a76b1719d0e6239c182` (PR #156); tesis SHA256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`.

## Capacidad funcional / Functional capability

**ES.** Permite importar el primer par de recibos históricos SSH R42.2 y R42.3 **realmente tomados en una VM DEV**, usando `r424_evidence_tui.read_physical`, `r422.verify_private_receipt` y el validador R423. No repite el ICMP, no ejecuta VMs y no establece una autenticación externa que no existe. Registra solo la proyección técnica verificada (ruta, ARP, contadores, PCAP, tiempos y huellas); mantiene los recibos originales en su ubicación privada. Un SQLite privado conserva la identidad determinista, deduplica reimportaciones y permite cerrar/reabrir la TUI, siempre que las fuentes originales permanezcan accesibles e idénticas. En cada reapertura **vuelve a verificar físicamente los archivos históricos**, no consulta en vivo el huésped.

**EN.** Imports an existing pinned, validated SSH R42.2/R42.3 historical physical observation into a durable private SQLite projection. On reopening it revalidates the unchanged original private receipts. This is **not** operational evidence admission or a network test.

## Limitaciones explícitas / Evidence boundaries

- R42.2 informa que la captura observó cero tramas TAP/bridge y el huésped reportó un ICMP enviado; R42.3 registra lectura posterior de ruta/ARP/contadores. Son mediciones de tiempos diferentes, sin demostración de causalidad ni de aislamiento general. No son una comprobación de login exitoso ni de vulnerabilidad SSH.
- Identidad `OBS_SSH_<SHA256>` determinista sobre hechos y marcas de captura; hash del registro SQLite detecta corrupción, **no garantiza autenticación contra un adversario que pueda editar también los hashes**.
- A5: sin identidad de intento enlazada. **No significa** que ningún intento físico haya existido en todo el laboratorio. A6=`ND` por falta de enlace con una condición declarada; `Rf` no calculado con esta observación y A9 no publicada. P8=`NO-GO`.
- La selección FTPS/SMB está visible, pero no admite automáticamente recibos de esos servicios: **sin recibo verificable** hasta que la barrera F11 y las pruebas de servicio se acrediten. Los 25 evaluadores de familias R58-K siguen siendo previsualizaciones.
- La vista de `R58-X` sobre `NO_START -> ND` corresponde a un **modelo separado** y no queda vinculada fraudulentamente al recibo físico SSH.
- Los timestamps se copian de los recibos validados, no del reloj de visualización. Falta aún la ruta de aceptación A6 con doble testigo, cálculo confirmado A7 y publicación integral A9.

## Uso desde Prometheus

Exige `CWD=/home/cicada/Development/GitHub/ardrec` y terminal Zsh. Recibos existentes según la documentación R42.4 (ajustar a la ruta REAL privada), y SQLite **fuera del repositorio**:

```zsh
cd /home/cicada/Development/GitHub/ardrec
mkdir -p -m 700 /home/cicada/ardrec-lab/r58y
BASE=/home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58y_observations.py --import-ssh \
  --r422-result "$BASE/r422-pcap-20261115T004614Z-5663" \
  --r423-result "$BASE/r423-guest-path-20261115T010451Z-5663" --texto
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58y_observations.py --tui
```

`--init` crea un registro vacío, sin evidencia ficticia. `--json`, `--texto` y `--verify` no ejecutan pruebas. La TUI permite `1 SSH`, `2 FTPS`, `3 SMB`, `j/k` entre servicios, flechas arriba/abajo para desplazamiento y `q` para volver al prompt. No se redirige la TUI a `more`; sí se paginan las salidas extensas de pruebas/inspección. Los caminos privados solo se almacenan en el SQLite local y **no se incorporan al ZIP ni al repositorio público**.

## Pruebas y trazabilidad

El incremento añade pruebas contra cambios entre lecturas, repetición idempotente, persistencia y reinicio, cambio de fuente después de importar, modificación de JSON o DB, recalculo malicioso de digest para A6=true, permiso 0644, symlink, ausencia de fuentes FTPS/SMB, geometría terminal y aislamiento de A5/A7/A9/P8. CI añade la suite `test_p14_r58y_*.py`. El ensamblador del ZIP y su lanzador no realizan commit ni merge: el operador deberá revisar el diff, ejecutar regresión, firmar GPG, crear PR y verificar CI antes de integrar.

**Criterio de aceptación del incremento:** Si las fuentes históricas siguen presentes y válidas: importación `IMPORTED`, repetición `REPLAY_IDENTICAL`, una sola observación SSH persistente y reapertura verificable con la misma identidad; fuente alterada, ausente o no reconocida produce salida 23. No confundir esta aceptación de software con A6 admitida ni F11 habilitado.
